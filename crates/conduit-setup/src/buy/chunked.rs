// ---------------------------------------------------------------------------
// A5: Chunk planner — eMule Intelligent Chunk Selection (ICS)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use conduit_core::{encrypt, invoice, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};
use rand::seq::SliceRandom;

use crate::events::*;
use crate::state::*;

/// ICS mode, selected automatically based on the number of complete sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcsMode {
    /// <= 3 complete sources: rarest-first with random tie-breaking
    Release,
    /// 4-10 complete sources: shortest-to-complete first, then rarest
    Spread,
    /// > 10 complete sources: random shuffle with load-balanced assignment
    Share,
}

impl IcsMode {
    pub fn select(complete_sources: usize) -> Self {
        if complete_sources <= 3 {
            IcsMode::Release
        } else if complete_sources <= 10 {
            IcsMode::Spread
        } else {
            IcsMode::Share
        }
    }

    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            IcsMode::Release => "RELEASE",
            IcsMode::Spread => "SPREAD",
            IcsMode::Share => "SHARE",
        }
    }
}

/// Count how many sources have ALL chunks.
#[allow(dead_code)]
pub fn count_complete_sources(seeder_bitfields: &[Vec<bool>], chunk_count: usize) -> usize {
    seeder_bitfields
        .iter()
        .filter(|bf| bf.len() >= chunk_count && bf.iter().take(chunk_count).all(|&b| b))
        .count()
}

/// eMule Intelligent Chunk Selection.
///
/// Selects one of three strategies based on `complete_sources`:
///   - **RELEASE** (<= 3): rarest-first, random tie-breaking
///   - **SPREAD** (4-10): shortest-to-complete first, then rarest
///   - **SHARE** (> 10): random order, load-balanced assignment
///
/// Returns `(download_order, assignments, mode)`.
pub fn plan_chunk_assignments_ics(
    chunk_count: usize,
    seeder_bitfields: &[Vec<bool>],
    complete_sources: usize,
) -> (Vec<usize>, Vec<Option<usize>>, IcsMode) {
    let mode = IcsMode::select(complete_sources);
    let num_seeders = seeder_bitfields.len();
    let mut rng = rand::thread_rng();

    let rarity: Vec<usize> = (0..chunk_count)
        .map(|ci| {
            (0..num_seeders)
                .filter(|&si| seeder_bitfields[si].get(ci).copied().unwrap_or(false))
                .count()
        })
        .collect();

    let mut order: Vec<usize> = (0..chunk_count).collect();

    match mode {
        IcsMode::Release => {
            order.shuffle(&mut rng);
            order.sort_by_key(|&ci| rarity[ci]);
        }
        IcsMode::Spread => {
            order.shuffle(&mut rng);
            order.sort_by_key(|&ci| {
                let partial_holders = (0..num_seeders)
                    .filter(|&si| {
                        seeder_bitfields[si].get(ci).copied().unwrap_or(false)
                            && seeder_bitfields[si].len() < chunk_count
                    })
                    .count();
                (std::cmp::Reverse(partial_holders), rarity[ci])
            });
        }
        IcsMode::Share => {
            order.shuffle(&mut rng);
        }
    }

    let mut assignments: Vec<Option<usize>> = vec![None; chunk_count];
    let mut seeder_load: Vec<usize> = vec![0; num_seeders];

    for &ci in &order {
        let available: Vec<usize> = (0..num_seeders)
            .filter(|&si| seeder_bitfields[si].get(ci).copied().unwrap_or(false))
            .collect();
        if let Some(&best) = available.iter().min_by_key(|&&si| seeder_load[si]) {
            assignments[ci] = Some(best);
            seeder_load[best] += 1;
        }
    }

    (order, assignments, mode)
}

/// Backward-compatible wrapper: always uses RELEASE mode (rarest-first).
pub fn plan_chunk_assignments(
    chunk_count: usize,
    seeder_bitfields: &[Vec<bool>],
) -> (Vec<usize>, Vec<Option<usize>>) {
    let (order, assignments, _) =
        plan_chunk_assignments_ics(chunk_count, seeder_bitfields, 0);
    (order, assignments)
}

// ---------------------------------------------------------------------------
// A5: Chunked buy — fetch chunks from multiple seeders, verify, reassemble
// ---------------------------------------------------------------------------

pub fn handle_buy_chunked(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    req: &BuyRequest,
) {
    let role = "buyer";
    let content_invoice = match req.content_invoice.as_deref() {
        Some(inv) => inv,
        None => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": "Chunked buy requires content_invoice",
                }),
            );
            return;
        }
    };
    let enc_hash_hex = match req.encrypted_hash.as_deref() {
        Some(h) => h.to_string(),
        None => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": "Chunked buy requires encrypted_hash",
                }),
            );
            return;
        }
    };
    if req.seeder_urls.is_empty() {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "Chunked buy requires at least one seeder_url",
            }),
        );
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 1: Pay creator for content key K (same as two-phase)
    // -----------------------------------------------------------------------

    for i in (1..=3).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying creator in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    let content_payment_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = content_invoice.parse().expect("Invalid content invoice");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };

    emitter.emit(
        role,
        "CONTENT_PAYING",
        serde_json::json!({
            "bolt11": content_invoice,
            "message": "Paying creator for content key K...",
        }),
    );

    let key: [u8; 32];
    match invoice::pay_invoice(node, content_invoice) {
        Ok(hash_bytes_k) => {
            let target_hash_k = PaymentHash(hash_bytes_k);
            emitter.emit(
                role,
                "CONTENT_PAYMENT_SENT",
                serde_json::json!({
                    "payment_hash": hex::encode(hash_bytes_k),
                }),
            );
            let rx = router.register(target_hash_k);
            loop {
                let event = rx.recv().expect("Event router dropped");
                match event {
                    Event::PaymentSuccessful {
                        payment_preimage: Some(preimage),
                        fee_paid_msat,
                        ..
                    } => {
                        key = preimage.0;
                        emitter.emit(
                            role,
                            "CONTENT_PAID",
                            serde_json::json!({
                                "preimage_k": hex::encode(key),
                                "fee_msat": fee_paid_msat,
                                "message": "Content key K received!",
                            }),
                        );
                        break;
                    }
                    Event::PaymentFailed { reason, .. } => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "reason": format!("{:?}", reason),
                                "message": "Content payment failed.",
                            }),
                        );
                        router.unregister(&target_hash_k);
                        return;
                    }
                    _ => {}
                }
            }
            router.unregister(&target_hash_k);
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("DuplicatePayment") {
                emitter.emit( role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));
                let target = PaymentHash(content_payment_hash);
                let payments = node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                });
                let found = payments.iter().find(|p| {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(_),
                        ..
                    } = &p.kind
                    {
                        *hash == target
                    } else {
                        false
                    }
                });
                match found {
                    Some(p) => {
                        if let PaymentKind::Bolt11 {
                            preimage: Some(pre),
                            ..
                        } = &p.kind
                        {
                            key = pre.0;
                            emitter.emit(
                                role,
                                "CONTENT_PAID",
                                serde_json::json!({
                                    "preimage_k": hex::encode(key),
                                    "message": "Recovered K from payment history.",
                                }),
                            );
                        } else {
                            emitter.emit(
                                role,
                                "CONTENT_PAYMENT_FAILED",
                                serde_json::json!({
                                    "message": "Found payment but no preimage.",
                                }),
                            );
                            return;
                        }
                    }
                    None => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "message": "DuplicatePayment but preimage not found in history.",
                            }),
                        );
                        return;
                    }
                }
            } else {
                emitter.emit(
                    role,
                    "CONTENT_PAYMENT_FAILED",
                    serde_json::json!({
                        "error": err_str,
                        "message": "Content payment failed.",
                    }),
                );
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 2: Fetch chunk metadata from first seeder
    // -----------------------------------------------------------------------

    let client = reqwest::blocking::Client::new();
    let meta_url = format!("{}/api/chunks/{}/meta", &req.seeder_urls[0], &enc_hash_hex);
    let meta: serde_json::Value = match client.get(&meta_url).send().and_then(|r| r.json()) {
        Ok(m) => m,
        Err(e) => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("Failed to fetch chunk metadata: {}", e),
                }),
            );
            return;
        }
    };

    let chunk_count = meta["chunk_count"].as_u64().unwrap_or(0) as usize;
    let chunk_size = meta["chunk_size"].as_u64().unwrap_or(0) as usize;
    let encrypted_root = meta["encrypted_root"].as_str().unwrap_or("").to_string();

    emitter.emit(
        role,
        "CHUNK_META_RECEIVED",
        serde_json::json!({
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "encrypted_root": &encrypted_root,
            "seeders": req.seeder_urls.len(),
        }),
    );

    if chunk_count == 0 {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "chunk_count is 0 — content has no chunks",
            }),
        );
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 3: Fetch bitfields from all seeders, build assignment plan
    // -----------------------------------------------------------------------

    // Collect bitfields: seeder_index -> Vec<bool>
    let mut seeder_bitfields: Vec<Vec<bool>> = Vec::new();
    for url in req.seeder_urls.iter() {
        let bf_url = format!("{}/api/chunks/{}/bitfield", url, &enc_hash_hex);
        match client
            .get(&bf_url)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(bf) => {
                let bits: Vec<bool> = bf["bitfield"]
                    .as_array()
                    .map(|arr| arr.iter().map(|v| v.as_bool().unwrap_or(false)).collect())
                    .unwrap_or_default();
                emitter.emit(
                    role,
                    "BITFIELD_RECEIVED",
                    serde_json::json!({
                        "seeder": url,
                        "chunks_available": bits.iter().filter(|&&b| b).count(),
                        "total": chunk_count,
                    }),
                );
                seeder_bitfields.push(bits);
            }
            Err(e) => {
                emitter.emit(
                    role,
                    "BITFIELD_FAILED",
                    serde_json::json!({
                        "seeder": url,
                        "error": format!("{}", e),
                    }),
                );
                seeder_bitfields.push(vec![false; chunk_count]);
            }
        }
    }

    // Rarest-first chunk assignment (BitTorrent-style)
    let (download_order, assignments) = plan_chunk_assignments(chunk_count, &seeder_bitfields);

    // Check for unassignable chunks (no seeder has them)
    for &ci in &download_order {
        if assignments[ci].is_none() {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("No seeder has chunk {}!", ci),
                    "chunk_index": ci,
                }),
            );
            return;
        }
    }

    // Build rarity histogram for diagnostics
    let rarity: Vec<usize> = (0..chunk_count)
        .map(|ci| {
            seeder_bitfields
                .iter()
                .filter(|bf| bf.get(ci).copied().unwrap_or(false))
                .count()
        })
        .collect();
    let mut rarity_histogram: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    for &r in &rarity {
        *rarity_histogram.entry(r).or_insert(0) += 1;
    }

    emitter.emit(
        role,
        "CHUNK_PLAN",
        serde_json::json!({
            "assignments": assignments.iter().map(|a| a.unwrap_or(0)).collect::<Vec<_>>(),
            "download_order": download_order,
            "rarity_histogram": rarity_histogram,
            "message": format!(
                "Rarest-first plan: {} chunks across {} seeders (rarity dist: {})",
                chunk_count,
                req.seeder_urls.len(),
                rarity_histogram.iter()
                    .map(|(r, n)| format!("{}x held-by-{}", n, r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }),
    );

    // -----------------------------------------------------------------------
    // PHASE 4: Request transport invoices from each seeder (batched per seeder)
    // -----------------------------------------------------------------------

    // Group chunks by seeder, ordered by rarity (rarest first within each batch).
    // Build a position map from download_order so we can sort each seeder's
    // chunks in the same rarest-first order.
    let mut rarity_pos: Vec<usize> = vec![0; chunk_count];
    for (pos, &ci) in download_order.iter().enumerate() {
        rarity_pos[ci] = pos;
    }
    let mut seeder_chunks: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for (ci, assignment) in assignments.iter().enumerate() {
        if let Some(si) = assignment {
            seeder_chunks.entry(*si).or_default().push(ci);
        }
    }
    // Sort each seeder's chunk list by rarity position (rarest first)
    for chunks in seeder_chunks.values_mut() {
        chunks.sort_by_key(|&ci| rarity_pos[ci]);
    }

    // For each seeder, request a transport invoice for its chunks
    struct SeederTransport {
        seeder_index: usize,
        chunks: Vec<usize>,
        bolt11: String,
        ks: Option<[u8; 32]>,
    }

    let mut transports: Vec<SeederTransport> = Vec::new();

    for (&si, chunks) in &seeder_chunks {
        let url = format!(
            "{}/api/transport-invoice/{}",
            &req.seeder_urls[si], &enc_hash_hex
        );
        let body = serde_json::json!({ "chunks": chunks });
        match client
            .post(&url)
            .json(&body)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(resp) => {
                let bolt11 = resp["bolt11"].as_str().unwrap_or("").to_string();
                emitter.emit(
                    role,
                    "TRANSPORT_INVOICE_RECEIVED",
                    serde_json::json!({
                        "seeder": &req.seeder_urls[si],
                        "bolt11": &bolt11,
                        "chunks": chunks,
                        "transport_price": resp["transport_price"],
                    }),
                );
                transports.push(SeederTransport {
                    seeder_index: si,
                    chunks: chunks.clone(),
                    bolt11,
                    ks: None,
                });
            }
            Err(e) => {
                emitter.emit( role, "BUY_ERROR", serde_json::json!({
                    "message": format!("Failed to get transport invoice from seeder {}: {}", si, e),
                }));
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 5: Pay transport invoices, collect K_S per seeder
    // -----------------------------------------------------------------------

    for transport in &mut transports {
        emitter.emit(
            role,
            "TRANSPORT_PAYING",
            serde_json::json!({
                "seeder": &req.seeder_urls[transport.seeder_index],
                "bolt11": &transport.bolt11,
                "chunks": &transport.chunks,
            }),
        );

        match invoice::pay_invoice(node, &transport.bolt11) {
            Ok(hash_bytes_ks) => {
                let target_hash_ks = PaymentHash(hash_bytes_ks);
                let rx_ks = router.register(target_hash_ks);
                loop {
                    let event = rx_ks.recv().expect("Event router dropped");
                    match event {
                        Event::PaymentSuccessful {
                            payment_preimage: Some(preimage),
                            fee_paid_msat,
                            ..
                        } => {
                            transport.ks = Some(preimage.0);
                            emitter.emit(
                                role,
                                "TRANSPORT_PAID",
                                serde_json::json!({
                                    "seeder": &req.seeder_urls[transport.seeder_index],
                                    "preimage_ks": hex::encode(preimage.0),
                                    "fee_msat": fee_paid_msat,
                                    "chunks": &transport.chunks,
                                }),
                            );
                            break;
                        }
                        Event::PaymentFailed { reason, .. } => {
                            emitter.emit(
                                role,
                                "TRANSPORT_PAYMENT_FAILED",
                                serde_json::json!({
                                    "seeder": &req.seeder_urls[transport.seeder_index],
                                    "reason": format!("{:?}", reason),
                                    "message": "Transport payment failed for this seeder.",
                                }),
                            );
                            router.unregister(&target_hash_ks);
                            return;
                        }
                        _ => {}
                    }
                }
                router.unregister(&target_hash_ks);
            }
            Err(e) => {
                emitter.emit(
                    role,
                    "TRANSPORT_PAYMENT_FAILED",
                    serde_json::json!({
                        "seeder": &req.seeder_urls[transport.seeder_index],
                        "error": format!("{:?}", e),
                    }),
                );
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 6: Download wrapped chunks, unwrap with K_S, verify Merkle proofs
    // -----------------------------------------------------------------------

    let mut enc_chunks: Vec<Option<Vec<u8>>> = vec![None; chunk_count];

    for transport in &transports {
        let ks = match transport.ks {
            Some(k) => k,
            None => continue,
        };

        for &ci in &transport.chunks {
            // Fetch wrapped chunk W_i
            let wc_url = format!(
                "{}/api/wrapped-chunks/{}/{}",
                &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci
            );
            let wrapped_chunk = match client.get(&wc_url).send().and_then(|r| r.bytes()) {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    emitter.emit(
                        role,
                        "CHUNK_DOWNLOAD_FAILED",
                        serde_json::json!({
                            "chunk_index": ci,
                            "seeder": &req.seeder_urls[transport.seeder_index],
                            "error": format!("{}", e),
                        }),
                    );
                    return;
                }
            };

            // Unwrap: E_i = Dec(W_i, K_S, chunk_index=i)
            let enc_chunk = encrypt::decrypt(&wrapped_chunk, &ks, ci as u64);

            // Fetch Merkle proof and verify
            let proof_url = format!(
                "{}/api/chunks/{}/proof/{}",
                &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci
            );
            match client
                .get(&proof_url)
                .send()
                .and_then(|r| r.json::<serde_json::Value>())
            {
                Ok(proof_json) => {
                    // Verify chunk against encrypted Merkle root
                    let proof_data = &proof_json["proof"];
                    if let Ok(proof_json_obj) = serde_json::from_value::<
                        conduit_core::merkle::MerkleProofJson,
                    >(proof_data.clone())
                    {
                        if let Ok(proof) =
                            conduit_core::merkle::MerkleProof::from_json(&proof_json_obj)
                        {
                            let root_bytes = hex::decode(&encrypted_root).unwrap_or_default();
                            let mut root = [0u8; 32];
                            if root_bytes.len() == 32 {
                                root.copy_from_slice(&root_bytes);
                            }
                            if proof.verify(&enc_chunk, ci, &root) {
                                emitter.emit(
                                    role,
                                    "CHUNK_VERIFIED",
                                    serde_json::json!({
                                        "chunk_index": ci,
                                        "message": format!("Chunk {} Merkle proof verified", ci),
                                    }),
                                );
                            } else {
                                emitter.emit( role, "CHUNK_VERIFICATION_FAILED", serde_json::json!({
                                    "chunk_index": ci,
                                    "message": format!("Chunk {} Merkle proof FAILED — seeder sent bad data!", ci),
                                }));
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    emitter.emit(
                        role,
                        "CHUNK_PROOF_FETCH_FAILED",
                        serde_json::json!({
                            "chunk_index": ci,
                            "error": format!("{}", e),
                            "message": "Proof fetch failed — continuing without verification",
                        }),
                    );
                }
            }

            enc_chunks[ci] = Some(enc_chunk);
            emitter.emit( role, "CHUNK_DOWNLOADED", serde_json::json!({
                "chunk_index": ci,
                "total": chunk_count,
                "progress": format!("{}/{}", enc_chunks.iter().filter(|c| c.is_some()).count(), chunk_count),
            }));
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 7: Reassemble encrypted file, decrypt per-chunk, verify
    // -----------------------------------------------------------------------

    // Check all chunks received
    for (ci, chunk) in enc_chunks.iter().enumerate() {
        if chunk.is_none() {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("Missing encrypted chunk {}", ci),
                }),
            );
            return;
        }
    }

    // Decrypt each chunk: F_i = Dec(E_i, K, i)
    let mut plaintext_chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
    for (ci, enc_chunk_opt) in enc_chunks.iter().enumerate() {
        let enc_chunk = enc_chunk_opt.as_ref().unwrap();
        let pt_chunk = encrypt::decrypt(enc_chunk, &key, ci as u64);
        plaintext_chunks.push(pt_chunk);
    }

    emitter.emit(
        role,
        "CHUNKS_DECRYPTED",
        serde_json::json!({
            "chunk_count": chunk_count,
            "message": format!("All {} chunks decrypted with K", chunk_count),
        }),
    );

    // Reassemble plaintext
    let original_size = meta["size_bytes"].as_u64().unwrap_or(0) as usize;
    let mut plaintext: Vec<u8> = Vec::new();
    for pt_chunk in &plaintext_chunks {
        plaintext.extend_from_slice(pt_chunk);
    }
    // Truncate to original size (last chunk may have padding)
    if original_size > 0 && plaintext.len() > original_size {
        plaintext.truncate(original_size);
    }

    emitter.emit(
        role,
        "CONTENT_REASSEMBLED",
        serde_json::json!({
            "bytes": plaintext.len(),
            "chunks": chunk_count,
        }),
    );

    // Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).unwrap_or_default();
    let actual_hash = verify::sha256_hash(&plaintext);
    let matches = expected_hash_bytes.len() == 32 && actual_hash[..] == expected_hash_bytes[..];
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": &req.hash,
            "actual": hex::encode(actual_hash),
        }),
    );
    if !matches {
        emitter.emit(
            role,
            "HASH_MISMATCH",
            serde_json::json!({
                "expected": &req.hash,
                "actual": hex::encode(actual_hash),
                "message": "Content hash mismatch after reassembly!",
            }),
        );
        return;
    }

    // Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": &req.output,
            "bytes": plaintext.len(),
            "chunks": chunk_count,
            "seeders": req.seeder_urls.len(),
            "message": "Chunked multi-source content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE (chunked) ===");
    println!(
        "Decrypted file: {} ({} bytes, {} chunks from {} seeders)",
        req.output,
        plaintext.len(),
        chunk_count,
        req.seeder_urls.len()
    );
    println!("SHA-256 verified: content is authentic.");
}

