// ---------------------------------------------------------------------------
// sell command
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use conduit_core::{chunk, encrypt, invoice, merkle::MerkleTree, pre, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::catalog::*;
use crate::events::*;
use crate::state::*;

pub fn handle_sell(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    file_path: &str,
    price: u64,
) {
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    println!("Read {} bytes from {}", plaintext.len(), file_path);

    // 2. Generate key
    let key = encrypt::generate_key();
    emitter.emit(
        role,
        "KEY_GENERATED",
        serde_json::json!({
            "key": hex::encode(key),
        }),
    );

    // 3. Encrypt
    let ciphertext = encrypt::encrypt(&plaintext, &key, 0);
    emitter.emit(
        role,
        "CONTENT_ENCRYPTED",
        serde_json::json!({
            "plaintext_bytes": plaintext.len(),
            "ciphertext_bytes": ciphertext.len(),
        }),
    );

    // 4. Hash plaintext
    let file_hash = verify::sha256_hash(&plaintext);
    emitter.emit(
        role,
        "HASH_COMPUTED",
        serde_json::json!({
            "hash": hex::encode(file_hash),
        }),
    );

    // 5. Create invoice
    let bolt11 = invoice::create_invoice_for_key(node, &key, price, file_path)
        .expect("Failed to create invoice");
    let payment_hash = verify::sha256_hash(&key);
    let enc_path = format!("{}.enc", file_path);
    let enc_filename = enc_path.split('/').next_back().unwrap_or("").to_string();
    let enc_hash = verify::sha256_hash(&ciphertext);
    emitter.emit(
        role,
        "INVOICE_CREATED",
        serde_json::json!({
            "payment_hash": hex::encode(payment_hash),
            "content_hash": hex::encode(file_hash),
            "encrypted_hash": hex::encode(enc_hash),
            "amount_sats": price,
            "bolt11": &bolt11,
            "enc_filename": &enc_filename,
            "file_name": file_path.split('/').next_back().unwrap_or(file_path),
        }),
    );

    // 6. Save encrypted file
    std::fs::write(&enc_path, &ciphertext).expect("Failed to write encrypted file");
    emitter.emit(
        role,
        "ENCRYPTED_FILE_SAVED",
        serde_json::json!({
            "path": &enc_path,
            "encrypted_hash": hex::encode(enc_hash),
            "bytes": ciphertext.len(),
        }),
    );

    // 7. Print summary for the buyer
    println!();
    println!("=== SELL READY ===");
    println!("Encrypted file:  {}", enc_path);
    println!("Plaintext hash:  {}", hex::encode(file_hash));
    println!("Encrypted hash:  {}", hex::encode(enc_hash));
    println!("Invoice:         {}", bolt11);
    println!();

    // 8. Wait for payment via event router
    emitter.emit(
        role,
        "WAITING_FOR_PAYMENT",
        serde_json::json!({
            "message": "Listening for incoming HTLC..."
        }),
    );

    let expected_hash = PaymentHash(payment_hash);
    let rx = router.register(expected_hash);
    loop {
        let event = rx.recv().expect("Event router dropped");
        match event {
            Event::PaymentClaimable {
                payment_hash: hash,
                claimable_amount_msat,
                claim_deadline,
                ..
            } => {
                emitter.emit(
                    role,
                    "HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                // Claim payment (reveals preimage to buyer)
                invoice::claim_payment(node, &key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emitter.emit(
                    role,
                    "PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(key),
                        "message": "Preimage revealed to buyer via HTLC settlement",
                    }),
                );
            }
            Event::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            } => {
                emitter.emit(
                    role,
                    "PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "Payment confirmed. Content sold.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

// ---------------------------------------------------------------------------
// Parse --chunks argument: "0,1,2,5-9" -> vec![0,1,2,5,6,7,8,9]
// Returns empty vec if arg is None (meaning "all chunks").
// ---------------------------------------------------------------------------

pub fn parse_chunks_arg(arg: &Option<String>, total_chunks: usize) -> Vec<usize> {
    let arg = match arg {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(), // empty = all chunks
    };

    let mut result = Vec::new();
    for part in arg.split(',') {
        let part = part.trim();
        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: usize = start_str.trim().parse().expect("Invalid chunk range start");
            let end: usize = end_str.trim().parse().expect("Invalid chunk range end");
            for i in start..=end {
                if i < total_chunks {
                    result.push(i);
                }
            }
        } else {
            let idx: usize = part.parse().expect("Invalid chunk index");
            if idx < total_chunks {
                result.push(idx);
            }
        }
    }
    result.sort();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// seed command (seeder: wrap with transport key K_S)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn handle_seed(
    emitter: &ConsoleEmitter,
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    enc_file_path: &str,
    expected_enc_hash_hex: &str,
    transport_price: u64,
    registry_info: &Option<RegistryInfo>,
    chunks_arg: &Option<String>,
) {
    let role = "seeder";

    // 1. Read encrypted file E (already encrypted by creator with K)
    let encrypted = std::fs::read(enc_file_path).expect("Failed to read encrypted file");
    println!(
        "Read {} encrypted bytes from {}",
        encrypted.len(),
        enc_file_path
    );

    // 2. Verify H(E) matches what the creator published
    let enc_hash = verify::sha256_hash(&encrypted);
    let expected_enc_hash = hex::decode(expected_enc_hash_hex).expect("Invalid hex hash");
    if enc_hash[..] != expected_enc_hash[..] {
        emitter.emit(
            role,
            "ENC_HASH_MISMATCH",
            serde_json::json!({
                "expected": expected_enc_hash_hex,
                "actual": hex::encode(enc_hash),
                "message": "Encrypted content hash mismatch! File may be corrupted.",
            }),
        );
        eprintln!("ERROR: Encrypted content hash mismatch");
        return;
    }
    emitter.emit(
        role,
        "ENC_HASH_VERIFIED",
        serde_json::json!({
            "hash": hex::encode(enc_hash),
        }),
    );

    // 3. Check if already in seeder catalog
    {
        let cat = catalog.lock().unwrap();
        if cat
            .iter()
            .any(|e| e.encrypted_hash == expected_enc_hash_hex)
        {
            emitter.emit(
                role,
                "ALREADY_SEEDED",
                serde_json::json!({
                    "encrypted_hash": expected_enc_hash_hex,
                    "message": "Content already in seeder catalog",
                }),
            );
            return;
        }
    }

    // 4. Derive file_name from enc_file_path (strip .enc suffix)
    let enc_filename = enc_file_path
        .split('/')
        .next_back()
        .unwrap_or("unknown.enc");
    let file_name = enc_filename
        .strip_suffix(".enc")
        .unwrap_or(enc_filename)
        .to_string();

    // 4b. Compute chunk metadata from the encrypted file
    let cs = chunk::select_chunk_size(encrypted.len());
    let (enc_chunks, meta) = chunk::split(&encrypted, cs);
    let enc_tree = MerkleTree::from_chunks(&enc_chunks);

    // 4c. Parse --chunks argument (e.g. "0,1,2,5-9")
    let chunks_held = parse_chunks_arg(chunks_arg, meta.count);
    if !chunks_held.is_empty() {
        emitter.emit(
            role,
            "CHUNKS_SELECTED",
            serde_json::json!({
                "chunks_held": &chunks_held,
                "total_chunks": meta.count,
                "message": format!("Seeding {} of {} chunks", chunks_held.len(), meta.count),
            }),
        );
    }

    // 5. Save to catalog
    let registered_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        secs.to_string()
    };

    let entry = CatalogEntry {
        content_hash: String::new(),
        file_name: file_name.clone(),
        file_path: String::new(),
        enc_file_path: enc_file_path.to_string(),
        key_hex: String::new(),
        price_sats: 0,
        encrypted_hash: expected_enc_hash_hex.to_string(),
        size_bytes: encrypted.len() as u64,
        registered_at: registered_at.clone(),
        transport_price,
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: String::new(),
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: chunks_held.clone(),
        pre_c1_hex: String::new(),
        pre_c2_hex: String::new(),
        pre_pk_creator_hex: String::new(),
        playback_policy: "open".to_string(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    let chunks_seeding = if chunks_held.is_empty() {
        meta.count
    } else {
        chunks_held.len()
    };
    emitter.emit( role, "CONTENT_SEEDED", serde_json::json!({
        "encrypted_hash": expected_enc_hash_hex,
        "file_name": &file_name,
        "transport_price": transport_price,
        "size_bytes": encrypted.len(),
        "chunk_count": meta.count,
        "chunk_size": meta.chunk_size,
        "chunks_seeding": chunks_seeding,
        "encrypted_root": hex::encode(enc_tree.root()),
        "message": format!("Content added to seeder catalog ({}/{} chunks). Transport invoices generated on demand.", chunks_seeding, meta.count),
    }));

    // Push seeder announcement to registry (blocking)
    if let Some(ref info) = registry_info {
        let body = serde_json::json!({
            "encrypted_hash": expected_enc_hash_hex,
            "seeder_pubkey": &info.node_pubkey,
            "seeder_address": &info.http_address,
            "seeder_ln_address": &info.ln_address,
            "seeder_alias": &info.node_alias,
            "transport_price": transport_price,
            "chunk_count": meta.count,
            "chunks_held": &chunks_held,
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", info.url);
        match reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .send()
        {
            Ok(resp) => println!("Registry: seeder announced ({})", resp.status()),
            Err(e) => eprintln!("Warning: failed to push seeder to registry: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// register command (add content to catalog)
// ---------------------------------------------------------------------------

pub fn handle_register(
    emitter: &ConsoleEmitter,
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    file_path: &str,
    price: u64,
    registry_info: &Option<RegistryInfo>,
) {
    // Derive creator PRE keypair from a seed stored alongside the catalog.
    // For the prototype, we use a fixed seed based on the storage directory.
    let pre_seed = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"conduit-pre-creator-seed:");
        h.update(storage_dir.as_bytes());
        let hash = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&hash);
        s
    };
    let creator_kp = pre::creator_keygen_from_seed(&pre_seed);
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    let file_name = file_path
        .split('/')
        .next_back()
        .unwrap_or(file_path)
        .to_string();
    let size_bytes = plaintext.len() as u64;

    // 2. Compute content hash H(F)
    let content_hash = hex::encode(verify::sha256_hash(&plaintext));
    emitter.emit(
        role,
        "HASH_COMPUTED",
        serde_json::json!({
            "hash": &content_hash,
            "file_name": &file_name,
        }),
    );

    // 3. Check if already registered
    {
        let cat = catalog.lock().unwrap();
        if let Some(existing) = cat.iter().find(|e| e.content_hash == content_hash) {
            println!(
                "Content already registered: {} ({})",
                file_name, content_hash
            );
            emitter.emit(
                role,
                "ALREADY_REGISTERED",
                serde_json::json!({
                    "content_hash": &content_hash,
                    "file_name": &file_name,
                    "price_sats": existing.price_sats,
                }),
            );
            return;
        }
    }

    // 4. Generate content key K (permanent, reused for every buyer)
    let key = encrypt::generate_key();
    emitter.emit(
        role,
        "KEY_GENERATED",
        serde_json::json!({
            "key": hex::encode(key),
            "message": "Content key K generated — stored in catalog, reused for every buyer",
        }),
    );

    // 5. Chunk, encrypt per-chunk, build Merkle trees
    let cs = chunk::select_chunk_size(plaintext.len());
    let (plain_chunks, meta) = chunk::split(&plaintext, cs);

    // Build plaintext Merkle tree
    let plain_tree = MerkleTree::from_chunks(&plain_chunks);

    // Encrypt each chunk with its own IV
    let enc_chunks: Vec<Vec<u8>> = plain_chunks
        .iter()
        .enumerate()
        .map(|(i, c)| encrypt::encrypt(c, &key, i as u64))
        .collect();

    // Build encrypted Merkle tree
    let enc_tree = MerkleTree::from_chunks(&enc_chunks);

    // Write concatenated encrypted chunks to disk (same format as before
    // for single-chunk files; for multi-chunk, it's the chunks back-to-back)
    let ciphertext: Vec<u8> = enc_chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let enc_path = format!("{}.enc", file_path);
    std::fs::write(&enc_path, &ciphertext).expect("Failed to write encrypted file");

    // Flat hashes remain for backward compat and seeder lookup
    let encrypted_hash = hex::encode(verify::sha256_hash(&ciphertext));

    emitter.emit(
        role,
        "CONTENT_ENCRYPTED",
        serde_json::json!({
            "plaintext_bytes": size_bytes,
            "ciphertext_bytes": ciphertext.len(),
            "enc_path": &enc_path,
            "encrypted_hash": &encrypted_hash,
        }),
    );

    // 6. Save to catalog
    let registered_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        secs.to_string()
    };

    // PRE: encrypt the AES key under the creator's PRE public key
    let pre_ct = pre::encrypt(&creator_kp.pk, &key);
    let ct_bytes = pre::serialize_ciphertext(&pre_ct);
    let pre_c1_hex = hex::encode(&ct_bytes[..48]);
    let pre_c2_hex = hex::encode(&ct_bytes[48..]);
    let pre_pk_hex = hex::encode(pre::serialize_creator_pk(&creator_kp.pk));

    emitter.emit(
        role,
        "PRE_CIPHERTEXT_CREATED",
        serde_json::json!({
            "pre_c1": &pre_c1_hex,
            "pre_c2": &pre_c2_hex,
            "pre_pk_creator": &pre_pk_hex,
            "message": "AES key encrypted under creator PRE public key (AFGH06)",
        }),
    );

    let entry = CatalogEntry {
        content_hash: content_hash.clone(),
        file_name: file_name.clone(),
        file_path: file_path.to_string(),
        enc_file_path: enc_path.clone(),
        key_hex: hex::encode(key),
        price_sats: price,
        encrypted_hash: encrypted_hash.clone(),
        size_bytes,
        registered_at: registered_at.clone(),
        transport_price: 0,
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: hex::encode(plain_tree.root()),
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: Vec::new(),
        // PRE fields
        pre_c1_hex: pre_c1_hex.clone(),
        pre_c2_hex: pre_c2_hex.clone(),
        pre_pk_creator_hex: pre_pk_hex.clone(),
        playback_policy: "open".to_string(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    emitter.emit(
        role,
        "CONTENT_REGISTERED",
        serde_json::json!({
            "content_hash": &content_hash,
            "file_name": &file_name,
            "encrypted_hash": &encrypted_hash,
            "size_bytes": size_bytes,
            "price_sats": price,
            "enc_path": &enc_path,
            "chunk_size": meta.chunk_size,
            "chunk_count": meta.count,
            "plaintext_root": hex::encode(plain_tree.root()),
            "encrypted_root": hex::encode(enc_tree.root()),
            "message": "Content registered in catalog and ready for sale",
        }),
    );

    println!();
    println!("=== CONTENT REGISTERED ===");
    println!("File:           {}", file_name);
    println!("Content hash:   {}", content_hash);
    println!("Encrypted hash: {}", encrypted_hash);
    println!("Encrypted file: {}", enc_path);
    println!("Price:          {} sats", price);
    println!("Chunks:         {} x {} bytes", meta.count, meta.chunk_size);
    println!("Plaintext root: {}", hex::encode(plain_tree.root()));
    println!("Encrypted root: {}", hex::encode(enc_tree.root()));
    println!("Catalog:        {}", catalog_path(storage_dir));
    println!();

    // Push listing to registry (blocking)
    if let Some(ref info) = registry_info {
        let body = serde_json::json!({
            "content_hash": &content_hash,
            "encrypted_hash": &encrypted_hash,
            "file_name": &file_name,
            "size_bytes": size_bytes,
            "price_sats": price,
            "chunk_size": meta.chunk_size,
            "chunk_count": meta.count,
            "plaintext_root": hex::encode(plain_tree.root()),
            "encrypted_root": hex::encode(enc_tree.root()),
            "creator_pubkey": &info.node_pubkey,
            "creator_address": &info.http_address,
            "creator_ln_address": &info.ln_address,
            "creator_alias": &info.node_alias,
            "registered_at": &registered_at,
            "pre_c1_hex": &pre_c1_hex,
            "pre_c2_hex": &pre_c2_hex,
            "pre_pk_creator_hex": &pre_pk_hex,
            "playback_policy": "open",
        });
        let url = format!("{}/api/listings", info.url);
        match reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .send()
        {
            Ok(resp) => println!("Registry: listing pushed ({})", resp.status()),
            Err(e) => eprintln!("Warning: failed to push listing to registry: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// sell from catalog (wait for payment using stored K)
// ---------------------------------------------------------------------------

pub fn handle_sell_from_catalog(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    key: &[u8; 32],
) {
    let role = "creator";

    emitter.emit(
        role,
        "WAITING_FOR_PAYMENT",
        serde_json::json!({
            "message": "Listening for incoming HTLC..."
        }),
    );

    let payment_hash = verify::sha256_hash(key);
    let expected_hash = PaymentHash(payment_hash);
    let rx = router.register(expected_hash);
    loop {
        let event = rx.recv().expect("Event router dropped");
        match event {
            Event::PaymentClaimable {
                payment_hash: hash,
                claimable_amount_msat,
                claim_deadline,
                ..
            } => {
                emitter.emit(
                    role,
                    "HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                invoice::claim_payment(node, key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emitter.emit(
                    role,
                    "PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(key),
                        "message": "Preimage revealed to buyer via HTLC settlement",
                    }),
                );
            }
            Event::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            } => {
                emitter.emit(
                    role,
                    "PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "Payment confirmed. Content sold.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

