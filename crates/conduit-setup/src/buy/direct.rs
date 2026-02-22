// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buy command (two-phase: seeder + creator)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use conduit_core::{chunk, encrypt, invoice, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};

use crate::events::*;
use crate::handlers::content::curl_fetch;
use crate::state::*;

pub fn handle_buy_two_phase(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    req: &BuyRequest,
) {
    let role = "buyer";
    let content_invoice = req.content_invoice.as_deref().unwrap();
    let transport_invoice = req.transport_invoice.as_deref().unwrap();
    let enc_hash_hex = req.encrypted_hash.as_deref().unwrap_or("");

    // -----------------------------------------------------------------------
    // PHASE 1: Pay creator for content key K
    //
    // This is the critical payment. Once we have K, we can decrypt content
    // from ANY seeder. If a seeder fails, we try another — K is ours forever.
    // -----------------------------------------------------------------------

    // 1. Countdown
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

    // 2. Pay content invoice -> get K
    //
    // Parse invoice first to get payment_hash (needed for DuplicatePayment lookup).
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

    // Try to pay; if DuplicatePayment, look up K from previous successful payment
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

            // Wait for K from new payment via event router
            let rx = router.register(target_hash_k);
            loop {
                let event = rx.recv().expect("Event router dropped");
                match event {
                    Event::PaymentSuccessful {
                        payment_hash,
                        payment_preimage: Some(preimage),
                        fee_paid_msat,
                        ..
                    } => {
                        key = preimage.0;
                        emitter.emit( role, "CONTENT_PAID", serde_json::json!({
                            "payment_hash": hex::encode(payment_hash.0),
                            "preimage_k": hex::encode(key),
                            "fee_msat": fee_paid_msat,
                            "message": "Content key K received! Can now decrypt from any seeder.",
                        }));
                        break;
                    }
                    Event::PaymentFailed { reason, .. } => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "payment_hash": hex::encode(target_hash_k.0),
                                "reason": format!("{:?}", reason),
                                "message": "Content payment failed. No money lost to seeders.",
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
                // Already paid for this content key K — look it up from payment history
                emitter.emit( role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));

                // Find the preimage from previous successful outbound payment with matching hash
                let target = PaymentHash(content_payment_hash);
                let mut found_key: Option<[u8; 32]> = None;
                for p in node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                }) {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(pre),
                        ..
                    } = &p.kind
                    {
                        if *hash == target {
                            found_key = Some(pre.0);
                            break;
                        }
                    }
                }

                match found_key {
                    Some(k) => {
                        key = k;
                        emitter.emit( role, "CONTENT_PAID", serde_json::json!({
                            "preimage_k": hex::encode(key),
                            "message": "Content key K recovered from payment history. Skipping to seeder phase.",
                        }));
                    }
                    None => {
                        emitter.emit( role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "message": "DuplicatePayment but could not find preimage in history. Cannot proceed.",
                        }));
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
    // PHASE 2: Fetch from seeder, pay transport, unwrap, decrypt
    //
    // We already have K. If this seeder fails, we could retry with another.
    // The transport payment is low-risk: small amount, and we already own K.
    // -----------------------------------------------------------------------

    // 3. Fetch wrapped file W from seeder
    let wrapped_path = if let Some(ref url) = req.wrapped_url {
        match curl_fetch(url, emitter) {
            Some(path) => path,
            None => return,
        }
    } else {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "No wrapped_url provided for two-phase buy",
            }),
        );
        return;
    };
    let wrapped = std::fs::read(&wrapped_path).expect("Failed to read wrapped file");

    // 4. Pay transport invoice -> get K_S
    emitter.emit(
        role,
        "TRANSPORT_PAYING",
        serde_json::json!({
            "bolt11": transport_invoice,
            "message": "Paying seeder for transport key K_S...",
        }),
    );
    let hash_bytes_ks =
        invoice::pay_invoice(node, transport_invoice).expect("Failed to pay transport invoice");
    let target_hash_ks = PaymentHash(hash_bytes_ks);
    emitter.emit(
        role,
        "TRANSPORT_PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes_ks),
        }),
    );

    // Wait for K_S via event router
    let ks: [u8; 32];
    let rx_ks = router.register(target_hash_ks);
    loop {
        let event = rx_ks.recv().expect("Event router dropped");
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                ks = preimage.0;
                emitter.emit(
                    role,
                    "TRANSPORT_PAID",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage_ks": hex::encode(ks),
                        "fee_msat": fee_paid_msat,
                        "message": "Transport key K_S received!",
                    }),
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit( role, "TRANSPORT_PAYMENT_FAILED", serde_json::json!({
                    "payment_hash": hex::encode(target_hash_ks.0),
                    "reason": format!("{:?}", reason),
                    "message": "Transport payment failed. You still have K — try another seeder.",
                }));
                router.unregister(&target_hash_ks);
                return;
            }
            _ => {}
        }
    }
    router.unregister(&target_hash_ks);

    // 5. Unwrap: E = Dec(W, K_S)
    let encrypted = encrypt::decrypt(&wrapped, &ks, 0);
    emitter.emit(
        role,
        "CONTENT_UNWRAPPED",
        serde_json::json!({
            "wrapped_bytes": wrapped.len(),
            "encrypted_bytes": encrypted.len(),
            "key_ks": hex::encode(ks),
            "message": "Transport layer stripped with K_S",
        }),
    );

    // 6. Verify H(E)
    if !enc_hash_hex.is_empty() {
        let enc_hash = verify::sha256_hash(&encrypted);
        let expected_bytes = hex::decode(enc_hash_hex).unwrap_or_default();
        let matches = enc_hash[..] == expected_bytes[..];
        emitter.emit(
            role,
            "ENCRYPTED_HASH_VERIFIED",
            serde_json::json!({
                "matches": matches,
                "expected": enc_hash_hex,
                "actual": hex::encode(enc_hash),
            }),
        );
        if !matches {
            emitter.emit(
                role,
                "ENCRYPTED_HASH_MISMATCH",
                serde_json::json!({
                    "expected": enc_hash_hex,
                    "actual": hex::encode(enc_hash),
                    "message": "Encrypted content hash mismatch after unwrap!",
                }),
            );
            return;
        }
    }

    // 7. Decrypt per-chunk: F_i = Dec(E_i, K, i) for each chunk, then reassemble
    //    The .enc file is E_0 || E_1 || ... || E_N where E_i = Enc(F_i, K, i)
    let cs = chunk::select_chunk_size(encrypted.len());
    let (enc_chunks, _meta) = chunk::split(&encrypted, cs);
    let plaintext: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &key, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": plaintext.len(),
            "key": hex::encode(key),
            "chunks": enc_chunks.len(),
        }),
    );

    // 8. Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).expect("Invalid hex hash");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);
    let matches = verify::verify_hash(&plaintext, &expected_hash);
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": &req.hash,
            "actual": hex::encode(verify::sha256_hash(&plaintext)),
        }),
    );
    if !matches {
        emitter.emit(
            role,
            "HASH_MISMATCH",
            serde_json::json!({
                "expected": &req.hash,
                "actual": hex::encode(verify::sha256_hash(&plaintext)),
                "message": "Content hash mismatch!",
            }),
        );
        return;
    }

    // 9. Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": &req.output,
            "bytes": plaintext.len(),
            "message": "Two-phase atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE (two-phase) ===");
    println!("Decrypted file: {} ({} bytes)", req.output, plaintext.len());
    println!("SHA-256 verified: content is authentic.");
}

