// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use conduit_core::{chunk, encrypt, invoice, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::events::*;

pub fn handle_buy(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    bolt11_str: &str,
    enc_file_path: &str,
    expected_hash_hex: &str,
    output_path: &str,
) {
    let role = "buyer";

    // 1. Read encrypted file
    let ciphertext = std::fs::read(enc_file_path).expect("Failed to read encrypted file");
    println!(
        "Read {} encrypted bytes from {}",
        ciphertext.len(),
        enc_file_path
    );

    // 2. Decode expected hash
    let expected_hash_bytes = hex::decode(expected_hash_hex).expect("Invalid hex hash");
    assert_eq!(expected_hash_bytes.len(), 32, "Hash must be 32 bytes");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);

    // 3. Countdown — give the browser SSE time to connect
    for i in (1..=5).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    // 4. Pay invoice
    //
    // Register event listener BEFORE sending to avoid race: direct-channel
    // payments can settle in <1s.
    let pre_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = bolt11_str.parse().expect("Invalid bolt11");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };
    let target_hash = PaymentHash(pre_hash);
    let rx = router.register(target_hash);

    emitter.emit(
        role,
        "PAYING_INVOICE",
        serde_json::json!({
            "bolt11": bolt11_str,
        }),
    );
    let hash_bytes = invoice::pay_invoice(node, bolt11_str).expect("Failed to pay invoice");
    emitter.emit(
        role,
        "PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes),
            "message": "HTLC in flight, routing to creator...",
        }),
    );

    // Wait for preimage via event router (rx was registered before send)
    let preimage_bytes: [u8; 32];
    loop {
        let event = rx.recv().expect("Event router dropped");
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                preimage_bytes = preimage.0;
                emitter.emit(
                    role,
                    "PAYMENT_CONFIRMED",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage": hex::encode(preimage_bytes),
                        "fee_msat": fee_paid_msat,
                        "message": "Preimage received! This is the decryption key.",
                    }),
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit(
                    role,
                    "PAYMENT_FAILED",
                    serde_json::json!({
                        "payment_hash": hex::encode(target_hash.0),
                        "reason": format!("{:?}", reason),
                    }),
                );
                router.unregister(&target_hash);
                panic!("Payment failed: {:?}", reason);
            }
            _ => {}
        }
    }
    router.unregister(&target_hash);

    // 5. Decrypt per-chunk: F_i = Dec(E_i, K, i)
    let cs = chunk::select_chunk_size(ciphertext.len());
    let (enc_chunks, _meta) = chunk::split(&ciphertext, cs);
    let decrypted: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &preimage_bytes, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": decrypted.len(),
            "key": hex::encode(preimage_bytes),
            "chunks": enc_chunks.len(),
        }),
    );

    // 6. Verify
    let matches = verify::verify_hash(&decrypted, &expected_hash);
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": expected_hash_hex,
            "actual": hex::encode(verify::sha256_hash(&decrypted)),
        }),
    );
    if !matches {
        emitter.emit( role, "HASH_MISMATCH", serde_json::json!({
            "expected": expected_hash_hex,
            "actual": hex::encode(verify::sha256_hash(&decrypted)),
            "message": "Content hash mismatch! File may be corrupted or the wrong .enc was used.",
        }));
        eprintln!(
            "ERROR: Content hash mismatch! Expected {} got {}",
            expected_hash_hex,
            hex::encode(verify::sha256_hash(&decrypted))
        );
        return;
    }

    // 7. Write output
    std::fs::write(output_path, &decrypted).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": output_path,
            "bytes": decrypted.len(),
            "message": "Atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE ===");
    println!(
        "Decrypted file: {} ({} bytes)",
        output_path,
        decrypted.len()
    );
    println!("SHA-256 verified: content is authentic.");
}

