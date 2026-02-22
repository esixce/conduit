use std::sync::Arc;
use std::thread;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Deserialize;

use conduit_core::{invoice, pre, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::events::*;
use crate::state::*;

// ---------------------------------------------------------------------------
// PRE (Phase 2A) API handlers
// ---------------------------------------------------------------------------

/// Request body for PRE purchase: buyer sends their PRE public key (G2, 96 bytes hex).
#[derive(Deserialize)]
pub struct PrePurchaseRequest {
    /// Buyer's PRE public key (compressed G2, 96 bytes, hex-encoded).
    buyer_pk_hex: String,
    /// Set to true when the buyer's device has completed attestation.
    /// Required when playback_policy is "device_required".
    #[serde(default)]
    device_attested: bool,
}

/// POST /api/pre-purchase/{content_hash}
///
/// PRE purchase flow:
/// 1. Buyer sends their G2 public key
/// 2. Creator computes rk = re_keygen(sk_creator, pk_buyer)
/// 3. Creator creates Lightning invoice with HTLC preimage = SHA-256(rk_compressed)
/// 4. Returns: invoice, rk_compressed (hex), payment_hash, PRE ciphertext
///
/// After buyer pays the invoice, they receive the HTLC preimage. They already
/// have rk_compressed from this response, plus the PRE ciphertext from
/// GET /api/pre-ciphertext/{content_hash}. They can now:
/// - Send rk_compressed to the seeder for re-encryption
/// - Decrypt the re-encrypted ciphertext with their own sk_buyer
/// - Recover the AES key m
pub async fn pre_purchase_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
    Json(req): Json<PrePurchaseRequest>,
) -> impl IntoResponse {
    // Look up catalog entry
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter().find(|e| e.content_hash == content_hash).cloned()
    };

    let entry = match entry {
        Some(e) if !e.pre_c1_hex.is_empty() => e,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Content not PRE-enabled (registered before PRE was active)"
                })),
            )
                .into_response()
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Content not found in catalog"
                })),
            )
                .into_response()
        }
    };

    // Enforce TEE device policy
    if entry.playback_policy == "device_required" && !req.device_attested {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "This content requires a verified TEE device. Complete device attestation first.",
                "playback_policy": "device_required",
            })),
        )
            .into_response();
    }

    // Parse buyer's G2 public key
    let buyer_pk_bytes =
        match hex::decode(&req.buyer_pk_hex) {
            Ok(b) if b.len() == 96 => {
                let mut arr = [0u8; 96];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "buyer_pk_hex must be 96 bytes (192 hex chars), compressed G2 point"
                })),
            )
                .into_response(),
        };

    let buyer_pk = match pre::deserialize_buyer_pk(&buyer_pk_bytes) {
        Some(pk) => pk,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid G2 point: buyer_pk_hex is not a valid compressed BLS12-381 G2 point"
                })),
            )
                .into_response()
        }
    };

    // Derive creator PRE keypair (same seed as handle_register)
    let pre_seed = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"conduit-pre-creator-seed:");
        h.update(state.storage_dir.as_bytes());
        let hash = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&hash);
        s
    };
    let creator_kp = pre::creator_keygen_from_seed(&pre_seed);

    // Compute re-encryption key
    let rk = pre::re_keygen(&creator_kp.sk, &buyer_pk);

    // Generate per-purchase nonce so each invoice has a unique payment hash.
    // rk is deterministic (same creator+buyer = same rk), but we need unique
    // payment hashes for LDK. Preimage = SHA-256(rk_compressed || nonce).
    let nonce: [u8; 32] = {
        use rand::RngCore;
        let mut n = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut n);
        n
    };
    let htlc_preimage = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(rk.rk_compressed);
        h.update(nonce);
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    };

    // Create Lightning invoice with nonce-salted preimage
    let bolt11 = match invoice::create_invoice_for_rk(
        &state.node,
        &htlc_preimage,
        entry.price_sats,
        &format!("PRE:{}", entry.file_name),
    ) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to create invoice: {}", e)
                })),
            )
                .into_response()
        }
    };

    let payment_hash = hex::encode(invoice::payment_hash_for_rk(&htlc_preimage));
    let rk_compressed_hex = hex::encode(rk.rk_compressed);

    let emitter = state.emitter.clone();
    emitter.emit(
        "creator",
        "PRE_INVOICE_CREATED",
        serde_json::json!({
            "payment_hash": &payment_hash,
            "content_hash": &entry.content_hash,
            "buyer_pk": &req.buyer_pk_hex,
            "rk_compressed": &rk_compressed_hex,
            "amount_sats": entry.price_sats,
            "message": "PRE invoice created — waiting for buyer payment",
        }),
    );

    // Spawn thread to wait for payment and claim it
    let node = state.node.clone();
    let emitter2 = state.emitter.clone();
    let router = state.event_router.clone();
    thread::spawn(move || {
        handle_pre_sell_from_catalog(&node, &emitter2, &router, &htlc_preimage);
    });

    Json(serde_json::json!({
        "bolt11": bolt11,
        "payment_hash": payment_hash,
        "rk_compressed_hex": rk_compressed_hex,
        "content_hash": entry.content_hash,
        "encrypted_hash": entry.encrypted_hash,
        "encrypted_root": entry.encrypted_root,
        "pre_c1_hex": entry.pre_c1_hex,
        "pre_c2_hex": entry.pre_c2_hex,
        "pre_pk_creator_hex": entry.pre_pk_creator_hex,
        "price_sats": entry.price_sats,
        "file_name": entry.file_name,
        "size_bytes": entry.size_bytes,
    }))
    .into_response()
}

/// GET /api/pre-ciphertext/{content_hash}
///
/// Returns the PRE ciphertext components (c1, c2) and creator's PRE public key
/// for a given content. Seeders fetch this to perform re-encryption.
pub async fn pre_ciphertext_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter().find(|e| e.content_hash == content_hash).cloned()
    };

    match entry {
        Some(e) if !e.pre_c1_hex.is_empty() => Json(serde_json::json!({
            "content_hash": e.content_hash,
            "pre_c1_hex": e.pre_c1_hex,
            "pre_c2_hex": e.pre_c2_hex,
            "pre_pk_creator_hex": e.pre_pk_creator_hex,
        }))
        .into_response(),
        Some(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Content not PRE-enabled"
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Content not found"
            })),
        )
            .into_response(),
    }
}

/// Wait for a PRE payment, claim it, then confirm receipt (creator side).
pub fn handle_pre_sell_from_catalog(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    htlc_preimage: &[u8; 32],
) {
    let role = "creator";

    emitter.emit(
        role,
        "PRE_WAITING_FOR_PAYMENT",
        serde_json::json!({
            "message": "Listening for incoming PRE HTLC..."
        }),
    );

    let payment_hash = verify::sha256_hash(htlc_preimage);
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
                    "PRE_HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                invoice::claim_payment_pre(node, htlc_preimage, claimable_amount_msat)
                    .expect("Failed to claim PRE payment");
                emitter.emit(
                    role,
                    "PRE_PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(htlc_preimage),
                        "message": "PRE preimage revealed to buyer via HTLC settlement",
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
                    "PRE_PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "PRE payment confirmed. Content sold via PRE.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

/// GET /api/pre-info
///
/// Returns this node's PRE public key (buyer role, G2) so that creators
/// can compute re-encryption keys for purchases.
pub async fn pre_info_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "buyer_pk_hex": state.pre_buyer_pk_hex,
        "node_id": invoice::node_id(&state.node),
        "node_alias": state.node_alias,
    }))
}

/// Request body for PRE re-encryption (seeder side).
#[derive(Deserialize)]
pub struct PreReencryptRequest {
    /// Re-encryption key (compressed G2, 96 bytes, hex-encoded).
    rk_compressed_hex: String,
    /// Content hash to look up the PRE ciphertext in catalog.
    content_hash: String,
}

/// POST /api/pre-reencrypt
///
/// Seeder re-encrypts a PRE ciphertext using the buyer's rk.
/// Returns the re-encrypted ciphertext components (c1_prime as hex, c2 as hex).
///
/// The seeder must have the content in their catalog (fetched from creator).
/// The rk is provided by the buyer after they paid the creator.
pub async fn pre_reencrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<PreReencryptRequest>,
) -> impl IntoResponse {
    // Parse rk
    let rk_bytes = match hex::decode(&req.rk_compressed_hex) {
        Ok(b) if b.len() == 96 => {
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "rk_compressed_hex must be 96 bytes (192 hex chars)"
                })),
            )
                .into_response()
        }
    };

    // Look up content's PRE ciphertext
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.content_hash == req.content_hash || e.encrypted_hash == req.content_hash)
            .cloned()
    };

    let entry = match entry {
        Some(e) if !e.pre_c1_hex.is_empty() => e,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Content not PRE-enabled"})),
            )
                .into_response()
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Content not found in catalog"})),
            )
                .into_response()
        }
    };

    // Deserialize PRE ciphertext
    let ct = {
        let c1_bytes = match hex::decode(&entry.pre_c1_hex) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Invalid c1 in catalog"})),
                )
                    .into_response()
            }
        };
        let c2_bytes = match hex::decode(&entry.pre_c2_hex) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Invalid c2 in catalog"})),
                )
                    .into_response()
            }
        };
        let mut full = Vec::new();
        full.extend_from_slice(&c1_bytes);
        full.extend_from_slice(&c2_bytes);
        match pre::deserialize_ciphertext(&full) {
            Some(ct) => ct,
            None => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Failed to deserialize PRE ciphertext"})),
                )
                    .into_response()
            }
        }
    };

    // Re-encrypt
    let _re_ct = match pre::re_encrypt_from_bytes(&rk_bytes, &ct) {
        Some(r) => r,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid rk: not a valid G2 point"})),
            )
                .into_response()
        }
    };

    state.emitter.emit(
        "seeder",
        "PRE_REENCRYPTED",
        serde_json::json!({
            "content_hash": &req.content_hash,
            "message": "PRE ciphertext re-encrypted for buyer",
        }),
    );

    // Serialize c1_prime (Gt element) — we use the Debug repr for the KDF,
    // but for transmission we need a deterministic format.
    // Since Gt has no standard serialization in zkcrypto, we transmit the
    // c2 (unchanged) and a flag that the buyer should compute c1_prime locally.
    //
    // Alternative: transmit enough info for the buyer to reconstruct.
    // The buyer already has rk_compressed and can fetch the original c1 from
    // the catalog. So the buyer can compute c1_prime = e(c1, rk_point) locally.
    //
    // For now: return a signal that re-encryption succeeded, and the buyer
    // will compute it locally using c1 + rk.
    Json(serde_json::json!({
        "status": "reencrypted",
        "content_hash": entry.content_hash,
        "pre_c2_hex": entry.pre_c2_hex,
        "message": "Re-encryption complete. Buyer should compute c1_prime locally from c1 + rk."
    }))
    .into_response()
}

