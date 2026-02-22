// ---------------------------------------------------------------------------
// Ad-subsidized invoice (creator side)
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Deserialize;

use conduit_core::{chunk, encrypt, invoice, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::events::*;
use crate::state::*;

use crate::buy::ad::handle_ad_sell_hold_and_claim;

#[derive(Deserialize)]
pub struct AdInvoiceRequest {
    /// URL of the advertiser node (e.g. "http://104.248.57.152:3005")
    advertiser_url: String,
}

/// POST /api/ad-invoice/{content_hash}
///
/// Two-payment ad-subsidized invoice flow (see docs/14_ad_attestation.md §4):
///
/// - **Invoice 1 (buyer_invoice):** preimage = K, amount = 1 sat.
///   The buyer pays this to atomically learn K. K never leaves the buyer.
///
/// - **Invoice 2 (advertiser_invoice):** preimage = K_ad (random), amount = content price.
///   The advertiser pays this after attestation. K_ad is meaningless.
///
/// **HOLD-AND-CLAIM-TOGETHER:** The creator does NOT claim Invoice 1 (which
/// would reveal K) until Invoice 2's HTLC also arrives. This protects the
/// creator from giving away K for 1 sat if the advertiser never pays.
/// Once BOTH HTLCs are pending, the creator claims both atomically.
///
/// The advertiser NEVER learns K. TEE-safe.
pub async fn ad_invoice_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
    Json(req): Json<AdInvoiceRequest>,
) -> impl IntoResponse {
    // Look up catalog entry
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter().find(|e| e.content_hash == content_hash).cloned()
    };

    let entry = match entry {
        Some(e) => e,
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

    // Fetch advertiser campaign list
    let advertiser_url = req.advertiser_url.trim_end_matches('/');
    let campaigns_url = format!("{}/api/campaigns", advertiser_url);
    let campaign_data = match reqwest::get(&campaigns_url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(data) => data,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!("Failed to parse advertiser response: {}", e)
                    })),
                )
                    .into_response()
            }
        },
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": format!("Failed to reach advertiser: {}", e)
                })),
            )
                .into_response()
        }
    };

    // Pick the first active campaign
    let campaigns = campaign_data["campaigns"].as_array();
    let campaign = match campaigns.and_then(|c| c.first()) {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "No active campaigns on advertiser"
                })),
            )
                .into_response()
        }
    };

    let advertiser_pubkey = campaign_data["advertiser_pubkey"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Parse stored content key K
    let key_bytes = hex::decode(&entry.key_hex).expect("Invalid key in catalog");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // -----------------------------------------------------------------------
    // Invoice 1: Buyer pays 1 sat, preimage = K (content decryption key)
    // -----------------------------------------------------------------------
    let buyer_bolt11 = match invoice::create_invoice_for_key(
        &state.node,
        &key,
        1,
        &format!("{} (ad-key)", entry.file_name),
    ) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to create buyer invoice: {}", e)
                })),
            )
                .into_response()
        }
    };
    let buyer_payment_hash = hex::encode(verify::sha256_hash(&key));

    // -----------------------------------------------------------------------
    // Invoice 2: Advertiser pays content price, preimage = K_ad (random)
    // -----------------------------------------------------------------------
    let mut k_ad = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut k_ad);

    let ad_bolt11 = match invoice::create_invoice_for_key(
        &state.node,
        &k_ad,
        entry.price_sats,
        &format!("{} (ad-subsidy)", entry.file_name),
    ) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to create advertiser invoice: {}", e)
                })),
            )
                .into_response()
        }
    };
    let ad_payment_hash = hex::encode(verify::sha256_hash(&k_ad));

    let enc_filename = entry
        .enc_file_path
        .split('/')
        .next_back()
        .unwrap_or("")
        .to_string();

    // Emit SSE event
    let emitter = state.emitter.clone();
    emitter.emit(
        "creator",
        "AD_INVOICE_CREATED",
        serde_json::json!({
            "buyer_payment_hash": &buyer_payment_hash,
            "ad_payment_hash": &ad_payment_hash,
            "content_hash": &entry.content_hash,
            "buyer_amount_sats": 1,
            "ad_amount_sats": entry.price_sats,
            "campaign_id": campaign["campaign_id"],
            "advertiser_url": advertiser_url,
            "mode": "ad-subsidized-two-payment",
        }),
    );

    // -----------------------------------------------------------------------
    // HOLD-AND-CLAIM-TOGETHER
    //
    // Spawn ONE thread that waits for BOTH HTLCs to arrive before claiming
    // either. This prevents the creator from revealing K (by claiming
    // Invoice 1) before the advertiser's HTLC (Invoice 2) is locked in.
    //
    // Without this, the creator would claim Invoice 1 immediately, the buyer
    // learns K and decrypts, and the advertiser could simply never pay —
    // leaving the creator with only 1 sat for their content.
    //
    // With hold-and-claim, the creator keeps both HTLCs pending until both
    // are in-flight, then claims both. If either HTLC times out before the
    // other arrives, the creator lets both expire (no content is delivered).
    // -----------------------------------------------------------------------
    {
        let node = state.node.clone();
        let tx2 = state.emitter.clone();
        let router = state.event_router.clone();
        thread::spawn(move || {
            handle_ad_sell_hold_and_claim(&node, &tx2, &router, &key, &k_ad);
        });
    }

    // Return BOTH invoices + campaign metadata
    Json(serde_json::json!({
        // Invoice 1: buyer pays 1 sat to learn K
        "buyer_invoice": buyer_bolt11,
        "buyer_payment_hash": buyer_payment_hash,
        // Invoice 2: advertiser pays content price (preimage = K_ad, useless)
        "advertiser_invoice": ad_bolt11,
        "ad_payment_hash": ad_payment_hash,
        // Content metadata
        "content_hash": entry.content_hash,
        "encrypted_hash": entry.encrypted_hash,
        "price_sats": entry.price_sats,
        "enc_filename": enc_filename,
        "file_name": entry.file_name,
        "size_bytes": entry.size_bytes,
        // Ad-specific fields
        "ad_subsidized": true,
        "campaign_id": campaign["campaign_id"],
        "advertiser_url": advertiser_url,
        "advertiser_pubkey": advertiser_pubkey,
        "ad_duration_ms": campaign["duration_ms"],
        "ad_creative_url": format!("{}/api/campaigns/{}/creative", advertiser_url, campaign["campaign_id"].as_str().unwrap_or("")),
        "subsidy_sats": campaign["subsidy_sats"],
    })).into_response()
}

/// Optional body for transport-invoice: request specific chunks instead of whole file.
#[derive(Deserialize, Default)]
pub struct TransportInvoiceBody {
    #[serde(default)]
    chunks: Vec<usize>, // empty = legacy whole-file wrapping
}

pub async fn transport_invoice_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
    body: Option<Json<TransportInvoiceBody>>,
) -> impl IntoResponse {
    let requested_chunks = body.map(|b| b.0.chunks).unwrap_or_default();

    // Look up catalog entry by encrypted_hash
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash && e.transport_price > 0)
            .cloned()
    };

    let entry = match entry {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "Content not found in seeder catalog"
                })),
            )
                .into_response()
        }
    };

    // Read encrypted file
    let encrypted = match std::fs::read(&entry.enc_file_path) {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to read encrypted file: {}", e)
                })),
            )
                .into_response()
        }
    };

    // Generate fresh transport key K_S
    let ks = encrypt::generate_key();

    if requested_chunks.is_empty() {
        // --- Legacy mode: wrap entire file as one blob ---
        let wrapped = encrypt::encrypt(&encrypted, &ks, 0);
        let wrapped_path = format!("{}.wrapped", entry.enc_file_path);
        let wrapped_filename = wrapped_path
            .split('/')
            .next_back()
            .unwrap_or("")
            .to_string();
        if let Err(e) = std::fs::write(&wrapped_path, &wrapped) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to write wrapped file: {}", e)
                })),
            )
                .into_response();
        }

        let bolt11 = match invoice::create_invoice_for_key(
            &state.node,
            &ks,
            entry.transport_price,
            "transport",
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

        let payment_hash = hex::encode(verify::sha256_hash(&ks));

        let emitter = state.emitter.clone();
        emitter.emit(
            "seeder",
            "TRANSPORT_INVOICE_CREATED",
            serde_json::json!({
                "payment_hash": &payment_hash,
                "amount_sats": entry.transport_price,
                "bolt11": &bolt11,
                "wrapped_filename": &wrapped_filename,
                "encrypted_hash": &encrypted_hash,
            }),
        );

        let node = state.node.clone();
        let tx2 = state.emitter.clone();
        let router = state.event_router.clone();
        thread::spawn(move || {
            handle_transport_payment(&node, &tx2, &router, &ks);
        });

        Json(serde_json::json!({
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "encrypted_hash": encrypted_hash,
            "transport_price": entry.transport_price,
            "wrapped_filename": wrapped_filename,
            "mode": "whole_file",
        }))
        .into_response()
    } else {
        // --- Chunked mode: wrap each requested chunk individually with K_S ---
        let cs = if entry.chunk_size > 0 {
            entry.chunk_size
        } else {
            chunk::select_chunk_size(encrypted.len())
        };
        let (enc_chunks, _meta) = chunk::split(&encrypted, cs);
        let total_chunks = enc_chunks.len();

        // Validate requested chunks
        for &idx in &requested_chunks {
            if idx >= total_chunks {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": format!("Chunk index {} out of range (total: {})", idx, total_chunks)
                }))).into_response();
            }
            // Check if seeder holds this chunk
            if !entry.chunks_held.is_empty() && !entry.chunks_held.contains(&idx) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("Seeder does not hold chunk {}", idx)
                    })),
                )
                    .into_response();
            }
        }

        // Wrap each requested chunk: W_i = Enc(E_i, K_S, chunk_index=i)
        let wrap_dir = format!("{}.wrapped_chunks", entry.enc_file_path);
        let _ = std::fs::create_dir_all(&wrap_dir);
        let mut wrapped_files = Vec::new();
        for &idx in &requested_chunks {
            let wrapped_chunk = encrypt::encrypt(&enc_chunks[idx], &ks, idx as u64);
            let chunk_path = format!("{}/{}", wrap_dir, idx);
            if let Err(e) = std::fs::write(&chunk_path, &wrapped_chunk) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to write wrapped chunk {}: {}", idx, e)
                    })),
                )
                    .into_response();
            }
            wrapped_files.push(idx);
        }

        let bolt11 = match invoice::create_invoice_for_key(
            &state.node,
            &ks,
            entry.transport_price,
            "transport",
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

        let payment_hash = hex::encode(verify::sha256_hash(&ks));

        let emitter = state.emitter.clone();
        emitter.emit(
            "seeder",
            "TRANSPORT_INVOICE_CREATED",
            serde_json::json!({
                "payment_hash": &payment_hash,
                "amount_sats": entry.transport_price,
                "bolt11": &bolt11,
                "chunks": &requested_chunks,
                "encrypted_hash": &encrypted_hash,
                "mode": "chunked",
            }),
        );

        let node = state.node.clone();
        let tx2 = state.emitter.clone();
        let router = state.event_router.clone();
        thread::spawn(move || {
            handle_transport_payment(&node, &tx2, &router, &ks);
        });

        Json(serde_json::json!({
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "encrypted_hash": encrypted_hash,
            "transport_price": entry.transport_price,
            "chunks": wrapped_files,
            "wrap_dir": wrap_dir.split('/').next_back().unwrap_or(""),
            "mode": "chunked",
        }))
        .into_response()
    }
}

/// Wait for a transport payment and claim it (reveals K_S to buyer).
pub fn handle_transport_payment(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    ks: &[u8; 32],
) {
    let role = "seeder";
    let payment_hash_bytes = verify::sha256_hash(ks);
    let expected_hash = PaymentHash(payment_hash_bytes);

    emitter.emit(
        role,
        "WAITING_FOR_TRANSPORT_PAYMENT",
        serde_json::json!({
            "payment_hash": hex::encode(payment_hash_bytes),
            "message": "Listening for incoming transport HTLC...",
        }),
    );

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
                    "TRANSPORT_HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                invoice::claim_payment(node, ks, claimable_amount_msat)
                    .expect("Failed to claim transport payment");
                emitter.emit(
                    role,
                    "TRANSPORT_PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(ks),
                        "message": "Transport key K_S revealed to buyer via HTLC settlement",
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
                    "TRANSPORT_PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "Transport payment confirmed. Content delivered.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

pub async fn decrypted_file_handler(
    State(state): State<AppState>,
    AxumPath(filename): AxumPath<String>,
) -> impl IntoResponse {
    let primary = format!("{}/{}", state.storage_dir, filename);
    let fallback = format!("/tmp/{}", filename);
    let path = if std::path::Path::new(&primary).exists() {
        primary
    } else {
        fallback
    };
    let ct = if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".gif") {
        "image/gif"
    } else if path.ends_with(".mp4") {
        "video/mp4"
    } else if path.ends_with(".webm") {
        "video/webm"
    } else if path.ends_with(".mov") {
        "video/quicktime"
    } else if path.ends_with(".txt") {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    match std::fs::read(&path) {
        Ok(data) => (StatusCode::OK, [("content-type", ct)], data).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
