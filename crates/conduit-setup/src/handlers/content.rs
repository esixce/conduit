use std::thread;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};

use conduit_core::invoice;
use conduit_core::pre;
use conduit_core::verify;

use crate::catalog::*;
use crate::events::*;
use crate::state::*;

use crate::buy::chunked::handle_buy_chunked;
use crate::buy::direct::handle_buy_two_phase;
use crate::buy::pre::handle_buy_pre;
use crate::buy::simple::handle_buy;
use crate::sell::{handle_register, handle_seed, handle_sell, handle_sell_from_catalog};

pub async fn sell_handler(
    State(state): State<AppState>,
    Json(req): Json<SellRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.emitter.clone();
    let router = state.event_router.clone();
    thread::spawn(move || {
        handle_sell(&node, tx.as_ref(), &router, &req.file, req.price);
    });
    Json(serde_json::json!({"status": "started"}))
}

pub async fn buy_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.emitter.clone();
    let router = state.event_router.clone();
    let is_chunked = matches!(req.mode.as_deref(), Some("chunked") | Some("seeder"));
    let is_two_phase = req.transport_invoice.is_some() && req.content_invoice.is_some();
    thread::spawn(move || {
        if is_chunked {
            // --- Chunked buy: multi-source chunk download (A5) ---
            handle_buy_chunked(&node, tx.as_ref(), &router, &req);
        } else if is_two_phase {
            // --- Two-phase buy: seeder + creator ---
            handle_buy_two_phase(&node, tx.as_ref(), &router, &req);
        } else {
            // --- Legacy single-phase buy ---
            let enc_path = if let Some(ref url) = req.enc_url {
                match curl_fetch(url, tx.as_ref()) {
                    Some(path) => path,
                    None => return,
                }
            } else if let Some(ref path) = req.encrypted_file {
                path.clone()
            } else {
                tx.emit(
                    "buyer",
                    "BUY_ERROR",
                    serde_json::json!({
                        "message": "No encrypted_file, enc_url, or wrapped_url provided",
                    }),
                );
                return;
            };
            let invoice = req.invoice.as_deref().unwrap_or("");
            handle_buy(
                &node,
                tx.as_ref(),
                &router,
                invoice,
                &enc_path,
                &req.hash,
                &req.output,
            );
        }
    });
    Json(serde_json::json!({"status": "started"}))
}


/// POST /api/buy-pre — Browser-initiated PRE buy.
///
/// Spawns a background thread that:
///   1. Calls creator /api/pre-purchase with this node's buyer G2 pk
///   2. Pays the Lightning invoice
///   3. Recovers AES key m via PRE decryption
///   4. Downloads & decrypts chunks
///   5. Emits SSE events throughout
pub async fn buy_pre_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyPreRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.emitter.clone();
    let router = state.event_router.clone();
    let storage_dir = state.storage_dir.clone();
    let p2p_node = state.p2p_node.clone();
    let p2p_rt = state.p2p_runtime_handle.clone();
    let registry_url = state.registry_info.as_ref().map(|r| r.url.clone());

    // Derive buyer PRE keypair (same seed as startup)
    let buyer_kp = {
        let seed = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"conduit-pre-buyer-seed:");
            h.update(storage_dir.as_bytes());
            let hash = h.finalize();
            let mut s = [0u8; 32];
            s.copy_from_slice(&hash);
            s
        };
        pre::buyer_keygen_from_seed(&seed)
    };

    thread::spawn(move || {
        handle_buy_pre(
            &node,
            tx.as_ref(),
            &router,
            &storage_dir,
            &buyer_kp,
            &req.creator_url,
            &req.content_hash,
            req.seeder_url.as_deref(),
            &req.output,
            p2p_node,
            p2p_rt,
            &req.source_mode,
            registry_url.as_deref(),
        );
    });
    Json(serde_json::json!({"status": "started"}))
}

/// Download a URL to /tmp/ via curl, emitting SSE events. Returns local path on success.
pub fn curl_fetch(url: &str, emitter: &ConsoleEmitter) -> Option<String> {
    let local = format!(
        "/tmp/fetched-{}",
        url.split('/').next_back().unwrap_or("download.enc")
    );
    emitter.emit(
        "buyer",
        "FETCHING_ENC",
        serde_json::json!({
            "url": url,
            "message": "Downloading encrypted file...",
        }),
    );
    let curl = std::process::Command::new("curl")
        .args(["-sS", "-o", &local, url])
        .output();
    match curl {
        Ok(out) if out.status.success() => {
            let bytes = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
            emitter.emit(
                "buyer",
                "ENC_FETCHED",
                serde_json::json!({
                    "bytes": bytes,
                    "path": &local,
                }),
            );
            Some(local)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            emitter.emit(
                "buyer",
                "FETCH_FAILED",
                serde_json::json!({
                    "error": format!("curl failed: {}", stderr),
                }),
            );
            None
        }
        Err(e) => {
            emitter.emit(
                "buyer",
                "FETCH_FAILED",
                serde_json::json!({
                    "error": format!("curl not found: {}", e),
                }),
            );
            None
        }
    }
}

pub async fn seed_handler(
    State(state): State<AppState>,
    Json(req): Json<SeedRequest>,
) -> Json<serde_json::Value> {
    let tx = state.emitter.clone();
    let catalog = state.catalog.clone();
    let storage_dir = state.storage_dir.clone();
    let registry_info = state.registry_info.clone();
    thread::spawn(move || {
        handle_seed(
            tx.as_ref(),
            &storage_dir,
            &catalog,
            &req.encrypted_file,
            &req.encrypted_hash,
            req.transport_price,
            &registry_info,
            &req.chunks,
        );
    });
    Json(serde_json::json!({"status": "started"}))
}

pub async fn wrapped_file_handler(
    State(state): State<AppState>,
    AxumPath(filename): AxumPath<String>,
) -> impl IntoResponse {
    // Try storage dir first, then fall back to /tmp/ for backward compat
    let primary = format!("{}/{}", state.storage_dir, filename);
    let fallback = format!("/tmp/{}", filename);
    let data = std::fs::read(&primary).or_else(|_| std::fs::read(&fallback));
    match data {
        Ok(bytes) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("content-disposition", "attachment"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "wrapped file not found").into_response(),
    }
}

pub async fn enc_file_handler(
    State(state): State<AppState>,
    AxumPath(filename): AxumPath<String>,
) -> impl IntoResponse {
    // Try storage dir first, then fall back to /tmp/ for backward compat
    let primary = format!("{}/{}", state.storage_dir, filename);
    let fallback = format!("/tmp/{}", filename);
    let data = std::fs::read(&primary).or_else(|_| std::fs::read(&fallback));
    match data {
        Ok(bytes) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("content-disposition", "attachment"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "file not found").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Catalog API endpoints
// ---------------------------------------------------------------------------

pub async fn catalog_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let cat = state.catalog.lock().unwrap();
    let items: Vec<serde_json::Value> = cat
        .iter()
        .map(|e| {
            let enc_filename = e
                .enc_file_path
                .split('/')
                .next_back()
                .unwrap_or("")
                .to_string();
            serde_json::json!({
                "content_hash": e.content_hash,
                "file_name": e.file_name,
                "price_sats": e.price_sats,
                "encrypted_hash": e.encrypted_hash,
                "size_bytes": e.size_bytes,
                "enc_filename": enc_filename,
                "transport_price": e.transport_price,
                "chunk_size": e.chunk_size,
                "chunk_count": e.chunk_count,
                "plaintext_root": e.plaintext_root,
                "encrypted_root": e.encrypted_root,
                "pre_c1_hex": e.pre_c1_hex,
                "pre_c2_hex": e.pre_c2_hex,
                "pre_pk_creator_hex": e.pre_pk_creator_hex,
                "playback_policy": e.playback_policy,
            })
        })
        .collect();
    Json(serde_json::json!({ "items": items }))
}

/// DELETE /api/catalog -- clear local catalog (for test re-provisioning)
pub async fn catalog_clear_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut cat = state.catalog.lock().unwrap();
    let count = cat.len();
    cat.clear();
    save_catalog(&state.storage_dir, &cat);
    println!("Catalog cleared ({} entries removed)", count);
    Json(serde_json::json!({ "deleted": count }))
}

pub async fn register_api_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<serde_json::Value> {
    let tx = state.emitter.clone();
    let catalog = state.catalog.clone();
    let storage_dir = state.storage_dir.clone();
    let registry_info = state.registry_info.clone();
    thread::spawn(move || {
        handle_register(
            tx.as_ref(),
            &storage_dir,
            &catalog,
            &req.file,
            req.price,
            &registry_info,
        );
    });
    Json(serde_json::json!({"status": "started"}))
}

pub async fn invoice_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
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

    // Parse stored key
    let key_bytes = hex::decode(&entry.key_hex).expect("Invalid key in catalog");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Create a fresh invoice with K as preimage
    let bolt11 = match invoice::create_invoice_for_key(
        &state.node,
        &key,
        entry.price_sats,
        &entry.file_name,
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

    let payment_hash = hex::encode(verify::sha256_hash(&key));
    let enc_filename = entry
        .enc_file_path
        .split('/')
        .next_back()
        .unwrap_or("")
        .to_string();

    // Emit SSE event so the console can see it
    let emitter = state.emitter.clone();
    emitter.emit(
        "creator",
        "INVOICE_CREATED",
        serde_json::json!({
            "payment_hash": &payment_hash,
            "content_hash": &entry.content_hash,
            "encrypted_hash": &entry.encrypted_hash,
            "amount_sats": entry.price_sats,
            "bolt11": &bolt11,
            "enc_filename": &enc_filename,
            "file_name": &entry.file_name,
        }),
    );

    // Spawn a thread to wait for payment and claim it
    let node = state.node.clone();
    let tx2 = state.emitter.clone();
    let router = state.event_router.clone();
    thread::spawn(move || {
        handle_sell_from_catalog(&node, &tx2, &router, &key);
    });

    // Return invoice data to caller
    Json(serde_json::json!({
        "bolt11": bolt11,
        "payment_hash": payment_hash,
        "content_hash": entry.content_hash,
        "encrypted_hash": entry.encrypted_hash,
        "price_sats": entry.price_sats,
        "enc_filename": enc_filename,
        "file_name": entry.file_name,
        "size_bytes": entry.size_bytes,
    }))
    .into_response()
}

