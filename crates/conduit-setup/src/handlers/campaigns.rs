// ===========================================================================
// Advertiser role — third-party ad campaigns, attestation tokens, ad creative
// serving, subsidy invoice payment. Advertisers are external parties (brands,
// businesses, anyone) who pay to show their ads to buyers in exchange for
// subsidizing content purchases. The creator's content is the delivery vehicle.
// See docs/14_ad_attestation.md and docs/15_unified_dashboard.md.
// ===========================================================================

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::Connection;
use uuid::Uuid;


use crate::state::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdvCampaign {
    campaign_id: String,
    name: String,
    creative_url: String,
    creative_hash: String,
    creative_format: String,
    duration_ms: u64,
    subsidy_sats: u64,
    budget_total_sats: u64,
    budget_spent_sats: u64,
    active: bool,
    created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdvStartSessionRequest {
    buyer_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct AdvCompleteSessionRequest {
    session_id: String,
    buyer_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdvAttestationPayload {
    campaign_id: String,
    buyer_pubkey: String,
    timestamp: u64,
    duration_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct AdvPayRequest {
    bolt11_invoice: String,
    attestation_token: String,
    attestation_payload: AdvAttestationPayload,
}

pub fn adv_init_db(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            creative_url TEXT NOT NULL,
            creative_hash TEXT NOT NULL DEFAULT '',
            creative_format TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            subsidy_sats INTEGER NOT NULL,
            budget_total_sats INTEGER NOT NULL,
            budget_spent_sats INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            buyer_pubkey TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS adv_payments (
            payment_hash TEXT PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            buyer_pubkey TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            paid_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_campaign ON sessions(campaign_id);
        CREATE INDEX IF NOT EXISTS idx_adv_payments_campaign ON adv_payments(campaign_id);",
    )
    .expect("Failed to initialize advertiser database schema");
}

pub fn adv_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn adv_load_campaigns(db: &Connection) -> Vec<AdvCampaign> {
    let mut stmt = db
        .prepare(
            "SELECT campaign_id, name, creative_url, creative_hash, creative_format,
                    duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
                    active, created_at
             FROM campaigns ORDER BY created_at DESC",
        )
        .unwrap();

    stmt.query_map([], |row| {
        Ok(AdvCampaign {
            campaign_id: row.get(0)?,
            name: row.get(1)?,
            creative_url: row.get(2)?,
            creative_hash: row.get(3)?,
            creative_format: row.get(4)?,
            duration_ms: row.get(5)?,
            subsidy_sats: row.get(6)?,
            budget_total_sats: row.get(7)?,
            budget_spent_sats: row.get(8)?,
            active: row.get::<_, i32>(9)? != 0,
            created_at: row.get(10)?,
        })
    })
    .unwrap()
    .filter_map(|r| r.ok())
    .collect()
}

pub fn adv_infer_format(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    if lower.ends_with(".mp4") {
        "video/mp4"
    } else if lower.ends_with(".webm") {
        "video/webm"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}

// Attestation crypto helpers

pub fn adv_canonical_json(payload: &AdvAttestationPayload) -> String {
    serde_json::to_string(payload).unwrap()
}

pub fn adv_sign_attestation(key: &SigningKey, payload: &AdvAttestationPayload) -> String {
    let message = adv_canonical_json(payload);
    let signature = key.sign(message.as_bytes());
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    )
}

pub fn adv_verify_attestation(
    verifying_key: &VerifyingKey,
    payload: &AdvAttestationPayload,
    token_b64: &str,
) -> bool {
    let message = adv_canonical_json(payload);
    let sig_bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    use ed25519_dalek::Verifier;
    verifying_key.verify(message.as_bytes(), &signature).is_ok()
}

pub fn adv_load_or_create_signing_key(storage_dir: &str) -> SigningKey {
    let key_path = format!("{}/advertiser_ed25519.key", storage_dir);
    if let Ok(data) = std::fs::read(&key_path) {
        if data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            return SigningKey::from_bytes(&bytes);
        }
    }
    let mut rng = rand::thread_rng();
    let key = SigningKey::generate(&mut rng);
    std::fs::write(&key_path, key.to_bytes()).expect("Failed to write signing key");
    println!("Generated new Ed25519 signing key at {}", key_path);
    key
}

// Advertiser HTTP handlers

/// GET /api/campaigns -- list active campaigns
pub async fn adv_list_campaigns(State(state): State<AppState>) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Advertiser role not enabled"})),
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let campaigns = adv_load_campaigns(&db);
    let active: Vec<_> = campaigns.into_iter().filter(|c| c.active).collect();
    let pubkey = state.advertiser_pubkey_hex.clone().unwrap_or_default();
    Json(serde_json::json!({ "campaigns": active, "advertiser_pubkey": pubkey })).into_response()
}

/// GET /api/campaigns/{campaign_id}
pub async fn adv_get_campaign(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Advertiser role not enabled",
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let result = db.query_row(
        "SELECT campaign_id, name, creative_url, creative_hash, creative_format,
                duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
                active, created_at
         FROM campaigns WHERE campaign_id = ?1",
        rusqlite::params![campaign_id],
        |row| {
            Ok(AdvCampaign {
                campaign_id: row.get(0)?,
                name: row.get(1)?,
                creative_url: row.get(2)?,
                creative_hash: row.get(3)?,
                creative_format: row.get(4)?,
                duration_ms: row.get(5)?,
                subsidy_sats: row.get(6)?,
                budget_total_sats: row.get(7)?,
                budget_spent_sats: row.get(8)?,
                active: row.get::<_, i32>(9)? != 0,
                created_at: row.get(10)?,
            })
        },
    );
    match result {
        Ok(c) => Json(serde_json::json!(c)).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Campaign not found"})),
        )
            .into_response(),
    }
}

/// GET /api/campaigns/{campaign_id}/creative -- redirect to advertiser-hosted creative
pub async fn adv_serve_creative(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Advertiser role not enabled",
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let url: Result<String, _> = db.query_row(
        "SELECT creative_url FROM campaigns WHERE campaign_id = ?1 AND active = 1",
        rusqlite::params![campaign_id],
        |row| row.get(0),
    );
    match url {
        Ok(u) => axum::response::Redirect::temporary(&u).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Campaign not found or inactive").into_response(),
    }
}

/// POST /api/campaigns -- create a new campaign via API
///
/// The advertiser hosts creative media on their own server and provides
/// a `creative_url` pointing to it. Conduit nodes never store ad creatives.
pub async fn adv_create_campaign(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Advertiser role not enabled"})),
            )
                .into_response()
        }
    };
    let name = req["name"]
        .as_str()
        .unwrap_or("Unnamed Campaign")
        .to_string();
    let creative_url = req["creative_url"].as_str().unwrap_or("").to_string();
    let duration_ms = req["duration_ms"].as_u64().unwrap_or(15000);
    let subsidy_sats = req["subsidy_sats"].as_u64().unwrap_or(50);
    let budget_total = req["budget_total_sats"].as_u64().unwrap_or(1_000_000);

    if creative_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "creative_url is required"})),
        )
            .into_response();
    }

    // Infer format from URL extension; caller can override with content_type
    let creative_format = req["content_type"]
        .as_str()
        .unwrap_or_else(|| adv_infer_format(&creative_url))
        .to_string();

    // Hash is optional — advertiser can supply it, otherwise left empty
    let creative_hash = req["creative_hash"].as_str().unwrap_or("").to_string();

    let campaign_id = Uuid::new_v4().to_string();
    let db = db.lock().unwrap();
    db.execute(
        "INSERT INTO campaigns
         (campaign_id, name, creative_url, creative_hash, creative_format,
          duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
          active, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9)",
        rusqlite::params![
            campaign_id,
            name,
            creative_url,
            creative_hash,
            creative_format,
            duration_ms,
            subsidy_sats,
            budget_total,
            adv_now_unix(),
        ],
    )
    .unwrap();
    println!(
        "[advertiser] Campaign created: {} → {} ({})",
        name, creative_url, campaign_id
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "campaign_id": campaign_id,
            "name": name,
            "creative_url": creative_url,
            "creative_format": creative_format,
        })),
    )
        .into_response()
}

/// DELETE /api/campaigns -- clear all campaigns (for test re-provisioning)
pub async fn adv_clear_campaigns(State(state): State<AppState>) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Advertiser role not enabled"})),
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let deleted = db.execute("DELETE FROM campaigns", []).unwrap_or(0);
    let _ = db.execute("DELETE FROM sessions", []);
    let _ = db.execute("DELETE FROM adv_payments", []);
    println!("[advertiser] Cleared {} campaigns", deleted);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "deleted": deleted })),
    )
        .into_response()
}

/// POST /api/campaigns/{campaign_id}/start -- begin a viewing session
pub async fn adv_start_session(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
    Json(req): Json<AdvStartSessionRequest>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Advertiser role not enabled"})),
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let campaign: Result<(u64, u64, u64), _> = db.query_row(
        "SELECT duration_ms, budget_total_sats, budget_spent_sats FROM campaigns WHERE campaign_id = ?1 AND active = 1",
        rusqlite::params![campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    let (duration_ms, budget_total, budget_spent) = match campaign {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Campaign not found or inactive"})),
            )
                .into_response()
        }
    };
    if budget_spent >= budget_total {
        return (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "Campaign budget exhausted"})),
        )
            .into_response();
    }
    let active_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE campaign_id = ?1 AND buyer_pubkey = ?2 AND completed = 0 AND started_at > ?3",
            rusqlite::params![campaign_id, req.buyer_pubkey, adv_now_unix() - 300],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if active_count >= 5 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many active sessions"})),
        )
            .into_response();
    }
    let session_id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO sessions (session_id, campaign_id, buyer_pubkey, started_at, completed, duration_ms) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        rusqlite::params![session_id, campaign_id, req.buyer_pubkey, adv_now_unix(), duration_ms],
    )
    .unwrap();
    println!(
        "[advertiser] Session started: {} for campaign {} by {}",
        session_id,
        campaign_id,
        &req.buyer_pubkey[..8.min(req.buyer_pubkey.len())]
    );
    Json(serde_json::json!({ "session_id": session_id, "duration_ms": duration_ms }))
        .into_response()
}

/// POST /api/campaigns/{campaign_id}/complete -- complete session, return attestation token
pub async fn adv_complete_session(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
    Json(req): Json<AdvCompleteSessionRequest>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Advertiser role not enabled"})),
            )
                .into_response()
        }
    };
    let db = db.lock().unwrap();
    let session: Result<(u64, i32, u64, String), _> = db.query_row(
        "SELECT started_at, completed, duration_ms, buyer_pubkey FROM sessions WHERE session_id = ?1 AND campaign_id = ?2",
        rusqlite::params![req.session_id, campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    );
    let (started_at, completed, duration_ms, stored_pubkey) = match session {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Session not found"})),
            )
                .into_response()
        }
    };
    if stored_pubkey != req.buyer_pubkey {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "buyer_pubkey mismatch"})),
        )
            .into_response();
    }
    if completed != 0 {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Session already completed"})),
        )
            .into_response();
    }
    let elapsed_ms = (adv_now_unix() - started_at) * 1000;
    if elapsed_ms < duration_ms {
        return (StatusCode::PRECONDITION_FAILED, Json(serde_json::json!({
            "error": "Ad viewing not yet complete", "elapsed_ms": elapsed_ms, "required_ms": duration_ms,
        }))).into_response();
    }
    db.execute(
        "UPDATE sessions SET completed = 1 WHERE session_id = ?1",
        rusqlite::params![req.session_id],
    )
    .unwrap();
    let payload = AdvAttestationPayload {
        campaign_id: campaign_id.clone(),
        buyer_pubkey: req.buyer_pubkey.clone(),
        timestamp: adv_now_unix(),
        duration_ms,
    };
    let signing_key = state.advertiser_signing_key.as_ref().unwrap();
    let token = adv_sign_attestation(signing_key, &payload);
    let pubkey_hex = state.advertiser_pubkey_hex.clone().unwrap_or_default();
    println!(
        "[advertiser] Attestation issued: campaign={} buyer={}",
        campaign_id,
        &req.buyer_pubkey[..8.min(req.buyer_pubkey.len())]
    );
    Json(serde_json::json!({ "token": token, "payload": payload, "advertiser_pubkey": pubkey_hex }))
        .into_response()
}

/// POST /api/campaigns/{campaign_id}/pay -- validate attestation + pay invoice via LDK
pub async fn adv_pay_invoice(
    State(state): State<AppState>,
    Json(req): Json<AdvPayRequest>,
) -> impl IntoResponse {
    let signing_key = match &state.advertiser_signing_key {
        Some(k) => k.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"status": "advertiser_not_enabled"})),
            )
                .into_response()
        }
    };
    let verifying_key = VerifyingKey::from(&*signing_key);
    if !adv_verify_attestation(
        &verifying_key,
        &req.attestation_payload,
        &req.attestation_token,
    ) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"status": "invalid_attestation", "payment_hash": serde_json::Value::Null}))).into_response();
    }
    let db = state.advertiser_db.as_ref().unwrap();
    let db = db.lock().unwrap();
    let campaign: Result<(u64, u64, u64), _> = db.query_row(
        "SELECT subsidy_sats, budget_total_sats, budget_spent_sats FROM campaigns WHERE campaign_id = ?1 AND active = 1",
        rusqlite::params![req.attestation_payload.campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    let (subsidy_sats, budget_total, budget_spent) = match campaign {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"status": "campaign_not_found", "payment_hash": serde_json::Value::Null}))).into_response(),
    };
    if budget_spent + subsidy_sats > budget_total {
        return (StatusCode::PAYMENT_REQUIRED, Json(serde_json::json!({"status": "budget_exhausted", "payment_hash": serde_json::Value::Null}))).into_response();
    }
    db.execute(
        "UPDATE campaigns SET budget_spent_sats = budget_spent_sats + ?1 WHERE campaign_id = ?2",
        rusqlite::params![subsidy_sats, req.attestation_payload.campaign_id],
    )
    .unwrap();
    drop(db);

    let invoice: ldk_node::lightning_invoice::Bolt11Invoice = match req.bolt11_invoice.parse() {
        Ok(inv) => inv,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"status": format!("invalid_invoice: {}", e), "payment_hash": serde_json::Value::Null}))).into_response(),
    };
    let hash_bytes: &[u8] = invoice.payment_hash().as_ref();
    let payment_hash_hex = hex::encode(hash_bytes);

    match state.node.bolt11_payment().send(&invoice, None) {
        Ok(_) => {
            println!(
                "[advertiser] Payment sent: {} sats for campaign {} (hash: {})",
                subsidy_sats, req.attestation_payload.campaign_id, payment_hash_hex
            );
            let db = state.advertiser_db.as_ref().unwrap().lock().unwrap();
            let _ = db.execute(
                "INSERT OR REPLACE INTO adv_payments (payment_hash, campaign_id, buyer_pubkey, amount_sats, paid_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![payment_hash_hex, req.attestation_payload.campaign_id, req.attestation_payload.buyer_pubkey, subsidy_sats, adv_now_unix()],
            );
            Json(serde_json::json!({"status": "payment_sent", "payment_hash": payment_hash_hex}))
                .into_response()
        }
        Err(e) => {
            eprintln!("[advertiser] Payment failed: {}", e);
            let db = state.advertiser_db.as_ref().unwrap().lock().unwrap();
            let _ = db.execute(
                "UPDATE campaigns SET budget_spent_sats = budget_spent_sats - ?1 WHERE campaign_id = ?2",
                rusqlite::params![subsidy_sats, req.attestation_payload.campaign_id],
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"status": format!("payment_failed: {}", e), "payment_hash": serde_json::Value::Null}))).into_response()
        }
    }
}

/// GET /api/advertiser/info -- advertiser-specific info
pub async fn adv_info_handler(State(state): State<AppState>) -> impl IntoResponse {
    let pubkey = state.advertiser_pubkey_hex.clone().unwrap_or_default();
    let enabled = state.advertiser_db.is_some();
    let mut stats = serde_json::json!({
        "enabled": enabled,
        "advertiser_pubkey": pubkey,
    });
    if let Some(db) = &state.advertiser_db {
        let db = db.lock().unwrap();
        let campaigns = adv_load_campaigns(&db);
        let total_payments: i64 = db
            .query_row("SELECT COUNT(*) FROM adv_payments", [], |row| row.get(0))
            .unwrap_or(0);
        let total_spent: i64 = db
            .query_row(
                "SELECT COALESCE(SUM(amount_sats), 0) FROM adv_payments",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        stats["campaign_count"] = serde_json::json!(campaigns.len());
        stats["total_payments"] = serde_json::json!(total_payments);
        stats["total_spent_sats"] = serde_json::json!(total_spent);
    }
    Json(stats)
}

