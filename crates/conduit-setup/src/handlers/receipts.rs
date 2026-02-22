use axum::extract::State;
use axum::response::Json;

use conduit_core::receipt;

use crate::state::AppState;

/// GET /api/receipts
///
/// Returns all stored purchase receipts with verification status.
pub async fn receipts_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let receipts_dir = std::path::Path::new(&state.storage_dir).join("receipts");
    let receipts = receipt::load_all(&receipts_dir);

    let items: Vec<serde_json::Value> = receipts
        .iter()
        .map(|r| {
            let result = receipt::verify(r);
            let checks: Vec<serde_json::Value> = result
                .checks
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "passed": c.passed,
                        "detail": c.detail,
                    })
                })
                .collect();
            serde_json::json!({
                "content_hash": r.content_hash,
                "file_name": r.file_name,
                "creator_pubkey": r.creator_pubkey,
                "price_sats": r.price_sats,
                "timestamp": r.timestamp,
                "valid": result.valid,
                "checks": checks,
            })
        })
        .collect();

    Json(serde_json::json!({
        "receipts": items,
        "count": items.len(),
    }))
}
