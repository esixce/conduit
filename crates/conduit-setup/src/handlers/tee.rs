
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Deserialize;

use crate::catalog::*;
use crate::state::*;

// ---------------------------------------------------------------------------
// TEE Trust List API handlers
// ---------------------------------------------------------------------------

/// GET /api/trusted-manufacturers -- list all trusted manufacturers
pub async fn trust_list_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let list = state.trust_list.lock().unwrap();
    Json(serde_json::json!({ "items": *list }))
}

#[derive(Deserialize)]
pub struct AddTrustRequest {
    pk_hex: String,
    name: String,
}

/// POST /api/trusted-manufacturers -- add a manufacturer to trust list
pub async fn trust_add_handler(
    State(state): State<AppState>,
    Json(req): Json<AddTrustRequest>,
) -> impl IntoResponse {
    let mut list = state.trust_list.lock().unwrap();
    if list.iter().any(|m| m.pk_hex == req.pk_hex) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Manufacturer already trusted"})),
        )
            .into_response();
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    list.push(TrustedManufacturer {
        pk_hex: req.pk_hex.clone(),
        name: req.name.clone(),
        added_at: ts,
    });
    save_trust_list(&state.storage_dir, &list);
    println!(
        "Trusted manufacturer added: {} ({})",
        req.name,
        &req.pk_hex[..16.min(req.pk_hex.len())]
    );
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

/// DELETE /api/trusted-manufacturers/{pk_hex} -- remove a manufacturer from trust list
pub async fn trust_remove_handler(
    State(state): State<AppState>,
    AxumPath(pk_hex): AxumPath<String>,
) -> impl IntoResponse {
    let mut list = state.trust_list.lock().unwrap();
    let before = list.len();
    list.retain(|m| m.pk_hex != pk_hex);
    if list.len() == before {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Manufacturer not in trust list"})),
        )
            .into_response();
    }
    save_trust_list(&state.storage_dir, &list);
    println!(
        "Trusted manufacturer removed: {}",
        &pk_hex[..16.min(pk_hex.len())]
    );
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

// ---------------------------------------------------------------------------
// TEE Device Attestation API handlers
// ---------------------------------------------------------------------------

/// POST /api/device-attest -- device sends identity, creator returns challenge
#[derive(Deserialize)]
pub struct DeviceAttestRequest {
    dev_pk_hex: String,
    device_pk_g2_hex: String,
    manufacturer_pk_hex: String,
    model: String,
    firmware_hash: String,
    manufacturer_sig_hex: String,
}

pub async fn device_attest_handler(
    State(state): State<AppState>,
    Json(req): Json<DeviceAttestRequest>,
) -> impl IntoResponse {
    // Check manufacturer is in trust list
    {
        let list = state.trust_list.lock().unwrap();
        if !list.iter().any(|m| m.pk_hex == req.manufacturer_pk_hex) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Manufacturer not in trust list",
                    "manufacturer_pk_hex": req.manufacturer_pk_hex,
                })),
            )
                .into_response();
        }
    }

    // Verify the cert is valid (signed by the manufacturer)
    let dev_pk_bytes = match hex::decode(&req.dev_pk_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid dev_pk_hex"})),
            )
                .into_response()
        }
    };
    let device_pk_g2_bytes = match hex::decode(&req.device_pk_g2_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid device_pk_g2_hex"})),
            )
                .into_response()
        }
    };
    let manufacturer_sig_bytes = match hex::decode(&req.manufacturer_sig_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid manufacturer_sig_hex"})),
            )
                .into_response()
        }
    };
    let manufacturer_pk_bytes = match hex::decode(&req.manufacturer_pk_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid manufacturer_pk_hex"})),
            )
                .into_response()
        }
    };

    // Parse manufacturer public key
    let mfr_pk = match p256::PublicKey::from_sec1_bytes(&manufacturer_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid manufacturer P-256 key"})),
            )
                .into_response()
        }
    };
    let mfr_vk = p256::ecdsa::VerifyingKey::from(&mfr_pk);

    // Build a cert struct and verify it
    use sha2::{Digest as Sha2Digest, Sha256 as Sha256Hasher};
    let mut body = Vec::new();
    body.extend_from_slice(&dev_pk_bytes);
    body.extend_from_slice(&device_pk_g2_bytes);
    body.extend_from_slice(req.model.as_bytes());
    body.extend_from_slice(req.firmware_hash.as_bytes());
    let digest: [u8; 32] = Sha256Hasher::digest(&body).into();

    let sig = match p256::ecdsa::Signature::from_der(&manufacturer_sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid DER signature"})),
            )
                .into_response()
        }
    };

    use p256::ecdsa::signature::Verifier;
    if mfr_vk.verify(&digest, &sig).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "certificate verification failed"})),
        )
            .into_response();
    }

    // Generate challenge nonce
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "challenge",
            "nonce_hex": hex::encode(nonce),
            "device_pk_g2_hex": req.device_pk_g2_hex,
        })),
    )
        .into_response()
}

/// POST /api/device-attest/respond -- device sends signed nonce, creator verifies
#[derive(Deserialize)]
pub struct DeviceAttestResponse {
    dev_pk_hex: String,
    nonce_hex: String,
    signature_hex: String,
}

pub async fn device_attest_respond_handler(
    State(_state): State<AppState>,
    Json(req): Json<DeviceAttestResponse>,
) -> impl IntoResponse {
    let dev_pk_bytes = match hex::decode(&req.dev_pk_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid dev_pk_hex"})),
            )
                .into_response()
        }
    };
    let nonce_bytes = match hex::decode(&req.nonce_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid nonce_hex"})),
            )
                .into_response()
        }
    };
    let sig_bytes = match hex::decode(&req.signature_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid signature_hex"})),
            )
                .into_response()
        }
    };

    // Parse device P-256 public key
    let dev_pk = match p256::PublicKey::from_sec1_bytes(&dev_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid P-256 device key"})),
            )
                .into_response()
        }
    };
    let dev_vk = p256::ecdsa::VerifyingKey::from(&dev_pk);

    // Verify the signature over SHA-256(nonce)
    use sha2::{Digest as Sha2Digest2, Sha256 as Sha256Hasher2};
    let digest: [u8; 32] = Sha256Hasher2::digest(nonce_bytes).into();
    let sig = match p256::ecdsa::Signature::from_der(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid DER signature"})),
            )
                .into_response()
        }
    };

    use p256::ecdsa::signature::Verifier as Verifier2;
    if dev_vk.verify(&digest, &sig).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "challenge verification failed"})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "attested",
            "dev_pk_hex": req.dev_pk_hex,
        })),
    )
        .into_response()
}

