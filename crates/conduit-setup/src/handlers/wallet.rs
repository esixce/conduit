
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};

use conduit_core::invoice;
use ldk_node::lightning::ln::msgs::SocketAddress;

use crate::console::CONSOLE_HTML;
use crate::state::*;

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

pub async fn index_handler(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(ref path) = state.dashboard_path {
        match std::fs::read_to_string(path) {
            Ok(html) => return Html(html).into_response(),
            Err(e) => {
                eprintln!("Failed to read dashboard file {}: {}", path, e);
            }
        }
    }
    Html(CONSOLE_HTML.to_string()).into_response()
}

pub fn resolve_dashboard_sibling(
    dashboard_path: &Option<String>,
    filename: &str,
) -> Option<std::path::PathBuf> {
    dashboard_path.as_ref().and_then(|p| {
        std::path::Path::new(p)
            .parent()
            .map(|dir| dir.join(filename))
    })
}

pub const PWA_FILES: &[(&str, &str)] = &[
    ("manifest.json", "application/manifest+json"),
    ("sw.js", "application/javascript"),
    ("icon-192.png", "image/png"),
    ("icon-512.png", "image/png"),
];

pub async fn pwa_static_handler(
    State(state): State<AppState>,
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> impl IntoResponse {
    let entry = PWA_FILES
        .iter()
        .find(|(name, _)| *name == filename.as_str());
    let Some((_, content_type)) = entry else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    let Some(path) = resolve_dashboard_sibling(&state.dashboard_path, &filename) else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    match std::fs::read(&path) {
        Ok(data) => {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                content_type.parse().unwrap(),
            );
            if filename == "sw.js" {
                headers.insert(
                    axum::http::header::HeaderName::from_static("service-worker-allowed"),
                    axum::http::header::HeaderValue::from_static("/"),
                );
            }
            (headers, data).into_response()
        }
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}


pub async fn info_handler(State(state): State<AppState>) -> Json<NodeInfo> {
    let balance = state.node.list_balances();
    let channels = state
        .node
        .list_channels()
        .iter()
        .map(|ch| ChannelInfo {
            channel_id: ch.channel_id.to_string(),
            user_channel_id: ch.user_channel_id.0.to_string(),
            counterparty_node_id: ch.counterparty_node_id.to_string(),
            value_sats: ch.channel_value_sats,
            outbound_msat: ch.outbound_capacity_msat,
            inbound_msat: ch.inbound_capacity_msat,
            ready: ch.is_channel_ready,
            usable: ch.is_usable,
        })
        .collect();
    Json(NodeInfo {
        node_id: invoice::node_id(&state.node),
        node_alias: state.node_alias.clone(),
        onchain_balance_sats: balance.total_onchain_balance_sats,
        spendable_onchain_sats: balance.spendable_onchain_balance_sats,
        lightning_balance_sats: balance.total_lightning_balance_sats,
        channels,
    })
}

/// GET /api/address -- on-chain wallet address (for funding)
pub async fn address_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.node.onchain_payment().new_address() {
        Ok(addr) => Json(serde_json::json!({"address": addr.to_string()})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ================================================================
// Channel management API
// ================================================================


/// POST /api/channels/open
pub async fn channel_open_handler(
    State(state): State<AppState>,
    Json(req): Json<OpenChannelRequest>,
) -> impl IntoResponse {
    let remote_pk: ldk_node::bitcoin::secp256k1::PublicKey = match req.node_id.parse() {
        Ok(pk) => pk,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid node_id: {e}")})),
            )
                .into_response()
        }
    };
    let remote_addr: SocketAddress = match req.addr.parse() {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid addr: {e}")})),
            )
                .into_response()
        }
    };

    match state
        .node
        .open_channel(remote_pk, remote_addr, req.amount_sats, None, None)
    {
        Ok(_) => Json(serde_json::json!({
            "status": "ok",
            "message": format!("Funding tx broadcast for {} sat channel to {}", req.amount_sats, req.node_id)
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}


/// POST /api/channels/{user_channel_id}/close
pub async fn channel_close_handler(
    State(state): State<AppState>,
    AxumPath(ucid_str): AxumPath<String>,
    Json(req): Json<CloseChannelRequest>,
) -> impl IntoResponse {
    let counterparty_pk: ldk_node::bitcoin::secp256k1::PublicKey =
        match req.counterparty_node_id.parse() {
            Ok(pk) => pk,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Invalid counterparty_node_id: {e}")})),
                )
                    .into_response()
            }
        };

    let ucid_val: u128 = match ucid_str.parse() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid user_channel_id: {e}")})),
            )
                .into_response()
        }
    };

    let user_channel_id = ldk_node::UserChannelId(ucid_val);

    match state
        .node
        .close_channel(&user_channel_id, counterparty_pk)
    {
        Ok(_) => Json(serde_json::json!({
            "status": "ok",
            "message": "Channel close initiated"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/channels/peers -- suggest peers from the registry
pub async fn channel_peers_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut peers = vec![];
    if let Some(ref reg) = state.registry_info {
        let reg_url = ensurehttp(&reg.url);
        if let Ok(resp) = reqwest::get(format!("{}/api/listings", reg_url)).await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let items = data["items"].as_array().or(data["listings"].as_array());
                if let Some(items) = items {
                    let mut seen = std::collections::HashSet::new();
                    for item in items {
                        if let Some(addr) = item["creator_address"].as_str() {
                            if seen.insert(addr.to_string()) {
                                let addr_str = addr.to_string();
                                let info_url =
                                    format!("{}/api/info", ensurehttp(&addr_str));
                                if let Ok(info_resp) = reqwest::get(&info_url).await {
                                    if let Ok(info) =
                                        info_resp.json::<serde_json::Value>().await
                                    {
                                        if let Some(nid) = info["node_id"].as_str() {
                                            let alias = info["node_alias"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_string();
                                            peers.push(serde_json::json!({
                                                "node_id": nid,
                                                "addr": addr_str,
                                                "alias": alias
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Json(serde_json::json!({ "peers": peers }))
}


/// GET /api/best-source/{content_hash}
///
/// Queries the registry for seeders holding this content, checks P2P availability,
/// and returns the best source URL (seeder or creator).
pub async fn best_source_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
) -> impl IntoResponse {
    let reg = match &state.registry_info {
        Some(r) => r.clone(),
        None => {
            return Json(serde_json::json!({
                "source": "creator",
                "reason": "no registry configured"
            }))
            .into_response()
        }
    };

    let reg_url = ensurehttp(&reg.url);
    let discover_url = format!("{}/api/discover/{}", reg_url, content_hash);
    let discover_resp = match reqwest::get(&discover_url).await {
        Ok(r) => r,
        Err(_) => {
            return Json(serde_json::json!({
                "source": "creator",
                "reason": "registry unreachable"
            }))
            .into_response()
        }
    };

    let data: serde_json::Value = match discover_resp.json().await {
        Ok(d) => d,
        Err(_) => {
            return Json(serde_json::json!({
                "source": "creator",
                "reason": "invalid registry response"
            }))
            .into_response()
        }
    };

    let seeders = data["seeders"].as_array();
    let listing = &data["listing"];
    let creator_addr = listing["creator_address"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if seeders.is_none() || seeders.unwrap().is_empty() {
        return Json(serde_json::json!({
            "source": "creator",
            "source_url": creator_addr,
            "reason": "no seeders available"
        }))
        .into_response();
    }

    let seeders = seeders.unwrap();
    let mut candidates: Vec<serde_json::Value> = vec![];

    for seeder in seeders {
        let addr = seeder["seeder_address"].as_str().unwrap_or("");
        if addr.is_empty() {
            continue;
        }
        let seeder_url = ensurehttp(addr);
        let start = std::time::Instant::now();
        let reachable = match reqwest::Client::new()
            .get(format!("{}/api/info", seeder_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        };
        let latency_ms = start.elapsed().as_millis() as u64;

        if reachable {
            let chunk_count = seeder["chunk_count"].as_u64().unwrap_or(0);
            let price = seeder["transport_price"].as_u64().unwrap_or(0);
            candidates.push(serde_json::json!({
                "address": addr,
                "latency_ms": latency_ms,
                "chunk_count": chunk_count,
                "transport_price": price,
                "alias": seeder["seeder_alias"].as_str().unwrap_or("")
            }));
        }
    }

    if candidates.is_empty() {
        return Json(serde_json::json!({
            "source": "creator",
            "source_url": creator_addr,
            "reason": "no seeders reachable",
            "seeders_checked": seeders.len()
        }))
        .into_response();
    }

    candidates.sort_by_key(|c| c["latency_ms"].as_u64().unwrap_or(u64::MAX));

    let best = &candidates[0];
    Json(serde_json::json!({
        "source": "seeder",
        "source_url": best["address"],
        "latency_ms": best["latency_ms"],
        "transport_price": best["transport_price"],
        "alias": best["alias"],
        "candidates": candidates.len(),
        "creator_url": creator_addr
    }))
    .into_response()
}

/// GET /api/discover-sources/{content_hash}
///
/// Returns ALL reachable sources (creator + seeders) with latency and P2P info.
/// Used by the frontend to populate the source picker and by ICS internally.
pub async fn discover_sources_handler(
    State(state): State<AppState>,
    AxumPath(content_hash): AxumPath<String>,
) -> impl IntoResponse {
    let reg = match &state.registry_info {
        Some(r) => r.clone(),
        None => {
            return Json(serde_json::json!({
                "sources": [],
                "complete_sources": 0,
                "ics_mode": "RELEASE",
                "reason": "no registry configured"
            }))
            .into_response()
        }
    };

    let reg_url = ensurehttp(&reg.url);
    let discover_url = format!("{}/api/discover/{}", reg_url, content_hash);
    let data: serde_json::Value = match reqwest::get(&discover_url).await {
        Ok(r) => match r.json().await {
            Ok(d) => d,
            Err(_) => {
                return Json(serde_json::json!({
                    "sources": [],
                    "complete_sources": 0,
                    "ics_mode": "RELEASE",
                    "reason": "invalid registry response"
                }))
                .into_response()
            }
        },
        Err(_) => {
            return Json(serde_json::json!({
                "sources": [],
                "complete_sources": 0,
                "ics_mode": "RELEASE",
                "reason": "registry unreachable"
            }))
            .into_response()
        }
    };

    let listing = &data["listing"];
    let creator_addr = listing["creator_address"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let mut sources: Vec<serde_json::Value> = Vec::new();
    let mut complete_count = 0usize;

    // Probe creator
    if !creator_addr.is_empty() {
        let url = ensurehttp(&creator_addr);
        if let Some(info) = probe_source_async(&url).await {
            complete_count += 1;
            sources.push(serde_json::json!({
                "type": "creator",
                "url": creator_addr,
                "latency_ms": info.0,
                "p2p": info.1,
            }));
        }
    }

    // Probe seeders
    if let Some(seeders) = data["seeders"].as_array() {
        for seeder in seeders {
            let addr = seeder["seeder_address"].as_str().unwrap_or("");
            if addr.is_empty() {
                continue;
            }
            let url = ensurehttp(addr);
            if let Some(info) = probe_source_async(&url).await {
                let chunk_count = seeder["chunk_count"].as_u64().unwrap_or(0);
                let total_chunks = listing["chunk_count"].as_u64().unwrap_or(0);
                if total_chunks > 0 && chunk_count >= total_chunks {
                    complete_count += 1;
                }
                sources.push(serde_json::json!({
                    "type": "seeder",
                    "url": addr,
                    "latency_ms": info.0,
                    "p2p": info.1,
                    "alias": seeder["seeder_alias"].as_str().unwrap_or(""),
                    "chunk_count": chunk_count,
                    "transport_price": seeder["transport_price"].as_u64().unwrap_or(0),
                }));
            }
        }
    }

    let mode = if complete_count <= 3 {
        "RELEASE"
    } else if complete_count <= 10 {
        "SPREAD"
    } else {
        "SHARE"
    };

    Json(serde_json::json!({
        "sources": sources,
        "complete_sources": complete_count,
        "ics_mode": mode,
    }))
    .into_response()
}

/// Probe a source for reachability and P2P support. Returns (latency_ms, p2p_enabled).
async fn probe_source_async(base_url: &str) -> Option<(u64, bool)> {
    let base = base_url.trim_end_matches('/');
    let start = std::time::Instant::now();
    let ok = reqwest::Client::new()
        .get(format!("{}/api/info", base))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if !ok {
        return None;
    }
    let latency = start.elapsed().as_millis() as u64;

    let p2p = match reqwest::Client::new()
        .get(format!("{}/api/p2p-info", base))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .map(|info| info["enabled"].as_bool() == Some(true))
            .unwrap_or(false),
        Err(_) => false,
    };

    Some((latency, p2p))
}

