use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Json};

use conduit_core::{chunk, encrypt, invoice, merkle::MerkleTree};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::events::*;
use crate::state::*;

// ===========================================================================
// P2P bridge: implements conduit_p2p::handler::ChunkStore for AppState
// ===========================================================================

/// Wraps AppState to implement the ChunkStore trait for the P2P layer.
#[derive(Clone)]
pub struct ConduitChunkStore {
    catalog: Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    node: Arc<Node>,
    emitter: Arc<ConsoleEmitter>,
    event_router: Arc<EventRouter>,
    /// Active transport keys: encrypted_hash -> K_S bytes.
    /// When a buyer pays the invoice, the preimage (= K_S) is revealed.
    pending_keys: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], [u8; 32]>>>,
}

impl std::fmt::Debug for ConduitChunkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConduitChunkStore").finish_non_exhaustive()
    }
}

impl ConduitChunkStore {
    pub fn new(state: &AppState) -> Self {
        Self {
            catalog: state.catalog.clone(),
            node: state.node.clone(),
            emitter: state.emitter.clone(),
            event_router: state.event_router.clone(),
            pending_keys: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub fn find_entry(&self, encrypted_hash: &[u8; 32]) -> Option<CatalogEntry> {
        let hash_hex = hex::encode(encrypted_hash);
        let cat = self.catalog.lock().unwrap();
        cat.iter().find(|e| e.encrypted_hash == hash_hex).cloned()
    }

    pub fn load_chunks(&self, entry: &CatalogEntry) -> Option<Vec<Vec<u8>>> {
        let encrypted = std::fs::read(&entry.enc_file_path).ok()?;
        let cs = if entry.chunk_size > 0 {
            entry.chunk_size
        } else {
            chunk::select_chunk_size(encrypted.len())
        };
        let (enc_chunks, _) = chunk::split(&encrypted, cs);
        Some(enc_chunks)
    }
}

impl conduit_p2p::handler::ChunkStore for ConduitChunkStore {
    fn get_chunk(&self, encrypted_hash: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let entry = self.find_entry(encrypted_hash)?;
        if !entry.chunks_held.is_empty() && !entry.chunks_held.contains(&(index as usize)) {
            return None;
        }
        let mut f = std::fs::File::open(&entry.enc_file_path).ok()?;
        let file_len = f.metadata().ok()?.len() as usize;
        let cs = if entry.chunk_size > 0 {
            entry.chunk_size
        } else {
            chunk::select_chunk_size(file_len)
        };
        let offset = (index as usize) * cs;
        if offset >= file_len {
            return None;
        }
        let len = cs.min(file_len - offset);
        f.seek(SeekFrom::Start(offset as u64)).ok()?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    fn get_proof(
        &self,
        encrypted_hash: &[u8; 32],
        index: u32,
    ) -> Option<Vec<conduit_p2p::wire::ProofNode>> {
        let entry = self.find_entry(encrypted_hash)?;
        let chunks = self.load_chunks(&entry)?;
        if index as usize >= chunks.len() {
            return None;
        }
        let tree = MerkleTree::from_chunks(&chunks);
        let proof = tree.proof(index as usize);
        Some(
            proof
                .siblings
                .iter()
                .map(|(hash, is_left)| conduit_p2p::wire::ProofNode {
                    hash: *hash,
                    is_left: *is_left,
                })
                .collect(),
        )
    }

    fn get_bitfield(&self, encrypted_hash: &[u8; 32]) -> Option<conduit_p2p::wire::Bitfield> {
        let entry = self.find_entry(encrypted_hash)?;
        let chunks = self.load_chunks(&entry)?;
        let total = chunks.len() as u32;
        let available: Vec<bool> = if entry.chunks_held.is_empty() {
            vec![true; total as usize]
        } else {
            (0..total)
                .map(|i| entry.chunks_held.contains(&(i as usize)))
                .collect()
        };
        let cs = if entry.chunk_size > 0 {
            entry.chunk_size as u32
        } else {
            chunk::select_chunk_size(0) as u32
        };
        let root = hex::decode(&entry.encrypted_root)
            .ok()
            .and_then(|b| {
                let mut arr = [0u8; 32];
                if b.len() == 32 {
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);
        Some(conduit_p2p::wire::Bitfield::from_bools(
            &available, cs, root,
        ))
    }

    fn create_invoice(
        &self,
        encrypted_hash: &[u8; 32],
        chunk_indices: &[u32],
        _buyer_ln_pubkey: &str,
    ) -> anyhow::Result<(String, u64)> {
        let entry = self
            .find_entry(encrypted_hash)
            .ok_or_else(|| anyhow::anyhow!("content not found"))?;
        let price_per_chunk = if entry.transport_price > 0 {
            entry.transport_price
        } else {
            1
        };
        let total_sats = price_per_chunk * chunk_indices.len() as u64;
        let ks = encrypt::generate_key();
        let bolt11 = invoice::create_invoice_for_key(&self.node, &ks, total_sats, "p2p-transport")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.pending_keys
            .lock()
            .unwrap()
            .insert(*encrypted_hash, ks);

        let payment_hash = PaymentHash(invoice::payment_hash_for_key(&ks));
        let rx = self.event_router.register(payment_hash);
        let node = self.node.clone();
        let router = self.event_router.clone();
        let emitter = self.emitter.clone();
        let eh = *encrypted_hash;
        std::thread::spawn(move || {
            eprintln!("[P2P-CLAIM] waiting for PaymentClaimable for transport invoice hash={}", hex::encode(payment_hash.0));
            loop {
                match rx.recv_timeout(std::time::Duration::from_secs(120)) {
                    Ok(Event::PaymentClaimable {
                        claimable_amount_msat,
                        payment_hash: ph,
                        ..
                    }) if ph == payment_hash => {
                        eprintln!("[P2P-CLAIM] PaymentClaimable received, claiming {}msat", claimable_amount_msat);
                        match invoice::claim_payment(&node, &ks, claimable_amount_msat) {
                            Ok(()) => {
                                eprintln!("[P2P-CLAIM] payment claimed successfully");
                                emitter.emit(
                                    "seeder",
                                    "P2P_TRANSPORT_CLAIMED",
                                    serde_json::json!({
                                        "encrypted_hash": hex::encode(eh),
                                        "amount_msat": claimable_amount_msat,
                                    }),
                                );
                            }
                            Err(e) => {
                                eprintln!("[P2P-CLAIM] claim_payment failed: {e}");
                            }
                        }
                        router.unregister(&payment_hash);
                        break;
                    }
                    Ok(_other) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        eprintln!("[P2P-CLAIM] timed out waiting for transport payment (120s)");
                        router.unregister(&payment_hash);
                        break;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        eprintln!("[P2P-CLAIM] event router channel disconnected");
                        break;
                    }
                }
            }
        });

        self.emitter.emit(
            "seeder",
            "P2P_INVOICE_CREATED",
            serde_json::json!({
                "encrypted_hash": hex::encode(encrypted_hash),
                "chunks": chunk_indices,
                "amount_sats": total_sats,
            }),
        );
        Ok((bolt11, total_sats * 1000))
    }

    fn verify_payment(&self, encrypted_hash: &[u8; 32], preimage: &[u8; 32]) -> bool {
        let expected = self
            .pending_keys
            .lock()
            .unwrap()
            .get(encrypted_hash)
            .copied();
        match expected {
            Some(ks) if &ks == preimage => {
                self.emitter.emit(
                    "seeder",
                    "P2P_PAYMENT_VERIFIED",
                    serde_json::json!({
                        "encrypted_hash": hex::encode(encrypted_hash),
                    }),
                );
                true
            }
            _ => false,
        }
    }
}

/// GET /api/p2p-info -- returns the iroh node ID and address for P2P connections.
pub async fn p2p_info_handler(State(state): State<AppState>) -> impl IntoResponse {
    match &state.p2p_node {
        Some(p2p) => {
            let addr = p2p.endpoint_addr();
            let direct_addrs: Vec<String> = addr.ip_addrs().map(|a| a.to_string()).collect();
            let relay_urls: Vec<String> = addr.relay_urls().map(|u| u.to_string()).collect();
            Json(serde_json::json!({
                "enabled": true,
                "node_id": p2p.node_id().to_string(),
                "direct_addrs": direct_addrs,
                "relay_urls": relay_urls,
            }))
            .into_response()
        }
        None => Json(serde_json::json!({
            "enabled": false,
        }))
        .into_response(),
    }
}

/// GET /api/p2p-test?target=http://host:port -- test P2P connectivity to a remote node.
///
/// Fetches the target's /api/p2p-info, builds an EndpointAddr, and attempts
/// endpoint.connect() with a 10s timeout. Returns timing and diagnostic info.
pub async fn p2p_test_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let target = match params.get("target") {
        Some(t) => t.clone(),
        None => {
            return Json(serde_json::json!({
                "error": "missing ?target=http://host:port query parameter"
            }))
            .into_response();
        }
    };

    let p2p = match &state.p2p_node {
        Some(p) => p.clone(),
        None => {
            return Json(serde_json::json!({
                "error": "P2P is not enabled on this node"
            }))
            .into_response();
        }
    };

    let p2p_rt = match &state.p2p_runtime_handle {
        Some(h) => h.clone(),
        None => {
            return Json(serde_json::json!({
                "error": "P2P runtime handle not available"
            }))
            .into_response();
        }
    };

    let info_url = format!("{}/api/p2p-info", target.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({
                "error": format!("failed to build HTTP client: {e}")
            }))
            .into_response();
        }
    };

    let info_resp = match client.get(&info_url).send().await {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                return Json(serde_json::json!({
                    "error": format!("failed to parse p2p-info JSON: {e}")
                }))
                .into_response();
            }
        },
        Err(e) => {
            return Json(serde_json::json!({
                "error": format!("failed to fetch {info_url}: {e}")
            }))
            .into_response();
        }
    };

    if info_resp["enabled"].as_bool() != Some(true) {
        return Json(serde_json::json!({
            "error": "target node does not have P2P enabled",
            "remote_info": info_resp,
        }))
        .into_response();
    }

    let remote_node_id = info_resp["node_id"].as_str().unwrap_or("").to_string();
    let direct_addrs: Vec<String> = info_resp["direct_addrs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let relay_urls: Vec<String> = info_resp["relay_urls"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let addr = match remote_node_id.parse::<conduit_p2p::iroh::PublicKey>() {
        Ok(pk) => {
            let mut a = conduit_p2p::iroh::EndpointAddr::from(pk);
            for s in &direct_addrs {
                if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                    a = a.with_ip_addr(sa);
                }
            }
            for u in &relay_urls {
                if let Ok(ru) = u.parse::<conduit_p2p::iroh::RelayUrl>() {
                    a = a.with_relay_url(ru);
                }
            }
            a
        }
        Err(e) => {
            return Json(serde_json::json!({
                "error": format!("failed to parse remote node id: {e}"),
                "remote_node_id": remote_node_id,
            }))
            .into_response();
        }
    };

    let ep = p2p.endpoint().clone();
    let start = std::time::Instant::now();

    let connect_result = p2p_rt.spawn(async move {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ep.connect(addr, conduit_p2p::CONDUIT_ALPN),
        )
        .await
    });

    match connect_result.await {
        Ok(Ok(Ok(conn))) => {
            let elapsed = start.elapsed();
            conn.close(0u8.into(), b"test");
            Json(serde_json::json!({
                "status": "ok",
                "remote_node_id": remote_node_id,
                "direct_addrs": direct_addrs,
                "relay_urls": relay_urls,
                "connect_ms": elapsed.as_millis(),
                "message": format!("Connected in {}ms", elapsed.as_millis()),
            }))
            .into_response()
        }
        Ok(Ok(Err(e))) => {
            let elapsed = start.elapsed();
            Json(serde_json::json!({
                "status": "connect_failed",
                "remote_node_id": remote_node_id,
                "direct_addrs": direct_addrs,
                "relay_urls": relay_urls,
                "elapsed_ms": elapsed.as_millis(),
                "error": format!("{e}"),
            }))
            .into_response()
        }
        Ok(Err(_)) => Json(serde_json::json!({
            "status": "timeout",
            "remote_node_id": remote_node_id,
            "direct_addrs": direct_addrs,
            "relay_urls": relay_urls,
            "elapsed_ms": 10000,
            "error": "P2P connect timed out after 10s",
        }))
        .into_response(),
        Err(e) => Json(serde_json::json!({
            "status": "runtime_error",
            "error": format!("tokio join error: {e}"),
        }))
        .into_response(),
    }
}

/// GET /api/p2p-test-download?target=http://host:port&hash=<encrypted_hash>
///
/// Runs the full Conduit chunk protocol (Handshake -> Bitfield -> Request ->
/// Invoice -> PaymentProof -> Chunks) over live iroh QUIC with a mock payment.
/// The seeder will reject at verify_payment (PaymentRequired) -- that is the
/// expected success case proving transport works end-to-end.
pub async fn p2p_test_download_handler(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::Json;

    let target = match params.get("target") {
        Some(t) => t.clone(),
        None => {
            return Json(serde_json::json!({"error": "missing ?target= parameter"}))
                .into_response()
        }
    };
    let hash_hex = match params.get("hash") {
        Some(h) => h.clone(),
        None => {
            return Json(serde_json::json!({"error": "missing ?hash= parameter"}))
                .into_response()
        }
    };

    let p2p = match &state.p2p_node {
        Some(p) => p.clone(),
        None => {
            return Json(serde_json::json!({"error": "P2P not enabled on this node"}))
                .into_response()
        }
    };
    let p2p_rt = match &state.p2p_runtime_handle {
        Some(h) => h.clone(),
        None => {
            return Json(serde_json::json!({"error": "P2P runtime handle not available"}))
                .into_response()
        }
    };

    let info_url = format!("{}/api/p2p-info", target.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Json(serde_json::json!({"error": format!("http client: {e}")}))
                .into_response()
        }
    };

    let info_resp = match client.get(&info_url).send().await {
        Ok(r) => match r.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                return Json(serde_json::json!({"error": format!("p2p-info parse: {e}")}))
                    .into_response()
            }
        },
        Err(e) => {
            return Json(serde_json::json!({"error": format!("fetch {info_url}: {e}")}))
                .into_response()
        }
    };

    if info_resp["enabled"].as_bool() != Some(true) {
        return Json(serde_json::json!({"error": "target P2P not enabled", "info": info_resp}))
            .into_response();
    }

    let remote_node_id = info_resp["node_id"].as_str().unwrap_or("").to_string();
    let direct_addrs: Vec<String> = info_resp["direct_addrs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let relay_urls: Vec<String> = info_resp["relay_urls"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let addr = match remote_node_id.parse::<conduit_p2p::iroh::PublicKey>() {
        Ok(pk) => {
            let mut a = conduit_p2p::iroh::EndpointAddr::from(pk);
            for s in &direct_addrs {
                if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                    a = a.with_ip_addr(sa);
                }
            }
            for u in &relay_urls {
                if let Ok(ru) = u.parse::<conduit_p2p::iroh::RelayUrl>() {
                    a = a.with_relay_url(ru);
                }
            }
            a
        }
        Err(e) => {
            return Json(serde_json::json!({"error": format!("parse node id: {e}")}))
                .into_response()
        }
    };

    let enc_hash_bytes: [u8; 32] = match hex::decode(&hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return Json(serde_json::json!({"error": "hash must be 64 hex chars (32 bytes)"}))
                .into_response()
        }
    };

    struct TestPayment;
    impl conduit_p2p::client::PaymentHandler for TestPayment {
        fn pay_invoice(&self, _bolt11: &str) -> anyhow::Result<[u8; 32]> {
            Ok([0u8; 32])
        }
    }

    let ep = p2p.endpoint().clone();
    let ln_pk = state.node.node_id().to_string();
    let buyer_client = conduit_p2p::client::BuyerClient::new(ep, ln_pk);

    let catalog_url = format!("{}/api/catalog", target.trim_end_matches('/'));
    let (num_chunks, expected_encrypted_root): (u32, Option<[u8; 32]>) =
        match client.get(&catalog_url).send().await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(cat) => {
                    let items = cat.as_array().or_else(|| cat["items"].as_array());
                    let entry = items.and_then(|arr| {
                        arr.iter()
                            .find(|e| {
                                e["encrypted_hash"].as_str() == Some(hash_hex.as_str())
                                    || e["content_hash"].as_str() == Some(hash_hex.as_str())
                            })
                            .cloned()
                    });
                    let chunks = entry
                        .as_ref()
                        .and_then(|e| {
                            e["chunk_count"]
                                .as_u64()
                                .or_else(|| e["total_chunks"].as_u64())
                        })
                        .unwrap_or(1) as u32;
                    let root = entry
                        .as_ref()
                        .and_then(|e| e["encrypted_root"].as_str())
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|b| <[u8; 32]>::try_from(b).ok());
                    (chunks, root)
                }
                Err(_) => (1, None),
            },
            Err(_) => (1, None),
        };

    let indices: Vec<u32> = (0..num_chunks).collect();
    let payment: std::sync::Arc<dyn conduit_p2p::client::PaymentHandler> =
        std::sync::Arc::new(TestPayment);

    let start = std::time::Instant::now();

    let (tx, rx) =
        std::sync::mpsc::sync_channel::<anyhow::Result<conduit_p2p::client::DownloadResult>>(1);
    let indices_owned = indices.clone();
    p2p_rt.spawn(async move {
        let result = buyer_client
            .download(addr, enc_hash_bytes, &indices_owned, payment, expected_encrypted_root)
            .await;
        let _ = tx.send(result);
    });

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || rx.recv()),
    )
    .await;

    let elapsed = start.elapsed();

    match outcome {
        Ok(Ok(Ok(Ok(result)))) => Json(serde_json::json!({
            "status": "download_complete",
            "chunks_received": result.chunks.len(),
            "total_paid_msat": result.total_paid_msat,
            "elapsed_ms": elapsed.as_millis(),
            "message": "Full protocol succeeded (mock payment accepted by seeder)",
        }))
        .into_response(),
        Ok(Ok(Ok(Err(e)))) => {
            let err_str = format!("{e:#}");
            let step = if err_str.contains("connect") || err_str.contains("timed out") {
                "connect"
            } else if err_str.contains("Bitfield") || err_str.contains("Handshake") {
                "handshake"
            } else if err_str.contains("Invoice") {
                "request"
            } else if err_str.contains("PaymentRequired") {
                "payment_verification"
            } else if err_str.contains("paying invoice") {
                "payment"
            } else if err_str.contains("chunk") {
                "chunk_transfer"
            } else {
                "unknown"
            };
            Json(serde_json::json!({
                "status": "protocol_error",
                "failed_at_step": step,
                "error": err_str,
                "elapsed_ms": elapsed.as_millis(),
                "remote_node_id": remote_node_id,
                "direct_addrs": direct_addrs,
                "relay_urls": relay_urls,
                "num_chunks_requested": num_chunks,
                "message": if step == "payment_verification" {
                    "Transport works! Seeder correctly rejected mock preimage. Problem is isolated to real Lightning payment."
                } else {
                    "Transport failed at the indicated step."
                },
            }))
            .into_response()
        }
        Ok(Ok(Err(e))) => Json(serde_json::json!({
            "status": "channel_error",
            "error": format!("recv error: {e}"),
            "elapsed_ms": elapsed.as_millis(),
        }))
        .into_response(),
        Ok(Err(e)) => Json(serde_json::json!({
            "status": "join_error",
            "error": format!("{e}"),
            "elapsed_ms": elapsed.as_millis(),
        }))
        .into_response(),
        Err(_) => Json(serde_json::json!({
            "status": "timeout",
            "error": "P2P test download timed out after 30s",
            "elapsed_ms": elapsed.as_millis(),
        }))
        .into_response(),
    }
}

