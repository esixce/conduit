// ---------------------------------------------------------------------------
// Multi-source chunk download with Intelligent Chunk Selection (ICS)
// ---------------------------------------------------------------------------

use std::time::Duration;

use crate::buy::chunked::{count_complete_sources, plan_chunk_assignments_ics, IcsMode};
use crate::events::ConsoleEmitter;
use crate::state::ensurehttp;

/// A reachable chunk source (creator or seeder).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ChunkSource {
    pub url: String,
    pub source_type: SourceType,
    pub latency_ms: u64,
    pub p2p_enabled: bool,
    pub p2p_node_id: Option<String>,
    pub p2p_direct_addrs: Vec<String>,
    pub p2p_relay_urls: Vec<String>,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceType {
    Creator,
    Seeder,
}

/// Discover all reachable sources (creator + seeders) for a content hash.
///
/// Calls the registry `/api/discover/{content_hash}`, then probes each source
/// for reachability and P2P info. Returns only sources that responded within
/// the timeout.
pub fn discover_all_sources(
    client: &reqwest::blocking::Client,
    registry_url: &str,
    content_hash: &str,
    creator_url: &str,
    emitter: &ConsoleEmitter,
) -> (Vec<ChunkSource>, String) {
    let role = "buyer";
    let mut sources: Vec<ChunkSource> = Vec::new();
    let mut encrypted_hash = String::new();

    let discover_url = format!(
        "{}/api/discover/{}",
        registry_url.trim_end_matches('/'),
        content_hash
    );
    let registry_resp = client
        .get(&discover_url)
        .timeout(Duration::from_secs(10))
        .send()
        .ok()
        .and_then(|r| r.json::<serde_json::Value>().ok());

    if let Some(data) = &registry_resp {
        if let Some(eh) = data["listing"]["encrypted_hash"].as_str() {
            encrypted_hash = eh.to_string();
        }
        if let Some(seeders) = data["seeders"].as_array() {
            for seeder in seeders {
                let addr = seeder["seeder_address"].as_str().unwrap_or("");
                if addr.is_empty() {
                    continue;
                }
                let url = ensurehttp(addr);
                if let Some(src) = probe_source(&client, &url, SourceType::Seeder) {
                    let mut src = src;
                    src.alias = seeder["seeder_alias"]
                        .as_str()
                        .map(|s| s.to_string())
                        .or_else(|| Some(addr.to_string()));
                    sources.push(src);
                }
            }
        }
    }

    if let Some(src) = probe_source(&client, &ensurehttp(creator_url), SourceType::Creator) {
        sources.insert(0, src);
    }

    emitter.emit(
        role,
        "SOURCES_DISCOVERED",
        serde_json::json!({
            "total": sources.len(),
            "creators": sources.iter().filter(|s| s.source_type == SourceType::Creator).count(),
            "seeders": sources.iter().filter(|s| s.source_type == SourceType::Seeder).count(),
            "sources": sources.iter().map(|s| serde_json::json!({
                "url": &s.url,
                "type": match s.source_type { SourceType::Creator => "creator", SourceType::Seeder => "seeder" },
                "latency_ms": s.latency_ms,
                "p2p": s.p2p_enabled,
                "alias": &s.alias,
            })).collect::<Vec<_>>(),
        }),
    );

    (sources, encrypted_hash)
}

/// Probe a single source for reachability and P2P info.
fn probe_source(
    client: &reqwest::blocking::Client,
    url: &str,
    source_type: SourceType,
) -> Option<ChunkSource> {
    let base = url.trim_end_matches('/');
    let start = std::time::Instant::now();
    let info_url = format!("{}/api/info", base);
    let reachable = client
        .get(&info_url)
        .timeout(Duration::from_secs(5))
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if !reachable {
        return None;
    }
    let latency_ms = start.elapsed().as_millis() as u64;

    let mut p2p_enabled = false;
    let mut p2p_node_id = None;
    let mut p2p_direct_addrs = Vec::new();
    let mut p2p_relay_urls = Vec::new();

    let p2p_url = format!("{}/api/p2p-info", base);
    if let Ok(r) = client.get(&p2p_url).timeout(Duration::from_secs(5)).send() {
        if let Ok(info) = r.json::<serde_json::Value>() {
            if info["enabled"].as_bool() == Some(true) {
                p2p_enabled = true;
                p2p_node_id = info["node_id"].as_str().map(String::from);
                p2p_direct_addrs = info["direct_addrs"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                p2p_relay_urls = info["relay_urls"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
            }
        }
    }

    Some(ChunkSource {
        url: base.to_string(),
        source_type,
        latency_ms,
        p2p_enabled,
        p2p_node_id,
        p2p_direct_addrs,
        p2p_relay_urls,
        alias: None,
    })
}

/// Fetch bitfields from all sources for a given encrypted hash.
///
/// Returns one `Vec<bool>` per source (same order as `sources`).
/// Sources that fail to respond get an all-false bitfield.
pub fn fetch_bitfields(
    client: &reqwest::blocking::Client,
    sources: &[ChunkSource],
    encrypted_hash: &str,
    chunk_count: usize,
    emitter: &ConsoleEmitter,
) -> Vec<Vec<bool>> {
    let role = "buyer";
    let mut bitfields = Vec::with_capacity(sources.len());

    for src in sources {
        let bf_url = format!("{}/api/chunks/{}/bitfield", src.url, encrypted_hash);
        match client
            .get(&bf_url)
            .timeout(Duration::from_secs(10))
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(bf) => {
                let bits: Vec<bool> = bf["bitfield"]
                    .as_array()
                    .map(|arr| arr.iter().map(|v| v.as_bool().unwrap_or(false)).collect())
                    .unwrap_or_default();
                let available = bits.iter().filter(|&&b| b).count();
                emitter.emit(
                    role,
                    "BITFIELD_RECEIVED",
                    serde_json::json!({
                        "source": &src.url,
                        "source_type": match src.source_type { SourceType::Creator => "creator", SourceType::Seeder => "seeder" },
                        "chunks_available": available,
                        "total": chunk_count,
                    }),
                );
                if bits.is_empty() && src.source_type == SourceType::Creator {
                    bitfields.push(vec![true; chunk_count]);
                } else {
                    bitfields.push(bits);
                }
            }
            Err(e) => {
                eprintln!(
                    "ICS: bitfield fetch failed for {}: {}",
                    src.url, e
                );
                if src.source_type == SourceType::Creator {
                    bitfields.push(vec![true; chunk_count]);
                } else {
                    bitfields.push(vec![false; chunk_count]);
                }
            }
        }
    }

    bitfields
}

/// Download chunks from multiple sources according to the ICS assignment plan.
///
/// Each chunk is downloaded from its assigned source via HTTP. Chunks are
/// downloaded in the order specified by `download_order` and reassembled
/// in sequential order. Preserved for future HTTP re-enablement.
///
/// Returns the concatenated encrypted data.
#[allow(dead_code)]
pub fn download_chunks_multisource(
    client: &reqwest::blocking::Client,
    sources: &[ChunkSource],
    assignments: &[Option<usize>],
    download_order: &[usize],
    encrypted_hash: &str,
    chunk_count: usize,
    emitter: &ConsoleEmitter,
    mode: IcsMode,
) -> Option<Vec<u8>> {
    let role = "buyer";

    emitter.emit(
        role,
        "ICS_DOWNLOAD_START",
        serde_json::json!({
            "mode": mode.label(),
            "chunk_count": chunk_count,
            "sources": sources.len(),
            "message": format!(
                "ICS {} mode: downloading {} chunks from {} sources",
                mode.label(), chunk_count, sources.len()
            ),
        }),
    );

    let mut chunks_data: Vec<Option<Vec<u8>>> = vec![None; chunk_count];
    let mut downloaded = 0usize;

    for &ci in download_order {
        let si = match assignments[ci] {
            Some(s) => s,
            None => {
                emitter.emit(
                    role,
                    "BUY_ERROR",
                    serde_json::json!({
                        "message": format!("No source assigned for chunk {}", ci),
                        "chunk_index": ci,
                    }),
                );
                return None;
            }
        };

        let source = &sources[si];
        let chunk_url = format!("{}/api/chunks/{}/{}", source.url, encrypted_hash, ci);

        match client.get(&chunk_url).timeout(Duration::from_secs(30)).send() {
            Ok(r) if r.status().is_success() => match r.bytes() {
                Ok(bytes) => {
                    chunks_data[ci] = Some(bytes.to_vec());
                    downloaded += 1;
                    emitter.emit(
                        role,
                        "CHUNK_PROGRESS",
                        serde_json::json!({
                            "current": downloaded,
                            "total": chunk_count,
                            "chunk_index": ci,
                            "source": &source.url,
                            "bytes": bytes.len(),
                        }),
                    );
                }
                Err(e) => {
                    emitter.emit(
                        role,
                        "CHUNK_DOWNLOAD_FAILED",
                        serde_json::json!({
                            "chunk_index": ci,
                            "source": &source.url,
                            "error": format!("{}", e),
                        }),
                    );
                    return None;
                }
            },
            Ok(r) => {
                emitter.emit(
                    role,
                    "CHUNK_DOWNLOAD_FAILED",
                    serde_json::json!({
                        "chunk_index": ci,
                        "source": &source.url,
                        "error": format!("HTTP {}", r.status()),
                    }),
                );
                return None;
            }
            Err(e) => {
                emitter.emit(
                    role,
                    "CHUNK_DOWNLOAD_FAILED",
                    serde_json::json!({
                        "chunk_index": ci,
                        "source": &source.url,
                        "error": format!("{}", e),
                    }),
                );
                return None;
            }
        }
    }

    let mut all_data = Vec::new();
    for ci in 0..chunk_count {
        match chunks_data[ci].take() {
            Some(data) => all_data.extend_from_slice(&data),
            None => {
                emitter.emit(
                    role,
                    "BUY_ERROR",
                    serde_json::json!({ "message": format!("Missing chunk {} after download", ci) }),
                );
                return None;
            }
        }
    }

    Some(all_data)
}

/// High-level ICS download: discover sources, fetch bitfields, plan, download.
///
/// If P2P-capable sources are found, downloads chunks via iroh QUIC in parallel
/// across multiple seeders. Falls back to single-source if no P2P sources or
/// no registry is configured.
///
/// Returns `(encrypted_data, num_chunks, ics_mode)` or None on failure.
pub fn ics_download(
    client: &reqwest::blocking::Client,
    registry_url: Option<&str>,
    creator_url: &str,
    content_hash: &str,
    emitter: &ConsoleEmitter,
    p2p_node: Option<&std::sync::Arc<conduit_p2p::node::P2pNode>>,
    p2p_runtime_handle: Option<&tokio::runtime::Handle>,
    node: &std::sync::Arc<ldk_node::Node>,
    event_router: &std::sync::Arc<crate::events::EventRouter>,
    storage_dir: &str,
    expected_encrypted_root: Option<[u8; 32]>,
) -> Option<(Vec<u8>, usize, IcsMode)> {
    let role = "buyer";

    let reg_url = match registry_url {
        Some(u) => u.to_string(),
        None => {
            emitter.emit(
                role,
                "ICS_FALLBACK",
                serde_json::json!({ "message": "No registry configured, falling back to creator only" }),
            );
            return None;
        }
    };

    let (sources, encrypted_hash) =
        discover_all_sources(client, &reg_url, content_hash, creator_url, emitter);

    if sources.is_empty() {
        emitter.emit(
            role,
            "ICS_FALLBACK",
            serde_json::json!({ "message": "No reachable sources found" }),
        );
        return None;
    }

    if encrypted_hash.is_empty() {
        emitter.emit(
            role,
            "ICS_FALLBACK",
            serde_json::json!({ "message": "Could not determine encrypted_hash from registry" }),
        );
        return None;
    }

    let catalog_url = format!("{}/api/catalog", sources[0].url);
    let chunk_count = client
        .get(&catalog_url)
        .timeout(Duration::from_secs(10))
        .send()
        .ok()
        .and_then(|r| r.json::<serde_json::Value>().ok())
        .and_then(|cat| {
            let items = cat.as_array().or_else(|| cat["items"].as_array())?;
            items.iter().find_map(|e| {
                let matches = e["content_hash"].as_str() == Some(content_hash)
                    || e["encrypted_hash"].as_str() == Some(&encrypted_hash);
                if matches {
                    e["chunk_count"]
                        .as_u64()
                        .or_else(|| e["total_chunks"].as_u64())
                        .map(|n| n as usize)
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);

    if chunk_count == 0 {
        emitter.emit(
            role,
            "ICS_FALLBACK",
            serde_json::json!({ "message": "Could not determine chunk_count, falling back to single-source" }),
        );
        return None;
    }

    let bitfields = fetch_bitfields(client, &sources, &encrypted_hash, chunk_count, emitter);
    let complete_sources = count_complete_sources(&bitfields, chunk_count);
    let (order, assignments, mode) =
        plan_chunk_assignments_ics(chunk_count, &bitfields, complete_sources);

    for &ci in &order {
        if assignments[ci].is_none() {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("No source has chunk {} — cannot proceed", ci),
                    "chunk_index": ci,
                }),
            );
            return None;
        }
    }

    emitter.emit(
        role,
        "ICS_PLAN",
        serde_json::json!({
            "mode": mode.label(),
            "chunk_count": chunk_count,
            "complete_sources": complete_sources,
            "total_sources": sources.len(),
        }),
    );

    let p2p = match (p2p_node, p2p_runtime_handle) {
        (Some(p), Some(rt)) => Some((p.clone(), rt.clone())),
        _ => None,
    };

    let p2p_sources: Vec<(usize, &ChunkSource)> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.p2p_enabled && s.p2p_node_id.is_some())
        .collect();

    if p2p.is_none() || p2p_sources.is_empty() {
        emitter.emit(
            role,
            "ICS_FALLBACK",
            serde_json::json!({
                "message": "No P2P-capable sources found, falling back to single-source.",
                "p2p_available": p2p.is_some(),
                "p2p_sources": p2p_sources.len(),
            }),
        );
        return None;
    }

    let (p2p_node_arc, p2p_rt) = p2p.unwrap();
    let enc_hash_bytes: [u8; 32] = hex::decode(&encrypted_hash)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())?;

    // Group chunks by assigned source index
    let mut per_source: std::collections::HashMap<usize, Vec<u32>> =
        std::collections::HashMap::new();
    for &ci in &order {
        if let Some(si) = assignments[ci] {
            per_source.entry(si).or_default().push(ci as u32);
        }
    }

    let sink_dir = std::path::PathBuf::from(storage_dir)
        .join("tmp_chunks")
        .join(&encrypted_hash);
    let disk_sink = match conduit_p2p::client::DiskSink::new(&sink_dir) {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            eprintln!("[ICS-P2P] failed to create disk sink: {e}");
            return None;
        }
    };

    let ep = p2p_node_arc.endpoint().clone();
    let ln_pk = node.node_id().to_string();

    // Build EndpointAddr for each P2P source
    let build_addr = |src: &ChunkSource| -> Option<conduit_p2p::iroh::EndpointAddr> {
        let pk = src
            .p2p_node_id
            .as_ref()?
            .parse::<conduit_p2p::iroh::PublicKey>()
            .ok()?;
        let mut addr = conduit_p2p::iroh::EndpointAddr::from(pk);
        for s in &src.p2p_direct_addrs {
            if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                addr = addr.with_ip_addr(sa);
            }
        }
        for u in &src.p2p_relay_urls {
            if let Ok(ru) = u.parse::<conduit_p2p::iroh::RelayUrl>() {
                addr = addr.with_relay_url(ru);
            }
        }
        Some(addr)
    };

    // Spawn parallel P2P downloads per source
    let (tx, rx) = std::sync::mpsc::channel::<(usize, anyhow::Result<u32>)>();

    let mut spawned = 0usize;
    for (si, chunk_indices) in &per_source {
        let src = match sources.get(*si) {
            Some(s) => s,
            None => continue,
        };
        let addr = match build_addr(src) {
            Some(a) => a,
            None => {
                eprintln!("[ICS-P2P] cannot build P2P addr for source {}", src.url);
                continue;
            }
        };

        let buyer_client =
            conduit_p2p::client::BuyerClient::new(ep.clone(), ln_pk.clone());
        let indices = chunk_indices.clone();
        let sink: std::sync::Arc<dyn conduit_p2p::client::DownloadSink> = disk_sink.clone();
        let tx = tx.clone();
        let si = *si;
        let node_for_pay = node.clone();
        let router_for_pay = event_router.clone();

        use conduit_core::invoice;
        use ldk_node::lightning_types::payment::PaymentHash;
        use ldk_node::Event;
        struct LdkPay {
            node: std::sync::Arc<ldk_node::Node>,
            router: std::sync::Arc<crate::events::EventRouter>,
        }
        impl conduit_p2p::client::PaymentHandler for LdkPay {
            fn pay_invoice(&self, bolt11: &str) -> anyhow::Result<[u8; 32]> {
                use ldk_node::lightning_invoice::Bolt11Invoice;
                let inv: Bolt11Invoice = bolt11
                    .parse()
                    .map_err(|e: ldk_node::lightning_invoice::ParseOrSemanticError| {
                        anyhow::anyhow!("bad bolt11: {e}")
                    })?;
                let h: &[u8] = inv.payment_hash().as_ref();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(h);
                let target = PaymentHash(hash);
                let rx = self.router.register(target);
                invoice::pay_invoice(&self.node, bolt11)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                loop {
                    let event = rx.recv().map_err(|_| anyhow::anyhow!("event router dropped"))?;
                    match event {
                        Event::PaymentSuccessful {
                            payment_preimage: Some(pre),
                            ..
                        } => {
                            self.router.unregister(&target);
                            return Ok(pre.0);
                        }
                        Event::PaymentFailed { reason, .. } => {
                            self.router.unregister(&target);
                            return Err(anyhow::anyhow!("payment failed: {:?}", reason));
                        }
                        _ => {}
                    }
                }
            }
        }
        let payment: std::sync::Arc<dyn conduit_p2p::client::PaymentHandler> =
            std::sync::Arc::new(LdkPay {
                node: node_for_pay,
                router: router_for_pay,
            });

        let expected_root = expected_encrypted_root;

        p2p_rt.spawn(async move {
            let result = buyer_client
                .download_to_sink(addr, enc_hash_bytes, &indices, payment, expected_root, sink)
                .await;
            let count = match &result {
                Ok(r) => Ok(r.chunks_received),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            };
            let _ = tx.send((si, count));
        });
        spawned += 1;
    }
    drop(tx);

    let mut total_received = 0u32;
    let mut errors = Vec::new();
    for _ in 0..spawned {
        match rx.recv_timeout(Duration::from_secs(60 + (chunk_count as u64) * 2)) {
            Ok((si, Ok(n))) => {
                eprintln!(
                    "[ICS-P2P] source {} delivered {} chunks",
                    sources.get(si).map(|s| s.url.as_str()).unwrap_or("?"),
                    n
                );
                total_received += n;
            }
            Ok((si, Err(e))) => {
                let url = sources.get(si).map(|s| s.url.as_str()).unwrap_or("?");
                eprintln!("[ICS-P2P] source {} failed: {e}", url);
                errors.push(format!("{}: {}", url, e));
            }
            Err(_) => {
                eprintln!("[ICS-P2P] timed out waiting for source download");
                errors.push("timeout waiting for download".to_string());
                break;
            }
        }
    }

    if total_received < chunk_count as u32 {
        emitter.emit(
            role,
            "ICS_INCOMPLETE",
            serde_json::json!({
                "received": total_received,
                "expected": chunk_count,
                "errors": errors,
                "message": format!("Only received {}/{} chunks", total_received, chunk_count),
            }),
        );
        let _ = std::fs::remove_dir_all(&sink_dir);
        return None;
    }

    match disk_sink.reassemble(chunk_count as u32) {
        Ok(data) => {
            let _ = std::fs::remove_dir_all(&sink_dir);
            emitter.emit(
                role,
                "ICS_DOWNLOAD_COMPLETE",
                serde_json::json!({
                    "mode": mode.label(),
                    "chunks": chunk_count,
                    "bytes": data.len(),
                    "sources_used": per_source.len(),
                    "message": format!("ICS {} complete: {} chunks from {} sources",
                        mode.label(), chunk_count, per_source.len()),
                }),
            );
            Some((data, chunk_count, mode))
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&sink_dir);
            eprintln!("[ICS-P2P] reassembly failed: {e}");
            None
        }
    }
}
