// ---------------------------------------------------------------------------
// Multi-source chunk download with eMule ICS
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
/// in sequential order.
///
/// Returns the concatenated encrypted data.
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
/// Returns `(encrypted_data, num_chunks, ics_mode)` or None on failure.
pub fn ics_download(
    client: &reqwest::blocking::Client,
    registry_url: Option<&str>,
    creator_url: &str,
    content_hash: &str,
    emitter: &ConsoleEmitter,
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

    emitter.emit(
        role,
        "ICS_FALLBACK",
        serde_json::json!({
            "message": "ICS multi-source via HTTP is disabled. Using P2P single-source with Merkle verification.",
        }),
    );
    return None;

    #[allow(unreachable_code)]
    let data = download_chunks_multisource(
        client,
        &sources,
        &assignments,
        &order,
        &encrypted_hash,
        chunk_count,
        emitter,
        mode,
    )?;

    Some((data, chunk_count, mode))
}
