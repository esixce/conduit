//! Conduit Lightning node with live console.
//!
//! Starts the node, runs a command, stays online. Ctrl-C to stop.
//! When `--http-port` is set, serves a browser console showing the
//! atomic swap flow in real time.
//!
//! Commands:
//!   address       Print on-chain wallet address
//!   info          Print node ID, addresses, balances
//!   open-channel  Open a channel to a peer
//!   channels      List open channels
//!   sell          Encrypt file, create invoice, wait for payment
//!   buy           Pay invoice, decrypt, verify

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::Path as AxumPath;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::IntoResponse;
use axum::response::{Html, Json};
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use conduit_core::chunk;
use conduit_core::encrypt;
use conduit_core::invoice::{self, ChainSource, LightningConfig};
use conduit_core::merkle::MerkleTree;
use conduit_core::pre;
use conduit_core::verify;

use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};
use ldk_node::{Event, Node};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
// Advertiser role
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::Connection;

use uuid::Uuid;

// ---------------------------------------------------------------------------
// Console event type
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct ConsoleEvent {
    id: u64,
    timestamp: String,
    role: String,
    event_type: String,
    data: serde_json::Value,
}

fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Append-only event log on disk (SQLite). Used for history API and audit trail.
struct EventLog {
    conn: std::sync::Mutex<Connection>,
}

impl EventLog {
    fn new(storage_dir: &str) -> Result<Self, rusqlite::Error> {
        let path = std::path::Path::new(storage_dir).join("events.db");
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                role      TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data      TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    fn append(&self, event: &ConsoleEvent) -> Result<u64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events (timestamp, role, event_type, data) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                event.timestamp,
                event.role,
                event.event_type,
                serde_json::to_string(&event.data).unwrap_or_default(),
            ],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    fn query(
        &self,
        since_id: u64,
        limit: u32,
        role_filter: Option<&str>,
    ) -> Result<Vec<ConsoleEvent>, rusqlite::Error> {
        let limit = limit.min(1000);
        let conn = self.conn.lock().unwrap();
        let mut out = Vec::new();
        if let Some(role) = role_filter {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, role, event_type, data FROM events WHERE id > ?1 AND role = ?2 ORDER BY id ASC LIMIT ?3",
            )?;
            let mapped = stmt.query_map(
                rusqlite::params![since_id as i64, role, limit as i32],
                |row| {
                    let data_str: String = row.get(4)?;
                    let data = serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
                    Ok(ConsoleEvent {
                        id: row.get::<_, i64>(0)? as u64,
                        timestamp: row.get(1)?,
                        role: row.get(2)?,
                        event_type: row.get(3)?,
                        data,
                    })
                },
            )?;
            for row in mapped {
                out.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, role, event_type, data FROM events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )?;
            let mapped =
                stmt.query_map(rusqlite::params![since_id as i64, limit as i32], |row| {
                    let data_str: String = row.get(4)?;
                    let data = serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
                    Ok(ConsoleEvent {
                        id: row.get::<_, i64>(0)? as u64,
                        timestamp: row.get(1)?,
                        role: row.get(2)?,
                        event_type: row.get(3)?,
                        data,
                    })
                })?;
            for row in mapped {
                out.push(row?);
            }
        }
        Ok(out)
    }
}

/// Single path for emitting console events: persist to log (if present) then broadcast.
#[derive(Clone)]
struct ConsoleEmitter {
    tx: broadcast::Sender<ConsoleEvent>,
    log: Option<Arc<EventLog>>,
}

impl ConsoleEmitter {
    fn new(tx: broadcast::Sender<ConsoleEvent>, log: Option<Arc<EventLog>>) -> Self {
        Self { tx, log }
    }

    fn subscribe(&self) -> broadcast::Receiver<ConsoleEvent> {
        self.tx.subscribe()
    }

    fn event_log(&self) -> Option<Arc<EventLog>> {
        self.log.clone()
    }

    fn emit(&self, role: &str, event_type: &str, data: serde_json::Value) {
        let mut event = ConsoleEvent {
            id: 0,
            timestamp: now_ts(),
            role: role.into(),
            event_type: event_type.into(),
            data,
        };
        if let Some(ref log) = self.log {
            if let Ok(id) = log.append(&event) {
                event.id = id;
            }
        }
        println!("[{}] {:<20} {}", event.role, event.event_type, event.data);
        let _ = self.tx.send(event);
    }
}

// ---------------------------------------------------------------------------
// Event router — single event loop, dispatches to registered handlers
// ---------------------------------------------------------------------------

/// Central event dispatcher. One background thread calls `wait_next_event()`,
/// matches on payment hash, and forwards to the registered handler. Events
/// that don't match any handler are logged and acknowledged — they never block
/// other handlers or eat events meant for the node's internal state machine.
struct EventRouter {
    waiters:
        std::sync::Mutex<std::collections::HashMap<PaymentHash, std::sync::mpsc::Sender<Event>>>,
    emitter: Arc<ConsoleEmitter>,
    role: std::sync::Mutex<String>,
}

impl EventRouter {
    fn new(emitter: Arc<ConsoleEmitter>) -> Self {
        Self {
            waiters: std::sync::Mutex::new(std::collections::HashMap::new()),
            emitter,
            role: std::sync::Mutex::new("node".into()),
        }
    }

    fn set_role(&self, role: &str) {
        *self.role.lock().unwrap() = role.into();
    }

    /// Register to receive events for a specific payment hash.
    /// Returns a receiver that will get `PaymentClaimable`, `PaymentReceived`,
    /// `PaymentSuccessful`, or `PaymentFailed` events matching this hash.
    fn register(&self, hash: PaymentHash) -> std::sync::mpsc::Receiver<Event> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.waiters.lock().unwrap().insert(hash, tx);
        rx
    }

    /// Unregister a handler (called when the handler is done).
    fn unregister(&self, hash: &PaymentHash) {
        self.waiters.lock().unwrap().remove(hash);
    }

    /// Extract payment hash from an event, if it has one.
    fn payment_hash_of(event: &Event) -> Option<PaymentHash> {
        match event {
            Event::PaymentClaimable { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentReceived { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentSuccessful { payment_hash, .. } => Some(*payment_hash),
            Event::PaymentFailed {
                payment_hash: Some(hash),
                ..
            } => Some(*hash),
            _ => None,
        }
    }

    /// Run the central event loop. Call from a dedicated background thread.
    fn run(&self, node: &Arc<Node>) {
        loop {
            let event = node.wait_next_event();

            let mut delivered = false;
            if let Some(hash) = Self::payment_hash_of(&event) {
                let waiters = self.waiters.lock().unwrap();
                if let Some(sender) = waiters.get(&hash) {
                    // If send fails, the handler dropped its receiver — that's fine.
                    let _ = sender.send(event.clone());
                    delivered = true;
                }
            }

            if !delivered {
                let role = self.role.lock().unwrap().clone();
                self.emitter.emit(
                    &role,
                    "LDK_EVENT",
                    serde_json::json!({
                        "event": format!("{:?}", event),
                    }),
                );
            }

            node.event_handled().expect("event_handled failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Registry push info (for publishing to the central registry)
// ---------------------------------------------------------------------------

/// Information needed to push listings/announcements to the registry.
/// Constructed once at startup and cloned into handlers.
#[derive(Clone)]
struct RegistryInfo {
    /// Registry base URL (e.g. "http://localhost:3003")
    url: String,
    /// This node's Lightning pubkey (hex)
    node_pubkey: String,
    /// This node's HTTP API address (e.g. "1.2.3.4:3000")
    http_address: String,
    /// This node's Lightning listening address (e.g. "1.2.3.4:9735")
    ln_address: String,
    /// Human-readable alias for this node
    node_alias: String,
}

// ---------------------------------------------------------------------------
// Axum app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    node_alias: String,
    emitter: Arc<ConsoleEmitter>,
    event_router: Arc<EventRouter>,
    catalog: Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    storage_dir: String,
    registry_info: Option<RegistryInfo>,
    // PRE (Phase 2A)
    pre_buyer_pk_hex: String,
    #[allow(dead_code)]
    pre_buyer_sk: bls12_381::Scalar,
    // TEE trust list
    trust_list: Arc<std::sync::Mutex<Vec<TrustedManufacturer>>>,
    // Advertiser role
    advertiser_db: Option<Arc<std::sync::Mutex<Connection>>>,
    advertiser_signing_key: Option<Arc<SigningKey>>,
    advertiser_pubkey_hex: Option<String>,
    #[allow(dead_code)]
    ads_dir: Option<String>,
    // Dashboard
    dashboard_path: Option<String>,
    // P2P (iroh)
    p2p_node: Option<Arc<conduit_p2p::node::P2pNode>>,
    p2p_runtime_handle: Option<tokio::runtime::Handle>,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn index_handler(State(state): State<AppState>) -> impl IntoResponse {
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

fn resolve_dashboard_sibling(
    dashboard_path: &Option<String>,
    filename: &str,
) -> Option<std::path::PathBuf> {
    dashboard_path.as_ref().and_then(|p| {
        std::path::Path::new(p)
            .parent()
            .map(|dir| dir.join(filename))
    })
}

const PWA_FILES: &[(&str, &str)] = &[
    ("manifest.json", "application/manifest+json"),
    ("sw.js", "application/javascript"),
    ("icon-192.png", "image/png"),
    ("icon-512.png", "image/png"),
];

async fn pwa_static_handler(
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

#[derive(Serialize)]
struct NodeInfo {
    node_id: String,
    node_alias: String,
    onchain_balance_sats: u64,
    spendable_onchain_sats: u64,
    lightning_balance_sats: u64,
    channels: Vec<ChannelInfo>,
}

#[derive(Serialize)]
struct ChannelInfo {
    channel_id: String,
    counterparty_node_id: String,
    value_sats: u64,
    outbound_msat: u64,
    inbound_msat: u64,
    ready: bool,
    usable: bool,
}

async fn info_handler(State(state): State<AppState>) -> Json<NodeInfo> {
    let balance = state.node.list_balances();
    let channels = state
        .node
        .list_channels()
        .iter()
        .map(|ch| ChannelInfo {
            channel_id: ch.channel_id.to_string(),
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
async fn address_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.node.onchain_payment().new_address() {
        Ok(addr) => Json(serde_json::json!({"address": addr.to_string()})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.emitter.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|event| {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Ok::<_, Infallible>(SseEvent::default().id(event.id.to_string()).data(json))
        })
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

#[derive(Deserialize)]
struct EventsHistoryQuery {
    #[serde(default)]
    since_id: Option<u64>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    role: Option<String>,
}

/// GET /api/events/history -- paginated event log (since_id, limit, role)
async fn events_history_handler(
    State(state): State<AppState>,
    Query(q): Query<EventsHistoryQuery>,
) -> Json<Vec<ConsoleEvent>> {
    let since_id = q.since_id.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).min(1000);
    let role = q.role.as_deref();
    let events = state
        .emitter
        .event_log()
        .and_then(|log| log.query(since_id, limit, role).ok())
        .unwrap_or_default();
    Json(events)
}

// ---------------------------------------------------------------------------
// API request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SellRequest {
    file: String,
    price: u64,
}

#[derive(Deserialize)]
struct BuyRequest {
    hash: String, // H(F) — plaintext hash
    output: String,
    // --- Two-phase buy (seeder flow) ---
    #[serde(default)]
    wrapped_url: Option<String>, // URL to fetch W from seeder
    #[serde(default)]
    transport_invoice: Option<String>, // Seeder's invoice (preimage = K_S)
    #[serde(default)]
    content_invoice: Option<String>, // Creator's invoice (preimage = K)
    #[serde(default)]
    encrypted_hash: Option<String>, // H(E) — for intermediate verification
    // --- Legacy single-phase buy ---
    #[serde(default)]
    invoice: Option<String>, // single invoice (backward compat)
    #[serde(default)]
    encrypted_file: Option<String>, // local path (legacy)
    #[serde(default)]
    enc_url: Option<String>, // HTTP URL to fetch .enc from creator
    // --- Chunked buy (A5: multi-source) ---
    #[serde(default)]
    seeder_urls: Vec<String>, // list of seeder HTTP base URLs
    #[serde(default)]
    mode: Option<String>, // "chunked" to enable chunk-level download
}

#[derive(Deserialize)]
struct SeedRequest {
    encrypted_file: String, // path to E on disk
    encrypted_hash: String, // H(E) hex
    transport_price: u64,   // sats for transport
    #[serde(default)]
    chunks: Option<String>, // which chunks to seed (e.g. "0,1,2,5-9"), omit for all
}

// ---------------------------------------------------------------------------
// Content Catalog — persistent registry of content available for sale
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogEntry {
    content_hash: String,   // H(F) hex — unique content ID (empty for seeder)
    file_name: String,      // display name (e.g. "btc-logo.png")
    file_path: String,      // original file path on disk (empty for seeder)
    enc_file_path: String,  // path to encrypted file E
    key_hex: String,        // K hex — SECRET, never exposed via API (empty for seeder)
    price_sats: u64,        // content price (0 for seeder — seeder uses transport_price)
    encrypted_hash: String, // H(E) hex
    size_bytes: u64,        // original plaintext size (enc size for seeder)
    registered_at: String,  // unix timestamp
    #[serde(default)]
    transport_price: u64, // sats for transport (0 for creator entries, >0 for seeder)
    // --- P2P chunk metadata (A3) ---
    #[serde(default)]
    chunk_size: usize, // bytes per chunk (0 = legacy single-blob)
    #[serde(default)]
    chunk_count: usize, // number of chunks (0 = legacy)
    #[serde(default)]
    plaintext_root: String, // Merkle root of H(plaintext chunks), hex
    #[serde(default)]
    encrypted_root: String, // Merkle root of H(encrypted chunks), hex
    #[serde(default)]
    chunks_held: Vec<usize>, // which chunk indices this node has (empty = all)
    // --- PRE (Phase 2A) ---
    #[serde(default)]
    pre_c1_hex: String, // PRE ciphertext c1 (compressed G1, 48 bytes, hex)
    #[serde(default)]
    pre_c2_hex: String, // PRE ciphertext c2 (m XOR mask, 32 bytes, hex)
    #[serde(default)]
    pre_pk_creator_hex: String, // Creator's PRE public key (compressed G1, 48 bytes, hex)
    // --- TEE playback policy ---
    #[serde(default = "default_playback_policy")]
    playback_policy: String, // "open" | "device_recommended" | "device_required"
}

fn default_playback_policy() -> String {
    "open".to_string()
}

#[derive(Deserialize)]
struct RegisterRequest {
    file: String,
    price: u64,
}

fn catalog_path(storage_dir: &str) -> String {
    format!("{}/catalog.json", storage_dir)
}

fn load_catalog(storage_dir: &str) -> Vec<CatalogEntry> {
    let path = catalog_path(storage_dir);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse catalog {}: {}", path, e);
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn save_catalog(storage_dir: &str, catalog: &[CatalogEntry]) {
    let path = catalog_path(storage_dir);
    // Ensure the directory exists
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(catalog).expect("Failed to serialize catalog");
    std::fs::write(&path, json).expect("Failed to write catalog");
    println!("Catalog saved: {} ({} entries)", path, catalog.len());
}

// ---------------------------------------------------------------------------
// Trusted manufacturers list — creator-local trust decisions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrustedManufacturer {
    pk_hex: String,
    name: String,
    #[serde(default)]
    added_at: String,
}

fn trust_list_path(storage_dir: &str) -> String {
    format!("{}/trusted_manufacturers.json", storage_dir)
}

fn load_trust_list(storage_dir: &str) -> Vec<TrustedManufacturer> {
    let path = trust_list_path(storage_dir);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse trust list {}: {}", path, e);
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn save_trust_list(storage_dir: &str, list: &[TrustedManufacturer]) {
    let path = trust_list_path(storage_dir);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(list).expect("Failed to serialize trust list");
    std::fs::write(&path, json).expect("Failed to write trust list");
    println!("Trust list saved: {} ({} entries)", path, list.len());
}

/// Startup migration: recompute chunk metadata for legacy seeder catalog entries
/// that have chunk_count == 0 but have an encrypted file on disk.
fn migrate_legacy_chunks(storage_dir: &str, catalog: &mut [CatalogEntry]) {
    let mut migrated = 0usize;
    for entry in catalog.iter_mut() {
        // Only migrate seeder entries: content_hash is empty (seeder doesn't know H(F)),
        // enc_file_path exists, and chunk_count is still 0 (legacy).
        if entry.chunk_count > 0 || entry.enc_file_path.is_empty() {
            continue;
        }
        // Read the encrypted file from disk
        let encrypted = match std::fs::read(&entry.enc_file_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "migrate_legacy_chunks: skip {} — cannot read {}: {}",
                    entry.file_name, entry.enc_file_path, e
                );
                continue;
            }
        };
        // Compute chunk metadata
        let cs = chunk::select_chunk_size(encrypted.len());
        let (enc_chunks, meta) = chunk::split(&encrypted, cs);
        let enc_tree = MerkleTree::from_chunks(&enc_chunks);

        entry.chunk_size = meta.chunk_size;
        entry.chunk_count = meta.count;
        entry.encrypted_root = hex::encode(enc_tree.root());
        // chunks_held stays empty → means "has all chunks"
        migrated += 1;
        println!(
            "migrate_legacy_chunks: {} → {} chunks (size {})",
            entry.file_name, meta.count, meta.chunk_size
        );
    }
    if migrated > 0 {
        save_catalog(storage_dir, catalog);
        println!(
            "Migrated {} legacy catalog entries with chunk metadata.",
            migrated
        );
    }
}

/// Startup resync: for each seeder catalog entry, check the registry listing.
/// If the creator re-published (new K → new encrypted_hash), re-fetch the
/// encrypted file from the creator and replace the stale catalog entry.
fn resync_stale_seeds(
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    registry_info: &RegistryInfo,
) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // 1. Fetch all listings from registry
    let listings_url = format!("{}/api/listings", registry_info.url);
    let listings: Vec<serde_json::Value> = match client
        .get(&listings_url)
        .send()
        .and_then(|r| r.json::<serde_json::Value>())
    {
        Ok(data) => {
            let items = data["items"]
                .as_array()
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();
            items
        }
        Err(e) => {
            eprintln!("resync_stale_seeds: failed to fetch listings: {}", e);
            return;
        }
    };

    println!(
        "resync_stale_seeds: {} listings in registry",
        listings.len()
    );

    // 2. For each listing, check if we have a seeder entry by file_name
    for listing in &listings {
        let listing_file = listing["file_name"].as_str().unwrap_or("");
        let listing_enc_hash = listing["encrypted_hash"].as_str().unwrap_or("");
        let creator_addr = listing["creator_address"].as_str().unwrap_or("");
        if listing_file.is_empty() || listing_enc_hash.is_empty() || creator_addr.is_empty() {
            continue;
        }

        // Check if our catalog has this file_name with a DIFFERENT encrypted_hash
        let stale = {
            let cat = catalog.lock().unwrap();
            cat.iter().any(|e| {
                e.file_name == listing_file
                    && !e.encrypted_hash.is_empty()
                    && e.content_hash.is_empty()  // seeder entry (not creator)
                    && e.encrypted_hash != listing_enc_hash
            })
        };

        if !stale {
            continue;
        }

        println!(
            "resync_stale_seeds: {} has stale encrypted_hash, re-fetching from creator {}",
            listing_file, creator_addr
        );

        // 3. Fetch the new encrypted file from creator
        let enc_filename = format!("{}.enc", listing_file);
        let creator_base = if creator_addr.starts_with("http") {
            creator_addr.to_string()
        } else {
            format!("http://{}", creator_addr)
        };
        let enc_url = format!("{}/api/enc/{}", creator_base, enc_filename);
        let enc_data = match client.get(&enc_url).send().and_then(|r| r.bytes()) {
            Ok(b) => b.to_vec(),
            Err(e) => {
                eprintln!(
                    "resync_stale_seeds: failed to fetch {} from {}: {}",
                    enc_filename, enc_url, e
                );
                continue;
            }
        };

        // Verify the downloaded file's hash matches the listing
        let actual_hash = hex::encode(verify::sha256_hash(&enc_data));
        if actual_hash != listing_enc_hash {
            eprintln!(
                "resync_stale_seeds: hash mismatch for {} — expected {} got {}",
                listing_file, listing_enc_hash, actual_hash
            );
            continue;
        }

        // 4. Save the new encrypted file to disk
        let enc_path = format!("{}/{}", storage_dir, enc_filename);
        if let Err(e) = std::fs::write(&enc_path, &enc_data) {
            eprintln!("resync_stale_seeds: failed to write {}: {}", enc_path, e);
            continue;
        }

        // 5. Compute chunk metadata
        let cs = chunk::select_chunk_size(enc_data.len());
        let (enc_chunks, meta) = chunk::split(&enc_data, cs);
        let enc_tree = MerkleTree::from_chunks(&enc_chunks);

        // 6. Remove old entry and insert new one
        let transport_price = {
            let mut cat = catalog.lock().unwrap();
            let old_tp = cat
                .iter()
                .find(|e| e.file_name == listing_file && e.content_hash.is_empty())
                .map(|e| e.transport_price)
                .unwrap_or(5);
            cat.retain(|e| !(e.file_name == listing_file && e.content_hash.is_empty()));
            old_tp
        };

        let registered_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        let entry = CatalogEntry {
            content_hash: String::new(),
            file_name: listing_file.to_string(),
            file_path: String::new(),
            enc_file_path: enc_path.clone(),
            key_hex: String::new(),
            price_sats: 0,
            encrypted_hash: listing_enc_hash.to_string(),
            size_bytes: enc_data.len() as u64,
            registered_at: registered_at.clone(),
            transport_price,
            chunk_size: meta.chunk_size,
            chunk_count: meta.count,
            plaintext_root: String::new(),
            encrypted_root: hex::encode(enc_tree.root()),
            chunks_held: Vec::new(),
            pre_c1_hex: String::new(),
            pre_c2_hex: String::new(),
            pre_pk_creator_hex: String::new(),
            playback_policy: "open".to_string(),
        };

        {
            let mut cat = catalog.lock().unwrap();
            cat.push(entry);
            save_catalog(storage_dir, &cat);
        }

        // 7. Re-announce to registry
        let body = serde_json::json!({
            "encrypted_hash": listing_enc_hash,
            "seeder_pubkey": &registry_info.node_pubkey,
            "seeder_address": &registry_info.http_address,
            "seeder_ln_address": &registry_info.ln_address,
            "seeder_alias": &registry_info.node_alias,
            "transport_price": transport_price,
            "chunk_count": meta.count,
            "chunks_held": Vec::<usize>::new(),
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", registry_info.url);
        match client.post(&url).json(&body).send() {
            Ok(resp) => println!(
                "resync_stale_seeds: {} reseeded & announced ({})",
                listing_file,
                resp.status()
            ),
            Err(e) => eprintln!(
                "resync_stale_seeds: announce failed for {}: {}",
                listing_file, e
            ),
        }
    }
}

async fn sell_handler(
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

async fn buy_handler(
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

/// Request body for PRE buy (browser-initiated).
#[derive(Deserialize)]
struct BuyPreRequest {
    /// Creator HTTP base URL (e.g. "http://167.172.152.231:3000")
    creator_url: String,
    /// Content hash from catalog
    content_hash: String,
    /// Optional seeder URL to download chunks from (defaults to creator)
    #[serde(default)]
    seeder_url: Option<String>,
    /// Output path for decrypted file
    #[serde(default = "default_pre_output")]
    output: String,
}

fn default_pre_output() -> String {
    format!(
        "/tmp/decrypted-pre-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}

/// POST /api/buy-pre — Browser-initiated PRE buy.
///
/// Spawns a background thread that:
///   1. Calls creator /api/pre-purchase with this node's buyer G2 pk
///   2. Pays the Lightning invoice
///   3. Recovers AES key m via PRE decryption
///   4. Downloads & decrypts chunks
///   5. Emits SSE events throughout
async fn buy_pre_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyPreRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.emitter.clone();
    let router = state.event_router.clone();
    let storage_dir = state.storage_dir.clone();
    let p2p_node = state.p2p_node.clone();
    let p2p_rt = state.p2p_runtime_handle.clone();

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
        );
    });
    Json(serde_json::json!({"status": "started"}))
}

/// Download a URL to /tmp/ via curl, emitting SSE events. Returns local path on success.
fn curl_fetch(url: &str, emitter: &ConsoleEmitter) -> Option<String> {
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

async fn seed_handler(
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

async fn wrapped_file_handler(
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

async fn enc_file_handler(
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

async fn catalog_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
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
async fn catalog_clear_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut cat = state.catalog.lock().unwrap();
    let count = cat.len();
    cat.clear();
    save_catalog(&state.storage_dir, &cat);
    println!("Catalog cleared ({} entries removed)", count);
    Json(serde_json::json!({ "deleted": count }))
}

async fn register_api_handler(
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

async fn invoice_handler(
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

// ---------------------------------------------------------------------------
// Ad-subsidized invoice (creator side)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AdInvoiceRequest {
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
async fn ad_invoice_handler(
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
struct TransportInvoiceBody {
    #[serde(default)]
    chunks: Vec<usize>, // empty = legacy whole-file wrapping
}

async fn transport_invoice_handler(
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
fn handle_transport_payment(
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

async fn decrypted_file_handler(
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

// ---------------------------------------------------------------------------
// A4: Chunk-level HTTP endpoints
// ---------------------------------------------------------------------------

/// Helper: find a catalog entry by encrypted_hash and return it with chunk metadata.
fn find_entry_with_chunks(
    state: &AppState,
    encrypted_hash: &str,
) -> Option<(CatalogEntry, Vec<Vec<u8>>, usize)> {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    let entry = entry?;

    let encrypted = std::fs::read(&entry.enc_file_path).ok()?;
    let cs = if entry.chunk_size > 0 {
        entry.chunk_size
    } else {
        chunk::select_chunk_size(encrypted.len())
    };
    let (enc_chunks, _meta) = chunk::split(&encrypted, cs);
    Some((entry, enc_chunks, cs))
}

/// GET /api/chunks/{encrypted_hash}/meta
/// Returns chunk count, chunk size, Merkle roots, file size.
async fn chunk_meta_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    match entry {
        Some(e) => Json(serde_json::json!({
            "encrypted_hash": e.encrypted_hash,
            "chunk_count": e.chunk_count,
            "chunk_size": e.chunk_size,
            "size_bytes": e.size_bytes,
            "encrypted_root": e.encrypted_root,
            "plaintext_root": e.plaintext_root,
            "content_hash": e.content_hash,
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "content not found").into_response(),
    }
}

/// GET /api/chunks/{encrypted_hash}/{index}
/// Serves a single encrypted chunk E_i by reading the .enc file and slicing.
async fn chunk_data_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let result = find_entry_with_chunks(&state, &encrypted_hash);
    match result {
        Some((entry, enc_chunks, _cs)) => {
            // Check if seeder has this chunk
            if !entry.chunks_held.is_empty() && !entry.chunks_held.contains(&index) {
                return (StatusCode::NOT_FOUND, "seeder does not hold this chunk").into_response();
            }
            if index >= enc_chunks.len() {
                return (StatusCode::NOT_FOUND, "chunk index out of range").into_response();
            }
            (
                StatusCode::OK,
                [
                    ("content-type", "application/octet-stream"),
                    ("x-chunk-index", &index.to_string()),
                    ("x-chunk-count", &enc_chunks.len().to_string()),
                ],
                enc_chunks[index].clone(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "content not found").into_response(),
    }
}

/// GET /api/chunks/{encrypted_hash}/proof/{index}
/// Returns a Merkle inclusion proof for chunk i against the encrypted Merkle root.
async fn chunk_proof_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let result = find_entry_with_chunks(&state, &encrypted_hash);
    match result {
        Some((entry, enc_chunks, _cs)) => {
            if index >= enc_chunks.len() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "chunk index out of range"
                    })),
                )
                    .into_response();
            }
            let tree = MerkleTree::from_chunks(&enc_chunks);
            let proof = tree.proof(index);
            let leaf_hash = hex::encode(tree.leaf_hash_at(index));
            Json(serde_json::json!({
                "index": index,
                "leaf_hash": leaf_hash,
                "proof": proof.to_json(),
                "encrypted_root": entry.encrypted_root,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "content not found"
            })),
        )
            .into_response(),
    }
}

/// GET /api/chunks/{encrypted_hash}/bitfield
/// Returns which chunks this node has. Empty chunks_held means "all".
async fn chunk_bitfield_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    match entry {
        Some(e) => {
            let total = if e.chunk_count > 0 { e.chunk_count } else { 1 };
            let bitfield: Vec<bool> = if e.chunks_held.is_empty() {
                // Empty = has all chunks
                vec![true; total]
            } else {
                (0..total).map(|i| e.chunks_held.contains(&i)).collect()
            };
            Json(serde_json::json!({
                "encrypted_hash": e.encrypted_hash,
                "chunk_count": total,
                "bitfield": bitfield,
                "chunks_held": if e.chunks_held.is_empty() {
                    (0..total).collect::<Vec<usize>>()
                } else {
                    e.chunks_held.clone()
                },
            }))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "content not found").into_response(),
    }
}

/// GET /api/wrapped-chunks/{encrypted_hash}/{index}
/// Serves a previously wrapped chunk W_i from the wrapped_chunks directory.
async fn wrapped_chunk_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    let entry = match entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, "content not found").into_response(),
    };

    let chunk_path = format!("{}.wrapped_chunks/{}", entry.enc_file_path, index);
    match std::fs::read(&chunk_path) {
        Ok(data) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("x-chunk-index", &index.to_string()),
            ],
            data,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "wrapped chunk not found (request transport-invoice first)",
        )
            .into_response(),
    }
}

// ===========================================================================
// Advertiser role — third-party ad campaigns, attestation tokens, ad creative
// serving, subsidy invoice payment. Advertisers are external parties (brands,
// businesses, anyone) who pay to show their ads to buyers in exchange for
// subsidizing content purchases. The creator's content is the delivery vehicle.
// See docs/14_ad_attestation.md and docs/15_unified_dashboard.md.
// ===========================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AdvCampaign {
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
struct AdvStartSessionRequest {
    buyer_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct AdvCompleteSessionRequest {
    session_id: String,
    buyer_pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdvAttestationPayload {
    campaign_id: String,
    buyer_pubkey: String,
    timestamp: u64,
    duration_ms: u64,
}

#[derive(Debug, Deserialize)]
struct AdvPayRequest {
    bolt11_invoice: String,
    attestation_token: String,
    attestation_payload: AdvAttestationPayload,
}

fn adv_init_db(conn: &Connection) {
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

fn adv_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn adv_load_campaigns(db: &Connection) -> Vec<AdvCampaign> {
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

fn adv_infer_format(url: &str) -> &'static str {
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

fn adv_canonical_json(payload: &AdvAttestationPayload) -> String {
    serde_json::to_string(payload).unwrap()
}

fn adv_sign_attestation(key: &SigningKey, payload: &AdvAttestationPayload) -> String {
    let message = adv_canonical_json(payload);
    let signature = key.sign(message.as_bytes());
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    )
}

fn adv_verify_attestation(
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

fn adv_load_or_create_signing_key(storage_dir: &str) -> SigningKey {
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
async fn adv_list_campaigns(State(state): State<AppState>) -> impl IntoResponse {
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
async fn adv_get_campaign(
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
async fn adv_serve_creative(
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
async fn adv_create_campaign(
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
async fn adv_clear_campaigns(State(state): State<AppState>) -> impl IntoResponse {
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
async fn adv_start_session(
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
async fn adv_complete_session(
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
async fn adv_pay_invoice(
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
async fn adv_info_handler(State(state): State<AppState>) -> impl IntoResponse {
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

// ===========================================================================
// End of advertiser role
// ===========================================================================

// ===========================================================================
// P2P bridge: implements conduit_p2p::handler::ChunkStore for AppState
// ===========================================================================

/// Wraps AppState to implement the ChunkStore trait for the P2P layer.
#[derive(Clone)]
struct ConduitChunkStore {
    catalog: Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    node: Arc<Node>,
    emitter: Arc<ConsoleEmitter>,
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
    fn new(state: &AppState) -> Self {
        Self {
            catalog: state.catalog.clone(),
            node: state.node.clone(),
            emitter: state.emitter.clone(),
            pending_keys: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn find_entry(&self, encrypted_hash: &[u8; 32]) -> Option<CatalogEntry> {
        let hash_hex = hex::encode(encrypted_hash);
        let cat = self.catalog.lock().unwrap();
        cat.iter().find(|e| e.encrypted_hash == hash_hex).cloned()
    }

    fn load_chunks(&self, entry: &CatalogEntry) -> Option<Vec<Vec<u8>>> {
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
        let entry = self.find_entry(encrypted_hash)?;
        if !entry.chunks_held.is_empty() && !entry.chunks_held.contains(&(index as usize)) {
            return None;
        }
        let chunks = self.load_chunks(&entry)?;
        chunks.get(index as usize).cloned()
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
async fn p2p_info_handler(State(state): State<AppState>) -> impl IntoResponse {
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
async fn p2p_test_handler(
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
async fn p2p_test_download_handler(
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
    let num_chunks: u32 = match client.get(&catalog_url).send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(cat) => {
                let items = cat.as_array().or_else(|| cat["items"].as_array());
                items
                    .and_then(|arr| {
                        let entry = arr.iter().find(|e| {
                            e["encrypted_hash"].as_str() == Some(hash_hex.as_str())
                                || e["content_hash"].as_str() == Some(hash_hex.as_str())
                        })?;
                        entry["chunk_count"]
                            .as_u64()
                            .or_else(|| entry["total_chunks"].as_u64())
                    })
                    .unwrap_or(1) as u32
            }
            Err(_) => 1,
        },
        Err(_) => 1,
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
            .download(addr, enc_hash_bytes, &indices_owned, payment)
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

fn start_http_server(port: u16, state: AppState) {
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            let app = Router::new()
                .route("/", get(index_handler))
                .route("/{filename}", get(pwa_static_handler))
                .route("/api/info", get(info_handler))
                .route("/api/address", get(address_handler))
                .route("/api/events", get(sse_handler))
                .route("/api/events/history", get(events_history_handler))
                .route(
                    "/api/catalog",
                    get(catalog_handler).delete(catalog_clear_handler),
                )
                .route("/api/register", post(register_api_handler))
                .route("/api/invoice/{content_hash}", post(invoice_handler))
                .route("/api/ad-invoice/{content_hash}", post(ad_invoice_handler))
                .route("/api/sell", post(sell_handler))
                .route("/api/buy", post(buy_handler))
                .route("/api/buy-pre", post(buy_pre_handler))
                .route("/api/seed", post(seed_handler))
                .route(
                    "/api/transport-invoice/{encrypted_hash}",
                    post(transport_invoice_handler),
                )
                .route("/api/enc/{filename}", get(enc_file_handler))
                .route("/api/wrapped/{filename}", get(wrapped_file_handler))
                .route("/api/decrypted/{filename}", get(decrypted_file_handler))
                // A4: Chunk-level endpoints
                .route("/api/chunks/{encrypted_hash}/meta", get(chunk_meta_handler))
                .route(
                    "/api/chunks/{encrypted_hash}/{index}",
                    get(chunk_data_handler),
                )
                .route(
                    "/api/chunks/{encrypted_hash}/proof/{index}",
                    get(chunk_proof_handler),
                )
                .route(
                    "/api/chunks/{encrypted_hash}/bitfield",
                    get(chunk_bitfield_handler),
                )
                .route(
                    "/api/wrapped-chunks/{encrypted_hash}/{index}",
                    get(wrapped_chunk_handler),
                )
                // Advertiser role routes
                .route(
                    "/api/campaigns",
                    get(adv_list_campaigns)
                        .post(adv_create_campaign)
                        .delete(adv_clear_campaigns),
                )
                .route("/api/campaigns/{campaign_id}", get(adv_get_campaign))
                .route(
                    "/api/campaigns/{campaign_id}/creative",
                    get(adv_serve_creative),
                )
                .route(
                    "/api/campaigns/{campaign_id}/start",
                    post(adv_start_session),
                )
                .route(
                    "/api/campaigns/{campaign_id}/complete",
                    post(adv_complete_session),
                )
                .route("/api/campaigns/pay", post(adv_pay_invoice))
                .route("/api/advertiser/info", get(adv_info_handler))
                // PRE (Phase 2A) routes
                .route(
                    "/api/pre-purchase/{content_hash}",
                    post(pre_purchase_handler),
                )
                .route(
                    "/api/pre-ciphertext/{content_hash}",
                    get(pre_ciphertext_handler),
                )
                .route("/api/pre-info", get(pre_info_handler))
                .route("/api/pre-reencrypt", post(pre_reencrypt_handler))
                // TEE trust list + attestation routes
                .route(
                    "/api/trusted-manufacturers",
                    get(trust_list_handler).post(trust_add_handler),
                )
                .route(
                    "/api/trusted-manufacturers/{pk_hex}",
                    axum::routing::delete(trust_remove_handler),
                )
                .route("/api/device-attest", post(device_attest_handler))
                .route(
                    "/api/device-attest/respond",
                    post(device_attest_respond_handler),
                )
                // P2P info and diagnostics
                .route("/api/p2p-info", get(p2p_info_handler))
                .route("/api/p2p-test", get(p2p_test_handler))
                .route("/api/p2p-test-download", get(p2p_test_download_handler))
                .layer(CorsLayer::permissive())
                .with_state(state);
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
                .await
                .expect("Failed to bind HTTP port");
            println!("Console: http://0.0.0.0:{}", port);
            axum::serve(listener, app).await.unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// TEE Trust List API handlers
// ---------------------------------------------------------------------------

/// GET /api/trusted-manufacturers -- list all trusted manufacturers
async fn trust_list_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let list = state.trust_list.lock().unwrap();
    Json(serde_json::json!({ "items": *list }))
}

#[derive(Deserialize)]
struct AddTrustRequest {
    pk_hex: String,
    name: String,
}

/// POST /api/trusted-manufacturers -- add a manufacturer to trust list
async fn trust_add_handler(
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
async fn trust_remove_handler(
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
struct DeviceAttestRequest {
    dev_pk_hex: String,
    device_pk_g2_hex: String,
    manufacturer_pk_hex: String,
    model: String,
    firmware_hash: String,
    manufacturer_sig_hex: String,
}

async fn device_attest_handler(
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
struct DeviceAttestResponse {
    dev_pk_hex: String,
    nonce_hex: String,
    signature_hex: String,
}

async fn device_attest_respond_handler(
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

// ---------------------------------------------------------------------------
// PRE (Phase 2A) API handlers
// ---------------------------------------------------------------------------

/// Request body for PRE purchase: buyer sends their PRE public key (G2, 96 bytes hex).
#[derive(Deserialize)]
struct PrePurchaseRequest {
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
async fn pre_purchase_handler(
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
async fn pre_ciphertext_handler(
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
fn handle_pre_sell_from_catalog(
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
async fn pre_info_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "buyer_pk_hex": state.pre_buyer_pk_hex,
        "node_id": invoice::node_id(&state.node),
        "node_alias": state.node_alias,
    }))
}

/// Request body for PRE re-encryption (seeder side).
#[derive(Deserialize)]
struct PreReencryptRequest {
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
async fn pre_reencrypt_handler(
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

// ---------------------------------------------------------------------------
// sell command
// ---------------------------------------------------------------------------

fn handle_sell(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    file_path: &str,
    price: u64,
) {
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    println!("Read {} bytes from {}", plaintext.len(), file_path);

    // 2. Generate key
    let key = encrypt::generate_key();
    emitter.emit(
        role,
        "KEY_GENERATED",
        serde_json::json!({
            "key": hex::encode(key),
        }),
    );

    // 3. Encrypt
    let ciphertext = encrypt::encrypt(&plaintext, &key, 0);
    emitter.emit(
        role,
        "CONTENT_ENCRYPTED",
        serde_json::json!({
            "plaintext_bytes": plaintext.len(),
            "ciphertext_bytes": ciphertext.len(),
        }),
    );

    // 4. Hash plaintext
    let file_hash = verify::sha256_hash(&plaintext);
    emitter.emit(
        role,
        "HASH_COMPUTED",
        serde_json::json!({
            "hash": hex::encode(file_hash),
        }),
    );

    // 5. Create invoice
    let bolt11 = invoice::create_invoice_for_key(node, &key, price, file_path)
        .expect("Failed to create invoice");
    let payment_hash = verify::sha256_hash(&key);
    let enc_path = format!("{}.enc", file_path);
    let enc_filename = enc_path.split('/').next_back().unwrap_or("").to_string();
    let enc_hash = verify::sha256_hash(&ciphertext);
    emitter.emit(
        role,
        "INVOICE_CREATED",
        serde_json::json!({
            "payment_hash": hex::encode(payment_hash),
            "content_hash": hex::encode(file_hash),
            "encrypted_hash": hex::encode(enc_hash),
            "amount_sats": price,
            "bolt11": &bolt11,
            "enc_filename": &enc_filename,
            "file_name": file_path.split('/').next_back().unwrap_or(file_path),
        }),
    );

    // 6. Save encrypted file
    std::fs::write(&enc_path, &ciphertext).expect("Failed to write encrypted file");
    emitter.emit(
        role,
        "ENCRYPTED_FILE_SAVED",
        serde_json::json!({
            "path": &enc_path,
            "encrypted_hash": hex::encode(enc_hash),
            "bytes": ciphertext.len(),
        }),
    );

    // 7. Print summary for the buyer
    println!();
    println!("=== SELL READY ===");
    println!("Encrypted file:  {}", enc_path);
    println!("Plaintext hash:  {}", hex::encode(file_hash));
    println!("Encrypted hash:  {}", hex::encode(enc_hash));
    println!("Invoice:         {}", bolt11);
    println!();

    // 8. Wait for payment via event router
    emitter.emit(
        role,
        "WAITING_FOR_PAYMENT",
        serde_json::json!({
            "message": "Listening for incoming HTLC..."
        }),
    );

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
                    "HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                // Claim payment (reveals preimage to buyer)
                invoice::claim_payment(node, &key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emitter.emit(
                    role,
                    "PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(key),
                        "message": "Preimage revealed to buyer via HTLC settlement",
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
                    "PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "Payment confirmed. Content sold.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

// ---------------------------------------------------------------------------
// Parse --chunks argument: "0,1,2,5-9" -> vec![0,1,2,5,6,7,8,9]
// Returns empty vec if arg is None (meaning "all chunks").
// ---------------------------------------------------------------------------

fn parse_chunks_arg(arg: &Option<String>, total_chunks: usize) -> Vec<usize> {
    let arg = match arg {
        Some(s) if !s.is_empty() => s,
        _ => return Vec::new(), // empty = all chunks
    };

    let mut result = Vec::new();
    for part in arg.split(',') {
        let part = part.trim();
        if let Some((start_str, end_str)) = part.split_once('-') {
            let start: usize = start_str.trim().parse().expect("Invalid chunk range start");
            let end: usize = end_str.trim().parse().expect("Invalid chunk range end");
            for i in start..=end {
                if i < total_chunks {
                    result.push(i);
                }
            }
        } else {
            let idx: usize = part.parse().expect("Invalid chunk index");
            if idx < total_chunks {
                result.push(idx);
            }
        }
    }
    result.sort();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// seed command (seeder: wrap with transport key K_S)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn handle_seed(
    emitter: &ConsoleEmitter,
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    enc_file_path: &str,
    expected_enc_hash_hex: &str,
    transport_price: u64,
    registry_info: &Option<RegistryInfo>,
    chunks_arg: &Option<String>,
) {
    let role = "seeder";

    // 1. Read encrypted file E (already encrypted by creator with K)
    let encrypted = std::fs::read(enc_file_path).expect("Failed to read encrypted file");
    println!(
        "Read {} encrypted bytes from {}",
        encrypted.len(),
        enc_file_path
    );

    // 2. Verify H(E) matches what the creator published
    let enc_hash = verify::sha256_hash(&encrypted);
    let expected_enc_hash = hex::decode(expected_enc_hash_hex).expect("Invalid hex hash");
    if enc_hash[..] != expected_enc_hash[..] {
        emitter.emit(
            role,
            "ENC_HASH_MISMATCH",
            serde_json::json!({
                "expected": expected_enc_hash_hex,
                "actual": hex::encode(enc_hash),
                "message": "Encrypted content hash mismatch! File may be corrupted.",
            }),
        );
        eprintln!("ERROR: Encrypted content hash mismatch");
        return;
    }
    emitter.emit(
        role,
        "ENC_HASH_VERIFIED",
        serde_json::json!({
            "hash": hex::encode(enc_hash),
        }),
    );

    // 3. Check if already in seeder catalog
    {
        let cat = catalog.lock().unwrap();
        if cat
            .iter()
            .any(|e| e.encrypted_hash == expected_enc_hash_hex)
        {
            emitter.emit(
                role,
                "ALREADY_SEEDED",
                serde_json::json!({
                    "encrypted_hash": expected_enc_hash_hex,
                    "message": "Content already in seeder catalog",
                }),
            );
            return;
        }
    }

    // 4. Derive file_name from enc_file_path (strip .enc suffix)
    let enc_filename = enc_file_path
        .split('/')
        .next_back()
        .unwrap_or("unknown.enc");
    let file_name = enc_filename
        .strip_suffix(".enc")
        .unwrap_or(enc_filename)
        .to_string();

    // 4b. Compute chunk metadata from the encrypted file
    let cs = chunk::select_chunk_size(encrypted.len());
    let (enc_chunks, meta) = chunk::split(&encrypted, cs);
    let enc_tree = MerkleTree::from_chunks(&enc_chunks);

    // 4c. Parse --chunks argument (e.g. "0,1,2,5-9")
    let chunks_held = parse_chunks_arg(chunks_arg, meta.count);
    if !chunks_held.is_empty() {
        emitter.emit(
            role,
            "CHUNKS_SELECTED",
            serde_json::json!({
                "chunks_held": &chunks_held,
                "total_chunks": meta.count,
                "message": format!("Seeding {} of {} chunks", chunks_held.len(), meta.count),
            }),
        );
    }

    // 5. Save to catalog
    let registered_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        secs.to_string()
    };

    let entry = CatalogEntry {
        content_hash: String::new(),
        file_name: file_name.clone(),
        file_path: String::new(),
        enc_file_path: enc_file_path.to_string(),
        key_hex: String::new(),
        price_sats: 0,
        encrypted_hash: expected_enc_hash_hex.to_string(),
        size_bytes: encrypted.len() as u64,
        registered_at: registered_at.clone(),
        transport_price,
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: String::new(),
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: chunks_held.clone(),
        pre_c1_hex: String::new(),
        pre_c2_hex: String::new(),
        pre_pk_creator_hex: String::new(),
        playback_policy: "open".to_string(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    let chunks_seeding = if chunks_held.is_empty() {
        meta.count
    } else {
        chunks_held.len()
    };
    emitter.emit( role, "CONTENT_SEEDED", serde_json::json!({
        "encrypted_hash": expected_enc_hash_hex,
        "file_name": &file_name,
        "transport_price": transport_price,
        "size_bytes": encrypted.len(),
        "chunk_count": meta.count,
        "chunk_size": meta.chunk_size,
        "chunks_seeding": chunks_seeding,
        "encrypted_root": hex::encode(enc_tree.root()),
        "message": format!("Content added to seeder catalog ({}/{} chunks). Transport invoices generated on demand.", chunks_seeding, meta.count),
    }));

    // Push seeder announcement to registry (blocking)
    if let Some(ref info) = registry_info {
        let body = serde_json::json!({
            "encrypted_hash": expected_enc_hash_hex,
            "seeder_pubkey": &info.node_pubkey,
            "seeder_address": &info.http_address,
            "seeder_ln_address": &info.ln_address,
            "seeder_alias": &info.node_alias,
            "transport_price": transport_price,
            "chunk_count": meta.count,
            "chunks_held": &chunks_held,
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", info.url);
        match reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .send()
        {
            Ok(resp) => println!("Registry: seeder announced ({})", resp.status()),
            Err(e) => eprintln!("Warning: failed to push seeder to registry: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// register command (add content to catalog)
// ---------------------------------------------------------------------------

fn handle_register(
    emitter: &ConsoleEmitter,
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    file_path: &str,
    price: u64,
    registry_info: &Option<RegistryInfo>,
) {
    // Derive creator PRE keypair from a seed stored alongside the catalog.
    // For the prototype, we use a fixed seed based on the storage directory.
    let pre_seed = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"conduit-pre-creator-seed:");
        h.update(storage_dir.as_bytes());
        let hash = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&hash);
        s
    };
    let creator_kp = pre::creator_keygen_from_seed(&pre_seed);
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    let file_name = file_path
        .split('/')
        .next_back()
        .unwrap_or(file_path)
        .to_string();
    let size_bytes = plaintext.len() as u64;

    // 2. Compute content hash H(F)
    let content_hash = hex::encode(verify::sha256_hash(&plaintext));
    emitter.emit(
        role,
        "HASH_COMPUTED",
        serde_json::json!({
            "hash": &content_hash,
            "file_name": &file_name,
        }),
    );

    // 3. Check if already registered
    {
        let cat = catalog.lock().unwrap();
        if let Some(existing) = cat.iter().find(|e| e.content_hash == content_hash) {
            println!(
                "Content already registered: {} ({})",
                file_name, content_hash
            );
            emitter.emit(
                role,
                "ALREADY_REGISTERED",
                serde_json::json!({
                    "content_hash": &content_hash,
                    "file_name": &file_name,
                    "price_sats": existing.price_sats,
                }),
            );
            return;
        }
    }

    // 4. Generate content key K (permanent, reused for every buyer)
    let key = encrypt::generate_key();
    emitter.emit(
        role,
        "KEY_GENERATED",
        serde_json::json!({
            "key": hex::encode(key),
            "message": "Content key K generated — stored in catalog, reused for every buyer",
        }),
    );

    // 5. Chunk, encrypt per-chunk, build Merkle trees
    let cs = chunk::select_chunk_size(plaintext.len());
    let (plain_chunks, meta) = chunk::split(&plaintext, cs);

    // Build plaintext Merkle tree
    let plain_tree = MerkleTree::from_chunks(&plain_chunks);

    // Encrypt each chunk with its own IV
    let enc_chunks: Vec<Vec<u8>> = plain_chunks
        .iter()
        .enumerate()
        .map(|(i, c)| encrypt::encrypt(c, &key, i as u64))
        .collect();

    // Build encrypted Merkle tree
    let enc_tree = MerkleTree::from_chunks(&enc_chunks);

    // Write concatenated encrypted chunks to disk (same format as before
    // for single-chunk files; for multi-chunk, it's the chunks back-to-back)
    let ciphertext: Vec<u8> = enc_chunks.iter().flat_map(|c| c.iter().copied()).collect();
    let enc_path = format!("{}.enc", file_path);
    std::fs::write(&enc_path, &ciphertext).expect("Failed to write encrypted file");

    // Flat hashes remain for backward compat and seeder lookup
    let encrypted_hash = hex::encode(verify::sha256_hash(&ciphertext));

    emitter.emit(
        role,
        "CONTENT_ENCRYPTED",
        serde_json::json!({
            "plaintext_bytes": size_bytes,
            "ciphertext_bytes": ciphertext.len(),
            "enc_path": &enc_path,
            "encrypted_hash": &encrypted_hash,
        }),
    );

    // 6. Save to catalog
    let registered_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        secs.to_string()
    };

    // PRE: encrypt the AES key under the creator's PRE public key
    let pre_ct = pre::encrypt(&creator_kp.pk, &key);
    let ct_bytes = pre::serialize_ciphertext(&pre_ct);
    let pre_c1_hex = hex::encode(&ct_bytes[..48]);
    let pre_c2_hex = hex::encode(&ct_bytes[48..]);
    let pre_pk_hex = hex::encode(pre::serialize_creator_pk(&creator_kp.pk));

    emitter.emit(
        role,
        "PRE_CIPHERTEXT_CREATED",
        serde_json::json!({
            "pre_c1": &pre_c1_hex,
            "pre_c2": &pre_c2_hex,
            "pre_pk_creator": &pre_pk_hex,
            "message": "AES key encrypted under creator PRE public key (AFGH06)",
        }),
    );

    let entry = CatalogEntry {
        content_hash: content_hash.clone(),
        file_name: file_name.clone(),
        file_path: file_path.to_string(),
        enc_file_path: enc_path.clone(),
        key_hex: hex::encode(key),
        price_sats: price,
        encrypted_hash: encrypted_hash.clone(),
        size_bytes,
        registered_at: registered_at.clone(),
        transport_price: 0,
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: hex::encode(plain_tree.root()),
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: Vec::new(),
        // PRE fields
        pre_c1_hex: pre_c1_hex.clone(),
        pre_c2_hex: pre_c2_hex.clone(),
        pre_pk_creator_hex: pre_pk_hex.clone(),
        playback_policy: "open".to_string(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    emitter.emit(
        role,
        "CONTENT_REGISTERED",
        serde_json::json!({
            "content_hash": &content_hash,
            "file_name": &file_name,
            "encrypted_hash": &encrypted_hash,
            "size_bytes": size_bytes,
            "price_sats": price,
            "enc_path": &enc_path,
            "chunk_size": meta.chunk_size,
            "chunk_count": meta.count,
            "plaintext_root": hex::encode(plain_tree.root()),
            "encrypted_root": hex::encode(enc_tree.root()),
            "message": "Content registered in catalog and ready for sale",
        }),
    );

    println!();
    println!("=== CONTENT REGISTERED ===");
    println!("File:           {}", file_name);
    println!("Content hash:   {}", content_hash);
    println!("Encrypted hash: {}", encrypted_hash);
    println!("Encrypted file: {}", enc_path);
    println!("Price:          {} sats", price);
    println!("Chunks:         {} x {} bytes", meta.count, meta.chunk_size);
    println!("Plaintext root: {}", hex::encode(plain_tree.root()));
    println!("Encrypted root: {}", hex::encode(enc_tree.root()));
    println!("Catalog:        {}", catalog_path(storage_dir));
    println!();

    // Push listing to registry (blocking)
    if let Some(ref info) = registry_info {
        let body = serde_json::json!({
            "content_hash": &content_hash,
            "encrypted_hash": &encrypted_hash,
            "file_name": &file_name,
            "size_bytes": size_bytes,
            "price_sats": price,
            "chunk_size": meta.chunk_size,
            "chunk_count": meta.count,
            "plaintext_root": hex::encode(plain_tree.root()),
            "encrypted_root": hex::encode(enc_tree.root()),
            "creator_pubkey": &info.node_pubkey,
            "creator_address": &info.http_address,
            "creator_ln_address": &info.ln_address,
            "creator_alias": &info.node_alias,
            "registered_at": &registered_at,
            "pre_c1_hex": &pre_c1_hex,
            "pre_c2_hex": &pre_c2_hex,
            "pre_pk_creator_hex": &pre_pk_hex,
            "playback_policy": "open",
        });
        let url = format!("{}/api/listings", info.url);
        match reqwest::blocking::Client::new()
            .post(&url)
            .json(&body)
            .send()
        {
            Ok(resp) => println!("Registry: listing pushed ({})", resp.status()),
            Err(e) => eprintln!("Warning: failed to push listing to registry: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// sell from catalog (wait for payment using stored K)
// ---------------------------------------------------------------------------

fn handle_sell_from_catalog(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    key: &[u8; 32],
) {
    let role = "creator";

    emitter.emit(
        role,
        "WAITING_FOR_PAYMENT",
        serde_json::json!({
            "message": "Listening for incoming HTLC..."
        }),
    );

    let payment_hash = verify::sha256_hash(key);
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
                    "HTLC_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": claimable_amount_msat,
                        "claim_deadline": claim_deadline,
                    }),
                );

                invoice::claim_payment(node, key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emitter.emit(
                    role,
                    "PAYMENT_CLAIMED",
                    serde_json::json!({
                        "preimage": hex::encode(key),
                        "message": "Preimage revealed to buyer via HTLC settlement",
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
                    "PAYMENT_RECEIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash.0),
                        "amount_msat": amount_msat,
                        "message": "Payment confirmed. Content sold.",
                    }),
                );
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

// ---------------------------------------------------------------------------
// Ad-subsidized sell: HOLD-AND-CLAIM-TOGETHER
//
// Waits for BOTH Invoice 1 (K, from buyer) and Invoice 2 (K_ad, from
// advertiser) HTLCs to arrive before claiming either. This guarantees
// the creator never reveals K unless the advertiser's payment is locked in.
//
// Trust analysis:
//   - Buyer:      Risks ~15s of time watching the ad. Acceptable.
//   - Advertiser: Trusts the buyer's app displayed the ad (attestation).
//   - Creator:    TRUSTLESS — holds K until both HTLCs are pending.
//   - If Invoice 2 never arrives (advertiser doesn't pay), the creator
//     lets Invoice 1 expire. The buyer's 1 sat is returned. No content
//     is delivered. Nobody loses money.
// ---------------------------------------------------------------------------

fn handle_ad_sell_hold_and_claim(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    key_k: &[u8; 32],    // Invoice 1 preimage: content key K
    key_k_ad: &[u8; 32], // Invoice 2 preimage: random K_ad
) {
    let role = "creator";

    // Compute payment hashes
    let hash_k = PaymentHash(verify::sha256_hash(key_k));
    let hash_k_ad = PaymentHash(verify::sha256_hash(key_k_ad));

    // Register for events on BOTH payment hashes
    let rx_k = router.register(hash_k);
    let rx_k_ad = router.register(hash_k_ad);

    emitter.emit( role, "AD_HOLD_WAITING", serde_json::json!({
        "message": "Waiting for BOTH Invoice 1 (buyer) and Invoice 2 (advertiser) HTLCs before claiming either",
        "buyer_payment_hash": hex::encode(hash_k.0),
        "ad_payment_hash": hex::encode(hash_k_ad.0),
    }));

    // Track which HTLCs have arrived
    let mut buyer_htlc: Option<u64> = None; // amount_msat when arrived
    let mut ad_htlc: Option<u64> = None; // amount_msat when arrived

    // Poll both receivers. We use try_recv with a short sleep to multiplex
    // two channels without blocking on either one forever.
    loop {
        // Check for Invoice 1 (buyer, K)
        if buyer_htlc.is_none() {
            if let Ok(Event::PaymentClaimable {
                claimable_amount_msat,
                ..
            }) = rx_k.try_recv()
            {
                emitter.emit(
                    role,
                    "AD_HTLC_BUYER_ARRIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash_k.0),
                        "amount_msat": claimable_amount_msat,
                        "message": "Buyer's HTLC arrived — HOLDING until advertiser's HTLC also arrives",
                    }),
                );
                buyer_htlc = Some(claimable_amount_msat);
            }
        }

        // Check for Invoice 2 (advertiser, K_ad)
        if ad_htlc.is_none() {
            if let Ok(Event::PaymentClaimable {
                claimable_amount_msat,
                ..
            }) = rx_k_ad.try_recv()
            {
                emitter.emit(
                    role,
                    "AD_HTLC_ADVERTISER_ARRIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash_k_ad.0),
                        "amount_msat": claimable_amount_msat,
                        "message": "Advertiser's HTLC arrived — HOLDING until buyer's HTLC also arrives",
                    }),
                );
                ad_htlc = Some(claimable_amount_msat);
            }
        }

        // If BOTH have arrived, claim both and break
        if let (Some(buyer_amt), Some(ad_amt)) = (buyer_htlc, ad_htlc) {
            emitter.emit(
                role,
                "AD_BOTH_HTLCS_READY",
                serde_json::json!({
                    "message": "BOTH HTLCs arrived — claiming both now",
                    "buyer_amount_msat": buyer_amt,
                    "ad_amount_msat": ad_amt,
                }),
            );

            // Claim Invoice 2 first (K_ad, meaningless) — order doesn't
            // matter since both HTLCs are already locked in, but claiming
            // the advertiser's payment first is a nice convention.
            invoice::claim_payment(node, key_k_ad, ad_amt)
                .expect("Failed to claim advertiser payment");
            emitter.emit(
                role,
                "AD_CLAIMED_ADVERTISER",
                serde_json::json!({
                    "preimage": hex::encode(key_k_ad),
                    "amount_msat": ad_amt,
                    "message": "Advertiser payment claimed (K_ad revealed — meaningless)",
                }),
            );

            // Claim Invoice 1 (K, the content key) — buyer learns K
            invoice::claim_payment(node, key_k, buyer_amt).expect("Failed to claim buyer payment");
            emitter.emit(
                role,
                "AD_CLAIMED_BUYER",
                serde_json::json!({
                    "preimage": hex::encode(key_k),
                    "amount_msat": buyer_amt,
                    "message": "Buyer payment claimed (K revealed — buyer can now decrypt content)",
                }),
            );

            break;
        }

        // Brief sleep to avoid busy-waiting
        thread::sleep(Duration::from_millis(100));
    }

    // Wait for PaymentReceived confirmations for both
    let mut k_confirmed = false;
    let mut k_ad_confirmed = false;
    while !k_confirmed || !k_ad_confirmed {
        if !k_confirmed {
            if let Ok(Event::PaymentReceived { amount_msat, .. }) = rx_k.try_recv() {
                emitter.emit(
                    role,
                    "AD_PAYMENT_CONFIRMED_BUYER",
                    serde_json::json!({
                        "amount_msat": amount_msat,
                        "message": "Buyer payment fully settled",
                    }),
                );
                k_confirmed = true;
            }
        }
        if !k_ad_confirmed {
            if let Ok(Event::PaymentReceived { amount_msat, .. }) = rx_k_ad.try_recv() {
                emitter.emit(
                    role,
                    "AD_PAYMENT_CONFIRMED_ADVERTISER",
                    serde_json::json!({
                        "amount_msat": amount_msat,
                        "message": "Advertiser payment fully settled",
                    }),
                );
                k_ad_confirmed = true;
            }
        }
        if !k_confirmed || !k_ad_confirmed {
            thread::sleep(Duration::from_millis(100));
        }
    }

    emitter.emit(
        role,
        "AD_SALE_COMPLETE",
        serde_json::json!({
            "message": "Ad-subsidized sale complete — both payments settled trustlessly",
        }),
    );

    router.unregister(&hash_k);
    router.unregister(&hash_k_ad);
}

// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buy command (two-phase: seeder + creator)
// ---------------------------------------------------------------------------

fn handle_buy_two_phase(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    req: &BuyRequest,
) {
    let role = "buyer";
    let content_invoice = req.content_invoice.as_deref().unwrap();
    let transport_invoice = req.transport_invoice.as_deref().unwrap();
    let enc_hash_hex = req.encrypted_hash.as_deref().unwrap_or("");

    // -----------------------------------------------------------------------
    // PHASE 1: Pay creator for content key K
    //
    // This is the critical payment. Once we have K, we can decrypt content
    // from ANY seeder. If a seeder fails, we try another — K is ours forever.
    // -----------------------------------------------------------------------

    // 1. Countdown
    for i in (1..=3).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying creator in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    // 2. Pay content invoice -> get K
    //
    // Parse invoice first to get payment_hash (needed for DuplicatePayment lookup).
    let content_payment_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = content_invoice.parse().expect("Invalid content invoice");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };

    emitter.emit(
        role,
        "CONTENT_PAYING",
        serde_json::json!({
            "bolt11": content_invoice,
            "message": "Paying creator for content key K...",
        }),
    );

    // Try to pay; if DuplicatePayment, look up K from previous successful payment
    let key: [u8; 32];
    match invoice::pay_invoice(node, content_invoice) {
        Ok(hash_bytes_k) => {
            let target_hash_k = PaymentHash(hash_bytes_k);
            emitter.emit(
                role,
                "CONTENT_PAYMENT_SENT",
                serde_json::json!({
                    "payment_hash": hex::encode(hash_bytes_k),
                }),
            );

            // Wait for K from new payment via event router
            let rx = router.register(target_hash_k);
            loop {
                let event = rx.recv().expect("Event router dropped");
                match event {
                    Event::PaymentSuccessful {
                        payment_hash,
                        payment_preimage: Some(preimage),
                        fee_paid_msat,
                        ..
                    } => {
                        key = preimage.0;
                        emitter.emit( role, "CONTENT_PAID", serde_json::json!({
                            "payment_hash": hex::encode(payment_hash.0),
                            "preimage_k": hex::encode(key),
                            "fee_msat": fee_paid_msat,
                            "message": "Content key K received! Can now decrypt from any seeder.",
                        }));
                        break;
                    }
                    Event::PaymentFailed { reason, .. } => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "payment_hash": hex::encode(target_hash_k.0),
                                "reason": format!("{:?}", reason),
                                "message": "Content payment failed. No money lost to seeders.",
                            }),
                        );
                        router.unregister(&target_hash_k);
                        return;
                    }
                    _ => {}
                }
            }
            router.unregister(&target_hash_k);
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("DuplicatePayment") {
                // Already paid for this content key K — look it up from payment history
                emitter.emit( role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));

                // Find the preimage from previous successful outbound payment with matching hash
                let target = PaymentHash(content_payment_hash);
                let mut found_key: Option<[u8; 32]> = None;
                for p in node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                }) {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(pre),
                        ..
                    } = &p.kind
                    {
                        if *hash == target {
                            found_key = Some(pre.0);
                            break;
                        }
                    }
                }

                match found_key {
                    Some(k) => {
                        key = k;
                        emitter.emit( role, "CONTENT_PAID", serde_json::json!({
                            "preimage_k": hex::encode(key),
                            "message": "Content key K recovered from payment history. Skipping to seeder phase.",
                        }));
                    }
                    None => {
                        emitter.emit( role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "message": "DuplicatePayment but could not find preimage in history. Cannot proceed.",
                        }));
                        return;
                    }
                }
            } else {
                emitter.emit(
                    role,
                    "CONTENT_PAYMENT_FAILED",
                    serde_json::json!({
                        "error": err_str,
                        "message": "Content payment failed.",
                    }),
                );
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 2: Fetch from seeder, pay transport, unwrap, decrypt
    //
    // We already have K. If this seeder fails, we could retry with another.
    // The transport payment is low-risk: small amount, and we already own K.
    // -----------------------------------------------------------------------

    // 3. Fetch wrapped file W from seeder
    let wrapped_path = if let Some(ref url) = req.wrapped_url {
        match curl_fetch(url, emitter) {
            Some(path) => path,
            None => return,
        }
    } else {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "No wrapped_url provided for two-phase buy",
            }),
        );
        return;
    };
    let wrapped = std::fs::read(&wrapped_path).expect("Failed to read wrapped file");

    // 4. Pay transport invoice -> get K_S
    emitter.emit(
        role,
        "TRANSPORT_PAYING",
        serde_json::json!({
            "bolt11": transport_invoice,
            "message": "Paying seeder for transport key K_S...",
        }),
    );
    let hash_bytes_ks =
        invoice::pay_invoice(node, transport_invoice).expect("Failed to pay transport invoice");
    let target_hash_ks = PaymentHash(hash_bytes_ks);
    emitter.emit(
        role,
        "TRANSPORT_PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes_ks),
        }),
    );

    // Wait for K_S via event router
    let ks: [u8; 32];
    let rx_ks = router.register(target_hash_ks);
    loop {
        let event = rx_ks.recv().expect("Event router dropped");
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                ks = preimage.0;
                emitter.emit(
                    role,
                    "TRANSPORT_PAID",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage_ks": hex::encode(ks),
                        "fee_msat": fee_paid_msat,
                        "message": "Transport key K_S received!",
                    }),
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit( role, "TRANSPORT_PAYMENT_FAILED", serde_json::json!({
                    "payment_hash": hex::encode(target_hash_ks.0),
                    "reason": format!("{:?}", reason),
                    "message": "Transport payment failed. You still have K — try another seeder.",
                }));
                router.unregister(&target_hash_ks);
                return;
            }
            _ => {}
        }
    }
    router.unregister(&target_hash_ks);

    // 5. Unwrap: E = Dec(W, K_S)
    let encrypted = encrypt::decrypt(&wrapped, &ks, 0);
    emitter.emit(
        role,
        "CONTENT_UNWRAPPED",
        serde_json::json!({
            "wrapped_bytes": wrapped.len(),
            "encrypted_bytes": encrypted.len(),
            "key_ks": hex::encode(ks),
            "message": "Transport layer stripped with K_S",
        }),
    );

    // 6. Verify H(E)
    if !enc_hash_hex.is_empty() {
        let enc_hash = verify::sha256_hash(&encrypted);
        let expected_bytes = hex::decode(enc_hash_hex).unwrap_or_default();
        let matches = enc_hash[..] == expected_bytes[..];
        emitter.emit(
            role,
            "ENCRYPTED_HASH_VERIFIED",
            serde_json::json!({
                "matches": matches,
                "expected": enc_hash_hex,
                "actual": hex::encode(enc_hash),
            }),
        );
        if !matches {
            emitter.emit(
                role,
                "ENCRYPTED_HASH_MISMATCH",
                serde_json::json!({
                    "expected": enc_hash_hex,
                    "actual": hex::encode(enc_hash),
                    "message": "Encrypted content hash mismatch after unwrap!",
                }),
            );
            return;
        }
    }

    // 7. Decrypt per-chunk: F_i = Dec(E_i, K, i) for each chunk, then reassemble
    //    The .enc file is E_0 || E_1 || ... || E_N where E_i = Enc(F_i, K, i)
    let cs = chunk::select_chunk_size(encrypted.len());
    let (enc_chunks, _meta) = chunk::split(&encrypted, cs);
    let plaintext: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &key, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": plaintext.len(),
            "key": hex::encode(key),
            "chunks": enc_chunks.len(),
        }),
    );

    // 8. Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).expect("Invalid hex hash");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);
    let matches = verify::verify_hash(&plaintext, &expected_hash);
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": &req.hash,
            "actual": hex::encode(verify::sha256_hash(&plaintext)),
        }),
    );
    if !matches {
        emitter.emit(
            role,
            "HASH_MISMATCH",
            serde_json::json!({
                "expected": &req.hash,
                "actual": hex::encode(verify::sha256_hash(&plaintext)),
                "message": "Content hash mismatch!",
            }),
        );
        return;
    }

    // 9. Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": &req.output,
            "bytes": plaintext.len(),
            "message": "Two-phase atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE (two-phase) ===");
    println!("Decrypted file: {} ({} bytes)", req.output, plaintext.len());
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// A5: Chunk planner — rarest-first selection (BitTorrent-style)
// ---------------------------------------------------------------------------

/// Rarest-first chunk assignment.
///
/// Computes chunk rarity (how many seeders hold each chunk), then assigns
/// chunks to seeders starting with the rarest.  Within the same rarity tier
/// the chunk with the lowest index wins (deterministic).  Each chunk is given
/// to the seeder that currently has the fewest assignments (load-balanced).
///
/// Returns `(download_order, assignments)` where:
///   - `download_order`: chunk indices sorted by rarity ascending
///   - `assignments[chunk_idx]`: `Some(seeder_index)` or `None` if no seeder
///     has that chunk
fn plan_chunk_assignments(
    chunk_count: usize,
    seeder_bitfields: &[Vec<bool>],
) -> (Vec<usize>, Vec<Option<usize>>) {
    let num_seeders = seeder_bitfields.len();

    // 1. Compute rarity per chunk (how many seeders hold it)
    let rarity: Vec<usize> = (0..chunk_count)
        .map(|ci| {
            (0..num_seeders)
                .filter(|&si| seeder_bitfields[si].get(ci).copied().unwrap_or(false))
                .count()
        })
        .collect();

    // 2. Sort chunk indices by rarity ascending (rarest first),
    //    tie-break by chunk index ascending (deterministic)
    let mut order: Vec<usize> = (0..chunk_count).collect();
    order.sort_by_key(|&ci| (rarity[ci], ci));

    // 3. Assign in rarity order: pick the seeder with the fewest assignments
    let mut assignments: Vec<Option<usize>> = vec![None; chunk_count];
    let mut seeder_load: Vec<usize> = vec![0; num_seeders];

    for &ci in &order {
        let available: Vec<usize> = (0..num_seeders)
            .filter(|&si| seeder_bitfields[si].get(ci).copied().unwrap_or(false))
            .collect();
        if let Some(&best) = available.iter().min_by_key(|&&si| seeder_load[si]) {
            assignments[ci] = Some(best);
            seeder_load[best] += 1;
        }
        // else: None — caller must handle missing chunks
    }

    (order, assignments)
}

// ---------------------------------------------------------------------------
// A5: Chunked buy — fetch chunks from multiple seeders, verify, reassemble
// ---------------------------------------------------------------------------

fn handle_buy_chunked(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    req: &BuyRequest,
) {
    let role = "buyer";
    let content_invoice = match req.content_invoice.as_deref() {
        Some(inv) => inv,
        None => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": "Chunked buy requires content_invoice",
                }),
            );
            return;
        }
    };
    let enc_hash_hex = match req.encrypted_hash.as_deref() {
        Some(h) => h.to_string(),
        None => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": "Chunked buy requires encrypted_hash",
                }),
            );
            return;
        }
    };
    if req.seeder_urls.is_empty() {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "Chunked buy requires at least one seeder_url",
            }),
        );
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 1: Pay creator for content key K (same as two-phase)
    // -----------------------------------------------------------------------

    for i in (1..=3).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying creator in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    let content_payment_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = content_invoice.parse().expect("Invalid content invoice");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };

    emitter.emit(
        role,
        "CONTENT_PAYING",
        serde_json::json!({
            "bolt11": content_invoice,
            "message": "Paying creator for content key K...",
        }),
    );

    let key: [u8; 32];
    match invoice::pay_invoice(node, content_invoice) {
        Ok(hash_bytes_k) => {
            let target_hash_k = PaymentHash(hash_bytes_k);
            emitter.emit(
                role,
                "CONTENT_PAYMENT_SENT",
                serde_json::json!({
                    "payment_hash": hex::encode(hash_bytes_k),
                }),
            );
            let rx = router.register(target_hash_k);
            loop {
                let event = rx.recv().expect("Event router dropped");
                match event {
                    Event::PaymentSuccessful {
                        payment_preimage: Some(preimage),
                        fee_paid_msat,
                        ..
                    } => {
                        key = preimage.0;
                        emitter.emit(
                            role,
                            "CONTENT_PAID",
                            serde_json::json!({
                                "preimage_k": hex::encode(key),
                                "fee_msat": fee_paid_msat,
                                "message": "Content key K received!",
                            }),
                        );
                        break;
                    }
                    Event::PaymentFailed { reason, .. } => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "reason": format!("{:?}", reason),
                                "message": "Content payment failed.",
                            }),
                        );
                        router.unregister(&target_hash_k);
                        return;
                    }
                    _ => {}
                }
            }
            router.unregister(&target_hash_k);
        }
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("DuplicatePayment") {
                emitter.emit( role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));
                let target = PaymentHash(content_payment_hash);
                let payments = node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                });
                let found = payments.iter().find(|p| {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(_),
                        ..
                    } = &p.kind
                    {
                        *hash == target
                    } else {
                        false
                    }
                });
                match found {
                    Some(p) => {
                        if let PaymentKind::Bolt11 {
                            preimage: Some(pre),
                            ..
                        } = &p.kind
                        {
                            key = pre.0;
                            emitter.emit(
                                role,
                                "CONTENT_PAID",
                                serde_json::json!({
                                    "preimage_k": hex::encode(key),
                                    "message": "Recovered K from payment history.",
                                }),
                            );
                        } else {
                            emitter.emit(
                                role,
                                "CONTENT_PAYMENT_FAILED",
                                serde_json::json!({
                                    "message": "Found payment but no preimage.",
                                }),
                            );
                            return;
                        }
                    }
                    None => {
                        emitter.emit(
                            role,
                            "CONTENT_PAYMENT_FAILED",
                            serde_json::json!({
                                "message": "DuplicatePayment but preimage not found in history.",
                            }),
                        );
                        return;
                    }
                }
            } else {
                emitter.emit(
                    role,
                    "CONTENT_PAYMENT_FAILED",
                    serde_json::json!({
                        "error": err_str,
                        "message": "Content payment failed.",
                    }),
                );
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 2: Fetch chunk metadata from first seeder
    // -----------------------------------------------------------------------

    let client = reqwest::blocking::Client::new();
    let meta_url = format!("{}/api/chunks/{}/meta", &req.seeder_urls[0], &enc_hash_hex);
    let meta: serde_json::Value = match client.get(&meta_url).send().and_then(|r| r.json()) {
        Ok(m) => m,
        Err(e) => {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("Failed to fetch chunk metadata: {}", e),
                }),
            );
            return;
        }
    };

    let chunk_count = meta["chunk_count"].as_u64().unwrap_or(0) as usize;
    let chunk_size = meta["chunk_size"].as_u64().unwrap_or(0) as usize;
    let encrypted_root = meta["encrypted_root"].as_str().unwrap_or("").to_string();

    emitter.emit(
        role,
        "CHUNK_META_RECEIVED",
        serde_json::json!({
            "chunk_count": chunk_count,
            "chunk_size": chunk_size,
            "encrypted_root": &encrypted_root,
            "seeders": req.seeder_urls.len(),
        }),
    );

    if chunk_count == 0 {
        emitter.emit(
            role,
            "BUY_ERROR",
            serde_json::json!({
                "message": "chunk_count is 0 — content has no chunks",
            }),
        );
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 3: Fetch bitfields from all seeders, build assignment plan
    // -----------------------------------------------------------------------

    // Collect bitfields: seeder_index -> Vec<bool>
    let mut seeder_bitfields: Vec<Vec<bool>> = Vec::new();
    for url in req.seeder_urls.iter() {
        let bf_url = format!("{}/api/chunks/{}/bitfield", url, &enc_hash_hex);
        match client
            .get(&bf_url)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(bf) => {
                let bits: Vec<bool> = bf["bitfield"]
                    .as_array()
                    .map(|arr| arr.iter().map(|v| v.as_bool().unwrap_or(false)).collect())
                    .unwrap_or_default();
                emitter.emit(
                    role,
                    "BITFIELD_RECEIVED",
                    serde_json::json!({
                        "seeder": url,
                        "chunks_available": bits.iter().filter(|&&b| b).count(),
                        "total": chunk_count,
                    }),
                );
                seeder_bitfields.push(bits);
            }
            Err(e) => {
                emitter.emit(
                    role,
                    "BITFIELD_FAILED",
                    serde_json::json!({
                        "seeder": url,
                        "error": format!("{}", e),
                    }),
                );
                seeder_bitfields.push(vec![false; chunk_count]);
            }
        }
    }

    // Rarest-first chunk assignment (BitTorrent-style)
    let (download_order, assignments) = plan_chunk_assignments(chunk_count, &seeder_bitfields);

    // Check for unassignable chunks (no seeder has them)
    for &ci in &download_order {
        if assignments[ci].is_none() {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("No seeder has chunk {}!", ci),
                    "chunk_index": ci,
                }),
            );
            return;
        }
    }

    // Build rarity histogram for diagnostics
    let rarity: Vec<usize> = (0..chunk_count)
        .map(|ci| {
            seeder_bitfields
                .iter()
                .filter(|bf| bf.get(ci).copied().unwrap_or(false))
                .count()
        })
        .collect();
    let mut rarity_histogram: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    for &r in &rarity {
        *rarity_histogram.entry(r).or_insert(0) += 1;
    }

    emitter.emit(
        role,
        "CHUNK_PLAN",
        serde_json::json!({
            "assignments": assignments.iter().map(|a| a.unwrap_or(0)).collect::<Vec<_>>(),
            "download_order": download_order,
            "rarity_histogram": rarity_histogram,
            "message": format!(
                "Rarest-first plan: {} chunks across {} seeders (rarity dist: {})",
                chunk_count,
                req.seeder_urls.len(),
                rarity_histogram.iter()
                    .map(|(r, n)| format!("{}x held-by-{}", n, r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }),
    );

    // -----------------------------------------------------------------------
    // PHASE 4: Request transport invoices from each seeder (batched per seeder)
    // -----------------------------------------------------------------------

    // Group chunks by seeder, ordered by rarity (rarest first within each batch).
    // Build a position map from download_order so we can sort each seeder's
    // chunks in the same rarest-first order.
    let mut rarity_pos: Vec<usize> = vec![0; chunk_count];
    for (pos, &ci) in download_order.iter().enumerate() {
        rarity_pos[ci] = pos;
    }
    let mut seeder_chunks: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for (ci, assignment) in assignments.iter().enumerate() {
        if let Some(si) = assignment {
            seeder_chunks.entry(*si).or_default().push(ci);
        }
    }
    // Sort each seeder's chunk list by rarity position (rarest first)
    for chunks in seeder_chunks.values_mut() {
        chunks.sort_by_key(|&ci| rarity_pos[ci]);
    }

    // For each seeder, request a transport invoice for its chunks
    struct SeederTransport {
        seeder_index: usize,
        chunks: Vec<usize>,
        bolt11: String,
        ks: Option<[u8; 32]>,
    }

    let mut transports: Vec<SeederTransport> = Vec::new();

    for (&si, chunks) in &seeder_chunks {
        let url = format!(
            "{}/api/transport-invoice/{}",
            &req.seeder_urls[si], &enc_hash_hex
        );
        let body = serde_json::json!({ "chunks": chunks });
        match client
            .post(&url)
            .json(&body)
            .send()
            .and_then(|r| r.json::<serde_json::Value>())
        {
            Ok(resp) => {
                let bolt11 = resp["bolt11"].as_str().unwrap_or("").to_string();
                emitter.emit(
                    role,
                    "TRANSPORT_INVOICE_RECEIVED",
                    serde_json::json!({
                        "seeder": &req.seeder_urls[si],
                        "bolt11": &bolt11,
                        "chunks": chunks,
                        "transport_price": resp["transport_price"],
                    }),
                );
                transports.push(SeederTransport {
                    seeder_index: si,
                    chunks: chunks.clone(),
                    bolt11,
                    ks: None,
                });
            }
            Err(e) => {
                emitter.emit( role, "BUY_ERROR", serde_json::json!({
                    "message": format!("Failed to get transport invoice from seeder {}: {}", si, e),
                }));
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 5: Pay transport invoices, collect K_S per seeder
    // -----------------------------------------------------------------------

    for transport in &mut transports {
        emitter.emit(
            role,
            "TRANSPORT_PAYING",
            serde_json::json!({
                "seeder": &req.seeder_urls[transport.seeder_index],
                "bolt11": &transport.bolt11,
                "chunks": &transport.chunks,
            }),
        );

        match invoice::pay_invoice(node, &transport.bolt11) {
            Ok(hash_bytes_ks) => {
                let target_hash_ks = PaymentHash(hash_bytes_ks);
                let rx_ks = router.register(target_hash_ks);
                loop {
                    let event = rx_ks.recv().expect("Event router dropped");
                    match event {
                        Event::PaymentSuccessful {
                            payment_preimage: Some(preimage),
                            fee_paid_msat,
                            ..
                        } => {
                            transport.ks = Some(preimage.0);
                            emitter.emit(
                                role,
                                "TRANSPORT_PAID",
                                serde_json::json!({
                                    "seeder": &req.seeder_urls[transport.seeder_index],
                                    "preimage_ks": hex::encode(preimage.0),
                                    "fee_msat": fee_paid_msat,
                                    "chunks": &transport.chunks,
                                }),
                            );
                            break;
                        }
                        Event::PaymentFailed { reason, .. } => {
                            emitter.emit(
                                role,
                                "TRANSPORT_PAYMENT_FAILED",
                                serde_json::json!({
                                    "seeder": &req.seeder_urls[transport.seeder_index],
                                    "reason": format!("{:?}", reason),
                                    "message": "Transport payment failed for this seeder.",
                                }),
                            );
                            router.unregister(&target_hash_ks);
                            return;
                        }
                        _ => {}
                    }
                }
                router.unregister(&target_hash_ks);
            }
            Err(e) => {
                emitter.emit(
                    role,
                    "TRANSPORT_PAYMENT_FAILED",
                    serde_json::json!({
                        "seeder": &req.seeder_urls[transport.seeder_index],
                        "error": format!("{:?}", e),
                    }),
                );
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 6: Download wrapped chunks, unwrap with K_S, verify Merkle proofs
    // -----------------------------------------------------------------------

    let mut enc_chunks: Vec<Option<Vec<u8>>> = vec![None; chunk_count];

    for transport in &transports {
        let ks = match transport.ks {
            Some(k) => k,
            None => continue,
        };

        for &ci in &transport.chunks {
            // Fetch wrapped chunk W_i
            let wc_url = format!(
                "{}/api/wrapped-chunks/{}/{}",
                &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci
            );
            let wrapped_chunk = match client.get(&wc_url).send().and_then(|r| r.bytes()) {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    emitter.emit(
                        role,
                        "CHUNK_DOWNLOAD_FAILED",
                        serde_json::json!({
                            "chunk_index": ci,
                            "seeder": &req.seeder_urls[transport.seeder_index],
                            "error": format!("{}", e),
                        }),
                    );
                    return;
                }
            };

            // Unwrap: E_i = Dec(W_i, K_S, chunk_index=i)
            let enc_chunk = encrypt::decrypt(&wrapped_chunk, &ks, ci as u64);

            // Fetch Merkle proof and verify
            let proof_url = format!(
                "{}/api/chunks/{}/proof/{}",
                &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci
            );
            match client
                .get(&proof_url)
                .send()
                .and_then(|r| r.json::<serde_json::Value>())
            {
                Ok(proof_json) => {
                    // Verify chunk against encrypted Merkle root
                    let proof_data = &proof_json["proof"];
                    if let Ok(proof_json_obj) = serde_json::from_value::<
                        conduit_core::merkle::MerkleProofJson,
                    >(proof_data.clone())
                    {
                        if let Ok(proof) =
                            conduit_core::merkle::MerkleProof::from_json(&proof_json_obj)
                        {
                            let root_bytes = hex::decode(&encrypted_root).unwrap_or_default();
                            let mut root = [0u8; 32];
                            if root_bytes.len() == 32 {
                                root.copy_from_slice(&root_bytes);
                            }
                            if proof.verify(&enc_chunk, ci, &root) {
                                emitter.emit(
                                    role,
                                    "CHUNK_VERIFIED",
                                    serde_json::json!({
                                        "chunk_index": ci,
                                        "message": format!("Chunk {} Merkle proof verified", ci),
                                    }),
                                );
                            } else {
                                emitter.emit( role, "CHUNK_VERIFICATION_FAILED", serde_json::json!({
                                    "chunk_index": ci,
                                    "message": format!("Chunk {} Merkle proof FAILED — seeder sent bad data!", ci),
                                }));
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    emitter.emit(
                        role,
                        "CHUNK_PROOF_FETCH_FAILED",
                        serde_json::json!({
                            "chunk_index": ci,
                            "error": format!("{}", e),
                            "message": "Proof fetch failed — continuing without verification",
                        }),
                    );
                }
            }

            enc_chunks[ci] = Some(enc_chunk);
            emitter.emit( role, "CHUNK_DOWNLOADED", serde_json::json!({
                "chunk_index": ci,
                "total": chunk_count,
                "progress": format!("{}/{}", enc_chunks.iter().filter(|c| c.is_some()).count(), chunk_count),
            }));
        }
    }

    // -----------------------------------------------------------------------
    // PHASE 7: Reassemble encrypted file, decrypt per-chunk, verify
    // -----------------------------------------------------------------------

    // Check all chunks received
    for (ci, chunk) in enc_chunks.iter().enumerate() {
        if chunk.is_none() {
            emitter.emit(
                role,
                "BUY_ERROR",
                serde_json::json!({
                    "message": format!("Missing encrypted chunk {}", ci),
                }),
            );
            return;
        }
    }

    // Decrypt each chunk: F_i = Dec(E_i, K, i)
    let mut plaintext_chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);
    for (ci, enc_chunk_opt) in enc_chunks.iter().enumerate() {
        let enc_chunk = enc_chunk_opt.as_ref().unwrap();
        let pt_chunk = encrypt::decrypt(enc_chunk, &key, ci as u64);
        plaintext_chunks.push(pt_chunk);
    }

    emitter.emit(
        role,
        "CHUNKS_DECRYPTED",
        serde_json::json!({
            "chunk_count": chunk_count,
            "message": format!("All {} chunks decrypted with K", chunk_count),
        }),
    );

    // Reassemble plaintext
    let original_size = meta["size_bytes"].as_u64().unwrap_or(0) as usize;
    let mut plaintext: Vec<u8> = Vec::new();
    for pt_chunk in &plaintext_chunks {
        plaintext.extend_from_slice(pt_chunk);
    }
    // Truncate to original size (last chunk may have padding)
    if original_size > 0 && plaintext.len() > original_size {
        plaintext.truncate(original_size);
    }

    emitter.emit(
        role,
        "CONTENT_REASSEMBLED",
        serde_json::json!({
            "bytes": plaintext.len(),
            "chunks": chunk_count,
        }),
    );

    // Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).unwrap_or_default();
    let actual_hash = verify::sha256_hash(&plaintext);
    let matches = expected_hash_bytes.len() == 32 && actual_hash[..] == expected_hash_bytes[..];
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": &req.hash,
            "actual": hex::encode(actual_hash),
        }),
    );
    if !matches {
        emitter.emit(
            role,
            "HASH_MISMATCH",
            serde_json::json!({
                "expected": &req.hash,
                "actual": hex::encode(actual_hash),
                "message": "Content hash mismatch after reassembly!",
            }),
        );
        return;
    }

    // Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": &req.output,
            "bytes": plaintext.len(),
            "chunks": chunk_count,
            "seeders": req.seeder_urls.len(),
            "message": "Chunked multi-source content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE (chunked) ===");
    println!(
        "Decrypted file: {} ({} bytes, {} chunks from {} seeders)",
        req.output,
        plaintext.len(),
        chunk_count,
        req.seeder_urls.len()
    );
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

fn handle_buy(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    bolt11_str: &str,
    enc_file_path: &str,
    expected_hash_hex: &str,
    output_path: &str,
) {
    let role = "buyer";

    // 1. Read encrypted file
    let ciphertext = std::fs::read(enc_file_path).expect("Failed to read encrypted file");
    println!(
        "Read {} encrypted bytes from {}",
        ciphertext.len(),
        enc_file_path
    );

    // 2. Decode expected hash
    let expected_hash_bytes = hex::decode(expected_hash_hex).expect("Invalid hex hash");
    assert_eq!(expected_hash_bytes.len(), 32, "Hash must be 32 bytes");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);

    // 3. Countdown — give the browser SSE time to connect
    for i in (1..=5).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    // 4. Pay invoice
    //
    // Register event listener BEFORE sending to avoid race: direct-channel
    // payments can settle in <1s.
    let pre_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = bolt11_str.parse().expect("Invalid bolt11");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };
    let target_hash = PaymentHash(pre_hash);
    let rx = router.register(target_hash);

    emitter.emit(
        role,
        "PAYING_INVOICE",
        serde_json::json!({
            "bolt11": bolt11_str,
        }),
    );
    let hash_bytes = invoice::pay_invoice(node, bolt11_str).expect("Failed to pay invoice");
    emitter.emit(
        role,
        "PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes),
            "message": "HTLC in flight, routing to creator...",
        }),
    );

    // Wait for preimage via event router (rx was registered before send)
    let preimage_bytes: [u8; 32];
    loop {
        let event = rx.recv().expect("Event router dropped");
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                preimage_bytes = preimage.0;
                emitter.emit(
                    role,
                    "PAYMENT_CONFIRMED",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage": hex::encode(preimage_bytes),
                        "fee_msat": fee_paid_msat,
                        "message": "Preimage received! This is the decryption key.",
                    }),
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit(
                    role,
                    "PAYMENT_FAILED",
                    serde_json::json!({
                        "payment_hash": hex::encode(target_hash.0),
                        "reason": format!("{:?}", reason),
                    }),
                );
                router.unregister(&target_hash);
                panic!("Payment failed: {:?}", reason);
            }
            _ => {}
        }
    }
    router.unregister(&target_hash);

    // 5. Decrypt per-chunk: F_i = Dec(E_i, K, i)
    let cs = chunk::select_chunk_size(ciphertext.len());
    let (enc_chunks, _meta) = chunk::split(&ciphertext, cs);
    let decrypted: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &preimage_bytes, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": decrypted.len(),
            "key": hex::encode(preimage_bytes),
            "chunks": enc_chunks.len(),
        }),
    );

    // 6. Verify
    let matches = verify::verify_hash(&decrypted, &expected_hash);
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": expected_hash_hex,
            "actual": hex::encode(verify::sha256_hash(&decrypted)),
        }),
    );
    if !matches {
        emitter.emit( role, "HASH_MISMATCH", serde_json::json!({
            "expected": expected_hash_hex,
            "actual": hex::encode(verify::sha256_hash(&decrypted)),
            "message": "Content hash mismatch! File may be corrupted or the wrong .enc was used.",
        }));
        eprintln!(
            "ERROR: Content hash mismatch! Expected {} got {}",
            expected_hash_hex,
            hex::encode(verify::sha256_hash(&decrypted))
        );
        return;
    }

    // 7. Write output
    std::fs::write(output_path, &decrypted).expect("Failed to write decrypted file");
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": output_path,
            "bytes": decrypted.len(),
            "message": "Atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY COMPLETE ===");
    println!(
        "Decrypted file: {} ({} bytes)",
        output_path,
        decrypted.len()
    );
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// buy-pre command
// ---------------------------------------------------------------------------

/// Helper macro: emit BUY_ERROR and return early on failure.
macro_rules! pre_bail {
    ($emitter:expr, $msg:expr) => {{
        $emitter.emit(
            "buyer",
            "BUY_ERROR",
            serde_json::json!({ "message": $msg }),
        );
        eprintln!("PRE buy error: {}", $msg);
        return;
    }};
}

#[allow(clippy::too_many_arguments)]
fn handle_buy_pre(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    _storage_dir: &str,
    buyer_kp: &pre::BuyerKeyPair,
    creator_url: &str,
    content_hash: &str,
    seeder_url: Option<&str>,
    output_path: &str,
    p2p_node: Option<Arc<conduit_p2p::node::P2pNode>>,
    p2p_runtime_handle: Option<tokio::runtime::Handle>,
) {
    let role = "buyer";
    let buyer_pk_hex = hex::encode(pre::serialize_buyer_pk(&buyer_kp.pk));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    emitter.emit(
        role,
        "PRE_BUY_START",
        serde_json::json!({
            "creator_url": creator_url,
            "content_hash": content_hash,
            "buyer_pk_hex": &buyer_pk_hex,
        }),
    );
    println!("=== BUY-PRE ===");
    println!("Creator: {}", creator_url);
    println!("Content: {}", content_hash);

    // 1. Call creator's /api/pre-purchase/{content_hash} with buyer pk
    let purchase_url = format!(
        "{}/api/pre-purchase/{}",
        creator_url.trim_end_matches('/'),
        content_hash
    );
    let resp = match client
        .post(&purchase_url)
        .json(&serde_json::json!({ "buyer_pk_hex": buyer_pk_hex }))
        .send()
    {
        Ok(r) => r,
        Err(e) => pre_bail!(emitter, format!("Failed to contact creator: {}", e)),
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        pre_bail!(emitter, format!("Creator returned {} — {}", status, body));
    }

    let purchase_resp: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => pre_bail!(emitter, format!("Invalid JSON from creator: {}", e)),
    };

    let bolt11 = match purchase_resp["bolt11"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing bolt11"),
    };
    let rk_compressed_hex = match purchase_resp["rk_compressed_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing rk_compressed_hex"),
    };
    let pre_c1_hex = match purchase_resp["pre_c1_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(
            emitter,
            "Creator response missing pre_c1_hex (content may not be PRE-enabled)"
        ),
    };
    let pre_c2_hex = match purchase_resp["pre_c2_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing pre_c2_hex"),
    };
    let price_sats = purchase_resp["price_sats"].as_u64().unwrap_or(0);
    let enc_hash = purchase_resp["encrypted_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();

    emitter.emit(
        role,
        "PRE_PURCHASE_RECEIVED",
        serde_json::json!({
            "bolt11_len": bolt11.len(),
            "rk_len": rk_compressed_hex.len(),
            "price_sats": price_sats,
            "encrypted_hash": &enc_hash,
        }),
    );
    println!("Invoice received ({} sats)", price_sats);

    // 2. Countdown
    for i in (1..=3).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying PRE invoice in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    // 3. Pay the Lightning invoice (with retry + DuplicatePayment recovery)
    //
    // Register the event listener BEFORE sending payment to avoid a race
    // where PaymentSuccessful fires before we start listening (direct
    // channels settle in <1s).
    let pre_payment_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = bolt11.parse().expect("Invalid bolt11 in PRE flow");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };
    let target_hash = PaymentHash(pre_payment_hash);
    let rx = router.register(target_hash);

    emitter.emit(
        role,
        "PAYING_INVOICE",
        serde_json::json!({ "bolt11": &bolt11 }),
    );

    let hash_bytes = match invoice::pay_invoice_with_retry(node, &bolt11, 3, Duration::from_secs(3))
    {
        Ok(h) => h,
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("DuplicatePayment") {
                eprintln!("[buy-pre] DuplicatePayment — looking up preimage from history");
                emitter.emit(
                    role,
                    "PRE_ALREADY_PAID",
                    serde_json::json!({
                        "message": "DuplicatePayment — looking up preimage from history...",
                    }),
                );

                let target = PaymentHash(pre_payment_hash);
                let mut found_preimage: Option<[u8; 32]> = None;
                for p in node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                }) {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(pre),
                        ..
                    } = &p.kind
                    {
                        if *hash == target {
                            found_preimage = Some(pre.0);
                            break;
                        }
                    }
                }

                match found_preimage {
                    Some(_preimage) => {
                        emitter.emit(
                            role,
                            "PRE_PAYMENT_CONFIRMED",
                            serde_json::json!({
                                "payment_hash": hex::encode(pre_payment_hash),
                                "message": "PRE payment recovered from history.",
                            }),
                        );
                        pre_payment_hash
                    }
                    None => {
                        router.unregister(&target_hash);
                        pre_bail!(
                            emitter,
                            "DuplicatePayment but preimage not found in history. Try again (new invoice will have a unique hash)."
                        );
                    }
                }
            } else {
                router.unregister(&target_hash);
                let usable_channels: Vec<String> = node
                    .list_channels()
                    .iter()
                    .filter(|c| c.is_usable)
                    .map(|c| {
                        format!(
                            "{}… out={}",
                            &c.counterparty_node_id.to_string()[..16],
                            c.outbound_capacity_msat / 1000
                        )
                    })
                    .collect();
                eprintln!(
                    "[buy-pre] payment failed after retries: {} | usable channels: {:?}",
                    err_str, usable_channels
                );
                emitter.emit(
                    role,
                    "BUY_ERROR",
                    serde_json::json!({
                        "message": format!("Failed to pay invoice: {}", err_str),
                        "usable_channels": usable_channels,
                    }),
                );
                return;
            }
        }
    };

    emitter.emit(
        role,
        "PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes),
            "message": "HTLC in flight — PRE payment routing...",
        }),
    );

    // 4. Wait for payment confirmation (rx was registered before send)
    loop {
        let event = match rx.recv() {
            Ok(e) => e,
            Err(_) => {
                router.unregister(&target_hash);
                pre_bail!(emitter, "Event router dropped");
            }
        };
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                emitter.emit(
                    role,
                    "PRE_PAYMENT_CONFIRMED",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage": hex::encode(preimage.0),
                        "fee_msat": fee_paid_msat,
                        "message": "PRE payment confirmed.",
                    }),
                );
                println!(
                    "Payment confirmed (fee: {} msat)",
                    fee_paid_msat.unwrap_or(0)
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit(
                    role,
                    "PAYMENT_FAILED",
                    serde_json::json!({
                        "payment_hash": hex::encode(target_hash.0),
                        "reason": format!("{:?}", reason),
                    }),
                );
                router.unregister(&target_hash);
                return;
            }
            _ => {}
        }
    }
    router.unregister(&target_hash);

    // 5. Recover AES key m via PRE decryption
    let m = match pre::buyer_decrypt_from_hex(
        &buyer_kp.sk,
        &pre_c1_hex,
        &pre_c2_hex,
        &rk_compressed_hex,
    ) {
        Some(m) => m,
        None => pre_bail!(emitter, "PRE decryption failed — invalid ciphertext or key"),
    };

    emitter.emit(
        role,
        "PRE_KEY_RECOVERED",
        serde_json::json!({
            "m_hex": hex::encode(m),
            "message": "AES key m recovered via PRE.",
        }),
    );
    println!("AES key recovered via PRE");

    // 6. Download encrypted chunks from seeder (or creator)
    let chunk_source = seeder_url.unwrap_or(creator_url);

    // Try P2P download first if we have an iroh node and the source supports it
    let p2p_result = if let Some(ref p2p) = p2p_node {
        let p2p_info_url = format!("{}/api/p2p-info", chunk_source.trim_end_matches('/'));
        match client.get(&p2p_info_url).send() {
            Ok(r) => match r.json::<serde_json::Value>() {
                Ok(info) if info["enabled"].as_bool() == Some(true) => {
                    let remote_node_id = info["node_id"].as_str().unwrap_or("").to_string();
                    let direct_addrs: Vec<String> = info["direct_addrs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let relay_urls: Vec<String> = info["relay_urls"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    emitter.emit(
                        role,
                        "P2P_CONNECTING",
                        serde_json::json!({
                            "remote_node_id": &remote_node_id,
                            "direct_addrs": &direct_addrs,
                            "relay_urls": &relay_urls,
                            "message": format!("Connecting to seeder via P2P (iroh QUIC)... addrs={}", direct_addrs.join(", ")),
                        }),
                    );
                    eprintln!(
                        "P2P: connecting to seeder {} addrs={:?} relays={:?}",
                        &remote_node_id[..16.min(remote_node_id.len())],
                        &direct_addrs,
                        &relay_urls
                    );

                    // Build EndpointAddr with the public key, direct IP addrs, and relay URLs
                    // so iroh can connect directly instead of relying on slow DHT discovery.
                    let addr_parse_result: Result<conduit_p2p::iroh::EndpointAddr, String> =
                        (|| {
                            let pk = remote_node_id
                                .parse::<conduit_p2p::iroh::PublicKey>()
                                .map_err(|e| format!("PublicKey parse: {e}"))?;
                            let mut addr = conduit_p2p::iroh::EndpointAddr::from(pk);
                            for s in &direct_addrs {
                                if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                                    addr = addr.with_ip_addr(sa);
                                }
                            }
                            for u in &relay_urls {
                                if let Ok(ru) = u.parse::<conduit_p2p::iroh::RelayUrl>() {
                                    addr = addr.with_relay_url(ru);
                                }
                            }
                            Ok(addr)
                        })();

                    match addr_parse_result {
                        Ok(addr) => {
                            let ep = p2p.endpoint().clone();
                            let enc_hash_bytes = hex::decode(&enc_hash).ok().and_then(|b| {
                                if b.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&b);
                                    Some(arr)
                                } else {
                                    None
                                }
                            });

                            match enc_hash_bytes {
                                Some(hash_bytes) => {
                                    let ln_pk = node.node_id().to_string();
                                    let buyer_client =
                                        conduit_p2p::client::BuyerClient::new(ep, ln_pk);
                                    // Fetch catalog to know chunk count
                                    let catalog_url = format!(
                                        "{}/api/catalog",
                                        chunk_source.trim_end_matches('/')
                                    );
                                    let cat_resp = client
                                        .get(&catalog_url)
                                        .send()
                                        .ok()
                                        .and_then(|r| r.json::<serde_json::Value>().ok());
                                    let num_chunks = cat_resp
                                        .as_ref()
                                        .and_then(|cat| {
                                            let items = cat
                                                .as_array()
                                                .or_else(|| cat["items"].as_array())?;
                                            let entry = items.iter().find(|e| {
                                                e["content_hash"].as_str() == Some(content_hash)
                                                    || e["encrypted_hash"].as_str()
                                                        == Some(content_hash)
                                            })?;
                                            entry["chunk_count"]
                                                .as_u64()
                                                .or_else(|| entry["total_chunks"].as_u64())
                                        })
                                        .unwrap_or(1)
                                        as u32;

                                    let indices: Vec<u32> = (0..num_chunks).collect();
                                    struct LdkPaymentHandler {
                                        node: Arc<Node>,
                                        router: Arc<EventRouter>,
                                    }
                                    impl conduit_p2p::client::PaymentHandler for LdkPaymentHandler {
                                        fn pay_invoice(
                                            &self,
                                            bolt11: &str,
                                        ) -> anyhow::Result<[u8; 32]>
                                        {
                                            use ldk_node::lightning_invoice::Bolt11Invoice;
                                            eprintln!("[LdkPaymentHandler] pay_invoice called, bolt11 len={}", bolt11.len());

                                            let inv: Bolt11Invoice = bolt11.parse()
                                                .map_err(|e: ldk_node::lightning_invoice::ParseOrSemanticError| {
                                                    eprintln!("[LdkPaymentHandler] bad bolt11 parse: {e}");
                                                    anyhow::anyhow!("bad bolt11: {e}")
                                                })?;

                                            let payee = inv.recover_payee_pub_key();
                                            let amt = inv.amount_milli_satoshis().unwrap_or(0);
                                            let h: &[u8] = inv.payment_hash().as_ref();
                                            let mut hash = [0u8; 32];
                                            hash.copy_from_slice(h);
                                            let target = PaymentHash(hash);

                                            eprintln!(
                                                "[LdkPaymentHandler] invoice: payee={}, amt_msat={}, payment_hash={}",
                                                payee, amt, hex::encode(hash)
                                            );

                                            let channels = self.node.list_channels();
                                            let usable = channels.iter().filter(|c| c.is_usable).count();
                                            let to_payee = channels.iter().find(|c| {
                                                c.counterparty_node_id.to_string() == payee.to_string()
                                            });
                                            eprintln!(
                                                "[LdkPaymentHandler] channels: total={}, usable={}, direct_to_payee={}",
                                                channels.len(),
                                                usable,
                                                if let Some(ch) = &to_payee {
                                                    format!("yes (outbound={}msat, usable={})", ch.outbound_capacity_msat, ch.is_usable)
                                                } else {
                                                    "no".to_string()
                                                }
                                            );

                                            let rx = self.router.register(target);
                                            eprintln!("[LdkPaymentHandler] registered EventRouter listener for {}", hex::encode(hash));

                                            eprintln!("[LdkPaymentHandler] calling invoice::pay_invoice...");
                                            let pay_start = std::time::Instant::now();
                                            let pay_result = invoice::pay_invoice(&self.node, bolt11)
                                                .map_err(|e| {
                                                    eprintln!("[LdkPaymentHandler] pay_invoice FAILED after {}ms: {e}", pay_start.elapsed().as_millis());
                                                    self.router.unregister(&target);
                                                    anyhow::anyhow!("{e}")
                                                });
                                            let _payment_hash = pay_result?;
                                            eprintln!("[LdkPaymentHandler] pay_invoice sent in {}ms, waiting for event...", pay_start.elapsed().as_millis());

                                            let wait_start = std::time::Instant::now();
                                            loop {
                                                let event = rx.recv().map_err(|_| {
                                                    eprintln!("[LdkPaymentHandler] event router channel dropped after {}ms", wait_start.elapsed().as_millis());
                                                    anyhow::anyhow!("event router dropped")
                                                })?;
                                                match event {
                                                    Event::PaymentSuccessful {
                                                        payment_preimage: Some(pre),
                                                        ..
                                                    } => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] PaymentSuccessful with preimage in {}ms",
                                                            wait_start.elapsed().as_millis()
                                                        );
                                                        self.router.unregister(&target);
                                                        return Ok(pre.0);
                                                    }
                                                    Event::PaymentFailed { reason, .. } => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] PaymentFailed after {}ms: {:?}",
                                                            wait_start.elapsed().as_millis(), reason
                                                        );
                                                        self.router.unregister(&target);
                                                        return Err(anyhow::anyhow!(
                                                            "P2P chunk payment failed: {:?}",
                                                            reason
                                                        ));
                                                    }
                                                    other => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] ignoring event {:?} after {}ms",
                                                            std::mem::discriminant(&other),
                                                            wait_start.elapsed().as_millis()
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    let payment_handler: std::sync::Arc<
                                        dyn conduit_p2p::client::PaymentHandler,
                                    > = std::sync::Arc::new(LdkPaymentHandler {
                                        node: Arc::clone(node),
                                        router: Arc::clone(router),
                                    });

                                    let p2p_rt = p2p_runtime_handle.as_ref().expect(
                                        "P2P runtime handle must exist when p2p_node is Some",
                                    );
                                    let (download_tx, download_rx) =
                                        std::sync::mpsc::sync_channel::<
                                            anyhow::Result<conduit_p2p::client::DownloadResult>,
                                        >(1);
                                    let indices_owned = indices.clone();
                                    let num_indices = indices_owned.len();
                                    eprintln!("[P2P-BUY] spawning download: {} chunks, hash={}", num_indices, hex::encode(hash_bytes));
                                    let dl_start = std::time::Instant::now();
                                    p2p_rt.spawn(async move {
                                        eprintln!("[P2P-BUY] download task started on P2P runtime");
                                        let result = buyer_client
                                            .download(
                                                addr,
                                                hash_bytes,
                                                &indices_owned,
                                                payment_handler,
                                            )
                                            .await;
                                        match &result {
                                            Ok(r) => eprintln!("[P2P-BUY] download completed: {} chunks, {}msat", r.chunks.len(), r.total_paid_msat),
                                            Err(e) => eprintln!("[P2P-BUY] download failed: {e:#}"),
                                        }
                                        let _ = download_tx.send(result);
                                    });
                                    match download_rx.recv().unwrap_or_else(|_| {
                                        eprintln!("[P2P-BUY] download channel dropped after {}ms", dl_start.elapsed().as_millis());
                                        Err(anyhow::anyhow!("P2P download task dropped"))
                                    }) {
                                        Ok(result) => {
                                            emitter.emit(
                                                role,
                                                "P2P_DOWNLOAD_COMPLETE",
                                                serde_json::json!({
                                                    "chunks": result.chunks.len(),
                                                    "total_bytes": result.chunks.iter().map(|(_, d)| d.len()).sum::<usize>(),
                                                    "message": "Chunks downloaded via P2P!",
                                                }),
                                            );
                                            println!(
                                                "P2P: downloaded {} chunks",
                                                result.chunks.len()
                                            );
                                            let mut sorted = result.chunks;
                                            sorted.sort_by_key(|(idx, _)| *idx);
                                            let data: Vec<u8> =
                                                sorted.into_iter().flat_map(|(_, d)| d).collect();
                                            Some(data)
                                        }
                                        Err(e) => {
                                            emitter.emit(
                                                role,
                                                "P2P_DOWNLOAD_FAILED",
                                                serde_json::json!({
                                                    "error": format!("{}", e),
                                                    "message": "P2P download failed, falling back to HTTP.",
                                                }),
                                            );
                                            println!(
                                                "P2P: download failed ({}), falling back to HTTP",
                                                e
                                            );
                                            None
                                        }
                                    }
                                }
                                None => None,
                            }
                        }
                        Err(e) => {
                            eprintln!("P2P: address parse failed: {e}");
                            None
                        }
                    }
                }
                _ => None,
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let all_enc_data = if let Some(data) = p2p_result {
        data
    } else {
        // HTTP fallback
        let catalog_url = format!("{}/api/catalog", chunk_source.trim_end_matches('/'));
        let catalog_json: serde_json::Value = match client.get(&catalog_url).send() {
            Ok(r) => match r.json() {
                Ok(v) => v,
                Err(e) => pre_bail!(emitter, format!("Invalid catalog JSON: {}", e)),
            },
            Err(e) => pre_bail!(
                emitter,
                format!("Failed to fetch catalog from {}: {}", chunk_source, e)
            ),
        };

        let catalog_items: Vec<serde_json::Value> = if let Some(arr) = catalog_json.as_array() {
            arr.clone()
        } else if let Some(arr) = catalog_json["items"].as_array() {
            arr.clone()
        } else {
            pre_bail!(emitter, "Catalog response has no items array");
        };

        let entry = match catalog_items.iter().find(|e| {
            e["content_hash"].as_str() == Some(content_hash)
                || e["encrypted_hash"].as_str() == Some(content_hash)
        }) {
            Some(e) => e.clone(),
            None => pre_bail!(
                emitter,
                format!(
                    "Content {} not found in catalog at {}",
                    content_hash, chunk_source
                )
            ),
        };

        let num_chunks = entry["chunk_count"]
            .as_u64()
            .or_else(|| entry["total_chunks"].as_u64())
            .unwrap_or(1) as usize;
        let enc_hash_str = entry["encrypted_hash"]
            .as_str()
            .unwrap_or(content_hash)
            .to_string();

        emitter.emit(
            role,
            "DOWNLOADING_CHUNKS",
            serde_json::json!({
                "source": chunk_source,
                "chunks": num_chunks,
                "encrypted_hash": &enc_hash_str,
            }),
        );
        println!(
            "HTTP: downloading {} chunks from {}...",
            num_chunks, chunk_source
        );

        let mut data = Vec::new();
        for i in 0..num_chunks {
            let chunk_url = format!(
                "{}/api/chunks/{}/{}",
                chunk_source.trim_end_matches('/'),
                enc_hash_str,
                i
            );
            match client.get(&chunk_url).send() {
                Ok(r) => {
                    if !r.status().is_success() {
                        pre_bail!(
                            emitter,
                            format!("Chunk {}: HTTP {} from {}", i, r.status(), chunk_url)
                        );
                    }
                    match r.bytes() {
                        Ok(bytes) => data.extend_from_slice(&bytes),
                        Err(e) => pre_bail!(emitter, format!("Chunk {} read error: {}", i, e)),
                    }
                }
                Err(e) => pre_bail!(emitter, format!("Failed to download chunk {}: {}", i, e)),
            }
        }
        data
    };

    let num_chunks = {
        let cs = chunk::select_chunk_size(all_enc_data.len());
        let (chunks, _) = chunk::split(&all_enc_data, cs);
        chunks.len()
    };
    emitter.emit(
        role,
        "CHUNKS_DOWNLOADED",
        serde_json::json!({
            "total_bytes": all_enc_data.len(),
            "chunks": num_chunks,
        }),
    );
    println!(
        "Downloaded {} bytes ({} chunks)",
        all_enc_data.len(),
        num_chunks
    );

    // 7. Decrypt per-chunk with recovered AES key m
    let cs = chunk::select_chunk_size(all_enc_data.len());
    let (enc_chunks, _meta) = chunk::split(&all_enc_data, cs);
    let decrypted: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &m, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": decrypted.len(),
            "chunks": enc_chunks.len(),
            "message": "Decrypted using PRE-recovered AES key.",
        }),
    );

    // 8. Verify content hash
    let actual_hash = verify::sha256_hash(&decrypted);
    let matches = hex::encode(actual_hash) == content_hash;
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": content_hash,
            "actual": hex::encode(actual_hash),
        }),
    );
    if !matches {
        eprintln!(
            "WARNING: Content hash mismatch. Expected {} got {}",
            content_hash,
            hex::encode(actual_hash)
        );
    }

    // 9. Write output
    if let Err(e) = std::fs::write(output_path, &decrypted) {
        pre_bail!(emitter, format!("Failed to write file: {}", e));
    }
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": output_path,
            "bytes": decrypted.len(),
            "message": "PRE atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY-PRE COMPLETE ===");
    println!(
        "Decrypted file: {} ({} bytes)",
        output_path,
        decrypted.len()
    );
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "conduit-setup")]
#[command(about = "Conduit Lightning node with live console")]
struct Cli {
    /// Storage directory for LDK node data
    #[arg(long, default_value = "/var/lib/conduit-node")]
    storage_dir: String,

    /// Lightning listening port
    #[arg(long, default_value = "9735")]
    port: u16,

    /// Esplora server URL
    #[arg(long)]
    esplora: Option<String>,

    /// Bitcoind RPC host
    #[arg(long)]
    rpc_host: Option<String>,

    /// Bitcoind RPC port
    #[arg(long, default_value = "38332")]
    rpc_port: u16,

    /// Bitcoind RPC username
    #[arg(long, default_value = "lightning")]
    rpc_user: String,

    /// Bitcoind RPC password
    #[arg(long, default_value = "lightning")]
    rpc_password: String,

    /// HTTP port for the live console (off if not set)
    #[arg(long)]
    http_port: Option<u16>,

    /// Registry URL for content discovery (optional, e.g. http://localhost:3003)
    #[arg(long)]
    registry_url: Option<String>,

    /// Public IP/hostname for this node (used in registry announcements).
    /// If omitted, attempts to detect via external service.
    #[arg(long)]
    public_ip: Option<String>,

    /// Enable advertiser role. Value is an arbitrary label (e.g. "enabled").
    /// Advertisers host creative media on their own servers and register
    /// campaigns via the API with a creative_url.
    #[arg(long)]
    ads_dir: Option<String>,

    /// Human-readable node alias (max 32 bytes). Shown in network explorers
    /// and the dashboard network visualization.
    #[arg(long)]
    alias: Option<String>,

    /// Path to dashboard HTML file (unified UI). If set, GET / serves this
    /// file instead of the embedded console HTML.
    #[arg(long)]
    dashboard: Option<String>,

    /// Enable P2P chunk transport (iroh QUIC). When set, the node also
    /// listens for direct peer connections in addition to HTTP.
    #[arg(long)]
    p2p: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print on-chain wallet address
    Address,
    /// Print node ID, addresses, balances
    Info,
    /// Open a channel to a peer
    OpenChannel {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "100000")]
        amount: u64,
    },
    /// List open channels
    Channels,
    /// Register content in the catalog (generates K once, encrypts, persists)
    Register {
        /// Path to the file to register
        #[arg(long)]
        file: String,
        /// Price in satoshis
        #[arg(long)]
        price: u64,
    },
    /// Sell content: encrypt, create invoice, wait for payment (legacy — prefer register + serve)
    Sell {
        /// Path to the file to sell
        #[arg(long)]
        file: String,
        /// Price in satoshis
        #[arg(long)]
        price: u64,
    },
    /// Start node with HTTP API only (no sell/buy — use the browser)
    Serve,
    /// Seed content: wrap with transport key K_S, create transport invoice, wait for payment
    Seed {
        /// Path to the encrypted file (received from creator)
        #[arg(long)]
        encrypted_file: String,
        /// SHA-256 hash of the encrypted content H(E) (hex)
        #[arg(long)]
        encrypted_hash: String,
        /// Price for transport in satoshis
        #[arg(long)]
        transport_price: u64,
        /// Which chunks to seed (e.g. "0,1,2,5-9"). Omit to seed all.
        #[arg(long)]
        chunks: Option<String>,
    },
    /// Buy content: pay invoice, decrypt, verify
    Buy {
        /// BOLT11 invoice string
        #[arg(long)]
        invoice: String,
        /// Path to the encrypted file
        #[arg(long)]
        encrypted_file: String,
        /// Expected SHA-256 hash of the plaintext (hex)
        #[arg(long)]
        hash: String,
        /// Output path for decrypted file
        #[arg(long)]
        output: String,
    },
    /// Buy content using PRE: call creator API, pay Lightning invoice, decrypt with buyer PRE key
    BuyPre {
        /// Creator's HTTP endpoint (e.g. http://creator-host:9735)
        #[arg(long)]
        creator_url: String,
        /// Content hash (SHA-256 hex) from the catalog
        #[arg(long)]
        content_hash: String,
        /// Seeder HTTP endpoint to download chunks from (e.g. http://seeder:9735)
        #[arg(long)]
        seeder_url: Option<String>,
        /// Output path for decrypted file
        #[arg(long)]
        output: String,
    },
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Build chain source
    let chain_source = if let Some(ref host) = cli.rpc_host {
        ChainSource::BitcoindRpc {
            host: host.clone(),
            port: cli.rpc_port,
            user: cli.rpc_user.clone(),
            password: cli.rpc_password.clone(),
        }
    } else {
        let url = cli
            .esplora
            .unwrap_or_else(|| "https://mempool.space/signet/api".into());
        ChainSource::Esplora(url)
    };

    let node_alias_value = cli.alias.clone().unwrap_or_default();

    let config = LightningConfig {
        storage_dir: cli.storage_dir,
        listening_port: cli.port,
        chain_source,
        node_alias: cli.alias.clone(),
        ..LightningConfig::default()
    };

    // Start node
    let node = Arc::new(invoice::start_node(&config).expect("Failed to start node"));
    thread::sleep(Duration::from_secs(5));

    let id = invoice::node_id(&node);
    println!("Node {} on port {}", id, cli.port);

    // Create broadcast channel for console events
    let (events_tx, _) = broadcast::channel::<ConsoleEvent>(256);

    // Persistent event log (optional; fall back to broadcast-only if e.g. read-only fs)
    let event_log = match EventLog::new(&config.storage_dir) {
        Ok(log) => Some(Arc::new(log)),
        Err(e) => {
            eprintln!(
                "Warning: event log disabled ({}), events will not persist",
                e
            );
            None
        }
    };
    let emitter = Arc::new(ConsoleEmitter::new(events_tx, event_log));

    // Create event router and start background event loop
    let event_router = Arc::new(EventRouter::new(emitter.clone()));
    {
        let router = event_router.clone();
        let node_for_router = node.clone();
        thread::spawn(move || {
            router.run(&node_for_router);
        });
    }

    // Load content catalog
    let mut cat_vec = load_catalog(&config.storage_dir);
    println!(
        "Catalog: {} entries loaded from {}",
        cat_vec.len(),
        catalog_path(&config.storage_dir)
    );

    // Migrate legacy seeder entries that lack chunk metadata
    migrate_legacy_chunks(&config.storage_dir, &mut cat_vec);

    let catalog = Arc::new(std::sync::Mutex::new(cat_vec));

    // Build registry info if --registry-url is set
    // Resolve public IP for registry announcements
    let public_ip = cli.public_ip.clone().unwrap_or_else(|| {
        // Try to detect public IP via external service
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()
            .and_then(|c| c.get("https://api.ipify.org").send().ok())
            .and_then(|r| r.text().ok())
            .map(|ip| ip.trim().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string())
    });
    println!("Public IP: {}", public_ip);

    let registry_info = cli.registry_url.as_ref().map(|url| {
        let http_addr = cli
            .http_port
            .map(|p| format!("{}:{}", &public_ip, p))
            .unwrap_or_default();
        let ln_addr = format!("{}:{}", &public_ip, cli.port);
        RegistryInfo {
            url: url.trim_end_matches('/').to_string(),
            node_pubkey: id.clone(),
            http_address: http_addr,
            ln_address: ln_addr,
            node_alias: node_alias_value.clone(),
        }
    });

    // Re-announce seeder entries to registry (picks up migrated chunk metadata)
    if let Some(ref info) = registry_info {
        let cat = catalog.lock().unwrap();
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        for entry in cat.iter() {
            // Only re-announce seeder entries (those with non-empty encrypted_hash
            // and empty content_hash — i.e. this node is a seeder, not the creator)
            if entry.encrypted_hash.is_empty() || !entry.content_hash.is_empty() {
                continue;
            }
            if entry.chunk_count == 0 {
                continue; // still legacy, nothing useful to announce
            }
            let body = serde_json::json!({
                "encrypted_hash": &entry.encrypted_hash,
                "seeder_pubkey": &info.node_pubkey,
                "seeder_address": &info.http_address,
                "seeder_ln_address": &info.ln_address,
                "seeder_alias": &info.node_alias,
                "transport_price": entry.transport_price,
                "chunk_count": entry.chunk_count,
                "chunks_held": &entry.chunks_held,
                "announced_at": &entry.registered_at,
            });
            let url = format!("{}/api/seeders", info.url);
            match client.post(&url).json(&body).send() {
                Ok(resp) => println!(
                    "Registry re-announce {}: {} ({})",
                    entry.file_name,
                    entry.encrypted_hash,
                    resp.status()
                ),
                Err(e) => eprintln!("Warning: re-announce failed for {}: {}", entry.file_name, e),
            }
        }
    }

    // Resync stale seeder entries (creator may have re-published with new K)
    if let Some(ref info) = registry_info {
        resync_stale_seeds(&config.storage_dir, &catalog, info);
    }

    // Start HTTP server if requested
    if let Some(http_port) = cli.http_port {
        // Initialize advertiser role if --ads-dir is set.
        // Advertisers host their own creative media externally; --ads-dir
        // only enables the advertiser API (campaigns, sessions, payments).
        let (adv_db, adv_signing_key, adv_pubkey_hex, adv_ads_dir) = if cli.ads_dir.is_some() {
            let db_path = format!("{}/advertiser.db", config.storage_dir);
            let conn = Connection::open(&db_path).expect("Failed to open advertiser database");
            adv_init_db(&conn);
            println!("[advertiser] Database: {}", db_path);
            let signing_key = adv_load_or_create_signing_key(&config.storage_dir);
            let verifying_key = VerifyingKey::from(&signing_key);
            let pubkey_hex = hex::encode(verifying_key.to_bytes());
            println!("[advertiser] Ed25519 pubkey: {}", pubkey_hex);
            (
                Some(Arc::new(std::sync::Mutex::new(conn))),
                Some(Arc::new(signing_key)),
                Some(pubkey_hex),
                cli.ads_dir.clone(),
            )
        } else {
            (None, None, None, None)
        };

        // Derive buyer PRE keypair from storage directory seed
        let buyer_pre_kp = {
            let seed = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"conduit-pre-buyer-seed:");
                h.update(config.storage_dir.as_bytes());
                let hash = h.finalize();
                let mut s = [0u8; 32];
                s.copy_from_slice(&hash);
                s
            };
            pre::buyer_keygen_from_seed(&seed)
        };
        let pre_buyer_pk_hex = hex::encode(pre::serialize_buyer_pk(&buyer_pre_kp.pk));

        let mut state = AppState {
            node: node.clone(),
            node_alias: node_alias_value.clone(),
            emitter: emitter.clone(),
            event_router: event_router.clone(),
            catalog: catalog.clone(),
            storage_dir: config.storage_dir.clone(),
            registry_info: registry_info.clone(),
            pre_buyer_pk_hex,
            pre_buyer_sk: buyer_pre_kp.sk,
            trust_list: Arc::new(std::sync::Mutex::new(load_trust_list(&config.storage_dir))),
            advertiser_db: adv_db,
            advertiser_signing_key: adv_signing_key,
            advertiser_pubkey_hex: adv_pubkey_hex,
            ads_dir: adv_ads_dir,
            dashboard_path: cli.dashboard.clone(),
            p2p_node: None,
            p2p_runtime_handle: None,
        };

        // Spawn P2P node if --p2p flag is set
        if cli.p2p {
            let p2p_state_for_store = state.clone();
            let chunk_store = Arc::new(ConduitChunkStore::new(&p2p_state_for_store));
            let handler = Arc::new(conduit_p2p::handler::ChunkProtocol::new(chunk_store));

            let p2p_sk_seed = {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                h.update(b"conduit-p2p-identity:");
                h.update(config.storage_dir.as_bytes());
                let hash = h.finalize();
                let mut s = [0u8; 32];
                s.copy_from_slice(&hash);
                s
            };
            let p2p_sk = conduit_p2p::iroh::SecretKey::from_bytes(&p2p_sk_seed);

            let p2p_config = conduit_p2p::node::P2pConfig {
                secret_key: Some(p2p_sk),
                enable_dht: true,
            };

            let rt = tokio::runtime::Runtime::new().expect("P2P tokio runtime");
            let p2p_handle = rt.handle().clone();
            let p2p_node = rt.block_on(async {
                conduit_p2p::node::P2pNode::spawn(p2p_config, handler)
                    .await
                    .expect("Failed to start P2P node")
            });
            let node_id = p2p_node.node_id();
            println!("P2P:     iroh node {} (QUIC, DHT-enabled)", node_id);
            state.p2p_node = Some(Arc::new(p2p_node));
            state.p2p_runtime_handle = Some(p2p_handle);

            // Keep the P2P runtime alive in a background thread
            thread::spawn(move || {
                rt.block_on(std::future::pending::<()>());
            });
        }

        start_http_server(http_port, state);
        // Give the server a moment to bind
        thread::sleep(Duration::from_millis(500));
    }

    // Handle command
    match cli.command {
        Commands::Address => {
            let address = node
                .onchain_payment()
                .new_address()
                .expect("Failed to generate address");
            println!("Address: {}", address);
        }

        Commands::Info => {
            let addrs = invoice::listening_addresses(&node);
            let balance = node.list_balances();
            println!("Addresses:  {:?}", addrs);
            println!(
                "On-chain:   {} sats (spendable: {})",
                balance.total_onchain_balance_sats, balance.spendable_onchain_balance_sats
            );
            println!("Lightning:  {} sats", balance.total_lightning_balance_sats);
        }

        Commands::OpenChannel {
            node_id,
            addr,
            amount,
        } => {
            let remote_pk: ldk_node::bitcoin::secp256k1::PublicKey =
                node_id.parse().expect("Invalid node ID");
            let remote_addr: SocketAddress = addr.parse().expect("Invalid address");
            println!("Opening {} sat channel to {}@{}...", amount, node_id, addr);
            node.open_channel(remote_pk, remote_addr, amount, None, None)
                .expect("Failed to open channel");
            println!("Funding tx broadcast. Waiting for confirmation.");
        }

        Commands::Channels => {
            let channels = node.list_channels();
            if channels.is_empty() {
                println!("No channels.");
            } else {
                for (i, ch) in channels.iter().enumerate() {
                    println!(
                        "Channel {}: {} sats | out: {} msat | in: {} msat | ready: {} | usable: {}",
                        i + 1,
                        ch.channel_value_sats,
                        ch.outbound_capacity_msat,
                        ch.inbound_capacity_msat,
                        ch.is_channel_ready,
                        ch.is_usable,
                    );
                }
            }
        }

        Commands::Register { file, price } => {
            handle_register(
                emitter.as_ref(),
                &config.storage_dir,
                &catalog,
                &file,
                price,
                &registry_info,
            );
        }

        Commands::Serve => {
            let cat = catalog.lock().unwrap();
            println!("Node online. {} content items in catalog.", cat.len());
            println!("Catalog:   {}", catalog_path(&config.storage_dir));
            println!("Endpoints: GET /api/catalog, POST /api/register, POST /api/invoice/{{id}}");
            println!("Legacy:    POST /api/sell, /api/buy, /api/seed");
        }

        Commands::Seed {
            encrypted_file,
            encrypted_hash,
            transport_price,
            chunks,
        } => {
            handle_seed(
                emitter.as_ref(),
                &config.storage_dir,
                &catalog,
                &encrypted_file,
                &encrypted_hash,
                transport_price,
                &registry_info,
                &chunks,
            );
        }

        Commands::Sell { file, price } => {
            event_router.set_role("creator");
            handle_sell(&node, emitter.as_ref(), &event_router, &file, price);
        }

        Commands::Buy {
            invoice,
            encrypted_file,
            hash,
            output,
        } => {
            event_router.set_role("buyer");
            handle_buy(
                &node,
                emitter.as_ref(),
                &event_router,
                &invoice,
                &encrypted_file,
                &hash,
                &output,
            );
        }

        Commands::BuyPre {
            creator_url,
            content_hash,
            seeder_url,
            output,
        } => {
            event_router.set_role("buyer");
            // Derive buyer PRE keypair from storage directory
            let buyer_kp = {
                let seed = {
                    use sha2::{Digest, Sha256};
                    let mut h = Sha256::new();
                    h.update(b"conduit-pre-buyer-seed:");
                    h.update(config.storage_dir.as_bytes());
                    let hash = h.finalize();
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&hash);
                    s
                };
                pre::buyer_keygen_from_seed(&seed)
            };
            handle_buy_pre(
                &node,
                emitter.as_ref(),
                &event_router,
                &config.storage_dir,
                &buyer_kp,
                &creator_url,
                &content_hash,
                seeder_url.as_deref(),
                &output,
                None,
                None,
            );
        }
    }

    // Stay online
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    node.stop().expect("Failed to stop node");
}

// ---------------------------------------------------------------------------
// Embedded HTML console
// ---------------------------------------------------------------------------

const CONSOLE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Conduit Console</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚡</text></svg>">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: #0d1117;
  color: #e6edf3;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  font-size: 13px;
  height: 100vh;
  display: flex;
  flex-direction: column;
}
header {
  background: #161b22;
  border-bottom: 1px solid #30363d;
  padding: 12px 20px;
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}
h1 { font-size: 16px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: #f0883e; }
.inputs { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.inputs label { color: #8b949e; font-size: 12px; display: flex; align-items: center; gap: 6px; }
.inputs input {
  background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
  padding: 4px 8px; border-radius: 4px; font-family: inherit; font-size: 12px; width: 260px;
}
.inputs input:focus { border-color: #58a6ff; outline: none; }
button {
  background: #238636; color: #fff; border: none; padding: 5px 14px;
  border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; font-weight: 600;
}
button:hover { background: #2ea043; }
button.disconnect { background: #da3633; }
button.disconnect:hover { background: #f85149; }
.status-row { display: flex; gap: 14px; font-size: 12px; align-items: center; }
.node-badge {
  display: flex; align-items: center; gap: 5px; position: relative;
  padding: 3px 10px; border-radius: 12px; border: 1px solid #30363d; cursor: default;
}
.node-badge.ok { border-color: #238636; background: rgba(35,134,54,0.1); }
.node-badge.ok.creator-badge { border-color: #1f6feb; background: rgba(31,111,235,0.1); }
.node-badge.ok.seeder-badge { border-color: #d29922; background: rgba(210,153,34,0.1); }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot.off { background: #484f58; animation: pulse-off 2s infinite; }
.dot.on { background: #3fb950; animation: none; }
.dot.creator.on { background: #58a6ff; }
.dot.seeder.on { background: #d29922; }
@keyframes pulse-off { 0%,100% { opacity: .4; } 50% { opacity: 1; } }

/* Node popover (hover card) */
.node-popover {
  display: none; position: absolute; top: calc(100% + 8px); left: 50%; transform: translateX(-50%);
  z-index: 100; min-width: 340px; max-width: 420px;
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 14px 18px; font-size: 12px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  pointer-events: auto;
}
.node-popover::before {
  content: ''; position: absolute; top: -6px; left: 50%; transform: translateX(-50%);
  border-left: 6px solid transparent; border-right: 6px solid transparent; border-bottom: 6px solid #30363d;
}
.node-badge:hover .node-popover { display: block; }
.node-popover h3 { font-size: 13px; margin-bottom: 10px; font-weight: 600; letter-spacing: 1px; }
.node-popover.creator h3 { color: #58a6ff; }
.node-popover.seeder h3 { color: #d29922; }
.node-popover.buyer h3 { color: #3fb950; }
.node-popover .row { display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px solid #21262d; }
.node-popover .row:last-child { border-bottom: none; }
.node-popover .lbl { color: #8b949e; }
.node-popover .val { color: #e6edf3; text-align: right; }
.node-popover .val.good { color: #3fb950; }
.node-popover .val.warn { color: #d29922; }
.node-popover .val.bad { color: #f85149; }
.node-popover .id { color: #79c0ff; font-size: 11px; word-break: break-all; }
.ch-bar {
  height: 6px; border-radius: 3px; background: #21262d; margin-top: 6px; overflow: hidden;
}
.ch-bar-fill { height: 100%; border-radius: 3px; }

/* Timeline */
#timeline-hdr {
  padding: 8px 20px; background: #161b22; border-bottom: 1px solid #30363d;
  font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px;
  display: flex; justify-content: space-between; align-items: center;
}
#timeline-hdr .count { color: #58a6ff; }
#timeline {
  flex: 1; overflow-y: auto; padding: 0 20px;
}
#timeline:empty::after {
  content: "Waiting for events... Connect to your nodes, then trigger a sell/buy.";
  display: block; padding: 40px 0; text-align: center; color: #484f58; font-style: italic;
}
.event {
  display: flex; gap: 10px; padding: 5px 0;
  border-bottom: 1px solid #21262d; align-items: baseline;
  animation: flash 0.6s ease-out;
}
@keyframes flash { 0% { background: rgba(88,166,255,0.08); } 100% { background: transparent; } }
.event:last-child { border-bottom: none; }
.ts { color: #484f58; min-width: 70px; }
.role { min-width: 70px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
.role.creator { color: #58a6ff; }
.role.seeder { color: #d29922; }
.role.buyer { color: #3fb950; }
.etype { color: #f0883e; min-width: 200px; font-weight: 600; }
.edata { color: #8b949e; word-break: break-all; }
.edata .key { color: #d2a8ff; }
.edata .hash { color: #79c0ff; }
.edata .amount { color: #3fb950; }
.edata .msg { color: #e6edf3; font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>⚡ Conduit</h1>
  <div class="inputs">
    <label>Creator <input id="url1" placeholder="http://creator-ip:3000"></label>
    <label>Seeder <input id="url3" placeholder="http://seeder-ip:3002 (optional)"></label>
    <label>Buyer <input id="url2" placeholder="http://buyer-ip:3001"></label>
    <button id="btn" onclick="toggle()">Connect</button>
  </div>
  <div class="status-row">
    <div id="badge1" class="node-badge"><span id="d1" class="dot creator off"></span> creator<div id="pop1" class="node-popover creator"></div></div>
    <div id="badge3" class="node-badge"><span id="d3" class="dot seeder off"></span> seeder<div id="pop3" class="node-popover seeder"></div></div>
    <div id="badge2" class="node-badge"><span id="d2" class="dot off"></span> buyer<div id="pop2" class="node-popover buyer"></div></div>
  </div>
</header>

<div id="timeline-hdr">
  <span>Event Timeline</span>
  <span><span id="evcount" class="count">0</span> events</span>
</div>
<div id="timeline"></div>

<script>
let sources = [];
let connected = false;
let evCount = 0;
let infoTimers = [];
const tl = document.getElementById('timeline');

function toggle() {
  if (connected) { disconnect(); return; }
  const u1 = document.getElementById('url1').value.replace(/\/+$/, '') || document.getElementById('url1').placeholder;
  const u3 = (document.getElementById('url3').value || '').replace(/\/+$/, '');
  const u2 = document.getElementById('url2').value.replace(/\/+$/, '') || document.getElementById('url2').placeholder;
  sources = [];
  if (u1) sources.push({ url: u1, dot: 'd1', badge: 'badge1', role: 'creator', card: null });
  if (u3) sources.push({ url: u3, dot: 'd3', badge: 'badge3', role: 'seeder', card: null });
  if (u2) sources.push({ url: u2, dot: 'd2', badge: 'badge2', role: 'buyer', card: null });
  if (!sources.length) return;

  sources.forEach(s => {
    // SSE connection
    const es = new EventSource(s.url + '/api/events');
    s.es = es;
    es.onopen = () => {
      document.getElementById(s.dot).className = 'dot ' + s.role + ' on';
      const badgeSuffix = s.role === 'creator' ? ' creator-badge' : (s.role === 'seeder' ? ' seeder-badge' : '');
      document.getElementById(s.badge).className = 'node-badge ok' + badgeSuffix;
    };
    es.onerror = () => {
      document.getElementById(s.dot).className = 'dot off';
      document.getElementById(s.badge).className = 'node-badge';
    };
    es.onmessage = (e) => { try { addEvent(JSON.parse(e.data)); } catch(err) {} };

    // Fetch node info immediately and every 10s
    fetchInfo(s);
    const t = setInterval(() => fetchInfo(s), 10000);
    infoTimers.push(t);
  });

  connected = true;
  const btn = document.getElementById('btn');
  btn.textContent = 'Disconnect';
  btn.className = 'disconnect';
}

function disconnect() {
  sources.forEach(s => { if (s.es) s.es.close(); });
  infoTimers.forEach(t => clearInterval(t));
  infoTimers = [];
  document.getElementById('d1').className = 'dot creator off';
  document.getElementById('d3').className = 'dot seeder off';
  document.getElementById('d2').className = 'dot off';
  document.getElementById('badge1').className = 'node-badge';
  document.getElementById('badge3').className = 'node-badge';
  document.getElementById('badge2').className = 'node-badge';
  document.getElementById('pop1').innerHTML = '';
  document.getElementById('pop3').innerHTML = '';
  document.getElementById('pop2').innerHTML = '';
  tl.innerHTML = '';
  evCount = 0;
  document.getElementById('evcount').textContent = '0';
  sources = [];
  connected = false;
  document.getElementById('btn').textContent = 'Connect';
  document.getElementById('btn').className = '';
}

async function fetchInfo(s) {
  try {
    const r = await fetch(s.url + '/api/info');
    const info = await r.json();
    renderCard(s, info);
  } catch(e) {
    // Node unreachable — card stays stale or empty
  }
}

function renderCard(s, info) {
  // Determine popover element from badge -> find nested .node-popover
  const popId = s.badge.replace('badge', 'pop');
  const pop = document.getElementById(popId);
  if (!pop) return;

  const totalBal = info.onchain_balance_sats + info.lightning_balance_sats;
  const balClass = totalBal > 0 ? 'good' : 'bad';

  let chHtml = '';
  if (info.channels && info.channels.length > 0) {
    info.channels.forEach((ch, i) => {
      const total = ch.outbound_msat + ch.inbound_msat;
      const outPct = total > 0 ? (ch.outbound_msat / total * 100) : 0;
      const statusClass = ch.usable ? 'good' : (ch.ready ? 'warn' : 'bad');
      const statusText = ch.usable ? 'USABLE' : (ch.ready ? 'READY' : 'PENDING');
      const barColor = s.role === 'creator' ? '#58a6ff' : (s.role === 'seeder' ? '#d29922' : '#3fb950');
      chHtml += '<div class="row"><span class="lbl">Channel ' + (i+1) + '</span><span class="val ' + statusClass + '">' + statusText + ' · ' + fmt(ch.value_sats) + ' sats</span></div>';
      chHtml += '<div class="row"><span class="lbl">out / in</span><span class="val">' + fmt(ch.outbound_msat/1000) + ' / ' + fmt(ch.inbound_msat/1000) + ' sats</span></div>';
      chHtml += '<div class="ch-bar"><div class="ch-bar-fill" style="width:' + outPct + '%;background:' + barColor + '"></div></div>';
    });
  } else {
    chHtml = '<div class="row"><span class="lbl">Channels</span><span class="val bad">NONE</span></div>';
  }

  pop.innerHTML =
    '<h3>' + s.role.toUpperCase() + '</h3>' +
    '<div class="row"><span class="lbl">Node ID</span></div>' +
    '<div class="id">' + esc(info.node_id) + '</div>' +
    '<div class="row" style="margin-top:8px"><span class="lbl">On-chain</span><span class="val">' + fmt(info.onchain_balance_sats) + ' sats</span></div>' +
    '<div class="row"><span class="lbl">Spendable</span><span class="val">' + fmt(info.spendable_onchain_sats) + ' sats</span></div>' +
    '<div class="row"><span class="lbl">Lightning</span><span class="val ' + balClass + '">' + fmt(info.lightning_balance_sats) + ' sats</span></div>' +
    '<div style="margin-top:10px;border-top:1px solid #30363d;padding-top:8px">' + chHtml + '</div>';
}

function fmt(n) { return Number(n).toLocaleString(); }

function addEvent(ev) {
  evCount++;
  document.getElementById('evcount').textContent = evCount;

  const div = document.createElement('div');
  div.className = 'event';

  const ts = document.createElement('span');
  ts.className = 'ts';
  ts.textContent = ev.timestamp || '';

  const role = document.createElement('span');
  role.className = 'role ' + (ev.role || '');
  role.textContent = ev.role || '';

  const etype = document.createElement('span');
  etype.className = 'etype';
  etype.textContent = ev.event_type || '';

  const edata = document.createElement('span');
  edata.className = 'edata';
  edata.innerHTML = formatData(ev.data || {});

  div.appendChild(ts);
  div.appendChild(role);
  div.appendChild(etype);
  div.appendChild(edata);
  tl.appendChild(div);
  tl.scrollTop = tl.scrollHeight;

  // Refresh node info on notable events
  if (['PAYMENT_RECEIVED','PAYMENT_CONFIRMED','HTLC_RECEIVED','PAYMENT_SENT','TRANSPORT_PAID','CONTENT_PAID','TRANSPORT_INVOICE_CREATED'].includes(ev.event_type)) {
    sources.forEach(s => fetchInfo(s));
  }
}

function formatData(d) {
  const parts = [];
  for (const [k, v] of Object.entries(d)) {
    if (k === 'message') {
      parts.push('<span class="msg">' + esc(v) + '</span>');
    } else if (k === 'key' || k === 'preimage') {
      parts.push(k + '=<span class="key">' + esc(v) + '</span>');
    } else if (k.includes('hash')) {
      parts.push(k + '=<span class="hash">' + esc(v) + '</span>');
    } else if (k.includes('amount') || k.includes('msat') || k.includes('sats') || k.includes('fee') || k.includes('price') || k.includes('bytes')) {
      parts.push(k + '=<span class="amount">' + esc(String(v)) + '</span>');
    } else if (k === 'bolt11') {
      const s = String(v);
      parts.push('bolt11=<span class="hash">' + esc(s.length > 40 ? s.slice(0,40) + '...' : s) + '</span>');
    } else if (k === 'event') {
      const s = String(v);
      parts.push(esc(s.length > 80 ? s.slice(0,80) + '...' : s));
    } else {
      parts.push(k + '=' + esc(String(v)));
    }
  }
  return parts.join('  ');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
</body>
</html>"##;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::plan_chunk_assignments;

    /// All seeders have all chunks → load should be balanced evenly.
    #[test]
    fn uniform_availability() {
        // 2 seeders, 6 chunks, both have everything
        let bf = vec![
            vec![true, true, true, true, true, true],
            vec![true, true, true, true, true, true],
        ];
        let (order, assignments) = plan_chunk_assignments(6, &bf);

        // Every chunk must be assigned
        assert!(assignments.iter().all(|a| a.is_some()));

        // Load should be balanced: 3 each
        let s0 = assignments.iter().filter(|a| **a == Some(0)).count();
        let s1 = assignments.iter().filter(|a| **a == Some(1)).count();
        assert_eq!(s0, 3);
        assert_eq!(s1, 3);

        // Order should contain all chunk indices
        assert_eq!(order.len(), 6);
        let mut sorted_order = order.clone();
        sorted_order.sort();
        assert_eq!(sorted_order, vec![0, 1, 2, 3, 4, 5]);
    }

    /// One chunk held by only 1 seeder → it should be assigned first to that
    /// seeder and appear first in download order.
    #[test]
    fn skewed_availability_rarest_first() {
        // 2 seeders, 4 chunks
        // Chunk 2 is only on seeder 0 (rarity 1)
        // Chunks 0,1,3 are on both seeders (rarity 2)
        let bf = vec![vec![true, true, true, true], vec![true, true, false, true]];
        let (order, assignments) = plan_chunk_assignments(4, &bf);

        // Chunk 2 must be first in download order (rarity 1)
        assert_eq!(order[0], 2);

        // Chunk 2 must be assigned to seeder 0 (only one that has it)
        assert_eq!(assignments[2], Some(0));

        // All chunks assigned
        assert!(assignments.iter().all(|a| a.is_some()));
    }

    /// A chunk held by no seeder → should get None.
    #[test]
    fn no_availability() {
        // 2 seeders, 3 chunks. Chunk 1 not held by anyone.
        let bf = vec![vec![true, false, true], vec![true, false, true]];
        let (order, assignments) = plan_chunk_assignments(3, &bf);

        // Chunk 1 has no seeder → None
        assert_eq!(assignments[1], None);

        // Chunk 1 should be first in order (rarity 0 < rarity 2)
        assert_eq!(order[0], 1);

        // Other chunks assigned
        assert!(assignments[0].is_some());
        assert!(assignments[2].is_some());
    }

    /// Single seeder has everything → all chunks go to seeder 0.
    #[test]
    fn single_seeder() {
        let bf = vec![vec![true, true, true, true, true]];
        let (_order, assignments) = plan_chunk_assignments(5, &bf);

        assert!(assignments.iter().all(|a| *a == Some(0)));
    }

    /// 3 seeders with partial overlap.
    /// Verify rarest chunks are prioritised and load is balanced.
    #[test]
    fn three_seeders_partial_overlap() {
        // 3 seeders, 6 chunks:
        //   chunk 0: seeder 0 only              → rarity 1
        //   chunk 1: seeders 0, 1               → rarity 2
        //   chunk 2: seeders 0, 1, 2            → rarity 3
        //   chunk 3: seeders 1, 2               → rarity 2
        //   chunk 4: seeder 2 only              → rarity 1
        //   chunk 5: seeders 0, 1, 2            → rarity 3
        let bf = vec![
            vec![true, true, true, false, false, true],
            vec![false, true, true, true, false, true],
            vec![false, false, true, true, true, true],
        ];
        let (order, assignments) = plan_chunk_assignments(6, &bf);

        // Rarest chunks (rarity 1) should appear first in order
        // chunk 0 (rarity 1) and chunk 4 (rarity 1) must be in first 2 positions
        let first_two: Vec<usize> = order[..2].to_vec();
        assert!(
            first_two.contains(&0),
            "chunk 0 (rarity 1) should be in first two"
        );
        assert!(
            first_two.contains(&4),
            "chunk 4 (rarity 1) should be in first two"
        );

        // chunk 0 can only go to seeder 0, chunk 4 can only go to seeder 2
        assert_eq!(assignments[0], Some(0));
        assert_eq!(assignments[4], Some(2));

        // All chunks assigned (every chunk has at least one seeder)
        assert!(assignments.iter().all(|a| a.is_some()));

        // Rarity-2 chunks (1, 3) should come next, then rarity-3 chunks (2, 5)
        let mid_two: Vec<usize> = order[2..4].to_vec();
        assert!(
            mid_two.contains(&1),
            "chunk 1 (rarity 2) should be in positions 2-3"
        );
        assert!(
            mid_two.contains(&3),
            "chunk 3 (rarity 2) should be in positions 2-3"
        );

        let last_two: Vec<usize> = order[4..6].to_vec();
        assert!(
            last_two.contains(&2),
            "chunk 2 (rarity 3) should be in positions 4-5"
        );
        assert!(
            last_two.contains(&5),
            "chunk 5 (rarity 3) should be in positions 4-5"
        );
    }
}
