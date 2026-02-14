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

use axum::extract::State;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::{Html, Json};
use axum::extract::Path as AxumPath;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use conduit_core::chunk;
use conduit_core::encrypt;
use conduit_core::invoice::{self, ChainSource, LightningConfig};
use conduit_core::merkle::MerkleTree;
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
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Console event type
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct ConsoleEvent {
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
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

fn emit(tx: &broadcast::Sender<ConsoleEvent>, role: &str, event_type: &str, data: serde_json::Value) {
    let event = ConsoleEvent {
        timestamp: now_ts(),
        role: role.into(),
        event_type: event_type.into(),
        data,
    };
    // Also print to terminal
    println!("[{}] {:<20} {}", event.role, event.event_type, event.data);
    let _ = tx.send(event);
}

// ---------------------------------------------------------------------------
// Event router — single event loop, dispatches to registered handlers
// ---------------------------------------------------------------------------

/// Central event dispatcher. One background thread calls `wait_next_event()`,
/// matches on payment hash, and forwards to the registered handler. Events
/// that don't match any handler are logged and acknowledged — they never block
/// other handlers or eat events meant for the node's internal state machine.
struct EventRouter {
    waiters: std::sync::Mutex<std::collections::HashMap<PaymentHash, std::sync::mpsc::Sender<Event>>>,
    console_tx: broadcast::Sender<ConsoleEvent>,
    role: std::sync::Mutex<String>,
}

impl EventRouter {
    fn new(console_tx: broadcast::Sender<ConsoleEvent>) -> Self {
        Self {
            waiters: std::sync::Mutex::new(std::collections::HashMap::new()),
            console_tx,
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
            Event::PaymentFailed { payment_hash: Some(hash), .. } => Some(*hash),
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
                emit(&self.console_tx, &role, "LDK_EVENT", serde_json::json!({
                    "event": format!("{:?}", event),
                }));
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
}

// ---------------------------------------------------------------------------
// Axum app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    events_tx: broadcast::Sender<ConsoleEvent>,
    event_router: Arc<EventRouter>,
    catalog: Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    storage_dir: String,
    registry_info: Option<RegistryInfo>,
    // Advertiser role
    advertiser_db: Option<Arc<std::sync::Mutex<Connection>>>,
    advertiser_signing_key: Option<Arc<SigningKey>>,
    advertiser_pubkey_hex: Option<String>,
    ads_dir: Option<String>,
    // Dashboard
    dashboard_path: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn index_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Serve external dashboard file if configured, otherwise fallback to embedded console
    if let Some(ref path) = state.dashboard_path {
        match std::fs::read_to_string(path) {
            Ok(html) => return Html(html).into_response(),
            Err(e) => {
                eprintln!("Failed to read dashboard file {}: {}", path, e);
                // Fall through to embedded console
            }
        }
    }
    Html(CONSOLE_HTML.to_string()).into_response()
}

#[derive(Serialize)]
struct NodeInfo {
    node_id: String,
    onchain_balance_sats: u64,
    spendable_onchain_sats: u64,
    lightning_balance_sats: u64,
    channels: Vec<ChannelInfo>,
}

#[derive(Serialize)]
struct ChannelInfo {
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
            value_sats: ch.channel_value_sats,
            outbound_msat: ch.outbound_capacity_msat,
            inbound_msat: ch.inbound_capacity_msat,
            ready: ch.is_channel_ready,
            usable: ch.is_usable,
        })
        .collect();
    Json(NodeInfo {
        node_id: invoice::node_id(&state.node),
        onchain_balance_sats: balance.total_onchain_balance_sats,
        spendable_onchain_sats: balance.spendable_onchain_balance_sats,
        lightning_balance_sats: balance.total_lightning_balance_sats,
        channels,
    })
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.events_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|event| {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Ok::<_, Infallible>(SseEvent::default().data(json))
        })
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
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
    hash: String,                        // H(F) — plaintext hash
    output: String,
    // --- Two-phase buy (seeder flow) ---
    #[serde(default)]
    wrapped_url: Option<String>,         // URL to fetch W from seeder
    #[serde(default)]
    transport_invoice: Option<String>,   // Seeder's invoice (preimage = K_S)
    #[serde(default)]
    content_invoice: Option<String>,     // Creator's invoice (preimage = K)
    #[serde(default)]
    encrypted_hash: Option<String>,      // H(E) — for intermediate verification
    // --- Legacy single-phase buy ---
    #[serde(default)]
    invoice: Option<String>,             // single invoice (backward compat)
    #[serde(default)]
    encrypted_file: Option<String>,      // local path (legacy)
    #[serde(default)]
    enc_url: Option<String>,             // HTTP URL to fetch .enc from creator
    // --- Chunked buy (A5: multi-source) ---
    #[serde(default)]
    seeder_urls: Vec<String>,            // list of seeder HTTP base URLs
    #[serde(default)]
    mode: Option<String>,                // "chunked" to enable chunk-level download
}

#[derive(Deserialize)]
struct SeedRequest {
    encrypted_file: String,      // path to E on disk
    encrypted_hash: String,      // H(E) hex
    transport_price: u64,        // sats for transport
    #[serde(default)]
    chunks: Option<String>,      // which chunks to seed (e.g. "0,1,2,5-9"), omit for all
}

// ---------------------------------------------------------------------------
// Content Catalog — persistent registry of content available for sale
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogEntry {
    content_hash: String,       // H(F) hex — unique content ID (empty for seeder)
    file_name: String,          // display name (e.g. "btc-logo.png")
    file_path: String,          // original file path on disk (empty for seeder)
    enc_file_path: String,      // path to encrypted file E
    key_hex: String,            // K hex — SECRET, never exposed via API (empty for seeder)
    price_sats: u64,            // content price (0 for seeder — seeder uses transport_price)
    encrypted_hash: String,     // H(E) hex
    size_bytes: u64,            // original plaintext size (enc size for seeder)
    registered_at: String,      // unix timestamp
    #[serde(default)]
    transport_price: u64,       // sats for transport (0 for creator entries, >0 for seeder)
    // --- P2P chunk metadata (A3) ---
    #[serde(default)]
    chunk_size: usize,          // bytes per chunk (0 = legacy single-blob)
    #[serde(default)]
    chunk_count: usize,         // number of chunks (0 = legacy)
    #[serde(default)]
    plaintext_root: String,     // Merkle root of H(plaintext chunks), hex
    #[serde(default)]
    encrypted_root: String,     // Merkle root of H(encrypted chunks), hex
    #[serde(default)]
    chunks_held: Vec<usize>,    // which chunk indices this node has (empty = all)
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

async fn sell_handler(
    State(state): State<AppState>,
    Json(req): Json<SellRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.events_tx.clone();
    let router = state.event_router.clone();
    thread::spawn(move || {
        handle_sell(&node, &tx, &router, &req.file, req.price);
    });
    Json(serde_json::json!({"status": "started"}))
}

async fn buy_handler(
    State(state): State<AppState>,
    Json(req): Json<BuyRequest>,
) -> Json<serde_json::Value> {
    let node = state.node.clone();
    let tx = state.events_tx.clone();
    let router = state.event_router.clone();
    let is_chunked = req.mode.as_deref() == Some("chunked");
    let is_two_phase = req.transport_invoice.is_some() && req.content_invoice.is_some();
    thread::spawn(move || {
        if is_chunked {
            // --- Chunked buy: multi-source chunk download (A5) ---
            handle_buy_chunked(&node, &tx, &router, &req);
        } else if is_two_phase {
            // --- Two-phase buy: seeder + creator ---
            handle_buy_two_phase(&node, &tx, &router, &req);
        } else {
            // --- Legacy single-phase buy ---
            let enc_path = if let Some(ref url) = req.enc_url {
                match curl_fetch(url, &tx) {
                    Some(path) => path,
                    None => return,
                }
            } else if let Some(ref path) = req.encrypted_file {
                path.clone()
            } else {
                emit(&tx, "buyer", "BUY_ERROR", serde_json::json!({
                    "message": "No encrypted_file, enc_url, or wrapped_url provided",
                }));
                return;
            };
            let invoice = req.invoice.as_deref().unwrap_or("");
            handle_buy(&node, &tx, &router, invoice, &enc_path, &req.hash, &req.output);
        }
    });
    Json(serde_json::json!({"status": "started"}))
}

/// Download a URL to /tmp/ via curl, emitting SSE events. Returns local path on success.
fn curl_fetch(url: &str, tx: &broadcast::Sender<ConsoleEvent>) -> Option<String> {
    let local = format!("/tmp/fetched-{}", url.split('/').last().unwrap_or("download.enc"));
    emit(tx, "buyer", "FETCHING_ENC", serde_json::json!({
        "url": url,
        "message": "Downloading encrypted file...",
    }));
    let curl = std::process::Command::new("curl")
        .args(["-sS", "-o", &local, url])
        .output();
    match curl {
        Ok(out) if out.status.success() => {
            let bytes = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
            emit(tx, "buyer", "ENC_FETCHED", serde_json::json!({
                "bytes": bytes,
                "path": &local,
            }));
            Some(local)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            emit(tx, "buyer", "FETCH_FAILED", serde_json::json!({
                "error": format!("curl failed: {}", stderr),
            }));
            None
        }
        Err(e) => {
            emit(tx, "buyer", "FETCH_FAILED", serde_json::json!({
                "error": format!("curl not found: {}", e),
            }));
            None
        }
    }
}

async fn seed_handler(
    State(state): State<AppState>,
    Json(req): Json<SeedRequest>,
) -> Json<serde_json::Value> {
    let tx = state.events_tx.clone();
    let catalog = state.catalog.clone();
    let storage_dir = state.storage_dir.clone();
    let registry_info = state.registry_info.clone();
    thread::spawn(move || {
        handle_seed(&tx, &storage_dir, &catalog, &req.encrypted_file, &req.encrypted_hash, req.transport_price, &registry_info, &req.chunks);
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
    let items: Vec<serde_json::Value> = cat.iter().map(|e| {
        let enc_filename = e.enc_file_path.split('/').last().unwrap_or("").to_string();
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
        })
    }).collect();
    Json(serde_json::json!({ "items": items }))
}

async fn register_api_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<serde_json::Value> {
    let tx = state.events_tx.clone();
    let catalog = state.catalog.clone();
    let storage_dir = state.storage_dir.clone();
    let registry_info = state.registry_info.clone();
    thread::spawn(move || {
        handle_register(&tx, &storage_dir, &catalog, &req.file, req.price, &registry_info);
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
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Content not found in catalog"
        }))).into_response(),
    };

    // Parse stored key
    let key_bytes = hex::decode(&entry.key_hex).expect("Invalid key in catalog");
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Create a fresh invoice with K as preimage
    let bolt11 = match invoice::create_invoice_for_key(
        &state.node, &key, entry.price_sats, &entry.file_name
    ) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to create invoice: {}", e)
        }))).into_response(),
    };

    let payment_hash = hex::encode(verify::sha256_hash(&key));
    let enc_filename = entry.enc_file_path.split('/').last().unwrap_or("").to_string();

    // Emit SSE event so the console can see it
    let tx = state.events_tx.clone();
    emit(&tx, "creator", "INVOICE_CREATED", serde_json::json!({
        "payment_hash": &payment_hash,
        "content_hash": &entry.content_hash,
        "encrypted_hash": &entry.encrypted_hash,
        "amount_sats": entry.price_sats,
        "bolt11": &bolt11,
        "enc_filename": &enc_filename,
        "file_name": &entry.file_name,
    }));

    // Spawn a thread to wait for payment and claim it
    let node = state.node.clone();
    let tx2 = state.events_tx.clone();
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
    })).into_response()
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
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Content not found in catalog"
        }))).into_response(),
    };

    // Fetch advertiser campaign list
    let advertiser_url = req.advertiser_url.trim_end_matches('/');
    let campaigns_url = format!("{}/api/campaigns", advertiser_url);
    let campaign_data = match reqwest::get(&campaigns_url).await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(data) => data,
            Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
                "error": format!("Failed to parse advertiser response: {}", e)
            }))).into_response(),
        },
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({
            "error": format!("Failed to reach advertiser: {}", e)
        }))).into_response(),
    };

    // Pick the first active campaign
    let campaigns = campaign_data["campaigns"].as_array();
    let campaign = match campaigns.and_then(|c| c.first()) {
        Some(c) => c.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "No active campaigns on advertiser"
        }))).into_response(),
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
        &state.node, &key, 1, &format!("{} (ad-key)", entry.file_name)
    ) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to create buyer invoice: {}", e)
        }))).into_response(),
    };
    let buyer_payment_hash = hex::encode(verify::sha256_hash(&key));

    // -----------------------------------------------------------------------
    // Invoice 2: Advertiser pays content price, preimage = K_ad (random)
    // -----------------------------------------------------------------------
    let mut k_ad = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut k_ad);

    let ad_bolt11 = match invoice::create_invoice_for_key(
        &state.node, &k_ad, entry.price_sats, &format!("{} (ad-subsidy)", entry.file_name)
    ) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to create advertiser invoice: {}", e)
        }))).into_response(),
    };
    let ad_payment_hash = hex::encode(verify::sha256_hash(&k_ad));

    let enc_filename = entry.enc_file_path.split('/').last().unwrap_or("").to_string();

    // Emit SSE event
    let tx = state.events_tx.clone();
    emit(&tx, "creator", "AD_INVOICE_CREATED", serde_json::json!({
        "buyer_payment_hash": &buyer_payment_hash,
        "ad_payment_hash": &ad_payment_hash,
        "content_hash": &entry.content_hash,
        "buyer_amount_sats": 1,
        "ad_amount_sats": entry.price_sats,
        "campaign_id": campaign["campaign_id"],
        "advertiser_url": advertiser_url,
        "mode": "ad-subsidized-two-payment",
    }));

    // Spawn threads to wait for BOTH payments and claim them
    {
        let node = state.node.clone();
        let tx2 = state.events_tx.clone();
        let router = state.event_router.clone();
        thread::spawn(move || {
            handle_sell_from_catalog(&node, &tx2, &router, &key);
        });
    }
    {
        let node = state.node.clone();
        let tx2 = state.events_tx.clone();
        let router = state.event_router.clone();
        thread::spawn(move || {
            handle_sell_from_catalog(&node, &tx2, &router, &k_ad);
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
    chunks: Vec<usize>,   // empty = legacy whole-file wrapping
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
        cat.iter().find(|e| e.encrypted_hash == encrypted_hash && e.transport_price > 0).cloned()
    };

    let entry = match entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Content not found in seeder catalog"
        }))).into_response(),
    };

    // Read encrypted file
    let encrypted = match std::fs::read(&entry.enc_file_path) {
        Ok(data) => data,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to read encrypted file: {}", e)
        }))).into_response(),
    };

    // Generate fresh transport key K_S
    let ks = encrypt::generate_key();

    if requested_chunks.is_empty() {
        // --- Legacy mode: wrap entire file as one blob ---
        let wrapped = encrypt::encrypt(&encrypted, &ks, 0);
        let wrapped_path = format!("{}.wrapped", entry.enc_file_path);
        let wrapped_filename = wrapped_path.split('/').last().unwrap_or("").to_string();
        if let Err(e) = std::fs::write(&wrapped_path, &wrapped) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to write wrapped file: {}", e)
            }))).into_response();
        }

        let bolt11 = match invoice::create_invoice_for_key(
            &state.node, &ks, entry.transport_price, "transport"
        ) {
            Ok(b) => b,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to create invoice: {}", e)
            }))).into_response(),
        };

        let payment_hash = hex::encode(verify::sha256_hash(&ks));

        let tx = state.events_tx.clone();
        emit(&tx, "seeder", "TRANSPORT_INVOICE_CREATED", serde_json::json!({
            "payment_hash": &payment_hash,
            "amount_sats": entry.transport_price,
            "bolt11": &bolt11,
            "wrapped_filename": &wrapped_filename,
            "encrypted_hash": &encrypted_hash,
        }));

        let node = state.node.clone();
        let tx2 = state.events_tx.clone();
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
        })).into_response()
    } else {
        // --- Chunked mode: wrap each requested chunk individually with K_S ---
        let cs = if entry.chunk_size > 0 { entry.chunk_size } else { chunk::select_chunk_size(encrypted.len()) };
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
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                    "error": format!("Seeder does not hold chunk {}", idx)
                }))).into_response();
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
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": format!("Failed to write wrapped chunk {}: {}", idx, e)
                }))).into_response();
            }
            wrapped_files.push(idx);
        }

        let bolt11 = match invoice::create_invoice_for_key(
            &state.node, &ks, entry.transport_price, "transport"
        ) {
            Ok(b) => b,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to create invoice: {}", e)
            }))).into_response(),
        };

        let payment_hash = hex::encode(verify::sha256_hash(&ks));

        let tx = state.events_tx.clone();
        emit(&tx, "seeder", "TRANSPORT_INVOICE_CREATED", serde_json::json!({
            "payment_hash": &payment_hash,
            "amount_sats": entry.transport_price,
            "bolt11": &bolt11,
            "chunks": &requested_chunks,
            "encrypted_hash": &encrypted_hash,
            "mode": "chunked",
        }));

        let node = state.node.clone();
        let tx2 = state.events_tx.clone();
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
            "wrap_dir": wrap_dir.split('/').last().unwrap_or(""),
            "mode": "chunked",
        })).into_response()
    }
}

/// Wait for a transport payment and claim it (reveals K_S to buyer).
fn handle_transport_payment(
    node: &Arc<Node>,
    tx: &broadcast::Sender<ConsoleEvent>,
    router: &Arc<EventRouter>,
    ks: &[u8; 32],
) {
    let role = "seeder";
    let payment_hash_bytes = verify::sha256_hash(ks);
    let expected_hash = PaymentHash(payment_hash_bytes);

    emit(tx, role, "WAITING_FOR_TRANSPORT_PAYMENT", serde_json::json!({
        "payment_hash": hex::encode(payment_hash_bytes),
        "message": "Listening for incoming transport HTLC...",
    }));

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
                emit(tx, role, "TRANSPORT_HTLC_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": claimable_amount_msat,
                    "claim_deadline": claim_deadline,
                }));

                invoice::claim_payment(node, ks, claimable_amount_msat)
                    .expect("Failed to claim transport payment");
                emit(tx, role, "TRANSPORT_PAYMENT_CLAIMED", serde_json::json!({
                    "preimage": hex::encode(ks),
                    "message": "Transport key K_S revealed to buyer via HTLC settlement",
                }));
            }
            Event::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            } => {
                emit(tx, role, "TRANSPORT_PAYMENT_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": amount_msat,
                    "message": "Transport payment confirmed. Content delivered.",
                }));
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
    let path = if std::path::Path::new(&primary).exists() { primary } else { fallback };
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
        cat.iter().find(|e| e.encrypted_hash == encrypted_hash).cloned()
    };
    let entry = entry?;

    let encrypted = std::fs::read(&entry.enc_file_path).ok()?;
    let cs = if entry.chunk_size > 0 { entry.chunk_size } else { chunk::select_chunk_size(encrypted.len()) };
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
        cat.iter().find(|e| e.encrypted_hash == encrypted_hash).cloned()
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
        })).into_response(),
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
            ).into_response()
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
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                    "error": "chunk index out of range"
                }))).into_response();
            }
            let tree = MerkleTree::from_chunks(&enc_chunks);
            let proof = tree.proof(index);
            let leaf_hash = hex::encode(tree.leaf_hash_at(index));
            Json(serde_json::json!({
                "index": index,
                "leaf_hash": leaf_hash,
                "proof": proof.to_json(),
                "encrypted_root": entry.encrypted_root,
            })).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "content not found"
        }))).into_response(),
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
        cat.iter().find(|e| e.encrypted_hash == encrypted_hash).cloned()
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
            })).into_response()
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
        cat.iter().find(|e| e.encrypted_hash == encrypted_hash).cloned()
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
        ).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "wrapped chunk not found (request transport-invoice first)").into_response(),
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
    creative_file: String,
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
            creative_file TEXT NOT NULL,
            creative_hash TEXT NOT NULL,
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
            "SELECT campaign_id, name, creative_file, creative_hash, creative_format,
                    duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
                    active, created_at
             FROM campaigns ORDER BY created_at DESC",
        )
        .unwrap();

    stmt.query_map([], |row| {
        Ok(AdvCampaign {
            campaign_id: row.get(0)?,
            name: row.get(1)?,
            creative_file: row.get(2)?,
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

fn adv_sha256_file(path: &str) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

fn adv_seed_default_campaign(db: &Connection, ads_dir: &str) {
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM campaigns", [], |row| row.get(0))
        .unwrap_or(0);
    if count > 0 {
        return;
    }
    let entries: Vec<_> = match std::fs::read_dir(ads_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .collect(),
        Err(_) => {
            println!("No ads directory found at '{}', skipping default campaign seed.", ads_dir);
            return;
        }
    };
    if entries.is_empty() {
        println!("No ad creative files found in '{}'. Place a video/image file there.", ads_dir);
        return;
    }
    let entry = &entries[0];
    let file_name = entry.file_name().to_string_lossy().to_string();
    let file_path = entry.path().to_string_lossy().to_string();
    let creative_hash = match adv_sha256_file(&file_path) {
        Ok(h) => h,
        Err(e) => { eprintln!("Failed to hash {}: {}", file_path, e); return; }
    };
    let ext = std::path::Path::new(&file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let creative_format = match ext.as_str() {
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        _ => "application/octet-stream",
    };
    let campaign_id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO campaigns
         (campaign_id, name, creative_file, creative_hash, creative_format,
          duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
          active, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 1, ?9)",
        rusqlite::params![
            campaign_id, format!("Bitcoin Ad - {}", file_name), file_name,
            creative_hash, creative_format, 15000, 50, 1_000_000, adv_now_unix(),
        ],
    )
    .unwrap();
    println!("Seeded default campaign: {} ({})", file_name, campaign_id);
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
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Advertiser role not enabled (no --ads-dir)"}))).into_response(),
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
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Advertiser role not enabled").into_response(),
    };
    let db = db.lock().unwrap();
    let result = db.query_row(
        "SELECT campaign_id, name, creative_file, creative_hash, creative_format,
                duration_ms, subsidy_sats, budget_total_sats, budget_spent_sats,
                active, created_at
         FROM campaigns WHERE campaign_id = ?1",
        rusqlite::params![campaign_id],
        |row| {
            Ok(AdvCampaign {
                campaign_id: row.get(0)?,
                name: row.get(1)?,
                creative_file: row.get(2)?,
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
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Campaign not found"}))).into_response(),
    }
}

/// GET /api/campaigns/{campaign_id}/creative -- serve ad creative file
async fn adv_serve_creative(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
) -> impl IntoResponse {
    let ads_dir = match &state.ads_dir {
        Some(d) => d.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Advertiser role not enabled").into_response(),
    };
    let db = state.advertiser_db.as_ref().unwrap().lock().unwrap();
    let creative: Result<(String, String), _> = db.query_row(
        "SELECT creative_file, creative_format FROM campaigns WHERE campaign_id = ?1 AND active = 1",
        rusqlite::params![campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    );
    let (file_name, content_type) = match creative {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, "Campaign not found or inactive").into_response(),
    };
    drop(db);
    let file_path = format!("{}/{}", ads_dir, file_name);
    match std::fs::read(&file_path) {
        Ok(data) => {
            let headers = [
                (axum::http::header::CONTENT_TYPE, content_type),
                (axum::http::header::CONTENT_DISPOSITION, format!("inline; filename=\"{}\"", file_name)),
            ];
            (headers, data).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Creative file not found on disk").into_response(),
    }
}

/// POST /api/campaigns/{campaign_id}/start -- begin a viewing session
async fn adv_start_session(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
    Json(req): Json<AdvStartSessionRequest>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Advertiser role not enabled"}))).into_response(),
    };
    let db = db.lock().unwrap();
    let campaign: Result<(u64, u64, u64), _> = db.query_row(
        "SELECT duration_ms, budget_total_sats, budget_spent_sats FROM campaigns WHERE campaign_id = ?1 AND active = 1",
        rusqlite::params![campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );
    let (duration_ms, budget_total, budget_spent) = match campaign {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Campaign not found or inactive"}))).into_response(),
    };
    if budget_spent >= budget_total {
        return (StatusCode::GONE, Json(serde_json::json!({"error": "Campaign budget exhausted"}))).into_response();
    }
    let active_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE campaign_id = ?1 AND buyer_pubkey = ?2 AND completed = 0 AND started_at > ?3",
            rusqlite::params![campaign_id, req.buyer_pubkey, adv_now_unix() - 300],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if active_count >= 5 {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "Too many active sessions"}))).into_response();
    }
    let session_id = Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO sessions (session_id, campaign_id, buyer_pubkey, started_at, completed, duration_ms) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        rusqlite::params![session_id, campaign_id, req.buyer_pubkey, adv_now_unix(), duration_ms],
    )
    .unwrap();
    println!("[advertiser] Session started: {} for campaign {} by {}", session_id, campaign_id, &req.buyer_pubkey[..8.min(req.buyer_pubkey.len())]);
    Json(serde_json::json!({ "session_id": session_id, "duration_ms": duration_ms })).into_response()
}

/// POST /api/campaigns/{campaign_id}/complete -- complete session, return attestation token
async fn adv_complete_session(
    State(state): State<AppState>,
    AxumPath(campaign_id): AxumPath<String>,
    Json(req): Json<AdvCompleteSessionRequest>,
) -> impl IntoResponse {
    let db = match &state.advertiser_db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Advertiser role not enabled"}))).into_response(),
    };
    let db = db.lock().unwrap();
    let session: Result<(u64, i32, u64, String), _> = db.query_row(
        "SELECT started_at, completed, duration_ms, buyer_pubkey FROM sessions WHERE session_id = ?1 AND campaign_id = ?2",
        rusqlite::params![req.session_id, campaign_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    );
    let (started_at, completed, duration_ms, stored_pubkey) = match session {
        Ok(s) => s,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"}))).into_response(),
    };
    if stored_pubkey != req.buyer_pubkey {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "buyer_pubkey mismatch"}))).into_response();
    }
    if completed != 0 {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Session already completed"}))).into_response();
    }
    let elapsed_ms = (adv_now_unix() - started_at) * 1000;
    if elapsed_ms < duration_ms {
        return (StatusCode::PRECONDITION_FAILED, Json(serde_json::json!({
            "error": "Ad viewing not yet complete", "elapsed_ms": elapsed_ms, "required_ms": duration_ms,
        }))).into_response();
    }
    db.execute("UPDATE sessions SET completed = 1 WHERE session_id = ?1", rusqlite::params![req.session_id]).unwrap();
    let payload = AdvAttestationPayload {
        campaign_id: campaign_id.clone(),
        buyer_pubkey: req.buyer_pubkey.clone(),
        timestamp: adv_now_unix(),
        duration_ms,
    };
    let signing_key = state.advertiser_signing_key.as_ref().unwrap();
    let token = adv_sign_attestation(signing_key, &payload);
    let pubkey_hex = state.advertiser_pubkey_hex.clone().unwrap_or_default();
    println!("[advertiser] Attestation issued: campaign={} buyer={}", campaign_id, &req.buyer_pubkey[..8.min(req.buyer_pubkey.len())]);
    Json(serde_json::json!({ "token": token, "payload": payload, "advertiser_pubkey": pubkey_hex })).into_response()
}

/// POST /api/campaigns/{campaign_id}/pay -- validate attestation + pay invoice via LDK
async fn adv_pay_invoice(
    State(state): State<AppState>,
    Json(req): Json<AdvPayRequest>,
) -> impl IntoResponse {
    let signing_key = match &state.advertiser_signing_key {
        Some(k) => k.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"status": "advertiser_not_enabled"}))).into_response(),
    };
    let verifying_key = VerifyingKey::from(&*signing_key);
    if !adv_verify_attestation(&verifying_key, &req.attestation_payload, &req.attestation_token) {
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
            println!("[advertiser] Payment sent: {} sats for campaign {} (hash: {})", subsidy_sats, req.attestation_payload.campaign_id, payment_hash_hex);
            let db = state.advertiser_db.as_ref().unwrap().lock().unwrap();
            let _ = db.execute(
                "INSERT OR REPLACE INTO adv_payments (payment_hash, campaign_id, buyer_pubkey, amount_sats, paid_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![payment_hash_hex, req.attestation_payload.campaign_id, req.attestation_payload.buyer_pubkey, subsidy_sats, adv_now_unix()],
            );
            Json(serde_json::json!({"status": "payment_sent", "payment_hash": payment_hash_hex})).into_response()
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
        let total_payments: i64 = db.query_row("SELECT COUNT(*) FROM adv_payments", [], |row| row.get(0)).unwrap_or(0);
        let total_spent: i64 = db.query_row("SELECT COALESCE(SUM(amount_sats), 0) FROM adv_payments", [], |row| row.get(0)).unwrap_or(0);
        stats["campaign_count"] = serde_json::json!(campaigns.len());
        stats["total_payments"] = serde_json::json!(total_payments);
        stats["total_spent_sats"] = serde_json::json!(total_spent);
    }
    Json(stats)
}

// ===========================================================================
// End of advertiser role
// ===========================================================================

fn start_http_server(port: u16, state: AppState) {
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            let app = Router::new()
                .route("/", get(index_handler))
                .route("/api/info", get(info_handler))
                .route("/api/events", get(sse_handler))
                .route("/api/catalog", get(catalog_handler))
                .route("/api/register", post(register_api_handler))
                .route("/api/invoice/{content_hash}", post(invoice_handler))
                .route("/api/ad-invoice/{content_hash}", post(ad_invoice_handler))
                .route("/api/sell", post(sell_handler))
                .route("/api/buy", post(buy_handler))
                .route("/api/seed", post(seed_handler))
                .route("/api/transport-invoice/{encrypted_hash}", post(transport_invoice_handler))
                .route("/api/enc/{filename}", get(enc_file_handler))
                .route("/api/wrapped/{filename}", get(wrapped_file_handler))
                .route("/api/decrypted/{filename}", get(decrypted_file_handler))
                // A4: Chunk-level endpoints
                .route("/api/chunks/{encrypted_hash}/meta", get(chunk_meta_handler))
                .route("/api/chunks/{encrypted_hash}/{index}", get(chunk_data_handler))
                .route("/api/chunks/{encrypted_hash}/proof/{index}", get(chunk_proof_handler))
                .route("/api/chunks/{encrypted_hash}/bitfield", get(chunk_bitfield_handler))
                .route("/api/wrapped-chunks/{encrypted_hash}/{index}", get(wrapped_chunk_handler))
                // Advertiser role routes
                .route("/api/campaigns", get(adv_list_campaigns))
                .route("/api/campaigns/{campaign_id}", get(adv_get_campaign))
                .route("/api/campaigns/{campaign_id}/creative", get(adv_serve_creative))
                .route("/api/campaigns/{campaign_id}/start", post(adv_start_session))
                .route("/api/campaigns/{campaign_id}/complete", post(adv_complete_session))
                .route("/api/campaigns/pay", post(adv_pay_invoice))
                .route("/api/advertiser/info", get(adv_info_handler))
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
// sell command
// ---------------------------------------------------------------------------

fn handle_sell(node: &Arc<Node>, tx: &broadcast::Sender<ConsoleEvent>, router: &Arc<EventRouter>, file_path: &str, price: u64) {
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    println!("Read {} bytes from {}", plaintext.len(), file_path);

    // 2. Generate key
    let key = encrypt::generate_key();
    emit(tx, role, "KEY_GENERATED", serde_json::json!({
        "key": hex::encode(key),
    }));

    // 3. Encrypt
    let ciphertext = encrypt::encrypt(&plaintext, &key, 0);
    emit(tx, role, "CONTENT_ENCRYPTED", serde_json::json!({
        "plaintext_bytes": plaintext.len(),
        "ciphertext_bytes": ciphertext.len(),
    }));

    // 4. Hash plaintext
    let file_hash = verify::sha256_hash(&plaintext);
    emit(tx, role, "HASH_COMPUTED", serde_json::json!({
        "hash": hex::encode(file_hash),
    }));

    // 5. Create invoice
    let bolt11 = invoice::create_invoice_for_key(node, &key, price, file_path)
        .expect("Failed to create invoice");
    let payment_hash = verify::sha256_hash(&key);
    let enc_path = format!("{}.enc", file_path);
    let enc_filename = enc_path.split('/').last().unwrap_or("").to_string();
    let enc_hash = verify::sha256_hash(&ciphertext);
    emit(tx, role, "INVOICE_CREATED", serde_json::json!({
        "payment_hash": hex::encode(payment_hash),
        "content_hash": hex::encode(file_hash),
        "encrypted_hash": hex::encode(enc_hash),
        "amount_sats": price,
        "bolt11": &bolt11,
        "enc_filename": &enc_filename,
        "file_name": file_path.split('/').last().unwrap_or(file_path),
    }));

    // 6. Save encrypted file
    std::fs::write(&enc_path, &ciphertext).expect("Failed to write encrypted file");
    emit(tx, role, "ENCRYPTED_FILE_SAVED", serde_json::json!({
        "path": &enc_path,
        "encrypted_hash": hex::encode(enc_hash),
        "bytes": ciphertext.len(),
    }));

    // 7. Print summary for the buyer
    println!();
    println!("=== SELL READY ===");
    println!("Encrypted file:  {}", enc_path);
    println!("Plaintext hash:  {}", hex::encode(file_hash));
    println!("Encrypted hash:  {}", hex::encode(enc_hash));
    println!("Invoice:         {}", bolt11);
    println!();

    // 8. Wait for payment via event router
    emit(tx, role, "WAITING_FOR_PAYMENT", serde_json::json!({
        "message": "Listening for incoming HTLC..."
    }));

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
                emit(tx, role, "HTLC_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": claimable_amount_msat,
                    "claim_deadline": claim_deadline,
                }));

                // Claim payment (reveals preimage to buyer)
                invoice::claim_payment(node, &key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emit(tx, role, "PAYMENT_CLAIMED", serde_json::json!({
                    "preimage": hex::encode(key),
                    "message": "Preimage revealed to buyer via HTLC settlement",
                }));
            }
            Event::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            } => {
                emit(tx, role, "PAYMENT_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": amount_msat,
                    "message": "Payment confirmed. Content sold.",
                }));
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

fn handle_seed(
    tx: &broadcast::Sender<ConsoleEvent>,
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
    println!("Read {} encrypted bytes from {}", encrypted.len(), enc_file_path);

    // 2. Verify H(E) matches what the creator published
    let enc_hash = verify::sha256_hash(&encrypted);
    let expected_enc_hash = hex::decode(expected_enc_hash_hex).expect("Invalid hex hash");
    if enc_hash[..] != expected_enc_hash[..] {
        emit(tx, role, "ENC_HASH_MISMATCH", serde_json::json!({
            "expected": expected_enc_hash_hex,
            "actual": hex::encode(enc_hash),
            "message": "Encrypted content hash mismatch! File may be corrupted.",
        }));
        eprintln!("ERROR: Encrypted content hash mismatch");
        return;
    }
    emit(tx, role, "ENC_HASH_VERIFIED", serde_json::json!({
        "hash": hex::encode(enc_hash),
    }));

    // 3. Check if already in seeder catalog
    {
        let cat = catalog.lock().unwrap();
        if cat.iter().any(|e| e.encrypted_hash == expected_enc_hash_hex) {
            emit(tx, role, "ALREADY_SEEDED", serde_json::json!({
                "encrypted_hash": expected_enc_hash_hex,
                "message": "Content already in seeder catalog",
            }));
            return;
        }
    }

    // 4. Derive file_name from enc_file_path (strip .enc suffix)
    let enc_filename = enc_file_path.split('/').last().unwrap_or("unknown.enc");
    let file_name = enc_filename.strip_suffix(".enc").unwrap_or(enc_filename).to_string();

    // 4b. Compute chunk metadata from the encrypted file
    let cs = chunk::select_chunk_size(encrypted.len());
    let (enc_chunks, meta) = chunk::split(&encrypted, cs);
    let enc_tree = MerkleTree::from_chunks(&enc_chunks);

    // 4c. Parse --chunks argument (e.g. "0,1,2,5-9")
    let chunks_held = parse_chunks_arg(chunks_arg, meta.count);
    if !chunks_held.is_empty() {
        emit(tx, role, "CHUNKS_SELECTED", serde_json::json!({
            "chunks_held": &chunks_held,
            "total_chunks": meta.count,
            "message": format!("Seeding {} of {} chunks", chunks_held.len(), meta.count),
        }));
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
        content_hash: String::new(),    // seeder doesn't know H(F)
        file_name: file_name.clone(),
        file_path: String::new(),       // seeder doesn't have plaintext
        enc_file_path: enc_file_path.to_string(),
        key_hex: String::new(),         // seeder doesn't have K
        price_sats: 0,                  // seeder doesn't set content price
        encrypted_hash: expected_enc_hash_hex.to_string(),
        size_bytes: encrypted.len() as u64,
        registered_at: registered_at.clone(),
        transport_price,
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: String::new(),  // seeder doesn't know plaintext root
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: chunks_held.clone(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    let chunks_seeding = if chunks_held.is_empty() { meta.count } else { chunks_held.len() };
    emit(tx, role, "CONTENT_SEEDED", serde_json::json!({
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
            "transport_price": transport_price,
            "chunk_count": meta.count,
            "chunks_held": &chunks_held,
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", info.url);
        match reqwest::blocking::Client::new().post(&url).json(&body).send() {
            Ok(resp) => println!("Registry: seeder announced ({})", resp.status()),
            Err(e) => eprintln!("Warning: failed to push seeder to registry: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// register command (add content to catalog)
// ---------------------------------------------------------------------------

fn handle_register(
    tx: &broadcast::Sender<ConsoleEvent>,
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    file_path: &str,
    price: u64,
    registry_info: &Option<RegistryInfo>,
) {
    let role = "creator";

    // 1. Read file
    let plaintext = std::fs::read(file_path).expect("Failed to read file");
    let file_name = file_path.split('/').last().unwrap_or(file_path).to_string();
    let size_bytes = plaintext.len() as u64;

    // 2. Compute content hash H(F)
    let content_hash = hex::encode(verify::sha256_hash(&plaintext));
    emit(tx, role, "HASH_COMPUTED", serde_json::json!({
        "hash": &content_hash,
        "file_name": &file_name,
    }));

    // 3. Check if already registered
    {
        let cat = catalog.lock().unwrap();
        if let Some(existing) = cat.iter().find(|e| e.content_hash == content_hash) {
            println!("Content already registered: {} ({})", file_name, content_hash);
            emit(tx, role, "ALREADY_REGISTERED", serde_json::json!({
                "content_hash": &content_hash,
                "file_name": &file_name,
                "price_sats": existing.price_sats,
            }));
            return;
        }
    }

    // 4. Generate content key K (permanent, reused for every buyer)
    let key = encrypt::generate_key();
    emit(tx, role, "KEY_GENERATED", serde_json::json!({
        "key": hex::encode(key),
        "message": "Content key K generated — stored in catalog, reused for every buyer",
    }));

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

    emit(tx, role, "CONTENT_ENCRYPTED", serde_json::json!({
        "plaintext_bytes": size_bytes,
        "ciphertext_bytes": ciphertext.len(),
        "enc_path": &enc_path,
        "encrypted_hash": &encrypted_hash,
    }));

    // 6. Save to catalog
    let registered_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        secs.to_string()
    };

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
        transport_price: 0,  // creator entries don't have transport price
        // P2P chunk metadata
        chunk_size: meta.chunk_size,
        chunk_count: meta.count,
        plaintext_root: hex::encode(plain_tree.root()),
        encrypted_root: hex::encode(enc_tree.root()),
        chunks_held: Vec::new(),  // empty = creator has all chunks
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    emit(tx, role, "CONTENT_REGISTERED", serde_json::json!({
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
    }));

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
            "registered_at": &registered_at,
        });
        let url = format!("{}/api/listings", info.url);
        match reqwest::blocking::Client::new().post(&url).json(&body).send() {
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
    tx: &broadcast::Sender<ConsoleEvent>,
    router: &Arc<EventRouter>,
    key: &[u8; 32],
) {
    let role = "creator";

    emit(tx, role, "WAITING_FOR_PAYMENT", serde_json::json!({
        "message": "Listening for incoming HTLC..."
    }));

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
                emit(tx, role, "HTLC_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": claimable_amount_msat,
                    "claim_deadline": claim_deadline,
                }));

                invoice::claim_payment(node, key, claimable_amount_msat)
                    .expect("Failed to claim payment");
                emit(tx, role, "PAYMENT_CLAIMED", serde_json::json!({
                    "preimage": hex::encode(key),
                    "message": "Preimage revealed to buyer via HTLC settlement",
                }));
            }
            Event::PaymentReceived {
                payment_hash: hash,
                amount_msat,
                ..
            } => {
                emit(tx, role, "PAYMENT_RECEIVED", serde_json::json!({
                    "payment_hash": hex::encode(hash.0),
                    "amount_msat": amount_msat,
                    "message": "Payment confirmed. Content sold.",
                }));
                break;
            }
            _ => {}
        }
    }
    router.unregister(&expected_hash);
}

// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buy command (two-phase: seeder + creator)
// ---------------------------------------------------------------------------

fn handle_buy_two_phase(
    node: &Arc<Node>,
    tx: &broadcast::Sender<ConsoleEvent>,
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
        emit(tx, role, "COUNTDOWN", serde_json::json!({
            "seconds": i,
            "message": format!("Paying creator in {}...", i),
        }));
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

    emit(tx, role, "CONTENT_PAYING", serde_json::json!({
        "bolt11": content_invoice,
        "message": "Paying creator for content key K...",
    }));

    // Try to pay; if DuplicatePayment, look up K from previous successful payment
    let key: [u8; 32];
    match invoice::pay_invoice(node, content_invoice) {
        Ok(hash_bytes_k) => {
            let target_hash_k = PaymentHash(hash_bytes_k);
            emit(tx, role, "CONTENT_PAYMENT_SENT", serde_json::json!({
                "payment_hash": hex::encode(hash_bytes_k),
            }));

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
                        emit(tx, role, "CONTENT_PAID", serde_json::json!({
                            "payment_hash": hex::encode(payment_hash.0),
                            "preimage_k": hex::encode(key),
                            "fee_msat": fee_paid_msat,
                            "message": "Content key K received! Can now decrypt from any seeder.",
                        }));
                        break;
                    }
                    Event::PaymentFailed {
                        reason,
                        ..
                    } => {
                        emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "payment_hash": hex::encode(target_hash_k.0),
                            "reason": format!("{:?}", reason),
                            "message": "Content payment failed. No money lost to seeders.",
                        }));
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
                emit(tx, role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));

                // Find the preimage from previous successful outbound payment with matching hash
                let target = PaymentHash(content_payment_hash);
                let mut found_key: Option<[u8; 32]> = None;
                for p in node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound && p.status == PaymentStatus::Succeeded
                }) {
                    if let PaymentKind::Bolt11 { hash, preimage: Some(pre), .. } = &p.kind {
                        if *hash == target {
                            found_key = Some(pre.0);
                            break;
                        }
                    }
                }

                match found_key {
                    Some(k) => {
                        key = k;
                        emit(tx, role, "CONTENT_PAID", serde_json::json!({
                            "preimage_k": hex::encode(key),
                            "message": "Content key K recovered from payment history. Skipping to seeder phase.",
                        }));
                    }
                    None => {
                        emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "message": "DuplicatePayment but could not find preimage in history. Cannot proceed.",
                        }));
                        return;
                    }
                }
            } else {
                emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                    "error": err_str,
                    "message": "Content payment failed.",
                }));
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
        match curl_fetch(url, tx) {
            Some(path) => path,
            None => return,
        }
    } else {
        emit(tx, role, "BUY_ERROR", serde_json::json!({
            "message": "No wrapped_url provided for two-phase buy",
        }));
        return;
    };
    let wrapped = std::fs::read(&wrapped_path).expect("Failed to read wrapped file");

    // 4. Pay transport invoice -> get K_S
    emit(tx, role, "TRANSPORT_PAYING", serde_json::json!({
        "bolt11": transport_invoice,
        "message": "Paying seeder for transport key K_S...",
    }));
    let hash_bytes_ks = invoice::pay_invoice(node, transport_invoice)
        .expect("Failed to pay transport invoice");
    let target_hash_ks = PaymentHash(hash_bytes_ks);
    emit(tx, role, "TRANSPORT_PAYMENT_SENT", serde_json::json!({
        "payment_hash": hex::encode(hash_bytes_ks),
    }));

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
                emit(tx, role, "TRANSPORT_PAID", serde_json::json!({
                    "payment_hash": hex::encode(payment_hash.0),
                    "preimage_ks": hex::encode(ks),
                    "fee_msat": fee_paid_msat,
                    "message": "Transport key K_S received!",
                }));
                break;
            }
            Event::PaymentFailed {
                reason,
                ..
            } => {
                emit(tx, role, "TRANSPORT_PAYMENT_FAILED", serde_json::json!({
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
    emit(tx, role, "CONTENT_UNWRAPPED", serde_json::json!({
        "wrapped_bytes": wrapped.len(),
        "encrypted_bytes": encrypted.len(),
        "key_ks": hex::encode(ks),
        "message": "Transport layer stripped with K_S",
    }));

    // 6. Verify H(E)
    if !enc_hash_hex.is_empty() {
        let enc_hash = verify::sha256_hash(&encrypted);
        let expected_bytes = hex::decode(enc_hash_hex).unwrap_or_default();
        let matches = enc_hash[..] == expected_bytes[..];
        emit(tx, role, "ENCRYPTED_HASH_VERIFIED", serde_json::json!({
            "matches": matches,
            "expected": enc_hash_hex,
            "actual": hex::encode(enc_hash),
        }));
        if !matches {
            emit(tx, role, "ENCRYPTED_HASH_MISMATCH", serde_json::json!({
                "expected": enc_hash_hex,
                "actual": hex::encode(enc_hash),
                "message": "Encrypted content hash mismatch after unwrap!",
            }));
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
    emit(tx, role, "CONTENT_DECRYPTED", serde_json::json!({
        "bytes": plaintext.len(),
        "key": hex::encode(key),
        "chunks": enc_chunks.len(),
    }));

    // 8. Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).expect("Invalid hex hash");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);
    let matches = verify::verify_hash(&plaintext, &expected_hash);
    emit(tx, role, "HASH_VERIFIED", serde_json::json!({
        "matches": matches,
        "expected": &req.hash,
        "actual": hex::encode(verify::sha256_hash(&plaintext)),
    }));
    if !matches {
        emit(tx, role, "HASH_MISMATCH", serde_json::json!({
            "expected": &req.hash,
            "actual": hex::encode(verify::sha256_hash(&plaintext)),
            "message": "Content hash mismatch!",
        }));
        return;
    }

    // 9. Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emit(tx, role, "FILE_SAVED", serde_json::json!({
        "path": &req.output,
        "bytes": plaintext.len(),
        "message": "Two-phase atomic content exchange complete.",
    }));
    println!();
    println!("=== BUY COMPLETE (two-phase) ===");
    println!("Decrypted file: {} ({} bytes)", req.output, plaintext.len());
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// A5: Chunked buy — fetch chunks from multiple seeders, verify, reassemble
// ---------------------------------------------------------------------------

fn handle_buy_chunked(
    node: &Arc<Node>,
    tx: &broadcast::Sender<ConsoleEvent>,
    router: &Arc<EventRouter>,
    req: &BuyRequest,
) {
    let role = "buyer";
    let content_invoice = match req.content_invoice.as_deref() {
        Some(inv) => inv,
        None => {
            emit(tx, role, "BUY_ERROR", serde_json::json!({
                "message": "Chunked buy requires content_invoice",
            }));
            return;
        }
    };
    let enc_hash_hex = match req.encrypted_hash.as_deref() {
        Some(h) => h.to_string(),
        None => {
            emit(tx, role, "BUY_ERROR", serde_json::json!({
                "message": "Chunked buy requires encrypted_hash",
            }));
            return;
        }
    };
    if req.seeder_urls.is_empty() {
        emit(tx, role, "BUY_ERROR", serde_json::json!({
            "message": "Chunked buy requires at least one seeder_url",
        }));
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 1: Pay creator for content key K (same as two-phase)
    // -----------------------------------------------------------------------

    for i in (1..=3).rev() {
        emit(tx, role, "COUNTDOWN", serde_json::json!({
            "seconds": i,
            "message": format!("Paying creator in {}...", i),
        }));
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

    emit(tx, role, "CONTENT_PAYING", serde_json::json!({
        "bolt11": content_invoice,
        "message": "Paying creator for content key K...",
    }));

    let key: [u8; 32];
    match invoice::pay_invoice(node, content_invoice) {
        Ok(hash_bytes_k) => {
            let target_hash_k = PaymentHash(hash_bytes_k);
            emit(tx, role, "CONTENT_PAYMENT_SENT", serde_json::json!({
                "payment_hash": hex::encode(hash_bytes_k),
            }));
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
                        emit(tx, role, "CONTENT_PAID", serde_json::json!({
                            "preimage_k": hex::encode(key),
                            "fee_msat": fee_paid_msat,
                            "message": "Content key K received!",
                        }));
                        break;
                    }
                    Event::PaymentFailed { reason, .. } => {
                        emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "reason": format!("{:?}", reason),
                            "message": "Content payment failed.",
                        }));
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
                emit(tx, role, "CONTENT_ALREADY_PAID", serde_json::json!({
                    "message": "Already paid for content key K. Looking up from payment history...",
                }));
                let target = PaymentHash(content_payment_hash);
                let payments = node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                });
                let found = payments.iter().find(|p| {
                    if let PaymentKind::Bolt11 { hash, preimage: Some(_), .. } = &p.kind {
                        *hash == target
                    } else {
                        false
                    }
                });
                match found {
                    Some(p) => {
                        if let PaymentKind::Bolt11 { preimage: Some(pre), .. } = &p.kind {
                            key = pre.0;
                            emit(tx, role, "CONTENT_PAID", serde_json::json!({
                                "preimage_k": hex::encode(key),
                                "message": "Recovered K from payment history.",
                            }));
                        } else {
                            emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                                "message": "Found payment but no preimage.",
                            }));
                            return;
                        }
                    }
                    None => {
                        emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                            "message": "DuplicatePayment but preimage not found in history.",
                        }));
                        return;
                    }
                }
            } else {
                emit(tx, role, "CONTENT_PAYMENT_FAILED", serde_json::json!({
                    "error": err_str,
                    "message": "Content payment failed.",
                }));
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
            emit(tx, role, "BUY_ERROR", serde_json::json!({
                "message": format!("Failed to fetch chunk metadata: {}", e),
            }));
            return;
        }
    };

    let chunk_count = meta["chunk_count"].as_u64().unwrap_or(0) as usize;
    let chunk_size = meta["chunk_size"].as_u64().unwrap_or(0) as usize;
    let encrypted_root = meta["encrypted_root"].as_str().unwrap_or("").to_string();

    emit(tx, role, "CHUNK_META_RECEIVED", serde_json::json!({
        "chunk_count": chunk_count,
        "chunk_size": chunk_size,
        "encrypted_root": &encrypted_root,
        "seeders": req.seeder_urls.len(),
    }));

    if chunk_count == 0 {
        emit(tx, role, "BUY_ERROR", serde_json::json!({
            "message": "chunk_count is 0 — content has no chunks",
        }));
        return;
    }

    // -----------------------------------------------------------------------
    // PHASE 3: Fetch bitfields from all seeders, build assignment plan
    // -----------------------------------------------------------------------

    // Collect bitfields: seeder_index -> Vec<bool>
    let mut seeder_bitfields: Vec<Vec<bool>> = Vec::new();
    for (_si, url) in req.seeder_urls.iter().enumerate() {
        let bf_url = format!("{}/api/chunks/{}/bitfield", url, &enc_hash_hex);
        match client.get(&bf_url).send().and_then(|r| r.json::<serde_json::Value>()) {
            Ok(bf) => {
                let bits: Vec<bool> = bf["bitfield"]
                    .as_array()
                    .map(|arr| arr.iter().map(|v| v.as_bool().unwrap_or(false)).collect())
                    .unwrap_or_default();
                emit(tx, role, "BITFIELD_RECEIVED", serde_json::json!({
                    "seeder": url,
                    "chunks_available": bits.iter().filter(|&&b| b).count(),
                    "total": chunk_count,
                }));
                seeder_bitfields.push(bits);
            }
            Err(e) => {
                emit(tx, role, "BITFIELD_FAILED", serde_json::json!({
                    "seeder": url,
                    "error": format!("{}", e),
                }));
                seeder_bitfields.push(vec![false; chunk_count]);
            }
        }
    }

    // Assign each chunk to a seeder (round-robin among seeders that have it)
    let mut assignments: Vec<Option<usize>> = vec![None; chunk_count];
    for chunk_idx in 0..chunk_count {
        // Find seeders that have this chunk
        let available: Vec<usize> = (0..req.seeder_urls.len())
            .filter(|&si| seeder_bitfields[si].get(chunk_idx).copied().unwrap_or(false))
            .collect();
        if available.is_empty() {
            emit(tx, role, "BUY_ERROR", serde_json::json!({
                "message": format!("No seeder has chunk {}!", chunk_idx),
                "chunk_index": chunk_idx,
            }));
            return;
        }
        // Round-robin: assign to seeder with fewest assignments so far
        let best = available.iter()
            .min_by_key(|&&si| assignments.iter().filter(|a| **a == Some(si)).count())
            .unwrap();
        assignments[chunk_idx] = Some(*best);
    }

    emit(tx, role, "CHUNK_PLAN", serde_json::json!({
        "assignments": assignments.iter().map(|a| a.unwrap_or(0)).collect::<Vec<_>>(),
        "message": format!("Chunk download plan ready: {} chunks across {} seeders", chunk_count, req.seeder_urls.len()),
    }));

    // -----------------------------------------------------------------------
    // PHASE 4: Request transport invoices from each seeder (batched per seeder)
    // -----------------------------------------------------------------------

    // Group chunks by seeder
    let mut seeder_chunks: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for (ci, assignment) in assignments.iter().enumerate() {
        if let Some(si) = assignment {
            seeder_chunks.entry(*si).or_default().push(ci);
        }
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
        let url = format!("{}/api/transport-invoice/{}", &req.seeder_urls[si], &enc_hash_hex);
        let body = serde_json::json!({ "chunks": chunks });
        match client.post(&url).json(&body).send().and_then(|r| r.json::<serde_json::Value>()) {
            Ok(resp) => {
                let bolt11 = resp["bolt11"].as_str().unwrap_or("").to_string();
                emit(tx, role, "TRANSPORT_INVOICE_RECEIVED", serde_json::json!({
                    "seeder": &req.seeder_urls[si],
                    "bolt11": &bolt11,
                    "chunks": chunks,
                    "transport_price": resp["transport_price"],
                }));
                transports.push(SeederTransport {
                    seeder_index: si,
                    chunks: chunks.clone(),
                    bolt11,
                    ks: None,
                });
            }
            Err(e) => {
                emit(tx, role, "BUY_ERROR", serde_json::json!({
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
        emit(tx, role, "TRANSPORT_PAYING", serde_json::json!({
            "seeder": &req.seeder_urls[transport.seeder_index],
            "bolt11": &transport.bolt11,
            "chunks": &transport.chunks,
        }));

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
                            emit(tx, role, "TRANSPORT_PAID", serde_json::json!({
                                "seeder": &req.seeder_urls[transport.seeder_index],
                                "preimage_ks": hex::encode(preimage.0),
                                "fee_msat": fee_paid_msat,
                                "chunks": &transport.chunks,
                            }));
                            break;
                        }
                        Event::PaymentFailed { reason, .. } => {
                            emit(tx, role, "TRANSPORT_PAYMENT_FAILED", serde_json::json!({
                                "seeder": &req.seeder_urls[transport.seeder_index],
                                "reason": format!("{:?}", reason),
                                "message": "Transport payment failed for this seeder.",
                            }));
                            router.unregister(&target_hash_ks);
                            return;
                        }
                        _ => {}
                    }
                }
                router.unregister(&target_hash_ks);
            }
            Err(e) => {
                emit(tx, role, "TRANSPORT_PAYMENT_FAILED", serde_json::json!({
                    "seeder": &req.seeder_urls[transport.seeder_index],
                    "error": format!("{:?}", e),
                }));
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
            let wc_url = format!("{}/api/wrapped-chunks/{}/{}", &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci);
            let wrapped_chunk = match client.get(&wc_url).send().and_then(|r| r.bytes()) {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    emit(tx, role, "CHUNK_DOWNLOAD_FAILED", serde_json::json!({
                        "chunk_index": ci,
                        "seeder": &req.seeder_urls[transport.seeder_index],
                        "error": format!("{}", e),
                    }));
                    return;
                }
            };

            // Unwrap: E_i = Dec(W_i, K_S, chunk_index=i)
            let enc_chunk = encrypt::decrypt(&wrapped_chunk, &ks, ci as u64);

            // Fetch Merkle proof and verify
            let proof_url = format!("{}/api/chunks/{}/proof/{}", &req.seeder_urls[transport.seeder_index], &enc_hash_hex, ci);
            match client.get(&proof_url).send().and_then(|r| r.json::<serde_json::Value>()) {
                Ok(proof_json) => {
                    // Verify chunk against encrypted Merkle root
                    let proof_data = &proof_json["proof"];
                    if let Ok(proof_json_obj) = serde_json::from_value::<conduit_core::merkle::MerkleProofJson>(proof_data.clone()) {
                        if let Ok(proof) = conduit_core::merkle::MerkleProof::from_json(&proof_json_obj) {
                            let root_bytes = hex::decode(&encrypted_root).unwrap_or_default();
                            let mut root = [0u8; 32];
                            if root_bytes.len() == 32 {
                                root.copy_from_slice(&root_bytes);
                            }
                            if proof.verify(&enc_chunk, ci, &root) {
                                emit(tx, role, "CHUNK_VERIFIED", serde_json::json!({
                                    "chunk_index": ci,
                                    "message": format!("Chunk {} Merkle proof verified", ci),
                                }));
                            } else {
                                emit(tx, role, "CHUNK_VERIFICATION_FAILED", serde_json::json!({
                                    "chunk_index": ci,
                                    "message": format!("Chunk {} Merkle proof FAILED — seeder sent bad data!", ci),
                                }));
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    emit(tx, role, "CHUNK_PROOF_FETCH_FAILED", serde_json::json!({
                        "chunk_index": ci,
                        "error": format!("{}", e),
                        "message": "Proof fetch failed — continuing without verification",
                    }));
                }
            }

            enc_chunks[ci] = Some(enc_chunk);
            emit(tx, role, "CHUNK_DOWNLOADED", serde_json::json!({
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
            emit(tx, role, "BUY_ERROR", serde_json::json!({
                "message": format!("Missing encrypted chunk {}", ci),
            }));
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

    emit(tx, role, "CHUNKS_DECRYPTED", serde_json::json!({
        "chunk_count": chunk_count,
        "message": format!("All {} chunks decrypted with K", chunk_count),
    }));

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

    emit(tx, role, "CONTENT_REASSEMBLED", serde_json::json!({
        "bytes": plaintext.len(),
        "chunks": chunk_count,
    }));

    // Verify H(F)
    let expected_hash_bytes = hex::decode(&req.hash).unwrap_or_default();
    let actual_hash = verify::sha256_hash(&plaintext);
    let matches = expected_hash_bytes.len() == 32 && actual_hash[..] == expected_hash_bytes[..];
    emit(tx, role, "HASH_VERIFIED", serde_json::json!({
        "matches": matches,
        "expected": &req.hash,
        "actual": hex::encode(actual_hash),
    }));
    if !matches {
        emit(tx, role, "HASH_MISMATCH", serde_json::json!({
            "expected": &req.hash,
            "actual": hex::encode(actual_hash),
            "message": "Content hash mismatch after reassembly!",
        }));
        return;
    }

    // Save
    std::fs::write(&req.output, &plaintext).expect("Failed to write decrypted file");
    emit(tx, role, "FILE_SAVED", serde_json::json!({
        "path": &req.output,
        "bytes": plaintext.len(),
        "chunks": chunk_count,
        "seeders": req.seeder_urls.len(),
        "message": "Chunked multi-source content exchange complete.",
    }));
    println!();
    println!("=== BUY COMPLETE (chunked) ===");
    println!("Decrypted file: {} ({} bytes, {} chunks from {} seeders)", req.output, plaintext.len(), chunk_count, req.seeder_urls.len());
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// buy command (single-phase: direct from creator)
// ---------------------------------------------------------------------------

fn handle_buy(
    node: &Arc<Node>,
    tx: &broadcast::Sender<ConsoleEvent>,
    router: &Arc<EventRouter>,
    bolt11_str: &str,
    enc_file_path: &str,
    expected_hash_hex: &str,
    output_path: &str,
) {
    let role = "buyer";

    // 1. Read encrypted file
    let ciphertext = std::fs::read(enc_file_path).expect("Failed to read encrypted file");
    println!("Read {} encrypted bytes from {}", ciphertext.len(), enc_file_path);

    // 2. Decode expected hash
    let expected_hash_bytes = hex::decode(expected_hash_hex).expect("Invalid hex hash");
    assert_eq!(expected_hash_bytes.len(), 32, "Hash must be 32 bytes");
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&expected_hash_bytes);

    // 3. Countdown — give the browser SSE time to connect
    for i in (1..=5).rev() {
        emit(tx, role, "COUNTDOWN", serde_json::json!({
            "seconds": i,
            "message": format!("Paying in {}...", i),
        }));
        thread::sleep(Duration::from_secs(1));
    }

    // 4. Pay invoice
    emit(tx, role, "PAYING_INVOICE", serde_json::json!({
        "bolt11": bolt11_str,
    }));
    let hash_bytes = invoice::pay_invoice(node, bolt11_str).expect("Failed to pay invoice");
    let target_hash = PaymentHash(hash_bytes);
    emit(tx, role, "PAYMENT_SENT", serde_json::json!({
        "payment_hash": hex::encode(hash_bytes),
        "message": "HTLC in flight, routing to creator...",
    }));

    // 4. Wait for preimage via event router
    let preimage_bytes: [u8; 32];
    let rx = router.register(target_hash);
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
                emit(tx, role, "PAYMENT_CONFIRMED", serde_json::json!({
                    "payment_hash": hex::encode(payment_hash.0),
                    "preimage": hex::encode(preimage_bytes),
                    "fee_msat": fee_paid_msat,
                    "message": "Preimage received! This is the decryption key.",
                }));
                break;
            }
            Event::PaymentFailed {
                reason,
                ..
            } => {
                emit(tx, role, "PAYMENT_FAILED", serde_json::json!({
                    "payment_hash": hex::encode(target_hash.0),
                    "reason": format!("{:?}", reason),
                }));
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
    emit(tx, role, "CONTENT_DECRYPTED", serde_json::json!({
        "bytes": decrypted.len(),
        "key": hex::encode(preimage_bytes),
        "chunks": enc_chunks.len(),
    }));

    // 6. Verify
    let matches = verify::verify_hash(&decrypted, &expected_hash);
    emit(tx, role, "HASH_VERIFIED", serde_json::json!({
        "matches": matches,
        "expected": expected_hash_hex,
        "actual": hex::encode(verify::sha256_hash(&decrypted)),
    }));
    if !matches {
        emit(tx, role, "HASH_MISMATCH", serde_json::json!({
            "expected": expected_hash_hex,
            "actual": hex::encode(verify::sha256_hash(&decrypted)),
            "message": "Content hash mismatch! File may be corrupted or the wrong .enc was used.",
        }));
        eprintln!("ERROR: Content hash mismatch! Expected {} got {}",
            expected_hash_hex, hex::encode(verify::sha256_hash(&decrypted)));
        return;
    }

    // 7. Write output
    std::fs::write(output_path, &decrypted).expect("Failed to write decrypted file");
    emit(tx, role, "FILE_SAVED", serde_json::json!({
        "path": output_path,
        "bytes": decrypted.len(),
        "message": "Atomic content exchange complete.",
    }));
    println!();
    println!("=== BUY COMPLETE ===");
    println!("Decrypted file: {} ({} bytes)", output_path, decrypted.len());
    println!("SHA-256 verified: content is authentic.");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "conduit-setup")]
#[command(about = "Conduit Lightning node with live console")]
struct Cli {
    /// Storage directory for LDK node data
    #[arg(long, default_value = "/tmp/conduit-node")]
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

    /// Path to directory containing ad creative files (advertiser role)
    #[arg(long)]
    ads_dir: Option<String>,

    /// Path to dashboard HTML file (unified UI). If set, GET / serves this
    /// file instead of the embedded console HTML.
    #[arg(long)]
    dashboard: Option<String>,

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
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
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

    let config = LightningConfig {
        storage_dir: cli.storage_dir,
        listening_port: cli.port,
        chain_source,
        ..LightningConfig::default()
    };

    // Start node
    let node = Arc::new(invoice::start_node(&config).expect("Failed to start node"));
    thread::sleep(Duration::from_secs(5));

    let id = invoice::node_id(&node);
    println!("Node {} on port {}", id, cli.port);

    // Create broadcast channel for console events
    let (events_tx, _) = broadcast::channel::<ConsoleEvent>(256);

    // Create event router and start background event loop
    let event_router = Arc::new(EventRouter::new(events_tx.clone()));
    {
        let router = event_router.clone();
        let node_for_router = node.clone();
        thread::spawn(move || {
            router.run(&node_for_router);
        });
    }

    // Load content catalog
    let catalog = Arc::new(std::sync::Mutex::new(load_catalog(&config.storage_dir)));
    {
        let cat = catalog.lock().unwrap();
        println!("Catalog: {} entries loaded from {}", cat.len(), catalog_path(&config.storage_dir));
    }

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
        let http_addr = cli.http_port
            .map(|p| format!("{}:{}", &public_ip, p))
            .unwrap_or_default();
        let ln_addr = format!("{}:{}", &public_ip, cli.port);
        RegistryInfo {
            url: url.trim_end_matches('/').to_string(),
            node_pubkey: id.clone(),
            http_address: http_addr,
            ln_address: ln_addr,
        }
    });

    // Start HTTP server if requested
    if let Some(http_port) = cli.http_port {
        // Initialize advertiser role if --ads-dir is set
        let (adv_db, adv_signing_key, adv_pubkey_hex, adv_ads_dir) = if let Some(ref ads_dir) = cli.ads_dir {
            let ads_path = if std::path::Path::new(ads_dir).is_absolute() {
                ads_dir.clone()
            } else {
                format!("{}/{}", config.storage_dir, ads_dir)
            };
            let _ = std::fs::create_dir_all(&ads_path);
            let db_path = format!("{}/advertiser.db", config.storage_dir);
            let conn = Connection::open(&db_path).expect("Failed to open advertiser database");
            adv_init_db(&conn);
            println!("[advertiser] Database: {}", db_path);
            let signing_key = adv_load_or_create_signing_key(&config.storage_dir);
            let verifying_key = VerifyingKey::from(&signing_key);
            let pubkey_hex = hex::encode(verifying_key.to_bytes());
            println!("[advertiser] Ed25519 pubkey: {}", pubkey_hex);
            adv_seed_default_campaign(&conn, &ads_path);
            (
                Some(Arc::new(std::sync::Mutex::new(conn))),
                Some(Arc::new(signing_key)),
                Some(pubkey_hex),
                Some(ads_path),
            )
        } else {
            (None, None, None, None)
        };

        let state = AppState {
            node: node.clone(),
            events_tx: events_tx.clone(),
            event_router: event_router.clone(),
            catalog: catalog.clone(),
            storage_dir: config.storage_dir.clone(),
            registry_info: registry_info.clone(),
            advertiser_db: adv_db,
            advertiser_signing_key: adv_signing_key,
            advertiser_pubkey_hex: adv_pubkey_hex,
            ads_dir: adv_ads_dir,
            dashboard_path: cli.dashboard.clone(),
        };
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
            handle_register(&events_tx, &config.storage_dir, &catalog, &file, price, &registry_info);
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
            handle_seed(&events_tx, &config.storage_dir, &catalog, &encrypted_file, &encrypted_hash, transport_price, &registry_info, &chunks);
        }

        Commands::Sell { file, price } => {
            event_router.set_role("creator");
            handle_sell(&node, &events_tx, &event_router, &file, price);
        }

        Commands::Buy {
            invoice,
            encrypted_file,
            hash,
            output,
        } => {
            event_router.set_role("buyer");
            handle_buy(&node, &events_tx, &event_router, &invoice, &encrypted_file, &hash, &output);
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
