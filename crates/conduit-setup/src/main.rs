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
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn index_handler() -> Html<&'static str> {
    Html(CONSOLE_HTML)
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
}

#[derive(Deserialize)]
struct SeedRequest {
    encrypted_file: String,      // path to E on disk
    encrypted_hash: String,      // H(E) hex
    transport_price: u64,        // sats for transport
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
    let is_two_phase = req.transport_invoice.is_some() && req.content_invoice.is_some();
    thread::spawn(move || {
        if is_two_phase {
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
        handle_seed(&tx, &storage_dir, &catalog, &req.encrypted_file, &req.encrypted_hash, req.transport_price, &registry_info);
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

async fn transport_invoice_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
) -> impl IntoResponse {
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

    // Wrap: W = Enc(E, K_S)
    let wrapped = encrypt::encrypt(&encrypted, &ks, 0);
    let wrapped_path = format!("{}.wrapped", entry.enc_file_path);
    let wrapped_filename = wrapped_path.split('/').last().unwrap_or("").to_string();
    if let Err(e) = std::fs::write(&wrapped_path, &wrapped) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to write wrapped file: {}", e)
        }))).into_response();
    }

    // Create transport invoice (preimage = K_S)
    let bolt11 = match invoice::create_invoice_for_key(
        &state.node, &ks, entry.transport_price, "transport"
    ) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to create invoice: {}", e)
        }))).into_response(),
    };

    let payment_hash = hex::encode(verify::sha256_hash(&ks));

    // Emit SSE event
    let tx = state.events_tx.clone();
    emit(&tx, "seeder", "TRANSPORT_INVOICE_CREATED", serde_json::json!({
        "payment_hash": &payment_hash,
        "amount_sats": entry.transport_price,
        "bolt11": &bolt11,
        "wrapped_filename": &wrapped_filename,
        "encrypted_hash": &encrypted_hash,
    }));

    // Spawn thread to wait for payment and claim it
    let node = state.node.clone();
    let tx2 = state.events_tx.clone();
    let router = state.event_router.clone();
    thread::spawn(move || {
        handle_transport_payment(&node, &tx2, &router, &ks);
    });

    // Return invoice data
    Json(serde_json::json!({
        "bolt11": bolt11,
        "payment_hash": payment_hash,
        "encrypted_hash": encrypted_hash,
        "transport_price": entry.transport_price,
        "wrapped_filename": wrapped_filename,
    })).into_response()
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
                .route("/api/sell", post(sell_handler))
                .route("/api/buy", post(buy_handler))
                .route("/api/seed", post(seed_handler))
                .route("/api/transport-invoice/{encrypted_hash}", post(transport_invoice_handler))
                .route("/api/enc/{filename}", get(enc_file_handler))
                .route("/api/wrapped/{filename}", get(wrapped_file_handler))
                .route("/api/decrypted/{filename}", get(decrypted_file_handler))
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
        // Seeder doesn't compute these -- will be fetched from creator catalog
        chunk_size: 0,
        chunk_count: 0,
        plaintext_root: String::new(),
        encrypted_root: String::new(),
    };

    {
        let mut cat = catalog.lock().unwrap();
        cat.push(entry);
        save_catalog(storage_dir, &cat);
    }

    emit(tx, role, "CONTENT_SEEDED", serde_json::json!({
        "encrypted_hash": expected_enc_hash_hex,
        "file_name": &file_name,
        "transport_price": transport_price,
        "size_bytes": encrypted.len(),
        "message": "Content added to seeder catalog. Transport invoices generated on demand.",
    }));

    // Push seeder announcement to registry (fire-and-forget)
    if let Some(ref info) = registry_info {
        let body = serde_json::json!({
            "encrypted_hash": expected_enc_hash_hex,
            "seeder_pubkey": &info.node_pubkey,
            "seeder_address": &info.http_address,
            "seeder_ln_address": &info.ln_address,
            "transport_price": transport_price,
            "chunk_count": 0,
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", info.url);
        let _ = tokio::runtime::Handle::current().spawn(async move {
            let client = reqwest::Client::new();
            match client.post(&url).json(&body).send().await {
                Ok(resp) => println!("Registry: seeder announced ({})", resp.status()),
                Err(e) => eprintln!("Warning: failed to push seeder to registry: {}", e),
            }
        });
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

    // Push listing to registry (fire-and-forget)
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
        let _ = tokio::runtime::Handle::current().spawn(async move {
            let client = reqwest::Client::new();
            match client.post(&url).json(&body).send().await {
                Ok(resp) => println!("Registry: listing pushed ({})", resp.status()),
                Err(e) => eprintln!("Warning: failed to push listing to registry: {}", e),
            }
        });
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

    // 7. Decrypt: F = Dec(E, K) — using the key we already got from the creator
    let plaintext = encrypt::decrypt(&encrypted, &key, 0);
    emit(tx, role, "CONTENT_DECRYPTED", serde_json::json!({
        "bytes": plaintext.len(),
        "key": hex::encode(key),
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

    // 5. Decrypt
    let decrypted = encrypt::decrypt(&ciphertext, &preimage_bytes, 0);
    emit(tx, role, "CONTENT_DECRYPTED", serde_json::json!({
        "bytes": decrypted.len(),
        "key": hex::encode(preimage_bytes),
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
    let registry_info = cli.registry_url.as_ref().map(|url| {
        let http_addr = cli.http_port
            .map(|p| format!("0.0.0.0:{}", p))
            .unwrap_or_default();
        let ln_addr = format!("0.0.0.0:{}", cli.port);
        RegistryInfo {
            url: url.trim_end_matches('/').to_string(),
            node_pubkey: id.clone(),
            http_address: http_addr,
            ln_address: ln_addr,
        }
    });

    // Start HTTP server if requested
    if let Some(http_port) = cli.http_port {
        let state = AppState {
            node: node.clone(),
            events_tx: events_tx.clone(),
            event_router: event_router.clone(),
            catalog: catalog.clone(),
            storage_dir: config.storage_dir.clone(),
            registry_info: registry_info.clone(),
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
        } => {
            handle_seed(&events_tx, &config.storage_dir, &catalog, &encrypted_file, &encrypted_hash, transport_price, &registry_info);
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
