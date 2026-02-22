use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::catalog::TrustedManufacturer;
use super::events::{ConsoleEmitter, EventRouter};

// ---------------------------------------------------------------------------
// Registry push info (for publishing to the central registry)
// ---------------------------------------------------------------------------

/// Information needed to push listings/announcements to the registry.
/// Constructed once at startup and cloned into handlers.
#[derive(Clone)]
pub struct RegistryInfo {
    /// Registry base URL (e.g. "http://localhost:3003")
    pub url: String,
    /// This node's Lightning pubkey (hex)
    pub node_pubkey: String,
    /// This node's HTTP API address (e.g. "1.2.3.4:3000")
    pub http_address: String,
    /// This node's Lightning listening address (e.g. "1.2.3.4:9735")
    pub ln_address: String,
    /// Human-readable alias for this node
    pub node_alias: String,
}

// ---------------------------------------------------------------------------
// Axum app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub node: Arc<ldk_node::Node>,
    pub node_alias: String,
    pub emitter: Arc<ConsoleEmitter>,
    pub event_router: Arc<EventRouter>,
    pub catalog: Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    pub storage_dir: String,
    pub registry_info: Option<RegistryInfo>,
    // PRE (Phase 2A)
    pub pre_buyer_pk_hex: String,
    #[allow(dead_code)]
    pub pre_buyer_sk: bls12_381::Scalar,
    // TEE trust list
    pub trust_list: Arc<std::sync::Mutex<Vec<TrustedManufacturer>>>,
    // Advertiser role
    pub advertiser_db: Option<Arc<std::sync::Mutex<Connection>>>,
    pub advertiser_signing_key: Option<Arc<SigningKey>>,
    pub advertiser_pubkey_hex: Option<String>,
    #[allow(dead_code)]
    pub ads_dir: Option<String>,
    // Dashboard
    pub dashboard_path: Option<String>,
    // Vite build output directory
    pub ui_dist: Option<String>,
    // P2P (iroh)
    pub p2p_node: Option<Arc<conduit_p2p::node::P2pNode>>,
    pub p2p_runtime_handle: Option<tokio::runtime::Handle>,
}

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub node_alias: String,
    pub onchain_balance_sats: u64,
    pub spendable_onchain_sats: u64,
    pub lightning_balance_sats: u64,
    pub channels: Vec<ChannelInfo>,
}

#[derive(Serialize)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub user_channel_id: String,
    pub counterparty_node_id: String,
    pub value_sats: u64,
    pub outbound_msat: u64,
    pub inbound_msat: u64,
    pub ready: bool,
    pub usable: bool,
}

// ---------------------------------------------------------------------------
// API request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OpenChannelRequest {
    pub node_id: String,
    pub addr: String,
    pub amount_sats: u64,
}

#[derive(Deserialize)]
pub struct CloseChannelRequest {
    pub counterparty_node_id: String,
}

#[derive(Deserialize)]
pub struct SellRequest {
    pub file: String,
    pub price: u64,
}

#[derive(Deserialize)]
pub struct BuyRequest {
    pub hash: String, // H(F) — plaintext hash
    pub output: String,
    // --- Two-phase buy (seeder flow) ---
    #[serde(default)]
    pub wrapped_url: Option<String>, // URL to fetch W from seeder
    #[serde(default)]
    pub transport_invoice: Option<String>, // Seeder's invoice (preimage = K_S)
    #[serde(default)]
    pub content_invoice: Option<String>, // Creator's invoice (preimage = K)
    #[serde(default)]
    pub encrypted_hash: Option<String>, // H(E) — for intermediate verification
    // --- Legacy single-phase buy ---
    #[serde(default)]
    pub invoice: Option<String>, // single invoice (backward compat)
    #[serde(default)]
    pub encrypted_file: Option<String>, // local path (legacy)
    #[serde(default)]
    pub enc_url: Option<String>, // HTTP URL to fetch .enc from creator
    // --- Chunked buy (A5: multi-source) ---
    #[serde(default)]
    pub seeder_urls: Vec<String>, // list of seeder HTTP base URLs
    #[serde(default)]
    pub mode: Option<String>, // "chunked" to enable chunk-level download
}

#[derive(Deserialize)]
pub struct SeedRequest {
    pub encrypted_file: String, // path to E on disk
    pub encrypted_hash: String, // H(E) hex
    pub transport_price: u64,   // sats for transport
    #[serde(default)]
    pub chunks: Option<String>, // which chunks to seed (e.g. "0,1,2,5-9"), omit for all
}

// ---------------------------------------------------------------------------
// Content Catalog — persistent registry of content available for sale
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub content_hash: String,   // H(F) hex — unique content ID (empty for seeder)
    pub file_name: String,      // display name (e.g. "btc-logo.png")
    pub file_path: String,      // original file path on disk (empty for seeder)
    pub enc_file_path: String,  // path to encrypted file E
    pub key_hex: String,        // K hex — SECRET, never exposed via API (empty for seeder)
    pub price_sats: u64,        // content price (0 for seeder — seeder uses transport_price)
    pub encrypted_hash: String, // H(E) hex
    pub size_bytes: u64,        // original plaintext size (enc size for seeder)
    pub registered_at: String,  // unix timestamp
    #[serde(default)]
    pub transport_price: u64, // sats for transport (0 for creator entries, >0 for seeder)
    // --- P2P chunk metadata (A3) ---
    #[serde(default)]
    pub chunk_size: usize, // bytes per chunk (0 = legacy single-blob)
    #[serde(default)]
    pub chunk_count: usize, // number of chunks (0 = legacy)
    #[serde(default)]
    pub plaintext_root: String, // Merkle root of H(plaintext chunks), hex
    #[serde(default)]
    pub encrypted_root: String, // Merkle root of H(encrypted chunks), hex
    #[serde(default)]
    pub chunks_held: Vec<usize>, // which chunk indices this node has (empty = all)
    // --- PRE (Phase 2A) ---
    #[serde(default)]
    pub pre_c1_hex: String, // PRE ciphertext c1 (compressed G1, 48 bytes, hex)
    #[serde(default)]
    pub pre_c2_hex: String, // PRE ciphertext c2 (m XOR mask, 32 bytes, hex)
    #[serde(default)]
    pub pre_pk_creator_hex: String, // Creator's PRE public key (compressed G1, 48 bytes, hex)
    // --- TEE playback policy ---
    #[serde(default = "default_playback_policy")]
    pub playback_policy: String, // "open" | "device_recommended" | "device_required"
}

pub fn default_playback_policy() -> String {
    "open".to_string()
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub file: String,
    pub price: u64,
}

/// Request body for PRE buy (browser-initiated).
#[derive(Deserialize)]
pub struct BuyPreRequest {
    /// Creator HTTP base URL (e.g. "http://167.172.152.231:3000")
    pub creator_url: String,
    /// Content hash from catalog
    pub content_hash: String,
    /// Optional seeder URL to download chunks from (defaults to creator)
    #[serde(default)]
    pub seeder_url: Option<String>,
    /// Output path for decrypted file
    #[serde(default = "default_pre_output")]
    pub output: String,
    /// Source mode: "smart" (ICS multi-source, default), "creator" (creator only),
    /// or a specific seeder URL to force.
    #[serde(default = "default_source_mode")]
    pub source_mode: String,
}

pub fn default_source_mode() -> String {
    "smart".to_string()
}

pub fn default_pre_output() -> String {
    format!(
        "/tmp/decrypted-pre-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )
}

#[derive(Deserialize)]
pub struct EventsHistoryQuery {
    #[serde(default)]
    pub since_id: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub role: Option<String>,
}

pub fn ensurehttp(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{}", addr)
    }
}
