use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "conduit-setup")]
#[command(about = "Conduit Lightning node with live console")]
pub struct Cli {
    /// Storage directory for LDK node data
    #[arg(long, default_value = "/var/lib/conduit-node")]
    pub storage_dir: String,

    /// Lightning listening port
    #[arg(long, default_value = "9735")]
    pub port: u16,

    /// Esplora server URL
    #[arg(long)]
    pub esplora: Option<String>,

    /// Bitcoind RPC host
    #[arg(long)]
    pub rpc_host: Option<String>,

    /// Bitcoind RPC port
    #[arg(long, default_value = "38332")]
    pub rpc_port: u16,

    /// Bitcoind RPC username
    #[arg(long, default_value = "lightning")]
    pub rpc_user: String,

    /// Bitcoind RPC password
    #[arg(long, default_value = "lightning")]
    pub rpc_password: String,

    /// HTTP port for the live console (off if not set)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Registry URL for content discovery (optional, e.g. http://localhost:3003)
    #[arg(long)]
    pub registry_url: Option<String>,

    /// Public IP/hostname for this node (used in registry announcements).
    /// If omitted, attempts to detect via external service.
    #[arg(long)]
    pub public_ip: Option<String>,

    /// Enable advertiser role. Value is an arbitrary label (e.g. "enabled").
    /// Advertisers host creative media on their own servers and register
    /// campaigns via the API with a creative_url.
    #[arg(long)]
    pub ads_dir: Option<String>,

    /// Human-readable node alias (max 32 bytes). Shown in network explorers
    /// and the dashboard network visualization.
    #[arg(long)]
    pub alias: Option<String>,

    /// Path to dashboard HTML file (unified UI). If set, GET / serves this
    /// file instead of the embedded console HTML.
    #[arg(long)]
    pub dashboard: Option<String>,

    /// Path to Vite build output directory. If set, serves the built
    /// frontend from this directory instead of the individual dashboard files.
    #[arg(long)]
    pub ui_dist: Option<String>,

    /// Enable P2P chunk transport (iroh QUIC). When set, the node also
    /// listens for direct peer connections in addition to HTTP.
    #[arg(long)]
    pub p2p: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
