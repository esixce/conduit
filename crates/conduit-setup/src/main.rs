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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;

mod buy;
mod catalog;
mod cli;
mod console;
mod events;
mod handlers;
mod sell;
mod state;

use catalog::*;
use cli::*;
use events::*;
use state::*;

use buy::pre::handle_buy_pre;
use buy::simple::handle_buy;
use handlers::campaigns::{adv_init_db, adv_load_or_create_signing_key};
use handlers::content::*;
use handlers::p2p::ConduitChunkStore;
use sell::*;

use clap::Parser;
use conduit_core::invoice::{self, ChainSource, LightningConfig};
use conduit_core::pre;

use ed25519_dalek::VerifyingKey;
use ldk_node::lightning::ln::msgs::SocketAddress;
use rusqlite::Connection;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

// ---------------------------------------------------------------------------
// HTTP server — route registration
// ---------------------------------------------------------------------------

fn start_http_server(port: u16, state: AppState) {
    use handlers::advertiser::*;
    use handlers::campaigns::*;
    use handlers::chunks::*;
    use handlers::p2p::*;
    use handlers::pre::*;
    use handlers::sse::*;
    use handlers::tee::*;
    use handlers::wallet::*;

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            let ui_dist = state.ui_dist.clone();

            let mut app = Router::new()
                .route("/", get(index_handler))
                .route("/{filename}", get(pwa_static_handler))
                .route("/api/info", get(info_handler))
                .route("/api/address", get(address_handler))
                .route("/api/channels/open", post(channel_open_handler))
                .route("/api/channels/{user_channel_id}/close", post(channel_close_handler))
                .route("/api/channels/peers", get(channel_peers_handler))
                .route("/api/best-source/{content_hash}", get(best_source_handler))
                .route("/api/discover-sources/{content_hash}", get(discover_sources_handler))
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

            if let Some(ref dist) = ui_dist {
                let index_fallback = ServeFile::new(format!("{}/index.html", dist));
                app = app.fallback_service(ServeDir::new(dist).fallback(index_fallback));
            }
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
                .await
                .expect("Failed to bind HTTP port");
            println!("Console: http://0.0.0.0:{}", port);
            axum::serve(listener, app).await.unwrap();
        });
    });
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
            if entry.encrypted_hash.is_empty() || !entry.content_hash.is_empty() {
                continue;
            }
            if entry.chunk_count == 0 {
                continue;
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
            ui_dist: cli.ui_dist.clone(),
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

            thread::spawn(move || {
                rt.block_on(std::future::pending::<()>());
            });
        }

        start_http_server(http_port, state);
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
                "smart",
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::buy::chunked::plan_chunk_assignments;

    #[test]
    fn uniform_availability() {
        let bf = vec![
            vec![true, true, true, true, true, true],
            vec![true, true, true, true, true, true],
        ];
        let (order, assignments) = plan_chunk_assignments(6, &bf);

        assert!(assignments.iter().all(|a| a.is_some()));

        let s0 = assignments.iter().filter(|a| **a == Some(0)).count();
        let s1 = assignments.iter().filter(|a| **a == Some(1)).count();
        assert_eq!(s0, 3);
        assert_eq!(s1, 3);

        assert_eq!(order.len(), 6);
        let mut sorted_order = order.clone();
        sorted_order.sort();
        assert_eq!(sorted_order, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn skewed_availability_rarest_first() {
        let bf = vec![vec![true, true, true, true], vec![true, true, false, true]];
        let (order, assignments) = plan_chunk_assignments(4, &bf);

        assert_eq!(order[0], 2);
        assert_eq!(assignments[2], Some(0));
        assert!(assignments.iter().all(|a| a.is_some()));
    }

    #[test]
    fn no_availability() {
        let bf = vec![vec![true, false, true], vec![true, false, true]];
        let (order, assignments) = plan_chunk_assignments(3, &bf);

        assert_eq!(assignments[1], None);
        assert_eq!(order[0], 1);
        assert!(assignments[0].is_some());
        assert!(assignments[2].is_some());
    }

    #[test]
    fn single_seeder() {
        let bf = vec![vec![true, true, true, true, true]];
        let (_order, assignments) = plan_chunk_assignments(5, &bf);

        assert!(assignments.iter().all(|a| *a == Some(0)));
    }

    #[test]
    fn three_seeders_partial_overlap() {
        let bf = vec![
            vec![true, true, true, false, false, true],
            vec![false, true, true, true, false, true],
            vec![false, false, true, true, true, true],
        ];
        let (order, assignments) = plan_chunk_assignments(6, &bf);

        let first_two: Vec<usize> = order[..2].to_vec();
        assert!(
            first_two.contains(&0),
            "chunk 0 (rarity 1) should be in first two"
        );
        assert!(
            first_two.contains(&4),
            "chunk 4 (rarity 1) should be in first two"
        );

        assert_eq!(assignments[0], Some(0));
        assert_eq!(assignments[4], Some(2));

        assert!(assignments.iter().all(|a| a.is_some()));

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
