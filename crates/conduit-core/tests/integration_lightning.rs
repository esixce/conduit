//! Integration tests for Conduit Lightning nodes.
//!
//! These tests spin up real LDK nodes, connect to a chain source
//! (bitcoind RPC or Esplora), and exercise the full invoice/payment
//! cycle including the atomic content exchange.
//!
//! **Chain source configuration (env vars):**
//!
//! For bitcoind RPC (custom signet):
//! ```bash
//! CONDUIT_RPC_HOST=YOUR_BITCOIND_HOST
//! CONDUIT_RPC_PORT=38332          # default
//! CONDUIT_RPC_USER=lightning      # default
//! CONDUIT_RPC_PASSWORD=lightning  # default
//! ```
//!
//! For Esplora:
//! ```bash
//! CONDUIT_ESPLORA_URL=https://mempool.space/signet/api
//! ```
//!
//! If neither is set, falls back to mempool.space/signet/api.
//!
//! **Run with:**
//! ```bash
//! CONDUIT_INTEGRATION=1 \
//! CONDUIT_RPC_HOST=YOUR_BITCOIND_HOST \
//! cargo test -p conduit-core --test integration_lightning -- --nocapture
//! ```
//!
//! **Prerequisites:**
//! - Network access to the chain source (bitcoind RPC or Esplora)
//! - For tests 3 & 4: funded nodes with an open channel
//!   (set CONDUIT_CREATOR_STORAGE / CONDUIT_BUYER_STORAGE)
//! - For tests 3 & 4: stop any running conduit-setup processes first
//!   (they lock the node storage)

use std::thread;
use std::time::Duration;

use conduit_core::invoice::{self, ChainSource, LightningConfig};
use conduit_core::verify;

/// Skip the test if CONDUIT_INTEGRATION is not set.
/// Returns `true` if the test should run, `false` to skip.
fn integration_enabled() -> bool {
    if std::env::var("CONDUIT_INTEGRATION").is_err() {
        eprintln!("SKIP: Set CONDUIT_INTEGRATION=1 to run integration tests.");
        return false;
    }
    true
}

/// Build a `ChainSource` from environment variables.
///
/// Priority:
/// 1. CONDUIT_RPC_HOST set -> BitcoindRpc
/// 2. CONDUIT_ESPLORA_URL set -> Esplora
/// 3. Neither -> Esplora with mempool.space/signet default
fn test_chain_source() -> ChainSource {
    if let Ok(host) = std::env::var("CONDUIT_RPC_HOST") {
        let port: u16 = std::env::var("CONDUIT_RPC_PORT")
            .unwrap_or_else(|_| "38332".into())
            .parse()
            .expect("CONDUIT_RPC_PORT must be a valid u16");
        let user = std::env::var("CONDUIT_RPC_USER").unwrap_or_else(|_| "lightning".into());
        let password = std::env::var("CONDUIT_RPC_PASSWORD").unwrap_or_else(|_| "lightning".into());
        ChainSource::BitcoindRpc {
            host,
            port,
            user,
            password,
        }
    } else if let Ok(url) = std::env::var("CONDUIT_ESPLORA_URL") {
        ChainSource::Esplora(url)
    } else {
        ChainSource::Esplora("https://mempool.space/signet/api".into())
    }
}

/// Create a unique temp directory for node storage.
fn temp_node_dir(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "conduit-integration-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir.to_string_lossy().to_string()
}

/// Clean up a node's storage directory.
fn cleanup_dir(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

// ---------------------------------------------------------------------------
// Test 1: Node lifecycle -- start_node, node_id, listening_addresses, stop
// ---------------------------------------------------------------------------

#[test]
fn test_start_and_stop_node() {
    if !integration_enabled() {
        return;
    }

    let storage = temp_node_dir("lifecycle");
    let config = LightningConfig {
        storage_dir: storage.clone(),
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: 19735,
        chain_source: test_chain_source(),
    };

    eprintln!("Starting node with storage: {}", storage);
    let node = invoice::start_node(&config).expect("node should start");

    // node_id should return a non-empty hex public key (66 hex chars for compressed)
    let id = invoice::node_id(&node);
    eprintln!("Node ID: {}", id);
    assert!(!id.is_empty(), "node_id must not be empty");
    assert!(
        id.len() == 66,
        "compressed public key should be 66 hex chars, got {}",
        id.len()
    );

    // listening_addresses should include our port
    let addrs = invoice::listening_addresses(&node);
    eprintln!("Listening addresses: {:?}", addrs);
    assert!(
        !addrs.is_empty(),
        "node should have at least one listening address"
    );
    assert!(
        addrs.iter().any(|a| a.contains("19735")),
        "listening addresses should contain our port 19735"
    );

    // Stop cleanly
    node.stop().expect("node should stop");
    eprintln!("Node stopped.");

    cleanup_dir(&storage);
}

// ---------------------------------------------------------------------------
// Test 2: Invoice creation -- create_invoice_for_key, verify payment_hash
// ---------------------------------------------------------------------------

#[test]
fn test_create_invoice_payment_hash() {
    if !integration_enabled() {
        return;
    }

    let storage = temp_node_dir("invoice");
    let config = LightningConfig {
        storage_dir: storage.clone(),
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: 19736,
        chain_source: test_chain_source(),
    };

    let node = invoice::start_node(&config).expect("node should start");
    eprintln!("Node started: {}", invoice::node_id(&node));

    // Give the node a moment to sync
    thread::sleep(Duration::from_secs(3));

    // Create an invoice with a known key
    let key = [0x42_u8; 32];
    let expected_hash = verify::sha256_hash(&key);

    let bolt11_str = invoice::create_invoice_for_key(&node, &key, 1000, "test content")
        .expect("invoice creation should succeed");

    eprintln!("Invoice: {}", bolt11_str);
    assert!(
        bolt11_str.starts_with("lntbs") || bolt11_str.starts_with("lnsb"),
        "signet invoice should start with lntbs or lnsb, got: {}",
        &bolt11_str[..8.min(bolt11_str.len())]
    );

    // Parse the invoice and verify payment hash matches SHA-256(key)
    use ldk_node::lightning_invoice::Bolt11Invoice;
    let invoice_parsed: Bolt11Invoice = bolt11_str.parse().expect("should parse as valid BOLT11");

    let invoice_hash_bytes: &[u8] = invoice_parsed.payment_hash().as_ref();
    let mut invoice_hash = [0u8; 32];
    invoice_hash.copy_from_slice(invoice_hash_bytes);

    assert_eq!(
        invoice_hash, expected_hash,
        "Invoice payment_hash must equal SHA-256(key)"
    );
    eprintln!("Payment hash matches SHA-256(key).");

    node.stop().expect("node should stop");
    cleanup_dir(&storage);
}

// ---------------------------------------------------------------------------
// Test 3: Full payment cycle
//
// This is the big one. It exercises:
//   - start_node (x2)
//   - create_invoice_for_key
//   - pay_invoice
//   - wait_and_claim_payment
//   - wait_for_outbound_payment
//   - claim_payment (called internally by wait_and_claim_payment)
//
// REQUIREMENTS:
//   - Both nodes must already have a funded, open channel between them.
//   - Set these env vars:
//       CONDUIT_CREATOR_STORAGE  -- path to creator node's persistent storage
//       CONDUIT_BUYER_STORAGE    -- path to buyer node's persistent storage
//       CONDUIT_CREATOR_PORT     -- creator's Lightning port (default 9735)
//       CONDUIT_BUYER_PORT       -- buyer's Lightning port (default 9736)
//
// If the storage env vars are not set, this test is skipped (it requires
// pre-existing funded nodes with a channel).
// ---------------------------------------------------------------------------

#[test]
fn test_full_payment_cycle() {
    if !integration_enabled() {
        return;
    }

    // These env vars point to pre-existing node storage with funded channels.
    let creator_storage = match std::env::var("CONDUIT_CREATOR_STORAGE") {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "SKIP: Set CONDUIT_CREATOR_STORAGE and CONDUIT_BUYER_STORAGE \
                 to run the full payment cycle test."
            );
            return;
        }
    };
    let buyer_storage = std::env::var("CONDUIT_BUYER_STORAGE")
        .expect("CONDUIT_BUYER_STORAGE must be set if CONDUIT_CREATOR_STORAGE is set");

    let creator_port: u16 = std::env::var("CONDUIT_CREATOR_PORT")
        .unwrap_or_else(|_| "9735".into())
        .parse()
        .expect("CONDUIT_CREATOR_PORT must be a valid port");
    let buyer_port: u16 = std::env::var("CONDUIT_BUYER_PORT")
        .unwrap_or_else(|_| "9736".into())
        .parse()
        .expect("CONDUIT_BUYER_PORT must be a valid port");

    // Start both nodes with their existing storage (channels, keys intact)
    let chain_source = test_chain_source();
    let creator_config = LightningConfig {
        storage_dir: creator_storage,
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: creator_port,
        chain_source: chain_source.clone(),
    };
    let buyer_config = LightningConfig {
        storage_dir: buyer_storage,
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: buyer_port,
        chain_source,
    };

    eprintln!("Starting creator node...");
    let creator_node = invoice::start_node(&creator_config).expect("creator node should start");
    eprintln!("Creator node: {}", invoice::node_id(&creator_node));

    eprintln!("Starting buyer node...");
    let buyer_node = invoice::start_node(&buyer_config).expect("buyer node should start");
    eprintln!("Buyer node: {}", invoice::node_id(&buyer_node));

    // Let nodes sync and discover each other's channels
    eprintln!("Waiting for nodes to sync...");
    thread::sleep(Duration::from_secs(10));

    // -- Creator: generate a key and create an invoice --
    let key = conduit_core::encrypt::generate_key();
    let expected_hash = verify::sha256_hash(&key);
    eprintln!("Content key (hex): {}", hex::encode(key));
    eprintln!("Expected payment hash: {}", hex::encode(expected_hash));

    let bolt11 = invoice::create_invoice_for_key(
        &creator_node,
        &key,
        100, // 100 sats
        "integration test content",
    )
    .expect("invoice creation should succeed");
    eprintln!("Invoice created: {}...", &bolt11[..60.min(bolt11.len())]);

    // -- Run creator claim loop and buyer payment in parallel threads --
    let creator_key = key;
    let bolt11_clone = bolt11.clone();

    // Creator thread: wait for payment, claim it
    let creator_handle = thread::spawn(move || {
        eprintln!("[creator] Waiting for payment...");
        let received = invoice::wait_and_claim_payment(&creator_node, &creator_key)
            .expect("creator should receive payment");
        eprintln!("[creator] Payment received: {} msat", received.amount_msat);

        // The preimage the creator revealed should be our original key
        assert_eq!(
            received.preimage, creator_key,
            "Creator's revealed preimage must be the original key"
        );
        assert!(
            received.amount_msat >= 100_000,
            "Should receive at least 100,000 msat (100 sats)"
        );

        creator_node.stop().expect("creator should stop");
        received
    });

    // Give creator a moment to start listening for events
    thread::sleep(Duration::from_secs(2));

    // Buyer thread: pay the invoice, wait for preimage
    let buyer_handle = thread::spawn(move || {
        eprintln!("[buyer] Paying invoice...");
        let payment_hash = invoice::pay_invoice(&buyer_node, &bolt11_clone)
            .expect("buyer should initiate payment");
        eprintln!("[buyer] Payment sent, hash: {}", hex::encode(payment_hash));

        assert_eq!(
            payment_hash, expected_hash,
            "Payment hash from pay_invoice must match expected"
        );

        let result = invoice::wait_for_outbound_payment(&buyer_node, &payment_hash)
            .expect("buyer should receive payment confirmation");
        eprintln!(
            "[buyer] Payment confirmed. Preimage: {}",
            hex::encode(result.preimage)
        );

        // The preimage the buyer learned IS the content key
        assert_eq!(
            result.preimage, key,
            "Buyer's received preimage must equal the content key"
        );
        assert_eq!(
            result.payment_hash, expected_hash,
            "Payment hash in result must match"
        );

        buyer_node.stop().expect("buyer should stop");
        result
    });

    // Wait for both threads
    let _creator_result = creator_handle
        .join()
        .expect("creator thread should not panic");
    let _buyer_result = buyer_handle.join().expect("buyer thread should not panic");

    eprintln!("Full payment cycle completed successfully.");
    eprintln!("The atomic exchange works: payment revealed the decryption key.");
}

// ---------------------------------------------------------------------------
// Test 4: Atomic content exchange (the full Conduit flow)
//
// Proves the core thesis: paying a Lightning invoice atomically reveals
// the decryption key for encrypted content.
//
//   Creator: encrypt file -> create invoice (preimage = key)
//   Buyer:   pay invoice -> receive preimage -> decrypt -> verify
//
// Same env-var requirements as test 3.
// ---------------------------------------------------------------------------

#[test]
fn test_atomic_content_exchange() {
    if !integration_enabled() {
        return;
    }

    let creator_storage = match std::env::var("CONDUIT_CREATOR_STORAGE") {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "SKIP: Set CONDUIT_CREATOR_STORAGE and CONDUIT_BUYER_STORAGE \
                 to run the atomic content exchange test."
            );
            return;
        }
    };
    let buyer_storage = std::env::var("CONDUIT_BUYER_STORAGE")
        .expect("CONDUIT_BUYER_STORAGE must be set if CONDUIT_CREATOR_STORAGE is set");

    let creator_port: u16 = std::env::var("CONDUIT_CREATOR_PORT")
        .unwrap_or_else(|_| "9735".into())
        .parse()
        .expect("CONDUIT_CREATOR_PORT must be a valid port");
    let buyer_port: u16 = std::env::var("CONDUIT_BUYER_PORT")
        .unwrap_or_else(|_| "9736".into())
        .parse()
        .expect("CONDUIT_BUYER_PORT must be a valid port");

    let chain_source = test_chain_source();

    let creator_config = LightningConfig {
        storage_dir: creator_storage,
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: creator_port,
        chain_source: chain_source.clone(),
    };
    let buyer_config = LightningConfig {
        storage_dir: buyer_storage,
        network: ldk_node::bitcoin::Network::Signet,
        listening_port: buyer_port,
        chain_source,
    };

    // ── Creator: prepare content ──────────────────────────────────────────

    // Sample content (could be any file bytes)
    let sample_content = b"This is a sample song. \
        In production this would be megabytes of audio data, \
        chunked and encrypted per-chunk. For the MVP test, \
        this small payload proves the mechanism.";

    // Generate encryption key
    let key = conduit_core::encrypt::generate_key();
    eprintln!("Content key: {}", hex::encode(key));

    // Encrypt the content
    let ciphertext = conduit_core::encrypt::encrypt(sample_content, &key, 0);
    eprintln!("Ciphertext length: {} bytes", ciphertext.len());

    // Hash the original plaintext for later verification
    let file_hash = verify::sha256_hash(sample_content);
    eprintln!("Plaintext hash: {}", hex::encode(file_hash));

    // Sanity: ciphertext differs from plaintext
    assert_ne!(
        ciphertext, sample_content,
        "Ciphertext must differ from plaintext"
    );

    // ── Start both nodes ──────────────────────────────────────────────────

    eprintln!("Starting creator node...");
    let creator_node = invoice::start_node(&creator_config).expect("creator node should start");
    eprintln!("Creator: {}", invoice::node_id(&creator_node));

    eprintln!("Starting buyer node...");
    let buyer_node = invoice::start_node(&buyer_config).expect("buyer node should start");
    eprintln!("Buyer: {}", invoice::node_id(&buyer_node));

    eprintln!("Waiting for nodes to sync...");
    thread::sleep(Duration::from_secs(10));

    // ── Creator: create invoice (preimage = encryption key) ───────────────

    let bolt11 = invoice::create_invoice_for_key(
        &creator_node,
        &key,
        50, // 50 sats
        "atomic content exchange test",
    )
    .expect("invoice creation should succeed");
    eprintln!("Invoice: {}...", &bolt11[..60.min(bolt11.len())]);

    // ── Atomic exchange: payment reveals the key ──────────────────────────

    let creator_key = key;
    let bolt11_for_buyer = bolt11.clone();

    // Creator thread: wait for payment and claim it (reveals preimage)
    let creator_handle = thread::spawn(move || {
        eprintln!("[creator] Waiting for payment...");
        let received = invoice::wait_and_claim_payment(&creator_node, &creator_key)
            .expect("creator should receive payment");
        eprintln!("[creator] Payment received: {} msat", received.amount_msat);
        creator_node.stop().expect("creator should stop");
        received
    });

    thread::sleep(Duration::from_secs(2));

    // Buyer thread: pay invoice, receive preimage
    let buyer_handle = thread::spawn(move || {
        eprintln!("[buyer] Paying invoice...");
        let payment_hash = invoice::pay_invoice(&buyer_node, &bolt11_for_buyer)
            .expect("buyer should initiate payment");
        eprintln!("[buyer] Payment sent, hash: {}", hex::encode(payment_hash));

        let result = invoice::wait_for_outbound_payment(&buyer_node, &payment_hash)
            .expect("buyer should receive payment confirmation");
        eprintln!(
            "[buyer] Preimage received: {}",
            hex::encode(result.preimage)
        );
        buyer_node.stop().expect("buyer should stop");
        result
    });

    let _creator_result = creator_handle.join().expect("creator thread ok");
    let buyer_result = buyer_handle.join().expect("buyer thread ok");

    // ── Buyer: decrypt and verify ─────────────────────────────────────────

    // The preimage from the payment IS the decryption key
    let recovered_key = buyer_result.preimage;
    eprintln!("Recovered key: {}", hex::encode(recovered_key));

    assert_eq!(
        recovered_key, key,
        "Recovered preimage must equal the original encryption key"
    );

    // Decrypt
    let decrypted = conduit_core::encrypt::decrypt(&ciphertext, &recovered_key, 0);

    // Verify content integrity
    assert!(
        verify::verify_hash(&decrypted, &file_hash),
        "Decrypted content must match the original plaintext hash"
    );
    assert_eq!(
        decrypted.as_slice(),
        sample_content,
        "Decrypted bytes must equal the original content"
    );

    eprintln!();
    eprintln!("=== ATOMIC CONTENT EXCHANGE SUCCESSFUL ===");
    eprintln!("  1. Creator encrypted content with key K");
    eprintln!("  2. Creator created invoice (preimage = K)");
    eprintln!("  3. Buyer paid invoice");
    eprintln!("  4. Payment settlement revealed K to buyer");
    eprintln!("  5. Buyer decrypted content with K");
    eprintln!("  6. SHA-256 hash verified: content is authentic");
    eprintln!("  Payment and content delivery were ATOMIC.");
}
