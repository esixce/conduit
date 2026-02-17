//! Lightning invoice integration for Conduit content exchange.
//!
//! Wraps `ldk-node` 0.7.0 to create and manage an embedded Lightning node.
//! The critical capability: creating BOLT 11 invoices where the payment
//! preimage IS the content encryption key. Paying the invoice atomically
//! reveals the decryption key. See `docs/mvp/04_invoice.md`.

use ldk_node::bitcoin::Network;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning_invoice::{Bolt11InvoiceDescription, Description};
use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
use ldk_node::{Builder, Event, Node};
use thiserror::Error;

use crate::verify;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum InvoiceError {
    #[error("LDK node error: {0}")]
    Ldk(#[from] ldk_node::NodeError),
    #[error("LDK build error: {0}")]
    Build(#[from] ldk_node::BuildError),
    #[error("Invalid socket address: {0}")]
    InvalidAddress(String),
    #[error("Invalid invoice description: {0}")]
    InvalidDescription(String),
    #[error("Payment failed: {0}")]
    PaymentFailed(String),
    #[error("Node start error: {0}")]
    NodeStart(String),
    #[error("Invoice parse error: {0}")]
    InvoiceParse(String),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Chain data source for the LDK node.
#[derive(Debug, Clone)]
pub enum ChainSource {
    /// Esplora HTTP API (e.g. `https://mempool.space/signet/api`).
    Esplora(String),
    /// Bitcoind RPC (host, port, user, password).
    BitcoindRpc {
        host: String,
        port: u16,
        user: String,
        password: String,
    },
}

/// Configuration for the embedded LDK Lightning node.
#[derive(Debug, Clone)]
pub struct LightningConfig {
    /// Directory to store LDK node data (keys, channels, etc.)
    pub storage_dir: String,
    /// Network: Signet for testing, Bitcoin for production.
    pub network: Network,
    /// Listening port for Lightning peer connections.
    pub listening_port: u16,
    /// Chain data source (Esplora or bitcoind RPC).
    pub chain_source: ChainSource,
    /// Human-readable node alias (max 32 bytes UTF-8). Gossiped to the Lightning network.
    pub node_alias: Option<String>,
}

impl Default for LightningConfig {
    fn default() -> Self {
        Self {
            storage_dir: "/tmp/conduit-node".into(),
            network: Network::Signet,
            listening_port: 9735,
            chain_source: ChainSource::Esplora("https://mempool.space/signet/api".into()),
            node_alias: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of a successful outbound payment (buyer side).
#[derive(Debug)]
pub struct PaymentResult {
    /// The preimage revealed by the payment (= decryption key).
    pub preimage: [u8; 32],
    /// The payment hash.
    pub payment_hash: [u8; 32],
}

/// Details of a received inbound payment (creator side).
#[derive(Debug)]
pub struct PaymentReceived {
    /// The preimage that was revealed to the payer.
    pub preimage: [u8; 32],
    /// Amount received in millisatoshis.
    pub amount_msat: u64,
}

// ---------------------------------------------------------------------------
// Node lifecycle
// ---------------------------------------------------------------------------

/// Start an LDK node with the given config.
///
/// The node begins syncing with the chain and listening for peers.
/// Call `node.stop()` when done.
pub fn start_node(config: &LightningConfig) -> Result<Node, InvoiceError> {
    let mut builder = Builder::new();

    builder.set_network(config.network);
    builder.set_storage_dir_path(config.storage_dir.clone());

    if let Some(ref alias) = config.node_alias {
        builder
            .set_node_alias(alias.clone())
            .map_err(|e| InvoiceError::NodeStart(format!("Invalid node alias: {:?}", e)))?;
    }

    match &config.chain_source {
        ChainSource::Esplora(url) => {
            builder.set_chain_source_esplora(url.clone(), None);
        }
        ChainSource::BitcoindRpc {
            host,
            port,
            user,
            password,
        } => {
            builder.set_chain_source_bitcoind_rpc(
                host.clone(),
                *port,
                user.clone(),
                password.clone(),
            );
        }
    }

    let addr: SocketAddress = format!("0.0.0.0:{}", config.listening_port)
        .parse()
        .map_err(|_| {
            InvoiceError::InvalidAddress(format!(
                "Could not parse listening address 0.0.0.0:{}",
                config.listening_port
            ))
        })?;
    builder
        .set_listening_addresses(vec![addr])
        .map_err(InvoiceError::Build)?;

    let node = builder.build()?;
    node.start()?;

    Ok(node)
}

/// Get the node's public key as a hex string.
pub fn node_id(node: &Node) -> String {
    node.node_id().to_string()
}

/// Get the node's listening addresses as strings.
pub fn listening_addresses(node: &Node) -> Vec<String> {
    node.listening_addresses()
        .unwrap_or_default()
        .iter()
        .map(|a| a.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Invoice creation (creator side)
// ---------------------------------------------------------------------------

/// Create a Lightning invoice where the preimage is the given encryption key.
///
/// The payment hash is `SHA-256(key)`. When the buyer pays, the HTLC
/// settlement reveals `key` as the preimage -- atomically unlocking the
/// content.
///
/// **Important:** Because we use `receive_for_hash`, the payment is NOT
/// auto-claimed. The caller MUST handle the `PaymentClaimable` event and
/// call [`claim_payment`] to complete the exchange.
pub fn create_invoice_for_key(
    node: &Node,
    key: &[u8; 32],
    amount_sats: u64,
    description: &str,
) -> Result<String, InvoiceError> {
    // The preimage IS the key; the hash is what goes in the invoice.
    let preimage = PaymentPreimage(*key);
    let payment_hash: PaymentHash = preimage.into();

    let desc = Description::new(description.to_string())
        .map_err(|e| InvoiceError::InvalidDescription(e.to_string()))?;
    let invoice_desc = Bolt11InvoiceDescription::Direct(desc);

    let amount_msat = amount_sats * 1000;
    let expiry_secs = 3600; // 1 hour

    let invoice = node.bolt11_payment().receive_for_hash(
        amount_msat,
        &invoice_desc,
        expiry_secs,
        payment_hash,
    )?;

    Ok(invoice.to_string())
}

/// Claim an inbound payment after a `PaymentClaimable` event.
///
/// This reveals the preimage (= encryption key) to the payer via the HTLC.
pub fn claim_payment(
    node: &Node,
    key: &[u8; 32],
    claimable_amount_msat: u64,
) -> Result<(), InvoiceError> {
    let preimage = PaymentPreimage(*key);
    let payment_hash: PaymentHash = preimage.into();

    node.bolt11_payment()
        .claim_for_hash(payment_hash, claimable_amount_msat, preimage)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Payment (buyer side)
// ---------------------------------------------------------------------------

/// Pay a BOLT 11 invoice string.
///
/// Returns the payment hash as bytes for tracking. The caller should then
/// use [`wait_for_outbound_payment`] with this hash to get the preimage
/// (= decryption key).
pub fn pay_invoice(node: &Node, bolt11: &str) -> Result<[u8; 32], InvoiceError> {
    use ldk_node::lightning_invoice::Bolt11Invoice;

    let invoice: Bolt11Invoice =
        bolt11
            .parse()
            .map_err(|e: ldk_node::lightning_invoice::ParseOrSemanticError| {
                InvoiceError::InvoiceParse(e.to_string())
            })?;

    // Extract payment hash before sending (we need it for event matching).
    // invoice.payment_hash() returns sha256::Hash; convert via AsRef<[u8]>.
    let hash_bytes: &[u8] = invoice.payment_hash().as_ref();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hash_bytes);

    let _payment_id = node.bolt11_payment().send(&invoice, None)?;
    Ok(hash)
}

// ---------------------------------------------------------------------------
// Event loops
// ---------------------------------------------------------------------------

/// (Creator side) Wait for a `PaymentClaimable` event, claim it, then wait
/// for the `PaymentReceived` confirmation.
///
/// Blocks the current thread until the full claim cycle completes.
/// Returns the amount received.
pub fn wait_and_claim_payment(
    node: &Node,
    key: &[u8; 32],
) -> Result<PaymentReceived, InvoiceError> {
    let expected_hash: PaymentHash = PaymentPreimage(*key).into();

    // Phase 1: wait for PaymentClaimable
    loop {
        let event = node.wait_next_event();
        match event {
            Event::PaymentClaimable {
                payment_hash,
                claimable_amount_msat,
                ..
            } if payment_hash == expected_hash => {
                node.event_handled()?;
                // Claim with our key as the preimage
                claim_payment(node, key, claimable_amount_msat)?;
                break;
            }
            _ => {
                node.event_handled()?;
            }
        }
    }

    // Phase 2: wait for PaymentReceived confirmation
    loop {
        let event = node.wait_next_event();
        match event {
            Event::PaymentReceived {
                payment_hash,
                amount_msat,
                ..
            } if payment_hash == expected_hash => {
                node.event_handled()?;
                return Ok(PaymentReceived {
                    preimage: *key,
                    amount_msat,
                });
            }
            _ => {
                node.event_handled()?;
            }
        }
    }
}

/// (Buyer side) Wait for a `PaymentSuccessful` event and extract the
/// preimage (= decryption key).
///
/// Blocks the current thread until the payment settles.
pub fn wait_for_outbound_payment(
    node: &Node,
    expected_payment_hash: &[u8; 32],
) -> Result<PaymentResult, InvoiceError> {
    let target_hash = PaymentHash(*expected_payment_hash);

    loop {
        let event = node.wait_next_event();
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                ..
            } if payment_hash == target_hash => {
                node.event_handled()?;
                return Ok(PaymentResult {
                    preimage: preimage.0,
                    payment_hash: payment_hash.0,
                });
            }
            Event::PaymentFailed {
                payment_hash: Some(hash),
                reason,
                ..
            } if hash == target_hash => {
                node.event_handled()?;
                return Err(InvoiceError::PaymentFailed(format!(
                    "Payment failed: {:?}",
                    reason
                )));
            }
            _ => {
                node.event_handled()?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PRE-aware invoice functions (Phase 2A)
// ---------------------------------------------------------------------------

/// Create a Lightning invoice where the preimage is the PRE HTLC preimage.
///
/// In the PRE flow, the preimage is `SHA-256(rk_compressed)` — the hash of
/// the re-encryption key point. This 32-byte value fits the HTLC preimage
/// slot. When the buyer pays, settlement reveals this preimage; the buyer
/// uses it together with `rk_point` (received via the purchase API) to
/// proceed with re-encryption and decryption.
///
/// Like [`create_invoice_for_key`], the payment is NOT auto-claimed.
/// The caller must handle `PaymentClaimable` and call [`claim_payment_pre`].
pub fn create_invoice_for_rk(
    node: &Node,
    htlc_preimage: &[u8; 32],
    amount_sats: u64,
    description: &str,
) -> Result<String, InvoiceError> {
    let preimage = PaymentPreimage(*htlc_preimage);
    let payment_hash: PaymentHash = preimage.into();

    let desc = Description::new(description.to_string())
        .map_err(|e| InvoiceError::InvalidDescription(e.to_string()))?;
    let invoice_desc = Bolt11InvoiceDescription::Direct(desc);

    let amount_msat = amount_sats * 1000;
    let expiry_secs = 3600;

    let invoice = node.bolt11_payment().receive_for_hash(
        amount_msat,
        &invoice_desc,
        expiry_secs,
        payment_hash,
    )?;

    Ok(invoice.to_string())
}

/// Claim an inbound PRE payment after a `PaymentClaimable` event.
///
/// Identical to [`claim_payment`] but takes the HTLC preimage directly
/// (instead of the AES key). In the PRE flow, the preimage is
/// `SHA-256(rk_compressed)`.
pub fn claim_payment_pre(
    node: &Node,
    htlc_preimage: &[u8; 32],
    claimable_amount_msat: u64,
) -> Result<(), InvoiceError> {
    let preimage = PaymentPreimage(*htlc_preimage);
    let payment_hash: PaymentHash = preimage.into();

    node.bolt11_payment()
        .claim_for_hash(payment_hash, claimable_amount_msat, preimage)?;

    Ok(())
}

/// (Creator side) Wait for a PRE payment, claim it, then confirm receipt.
///
/// Same as [`wait_and_claim_payment`] but uses the PRE HTLC preimage.
pub fn wait_and_claim_payment_pre(
    node: &Node,
    htlc_preimage: &[u8; 32],
) -> Result<PaymentReceived, InvoiceError> {
    let expected_hash: PaymentHash = PaymentPreimage(*htlc_preimage).into();

    loop {
        let event = node.wait_next_event();
        match event {
            Event::PaymentClaimable {
                payment_hash,
                claimable_amount_msat,
                ..
            } if payment_hash == expected_hash => {
                node.event_handled()?;
                claim_payment_pre(node, htlc_preimage, claimable_amount_msat)?;
                break;
            }
            _ => {
                node.event_handled()?;
            }
        }
    }

    loop {
        let event = node.wait_next_event();
        match event {
            Event::PaymentReceived {
                payment_hash,
                amount_msat,
                ..
            } if payment_hash == expected_hash => {
                node.event_handled()?;
                return Ok(PaymentReceived {
                    preimage: *htlc_preimage,
                    amount_msat,
                });
            }
            _ => {
                node.event_handled()?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility: compute payment hash from key (for buyer convenience)
// ---------------------------------------------------------------------------

/// Compute the Lightning payment hash for a given key.
///
/// This is `SHA-256(key)` -- the same value embedded in the invoice.
/// The buyer can use this to verify the invoice matches expectations.
pub fn payment_hash_for_key(key: &[u8; 32]) -> [u8; 32] {
    verify::sha256_hash(key)
}

/// Compute the Lightning payment hash for a PRE HTLC preimage.
///
/// This is `SHA-256(htlc_preimage)` — the double-hash of the rk point.
/// Alias for [`payment_hash_for_key`] since the operation is identical
/// (SHA-256 of 32 bytes).
pub fn payment_hash_for_rk(htlc_preimage: &[u8; 32]) -> [u8; 32] {
    verify::sha256_hash(htlc_preimage)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_hash_matches_sha256() {
        // Verify that PaymentPreimage -> PaymentHash conversion matches
        // our SHA-256 implementation (they must agree for the atomic
        // exchange to work).
        let key = [42u8; 32];
        let our_hash = payment_hash_for_key(&key);
        let ldk_hash: PaymentHash = PaymentPreimage(key).into();
        assert_eq!(our_hash, ldk_hash.0);
    }

    #[test]
    fn test_default_config() {
        let config = LightningConfig::default();
        assert_eq!(config.network, Network::Signet);
        assert_eq!(config.listening_port, 9735);
        assert!(matches!(&config.chain_source, ChainSource::Esplora(url) if !url.is_empty()));
    }

    #[test]
    fn test_payment_hash_different_keys() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let k3 = [3u8; 32];
        let h1 = payment_hash_for_key(&k1);
        let h2 = payment_hash_for_key(&k2);
        let h3 = payment_hash_for_key(&k3);
        assert_ne!(
            h1, h2,
            "Different keys must produce different payment hashes"
        );
        assert_ne!(
            h2, h3,
            "Different keys must produce different payment hashes"
        );
        assert_ne!(
            h1, h3,
            "Different keys must produce different payment hashes"
        );
    }

    #[test]
    fn test_payment_hash_all_zeros() {
        let key = [0u8; 32];
        let hash = payment_hash_for_key(&key);
        let expected = verify::sha256_hash(&key);
        assert_eq!(
            hash, expected,
            "payment_hash_for_key must equal sha256_hash for all-zero key"
        );
    }

    #[test]
    fn test_config_custom_esplora() {
        let config = LightningConfig {
            storage_dir: "/custom/path".into(),
            network: Network::Bitcoin,
            listening_port: 19735,
            chain_source: ChainSource::Esplora("https://example.com/api".into()),
            node_alias: None,
        };
        assert_eq!(config.storage_dir, "/custom/path");
        assert_eq!(config.network, Network::Bitcoin);
        assert_eq!(config.listening_port, 19735);
        assert!(
            matches!(&config.chain_source, ChainSource::Esplora(url) if url == "https://example.com/api")
        );
    }

    #[test]
    fn test_config_custom_rpc() {
        let config = LightningConfig {
            storage_dir: "/rpc/path".into(),
            network: Network::Signet,
            listening_port: 29735,
            chain_source: ChainSource::BitcoindRpc {
                host: "127.0.0.1".into(),
                port: 38332,
                user: "rpcuser".into(),
                password: "rpcpass".into(),
            },
            node_alias: None,
        };
        assert_eq!(config.listening_port, 29735);
        assert!(
            matches!(&config.chain_source, ChainSource::BitcoindRpc { host, port, .. } if host == "127.0.0.1" && *port == 38332)
        );
    }
}
