//! Conduit P2P node: wraps an iroh Endpoint with protocol routing.

use std::sync::Arc;

use anyhow::Result;
use iroh::address_lookup::pkarr::dht::DhtAddressLookup;
use iroh::protocol::Router;
use iroh::{Endpoint, SecretKey};
use tracing::info;

use crate::handler::ChunkProtocol;

/// Configuration for starting a P2P node.
pub struct P2pConfig {
    /// Optional pre-existing secret key (for persistent identity).
    /// If None, a random key is generated.
    pub secret_key: Option<SecretKey>,
    /// Enable DHT-based peer discovery (Mainline DHT via pkarr).
    pub enable_dht: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            secret_key: None,
            enable_dht: true,
        }
    }
}

/// A running Conduit P2P node.
///
/// Wraps an iroh Router that accepts incoming connections for the
/// Conduit chunk protocol ALPN (`/conduit/chunk/1`).
pub struct P2pNode {
    router: Router,
    endpoint: Endpoint,
}

impl P2pNode {
    /// Start a new P2P node.
    ///
    /// `chunk_handler` is the application-level handler that serves chunks
    /// to incoming buyer connections.
    pub async fn spawn(config: P2pConfig, chunk_handler: Arc<ChunkProtocol>) -> Result<Self> {
        let mut builder = Endpoint::builder();

        if let Some(sk) = config.secret_key {
            builder = builder.secret_key(sk);
        }

        if config.enable_dht {
            builder = builder.address_lookup(DhtAddressLookup::builder());
        }

        builder = builder.alpns(vec![crate::CONDUIT_ALPN.to_vec()]);

        let endpoint = builder.bind().await?;

        let node_id = endpoint.id();
        info!(%node_id, "P2P node starting");

        let router = Router::builder(endpoint.clone())
            .accept(crate::CONDUIT_ALPN, chunk_handler.as_ref().clone())
            .spawn();

        info!(%node_id, "P2P node ready, accepting connections");

        Ok(Self { router, endpoint })
    }

    /// Create a P2P node for a buyer (no protocol handler, outbound only).
    pub async fn spawn_buyer(config: P2pConfig) -> Result<Self> {
        let mut builder = Endpoint::builder();

        if let Some(sk) = config.secret_key {
            builder = builder.secret_key(sk);
        }

        if config.enable_dht {
            builder = builder.address_lookup(DhtAddressLookup::builder());
        }

        let endpoint = builder.bind().await?;
        let node_id = endpoint.id();
        info!(%node_id, "P2P buyer node started (outbound only)");

        let router = Router::builder(endpoint.clone()).spawn();

        Ok(Self { router, endpoint })
    }

    /// The iroh Endpoint (for making outgoing connections).
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// This node's public key / endpoint ID.
    pub fn node_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    /// The node's address info (for sharing with peers).
    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }

    /// Gracefully shut down the P2P node.
    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}
