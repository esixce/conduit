//! Conduit P2P networking layer.
//!
//! Replaces HTTP inter-node communication with direct QUIC connections
//! via iroh. Keeps HTTP only for browser dashboards.
//!
//! Design: [`docs/02_p2p_distribution.md`], [`docs/13_transport_and_dht.md`]

pub mod client;
pub mod dht;
pub mod handler;
pub mod node;
pub mod wire;

pub use iroh;

/// ALPN protocol identifier for Conduit chunk protocol.
pub const CONDUIT_ALPN: &[u8] = b"/conduit/chunk/1";
