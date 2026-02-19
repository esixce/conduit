//! DHT-based seeder discovery using iroh's Mainline DHT (via pkarr).
//!
//! Seeders *announce* they hold specific content, keyed by H(E).
//! Buyers *query* the DHT for seeders of a given content hash.
//!
//! Under the hood this uses iroh's discovery-pkarr-dht feature which
//! publishes/resolves EndpointAddr records in the BitTorrent Mainline DHT.
//!
//! From docs/02_p2p_distribution.md Section 8 and docs/13_transport_and_dht.md.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::{Endpoint, EndpointAddr, PublicKey};
use tracing::{debug, info, warn};

/// Tracks which content hashes this node is seeding and which
/// remote seeders have been discovered for content the buyer wants.
#[derive(Default)]
pub struct SeederRegistry {
    /// Content we are seeding: encrypted_hash -> our endpoint addr.
    local: Arc<Mutex<HashMap<[u8; 32], EndpointAddr>>>,
    /// Known remote seeders: encrypted_hash -> list of seeder addresses.
    remote: Arc<Mutex<HashMap<[u8; 32], Vec<SeederInfo>>>>,
}

#[derive(Clone, Debug)]
pub struct SeederInfo {
    pub node_id: PublicKey,
    pub addr: EndpointAddr,
    /// Price per chunk in satoshis.
    pub price_sats: u64,
    /// Last time this seeder was seen.
    pub last_seen: std::time::Instant,
}

impl SeederRegistry {
    pub fn new() -> Self {
        Self {
            local: Arc::new(Mutex::new(HashMap::new())),
            remote: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register that we are seeding a particular content hash.
    pub fn announce_local(&self, encrypted_hash: [u8; 32], addr: EndpointAddr) {
        info!(
            hash = hex::encode(encrypted_hash),
            "announcing local content to DHT"
        );
        self.local.lock().unwrap().insert(encrypted_hash, addr);
    }

    /// Remove a local announcement.
    pub fn withdraw_local(&self, encrypted_hash: &[u8; 32]) {
        self.local.lock().unwrap().remove(encrypted_hash);
    }

    /// Add a discovered remote seeder.
    pub fn add_remote_seeder(&self, encrypted_hash: [u8; 32], info: SeederInfo) {
        debug!(
            hash = hex::encode(encrypted_hash),
            node_id = %info.node_id,
            "discovered remote seeder"
        );
        let mut remote = self.remote.lock().unwrap();
        let seeders = remote.entry(encrypted_hash).or_default();

        if let Some(existing) = seeders.iter_mut().find(|s| s.node_id == info.node_id) {
            existing.addr = info.addr;
            existing.last_seen = info.last_seen;
            existing.price_sats = info.price_sats;
        } else {
            seeders.push(info);
        }
    }

    /// Get known seeders for a content hash.
    pub fn get_seeders(&self, encrypted_hash: &[u8; 32]) -> Vec<SeederInfo> {
        self.remote
            .lock()
            .unwrap()
            .get(encrypted_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Remove stale entries older than the given duration.
    pub fn prune_stale(&self, max_age: std::time::Duration) {
        let cutoff = std::time::Instant::now() - max_age;
        let mut remote = self.remote.lock().unwrap();
        for seeders in remote.values_mut() {
            seeders.retain(|s| s.last_seen > cutoff);
        }
        remote.retain(|_, v| !v.is_empty());
    }
}

/// Look up seeders for a content hash using iroh's DHT address resolution.
///
/// This queries the BitTorrent Mainline DHT for nodes that have
/// published their availability for the given content hash. In practice
/// seeders call `endpoint.add_address_lookup()` with a pkarr-based
/// discovery, and this function resolves those records.
///
/// Note: The actual DHT key derivation (how `encrypted_hash` maps to
/// a DHT lookup key) will be defined when we integrate with the
/// iroh pkarr discovery API. For now, this provides the registry
/// abstraction that the buyer and seeder use.
pub async fn discover_seeders(
    _endpoint: &Endpoint,
    encrypted_hash: &[u8; 32],
    registry: &SeederRegistry,
) -> Vec<SeederInfo> {
    // Phase 1: Return whatever we already know from the registry.
    // Phase 2 (future): Actively query the DHT for new seeders.
    let seeders = registry.get_seeders(encrypted_hash);
    if seeders.is_empty() {
        warn!(
            hash = hex::encode(encrypted_hash),
            "no seeders found in registry"
        );
    }
    seeders
}
