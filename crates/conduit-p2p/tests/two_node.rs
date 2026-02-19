//! Integration test: full buyer ↔ seeder flow over local iroh endpoints.
//!
//! Spins up two iroh endpoints on localhost (no relay), runs the
//! Conduit chunk protocol, and verifies the complete cycle:
//!   Handshake → Bitfield → Request → Invoice → PaymentProof → Chunks

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use conduit_p2p::handler::{ChunkProtocol, ChunkStore};
use conduit_p2p::wire::{Bitfield, ProofNode};
use conduit_p2p::CONDUIT_ALPN;

use iroh::protocol::Router;
use iroh::{Endpoint, SecretKey};

// ── Mock ChunkStore ────────────────────────────────────────────────────

#[derive(Debug)]
struct MockStore {
    chunks: HashMap<u32, Vec<u8>>,
    encrypted_hash: [u8; 32],
    chunk_size: u32,
    /// Track invoices so we can verify payment.
    pending_preimage: Mutex<Option<[u8; 32]>>,
}

impl MockStore {
    fn new(encrypted_hash: [u8; 32], chunks: Vec<Vec<u8>>) -> Self {
        let map: HashMap<u32, Vec<u8>> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| (i as u32, c))
            .collect();
        Self {
            chunk_size: 256,
            encrypted_hash,
            chunks: map,
            pending_preimage: Mutex::new(None),
        }
    }
}

impl ChunkStore for MockStore {
    fn get_chunk(&self, hash: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        if hash != &self.encrypted_hash {
            return None;
        }
        self.chunks.get(&index).cloned()
    }

    fn get_proof(&self, hash: &[u8; 32], index: u32) -> Option<Vec<ProofNode>> {
        if hash != &self.encrypted_hash {
            return None;
        }
        if self.chunks.contains_key(&index) {
            Some(vec![ProofNode {
                hash: [0xAB; 32],
                is_left: true,
            }])
        } else {
            None
        }
    }

    fn get_bitfield(&self, hash: &[u8; 32]) -> Option<Bitfield> {
        if hash != &self.encrypted_hash {
            return None;
        }
        let available: Vec<bool> = (0..self.chunks.len() as u32)
            .map(|i| self.chunks.contains_key(&i))
            .collect();
        Some(Bitfield::from_bools(
            &available,
            self.chunk_size,
            [0xCC; 32],
        ))
    }

    fn create_invoice(
        &self,
        _hash: &[u8; 32],
        chunk_indices: &[u32],
        _buyer_ln: &str,
    ) -> anyhow::Result<(String, u64)> {
        let preimage = [0x42; 32];
        *self.pending_preimage.lock().unwrap() = Some(preimage);
        let amount = chunk_indices.len() as u64 * 100;
        Ok(("lnbcrt1mock_invoice_for_test".to_string(), amount))
    }

    fn verify_payment(&self, _hash: &[u8; 32], preimage: &[u8; 32]) -> bool {
        let expected = self.pending_preimage.lock().unwrap();
        expected.as_ref() == Some(preimage)
    }
}

// ── Mock PaymentHandler ────────────────────────────────────────────────

struct MockPayment;

impl conduit_p2p::client::PaymentHandler for MockPayment {
    fn pay_invoice(&self, _bolt11: &str) -> anyhow::Result<[u8; 32]> {
        Ok([0x42; 32])
    }
}

// ── Helper: create a local endpoint pair (no relay) ────────────────────

async fn make_endpoint(alpns: Vec<Vec<u8>>) -> Endpoint {
    let sk = SecretKey::generate(&mut rand::rng());
    let mut builder = Endpoint::builder().secret_key(sk);
    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }
    builder.bind().await.expect("bind endpoint")
}

// ── Tests ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn full_download_flow() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x01; 32];
    let chunk_data: Vec<Vec<u8>> = vec![
        b"chunk-zero-data-here".to_vec(),
        b"chunk-one-data-here!".to_vec(),
        b"chunk-two-bytes-yep!".to_vec(),
    ];
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    // Seeder endpoint with Router
    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    // Wait for the seeder to be ready
    let seeder_addr = seeder_ep.addr();

    // Buyer endpoint (outbound-only)
    let buyer_ep = make_endpoint(vec![]).await;
    let client = conduit_p2p::client::BuyerClient::new(
        buyer_ep.clone(),
        "mock_ln_pubkey".to_string(),
    );

    let result = client
        .download(seeder_addr, encrypted_hash, &[0, 1, 2], &MockPayment)
        .await
        .expect("download should succeed");

    assert_eq!(result.chunks.len(), 3);
    assert_eq!(result.total_paid_msat, 300); // 3 chunks * 100

    // Verify chunk contents
    let mut by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
    assert_eq!(by_index.remove(&0).unwrap(), b"chunk-zero-data-here");
    assert_eq!(by_index.remove(&1).unwrap(), b"chunk-one-data-here!");
    assert_eq!(by_index.remove(&2).unwrap(), b"chunk-two-bytes-yep!");

    // Clean shutdown
    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}

#[tokio::test]
async fn partial_chunk_request() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x02; 32];
    let chunk_data: Vec<Vec<u8>> = vec![
        b"aaa".to_vec(),
        b"bbb".to_vec(),
        b"ccc".to_vec(),
        b"ddd".to_vec(),
    ];
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    let seeder_addr = seeder_ep.addr();
    let buyer_ep = make_endpoint(vec![]).await;
    let client = conduit_p2p::client::BuyerClient::new(
        buyer_ep.clone(),
        "partial_test_ln".to_string(),
    );

    // Only request chunks 1 and 3
    let result = client
        .download(seeder_addr, encrypted_hash, &[1, 3], &MockPayment)
        .await
        .expect("download should succeed");

    assert_eq!(result.chunks.len(), 2);
    assert_eq!(result.total_paid_msat, 200);

    let by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
    assert_eq!(by_index[&1], b"bbb");
    assert_eq!(by_index[&3], b"ddd");

    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}

#[tokio::test]
async fn bitfield_encoding_roundtrip() {
    let available = vec![true, false, true, true, false, false, true, false, true];
    let bf = Bitfield::from_bools(&available, 256, [0; 32]);

    assert_eq!(bf.chunk_count, 9);
    assert!(bf.has_chunk(0));
    assert!(!bf.has_chunk(1));
    assert!(bf.has_chunk(2));
    assert!(bf.has_chunk(3));
    assert!(!bf.has_chunk(4));
    assert!(!bf.has_chunk(5));
    assert!(bf.has_chunk(6));
    assert!(!bf.has_chunk(7));
    assert!(bf.has_chunk(8));
    assert!(!bf.has_chunk(99));
}

#[tokio::test]
async fn wire_message_roundtrip() {
    use conduit_p2p::wire::*;

    let msg = Message::Handshake(Handshake::new([0xAA; 32], "02abc".to_string()));
    let bytes = postcard::to_allocvec(&msg).expect("serialize");
    let decoded: Message = postcard::from_bytes(&bytes).expect("deserialize");

    match decoded {
        Message::Handshake(h) => {
            assert_eq!(h.version, 1);
            assert_eq!(h.encrypted_hash, [0xAA; 32]);
            assert_eq!(h.lightning_pubkey, "02abc");
        }
        _ => panic!("wrong variant"),
    }
}
