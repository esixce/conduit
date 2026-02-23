//! Integration test: full buyer ↔ seeder flow over local iroh endpoints.
//!
//! Spins up two iroh endpoints on localhost (no relay), runs the
//! Conduit chunk protocol, and verifies the complete cycle:
//!   Handshake → Bitfield → Request → Invoice → PaymentProof → Chunks

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use conduit_core::merkle::MerkleTree;
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
    tree: MerkleTree,
    pending_preimage: Mutex<Option<[u8; 32]>>,
}

impl MockStore {
    fn new(encrypted_hash: [u8; 32], chunks: Vec<Vec<u8>>) -> Self {
        let tree = MerkleTree::from_chunks(&chunks);
        let map: HashMap<u32, Vec<u8>> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, c)| (i as u32, c))
            .collect();
        Self {
            chunk_size: 256,
            encrypted_hash,
            chunks: map,
            tree,
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
            let proof = self.tree.proof(index as usize);
            Some(
                proof
                    .siblings
                    .iter()
                    .map(|(h, is_left)| ProofNode {
                        hash: *h,
                        is_left: *is_left,
                    })
                    .collect(),
            )
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
            self.tree.root(),
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
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "mock_ln_pubkey".to_string());

    let result = client
        .download(seeder_addr, encrypted_hash, &[0, 1, 2], Arc::new(MockPayment), None)
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
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "partial_test_ln".to_string());

    // Only request chunks 1 and 3
    let result = client
        .download(seeder_addr, encrypted_hash, &[1, 3], Arc::new(MockPayment), None)
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

// ── Layer 2: Cross-runtime tests ─────────────────────────────────────
// These reproduce the production architecture where the seeder's iroh
// endpoint lives on Runtime A and the buyer drives the download from
// Runtime B via handle.spawn() + sync channel.

#[test]
fn cross_runtime_download() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x03; 32];
    let chunk_data: Vec<Vec<u8>> = vec![
        b"cross-runtime-chunk-0".to_vec(),
        b"cross-runtime-chunk-1".to_vec(),
    ];
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    // Runtime A: seeder + buyer iroh endpoints live here
    let rt_a = tokio::runtime::Runtime::new().expect("runtime A");
    let rt_a_handle = rt_a.handle().clone();

    let (seeder_addr, buyer_ep, router) = rt_a.block_on(async {
        let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
        let handler = Arc::new(ChunkProtocol::new(store));
        let router = Router::builder(seeder_ep.clone())
            .accept(CONDUIT_ALPN, handler.as_ref().clone())
            .spawn();
        let addr = seeder_ep.addr();
        let buyer_ep = make_endpoint(vec![]).await;
        (addr, buyer_ep, router)
    });

    // Keep Runtime A alive in a background thread (like production)
    std::thread::spawn(move || {
        rt_a.block_on(std::future::pending::<()>());
    });

    // Drive the download from here (a bare OS thread, not in any runtime)
    // using handle.spawn() + sync channel -- exactly like handle_buy_pre
    let (tx, rx) = std::sync::mpsc::sync_channel::<anyhow::Result<conduit_p2p::client::DownloadResult>>(1);
    let client = conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "cross_rt_ln".to_string());

    rt_a_handle.spawn(async move {
        let result = client
            .download(seeder_addr, encrypted_hash, &[0, 1], Arc::new(MockPayment), None)
            .await;
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(std::time::Duration::from_secs(15))
        .expect("download timed out (recv)")
        .expect("download failed");

    assert_eq!(result.chunks.len(), 2);
    let by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
    assert_eq!(by_index[&0], b"cross-runtime-chunk-0");
    assert_eq!(by_index[&1], b"cross-runtime-chunk-1");

    rt_a_handle.spawn(async move {
        buyer_ep.close().await;
        router.shutdown().await.expect("router shutdown");
    });
}

// ── Layer 2b: Blocking payment inside spawn_blocking ─────────────────

struct SlowMockPayment;

impl conduit_p2p::client::PaymentHandler for SlowMockPayment {
    fn pay_invoice(&self, _bolt11: &str) -> anyhow::Result<[u8; 32]> {
        std::thread::sleep(std::time::Duration::from_millis(500));
        Ok([0x42; 32])
    }
}

#[test]
fn cross_runtime_blocking_payment() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x04; 32];
    let chunk_data: Vec<Vec<u8>> = vec![b"blocking-pay-chunk".to_vec()];
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let rt_a = tokio::runtime::Runtime::new().expect("runtime A");
    let rt_a_handle = rt_a.handle().clone();

    let (seeder_addr, buyer_ep, router) = rt_a.block_on(async {
        let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
        let handler = Arc::new(ChunkProtocol::new(store));
        let router = Router::builder(seeder_ep.clone())
            .accept(CONDUIT_ALPN, handler.as_ref().clone())
            .spawn();
        let addr = seeder_ep.addr();
        let buyer_ep = make_endpoint(vec![]).await;
        (addr, buyer_ep, router)
    });

    std::thread::spawn(move || {
        rt_a.block_on(std::future::pending::<()>());
    });

    let (tx, rx) = std::sync::mpsc::sync_channel::<anyhow::Result<conduit_p2p::client::DownloadResult>>(1);
    let client = conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "slow_pay_ln".to_string());

    let start = std::time::Instant::now();
    rt_a_handle.spawn(async move {
        let result = client
            .download(seeder_addr, encrypted_hash, &[0], Arc::new(SlowMockPayment), None)
            .await;
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(std::time::Duration::from_secs(15))
        .expect("download timed out (recv)")
        .expect("download failed with blocking payment");

    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() >= 450, "payment should have blocked ~500ms");
    assert_eq!(result.chunks.len(), 1);

    rt_a_handle.spawn(async move {
        buyer_ep.close().await;
        router.shutdown().await.expect("router shutdown");
    });
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

// ── Phase 3A: Large file tests ──────────────────────────────────────────

fn make_random_chunks(count: usize, chunk_size: usize) -> Vec<Vec<u8>> {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            let mut buf = vec![0u8; chunk_size];
            rng.fill(&mut buf[..]);
            buf
        })
        .collect()
}

#[tokio::test]
async fn large_file_download_500_chunks() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x10; 32];
    let chunk_data = make_random_chunks(500, 1024);
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    let seeder_addr = seeder_ep.addr();
    let buyer_ep = make_endpoint(vec![]).await;
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "large_500_ln".to_string());

    let indices: Vec<u32> = (0..500).collect();
    let result = client
        .download(seeder_addr, encrypted_hash, &indices, Arc::new(MockPayment), None)
        .await
        .expect("500-chunk download should succeed");

    assert_eq!(result.chunks.len(), 500);
    assert_eq!(result.chunks_received, 500);

    let mut by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
    for (i, original) in chunk_data.iter().enumerate() {
        let downloaded = by_index.remove(&(i as u32)).unwrap();
        assert_eq!(downloaded, *original, "chunk {} data mismatch", i);
    }

    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}

#[tokio::test]
async fn large_file_download_1500_chunks() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x11; 32];
    let chunk_data = make_random_chunks(1500, 256);
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    let seeder_addr = seeder_ep.addr();
    let buyer_ep = make_endpoint(vec![]).await;
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "large_1500_ln".to_string());

    let indices: Vec<u32> = (0..1500).collect();
    let result = client
        .download(seeder_addr, encrypted_hash, &indices, Arc::new(MockPayment), None)
        .await
        .expect("1500-chunk download should succeed");

    assert_eq!(result.chunks.len(), 1500);
    assert_eq!(result.chunks_received, 1500);

    let mut by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
    for (i, original) in chunk_data.iter().enumerate() {
        let downloaded = by_index.remove(&(i as u32)).unwrap();
        assert_eq!(downloaded, *original, "chunk {} data mismatch", i);
    }

    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}

// ── Phase 3B: Concurrent buyers ─────────────────────────────────────────

#[tokio::test]
async fn concurrent_buyers_same_content() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x20; 32];
    let chunk_data = make_random_chunks(50, 512);
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();
    let seeder_addr = seeder_ep.addr();

    let mut handles = Vec::new();
    for buyer_id in 0..3u8 {
        let addr = seeder_addr.clone();
        let data = chunk_data.clone();
        let handle = tokio::spawn(async move {
            let ep = make_endpoint(vec![]).await;
            let client = conduit_p2p::client::BuyerClient::new(
                ep.clone(),
                format!("concurrent_buyer_{buyer_id}"),
            );
            let indices: Vec<u32> = (0..50).collect();
            let result = client
                .download(addr, encrypted_hash, &indices, Arc::new(MockPayment), None)
                .await
                .unwrap_or_else(|e| panic!("buyer {buyer_id} download failed: {e}"));

            assert_eq!(result.chunks.len(), 50, "buyer {buyer_id}");
            let by_index: HashMap<u32, Vec<u8>> = result.chunks.into_iter().collect();
            for (i, original) in data.iter().enumerate() {
                assert_eq!(
                    by_index[&(i as u32)],
                    *original,
                    "buyer {} chunk {} mismatch",
                    buyer_id,
                    i
                );
            }
            ep.close().await;
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.expect("buyer task panicked");
    }

    router.shutdown().await.expect("router shutdown");
}

// ── Phase 3C: Timeout and failure recovery ──────────────────────────────

#[derive(Debug)]
struct SlowStore {
    inner: MockStore,
    delay_chunk: u32,
}

impl ChunkStore for SlowStore {
    fn get_chunk(&self, hash: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        if index == self.delay_chunk {
            std::thread::sleep(std::time::Duration::from_secs(65));
        }
        self.inner.get_chunk(hash, index)
    }
    fn get_proof(&self, hash: &[u8; 32], index: u32) -> Option<Vec<conduit_p2p::wire::ProofNode>> {
        self.inner.get_proof(hash, index)
    }
    fn get_bitfield(&self, hash: &[u8; 32]) -> Option<Bitfield> {
        self.inner.get_bitfield(hash)
    }
    fn create_invoice(
        &self,
        hash: &[u8; 32],
        indices: &[u32],
        buyer_ln: &str,
    ) -> anyhow::Result<(String, u64)> {
        self.inner.create_invoice(hash, indices, buyer_ln)
    }
    fn verify_payment(&self, hash: &[u8; 32], preimage: &[u8; 32]) -> bool {
        self.inner.verify_payment(hash, preimage)
    }
}

#[tokio::test]
async fn chunk_timeout_triggers_error() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x30; 32];
    let chunk_data: Vec<Vec<u8>> = vec![b"ok-chunk".to_vec(), b"slow-chunk".to_vec()];
    let inner = MockStore::new(encrypted_hash, chunk_data);
    let store = Arc::new(SlowStore {
        inner,
        delay_chunk: 1,
    });

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    let seeder_addr = seeder_ep.addr();
    let buyer_ep = make_endpoint(vec![]).await;
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "timeout_test_ln".to_string());

    let result = client
        .download(
            seeder_addr,
            encrypted_hash,
            &[0, 1],
            Arc::new(MockPayment),
            None,
        )
        .await;

    assert!(result.is_err(), "should have timed out");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timed out"),
        "error should mention timeout, got: {err_msg}"
    );

    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}

// ── Phase 3D: Disk sink test ────────────────────────────────────────────

#[tokio::test]
async fn download_to_disk_sink() {
    let _ = tracing_subscriber::fmt::try_init();

    let encrypted_hash = [0x40; 32];
    let chunk_data = make_random_chunks(200, 512);
    let store = Arc::new(MockStore::new(encrypted_hash, chunk_data.clone()));

    let seeder_ep = make_endpoint(vec![CONDUIT_ALPN.to_vec()]).await;
    let handler = Arc::new(ChunkProtocol::new(store));
    let router = Router::builder(seeder_ep.clone())
        .accept(CONDUIT_ALPN, handler.as_ref().clone())
        .spawn();

    let seeder_addr = seeder_ep.addr();
    let buyer_ep = make_endpoint(vec![]).await;
    let client =
        conduit_p2p::client::BuyerClient::new(buyer_ep.clone(), "disk_sink_ln".to_string());

    let tmp_dir = std::env::temp_dir().join(format!("conduit-test-sink-{}", std::process::id()));
    let sink =
        std::sync::Arc::new(conduit_p2p::client::DiskSink::new(&tmp_dir).expect("create sink"));

    let indices: Vec<u32> = (0..200).collect();
    let result = client
        .download_to_sink(
            seeder_addr,
            encrypted_hash,
            &indices,
            Arc::new(MockPayment),
            None,
            sink.clone(),
        )
        .await
        .expect("disk sink download should succeed");

    assert_eq!(result.chunks_received, 200);
    assert!(result.chunks.is_empty(), "chunks should be empty when using sink");

    let reassembled = sink.reassemble(200).expect("reassembly");
    let expected: Vec<u8> = chunk_data.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(reassembled, expected, "reassembled data should match original");

    // Verify individual chunk files exist
    for i in 0..200u32 {
        assert!(sink.chunk_path(i).exists(), "chunk file {} should exist", i);
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
    buyer_ep.close().await;
    router.shutdown().await.expect("router shutdown");
}
