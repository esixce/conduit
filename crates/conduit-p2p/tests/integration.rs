//! Integration tests: spin up a seeder and buyer node, perform a full
//! handshake → request → invoice → payment → chunk transfer flow.

use std::sync::Arc;

use anyhow::Result;
use conduit_core::merkle::MerkleTree;
use conduit_p2p::handler::{ChunkProtocol, ChunkStore};
use conduit_p2p::node::{P2pConfig, P2pNode};
use conduit_p2p::wire::{Bitfield, ProofNode};

/// Deterministic test content: 3 chunks of 4 bytes each.
const TEST_ENCRYPTED_HASH: [u8; 32] = [0xAA; 32];
const CHUNK_SIZE: u32 = 4;
const CHUNK_DATA: [[u8; 4]; 3] = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
const FAKE_PREIMAGE: [u8; 32] = [0xBB; 32];

fn build_test_tree() -> MerkleTree {
    let chunks: Vec<Vec<u8>> = CHUNK_DATA.iter().map(|c| c.to_vec()).collect();
    MerkleTree::from_chunks(&chunks)
}

#[derive(Debug)]
struct MockStore {
    tree: MerkleTree,
}

impl MockStore {
    fn new() -> Self {
        Self {
            tree: build_test_tree(),
        }
    }
}

impl ChunkStore for MockStore {
    fn get_chunk(&self, hash: &[u8; 32], index: u32) -> Option<Vec<u8>> {
        if hash == &TEST_ENCRYPTED_HASH && (index as usize) < CHUNK_DATA.len() {
            Some(CHUNK_DATA[index as usize].to_vec())
        } else {
            None
        }
    }

    fn get_proof(&self, hash: &[u8; 32], index: u32) -> Option<Vec<ProofNode>> {
        if hash == &TEST_ENCRYPTED_HASH && (index as usize) < CHUNK_DATA.len() {
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
        if hash == &TEST_ENCRYPTED_HASH {
            Some(Bitfield::from_bools(
                &[true, true, true],
                CHUNK_SIZE,
                self.tree.root(),
            ))
        } else {
            None
        }
    }

    fn create_invoice(
        &self,
        _hash: &[u8; 32],
        indices: &[u32],
        _buyer_ln: &str,
    ) -> Result<(String, u64)> {
        let amount = indices.len() as u64 * 100;
        Ok(("lnbcrt1fake_invoice".to_string(), amount))
    }

    fn verify_payment(&self, _hash: &[u8; 32], preimage: &[u8; 32]) -> bool {
        preimage == &FAKE_PREIMAGE
    }
}

struct MockPayment;

impl conduit_p2p::client::PaymentHandler for MockPayment {
    fn pay_invoice(&self, _bolt11: &str) -> Result<[u8; 32]> {
        Ok(FAKE_PREIMAGE)
    }
}

#[tokio::test]
async fn test_full_download_flow() {
    let _ = tracing_subscriber::fmt::try_init();

    let store = Arc::new(MockStore::new());
    let handler = Arc::new(ChunkProtocol::new(store));

    let seeder = P2pNode::spawn(
        P2pConfig {
            secret_key: None,
            enable_dht: false,
        },
        handler,
    )
    .await
    .expect("seeder node failed to start");

    let buyer = P2pNode::spawn_buyer(P2pConfig {
        secret_key: None,
        enable_dht: false,
    })
    .await
    .expect("buyer node failed to start");

    let seeder_addr = seeder.endpoint_addr();

    let client = conduit_p2p::client::BuyerClient::new(
        buyer.endpoint().clone(),
        "02fake_ln_pubkey".to_string(),
    );

    let result = client
        .download(seeder_addr, TEST_ENCRYPTED_HASH, &[0, 1, 2], Arc::new(MockPayment), None)
        .await
        .expect("download failed");

    assert_eq!(result.chunks.len(), 3);
    assert_eq!(result.total_paid_msat, 300);

    for (idx, data) in &result.chunks {
        assert_eq!(data, &CHUNK_DATA[*idx as usize]);
    }

    buyer.shutdown().await.expect("buyer shutdown failed");
    seeder.shutdown().await.expect("seeder shutdown failed");
}

#[tokio::test]
async fn test_bitfield_operations() {
    let bf = Bitfield::from_bools(&[true, false, true, true, false], 256, [0; 32]);
    assert!(bf.has_chunk(0));
    assert!(!bf.has_chunk(1));
    assert!(bf.has_chunk(2));
    assert!(bf.has_chunk(3));
    assert!(!bf.has_chunk(4));
    assert!(!bf.has_chunk(99));
}

#[tokio::test]
async fn test_wire_roundtrip() {
    use conduit_p2p::wire::*;

    let original = Handshake::new([0x42; 32], "02abcdef".to_string());
    let bytes = postcard::to_allocvec(&Message::Handshake(original.clone())).unwrap();
    let decoded: Message = postcard::from_bytes(&bytes).unwrap();

    match decoded {
        Message::Handshake(h) => {
            assert_eq!(h.version, Handshake::CURRENT_VERSION);
            assert_eq!(h.encrypted_hash, [0x42; 32]);
            assert_eq!(h.lightning_pubkey, "02abcdef");
        }
        _ => panic!("wrong message type"),
    }
}
