//! Merkle tree construction and verification for P2P chunk integrity.
//!
//! Each chunk becomes a leaf: `H_leaf = SHA-256(0x00 || chunk_data)`.
//! Internal nodes: `H_node = SHA-256(0x01 || left || right)`.
//! The 0x00/0x01 domain-separation prefix prevents second-preimage attacks
//! (RFC 6962, Certificate Transparency).
//!
//! A Merkle proof for chunk *i* lets a buyer verify a single chunk against
//! the published root without downloading the entire file.
//!
//! Design: [`docs/02_p2p_distribution.md`], Section 3.

use crate::verify::sha256_hash;
use serde::{Deserialize, Serialize};

// Domain-separation prefixes (RFC 6962).
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf (chunk data).
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    sha256_hash(&buf)
}

/// Hash an internal node (two children).
fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256_hash(&buf)
}

/// A complete Merkle tree built over chunk hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes stored in a flat array.
    /// Index 0 is the root. For a tree with `n` leaves, the leaves
    /// start at index `n - 1` (for a perfect binary tree). We use
    /// a simpler layer-by-layer representation.
    layers: Vec<Vec<[u8; 32]>>,
    /// Number of original leaves (chunks).
    pub leaf_count: usize,
}

/// A Merkle inclusion proof for a single leaf.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The sibling hashes along the path from leaf to root.
    /// Each entry is `(hash, is_left)` where `is_left` indicates
    /// whether the sibling is on the left side.
    pub siblings: Vec<([u8; 32], bool)>,
}

/// JSON-serializable representation of a Merkle proof.
/// Used for HTTP API responses (`/api/chunks/{id}/proof/{index}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofJson {
    /// Sibling hashes and directions: `[["hex_hash", true/false], ...]`
    /// `true` means the sibling is on the left.
    pub siblings: Vec<(String, bool)>,
}

impl MerkleTree {
    /// Build a Merkle tree from chunk data.
    ///
    /// Panics if `chunks` is empty.
    pub fn from_chunks(chunks: &[Vec<u8>]) -> Self {
        assert!(!chunks.is_empty(), "Cannot build Merkle tree from 0 chunks");

        // Layer 0: leaves
        let mut leaves: Vec<[u8; 32]> = chunks.iter().map(|c| leaf_hash(c)).collect();

        // If odd number of leaves, duplicate the last one
        if leaves.len() > 1 && leaves.len() % 2 != 0 {
            leaves.push(*leaves.last().unwrap());
        }

        let leaf_count = chunks.len();
        let mut layers = vec![leaves];

        // Build parent layers until we reach the root
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut parent = Vec::with_capacity((prev.len() + 1) / 2);
            for pair in prev.chunks(2) {
                if pair.len() == 2 {
                    parent.push(internal_hash(&pair[0], &pair[1]));
                } else {
                    // Odd node at this level: promote (duplicate)
                    parent.push(internal_hash(&pair[0], &pair[0]));
                }
            }
            layers.push(parent);
        }

        MerkleTree { layers, leaf_count }
    }

    /// The Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    /// Generate a Merkle proof for the leaf at `index`.
    ///
    /// Panics if `index >= leaf_count`.
    pub fn proof(&self, index: usize) -> MerkleProof {
        assert!(
            index < self.leaf_count,
            "Leaf index {} out of range (leaf_count={})",
            index,
            self.leaf_count
        );

        let mut siblings = Vec::new();
        let mut idx = index;

        // If there was an odd number of original leaves, the leaf layer
        // was padded. Adjust idx within the padded layer.
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            // The sibling might be the same index if the layer has been
            // promoted (single-element layer), but that shouldn't happen
            // for layers > 1 element.
            if sibling_idx < layer.len() {
                // `is_left` means the sibling is on the left (i.e., current node is on the right)
                let is_left = idx % 2 == 1;
                siblings.push((layer[sibling_idx], is_left));
            } else {
                // Edge case: sibling doesn't exist (promoted node)
                siblings.push((layer[idx], false));
            }

            idx /= 2;
        }

        MerkleProof { siblings }
    }

    /// Get the hash of a specific leaf by index.
    pub fn leaf_hash_at(&self, index: usize) -> [u8; 32] {
        assert!(
            index < self.leaf_count,
            "Leaf index {} out of range (leaf_count={})",
            index,
            self.leaf_count
        );
        self.layers[0][index]
    }
}

impl MerkleProof {
    /// Verify that `chunk_data` at position `index` produces the expected `root`.
    pub fn verify(&self, chunk_data: &[u8], _index: usize, expected_root: &[u8; 32]) -> bool {
        let mut hash = leaf_hash(chunk_data);

        for (sibling, is_left) in &self.siblings {
            if *is_left {
                hash = internal_hash(sibling, &hash);
            } else {
                hash = internal_hash(&hash, sibling);
            }
        }

        hash == *expected_root
    }

    /// Convert to a JSON-serializable representation.
    pub fn to_json(&self) -> MerkleProofJson {
        MerkleProofJson {
            siblings: self
                .siblings
                .iter()
                .map(|(hash, is_left)| (hex::encode(hash), *is_left))
                .collect(),
        }
    }

    /// Reconstruct from a JSON representation.
    pub fn from_json(json: &MerkleProofJson) -> Result<Self, hex::FromHexError> {
        let mut siblings = Vec::with_capacity(json.siblings.len());
        for (hex_hash, is_left) in &json.siblings {
            let bytes = hex::decode(hex_hash)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            siblings.push((hash, *is_left));
        }
        Ok(MerkleProof { siblings })
    }
}

/// Convenience: build a tree from chunks and return the root as a hex string.
pub fn root_hex(chunks: &[Vec<u8>]) -> String {
    hex::encode(MerkleTree::from_chunks(chunks).root())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_chunk() {
        let chunks = vec![b"only chunk".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count, 1);

        // Root should be the leaf hash itself (no internal nodes)
        let expected = leaf_hash(b"only chunk");
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_two_chunks() {
        let chunks = vec![b"chunk0".to_vec(), b"chunk1".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count, 2);

        let l0 = leaf_hash(b"chunk0");
        let l1 = leaf_hash(b"chunk1");
        let expected_root = internal_hash(&l0, &l1);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_three_chunks_padding() {
        // 3 chunks => leaf layer padded to [L0, L1, L2, L2]
        let chunks = vec![b"chunk0".to_vec(), b"chunk1".to_vec(), b"chunk2".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count, 3);

        let l0 = leaf_hash(b"chunk0");
        let l1 = leaf_hash(b"chunk1");
        let l2 = leaf_hash(b"chunk2");
        let n01 = internal_hash(&l0, &l1);
        let n22 = internal_hash(&l2, &l2); // duplicated
        let expected_root = internal_hash(&n01, &n22);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_four_chunks() {
        let chunks: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 100]).collect();
        let tree = MerkleTree::from_chunks(&chunks);
        assert_eq!(tree.leaf_count, 4);
        assert_eq!(tree.layers.len(), 3); // leaves, internal, root
    }

    #[test]
    fn test_proof_verify_all_leaves() {
        let chunks: Vec<Vec<u8>> = (0..7)
            .map(|i| format!("chunk number {}", i).into_bytes())
            .collect();
        let tree = MerkleTree::from_chunks(&chunks);
        let root = tree.root();

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(
                proof.verify(chunk, i, &root),
                "Proof verification failed for chunk {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_rejects_wrong_data() {
        let chunks = vec![b"good".to_vec(), b"data".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        let root = tree.root();
        let proof = tree.proof(0);

        assert!(!proof.verify(b"tampered", 0, &root));
    }

    #[test]
    fn test_proof_rejects_wrong_root() {
        let chunks = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        let proof = tree.proof(0);
        let wrong_root = [0xFF; 32];

        assert!(!proof.verify(b"a", 0, &wrong_root));
    }

    #[test]
    fn test_domain_separation() {
        // Leaf hash and internal hash of the same data must differ
        let data = [0u8; 32];
        let lh = leaf_hash(&data);
        let ih = internal_hash(&data.try_into().unwrap(), &[0u8; 32]);
        assert_ne!(
            lh, ih,
            "Leaf and internal hashes must differ (domain separation)"
        );
    }

    #[test]
    fn test_deterministic() {
        let chunks = vec![b"determinism".to_vec()];
        let t1 = MerkleTree::from_chunks(&chunks);
        let t2 = MerkleTree::from_chunks(&chunks);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_root_hex() {
        let chunks = vec![b"test".to_vec()];
        let hex_str = root_hex(&chunks);
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_leaf_hash_at() {
        let chunks = vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);

        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(tree.leaf_hash_at(i), leaf_hash(chunk));
        }
    }

    #[test]
    fn test_large_tree() {
        // 256 chunks -- verifies scaling and correctness at moderate size
        let chunks: Vec<Vec<u8>> = (0..256)
            .map(|i| {
                let mut data = vec![0u8; 1024];
                data[0] = (i & 0xFF) as u8;
                data[1] = ((i >> 8) & 0xFF) as u8;
                data
            })
            .collect();
        let tree = MerkleTree::from_chunks(&chunks);
        let root = tree.root();

        // Spot-check a few proofs
        for i in [0, 1, 127, 128, 255] {
            let proof = tree.proof(i);
            assert!(
                proof.verify(&chunks[i], i, &root),
                "Large tree proof failed for chunk {}",
                i
            );
        }
    }

    #[test]
    #[should_panic(expected = "Cannot build Merkle tree from 0 chunks")]
    fn test_empty_panics() {
        let empty: Vec<Vec<u8>> = vec![];
        MerkleTree::from_chunks(&empty);
    }

    #[test]
    #[should_panic(expected = "Leaf index 5 out of range")]
    fn test_proof_out_of_range() {
        let chunks = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::from_chunks(&chunks);
        tree.proof(5);
    }

    /// Integration test: split + encrypt + merkle round-trip.
    ///
    /// Simulates the full pipeline:
    /// 1. Split plaintext into chunks
    /// 2. Encrypt each chunk with a per-chunk IV
    /// 3. Build Merkle tree over encrypted chunks
    /// 4. Verify each encrypted chunk against the Merkle root
    /// 5. Decrypt and reassemble
    #[test]
    fn test_chunk_encrypt_merkle_pipeline() {
        use crate::chunk;
        use crate::encrypt;

        let plaintext: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let key = encrypt::generate_key();

        // Step 1: Split
        let (chunks, meta) = chunk::split(&plaintext, 256);
        assert_eq!(meta.count, 8); // 2000 / 256 = 7.8 => 8 chunks

        // Step 2: Encrypt each chunk
        let encrypted_chunks: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| encrypt::encrypt(c, &key, i as u64))
            .collect();

        // Step 3: Build Merkle tree over encrypted chunks
        let tree = MerkleTree::from_chunks(&encrypted_chunks);
        let root = tree.root();

        // Step 4: Verify each chunk
        for (i, enc_chunk) in encrypted_chunks.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(
                proof.verify(enc_chunk, i, &root),
                "Pipeline Merkle verification failed for chunk {}",
                i
            );
        }

        // Step 5: Decrypt and reassemble
        let decrypted_chunks: Vec<Vec<u8>> = encrypted_chunks
            .iter()
            .enumerate()
            .map(|(i, c)| encrypt::decrypt(c, &key, i as u64))
            .collect();
        let reassembled = chunk::reassemble(&decrypted_chunks, meta.original_size);
        assert_eq!(reassembled, plaintext);
    }

    #[test]
    fn test_proof_json_round_trip() {
        let chunks: Vec<Vec<u8>> = (0..7)
            .map(|i| format!("chunk number {}", i).into_bytes())
            .collect();
        let tree = MerkleTree::from_chunks(&chunks);
        let root = tree.root();

        for (i, chunk) in chunks.iter().enumerate() {
            let proof = tree.proof(i);
            let json = proof.to_json();

            // Serialize to JSON string and back
            let json_str = serde_json::to_string(&json).unwrap();
            let json_back: super::MerkleProofJson = serde_json::from_str(&json_str).unwrap();
            let proof_back = MerkleProof::from_json(&json_back).unwrap();

            assert!(
                proof_back.verify(chunk, i, &root),
                "JSON round-trip proof verification failed for chunk {}",
                i
            );
        }
    }
}
