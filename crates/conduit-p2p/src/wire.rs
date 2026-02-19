//! Wire protocol: message types exchanged between buyer and seeder.
//!
//! Binary format uses postcard (varint-prefixed, zero-copy friendly).
//! Each message on the wire is: [u32 LE length][postcard bytes].
//!
//! From docs/02_p2p_distribution.md Section 9.

use serde::{Deserialize, Serialize};

// ── Framing ────────────────────────────────────────────────────────────

/// Maximum message size (16 MB — generous for chunk data).
pub const MAX_MSG_SIZE: u32 = 16 * 1024 * 1024;

/// Write a length-prefixed postcard message to an iroh SendStream.
pub async fn write_msg<T: Serialize>(
    stream: &mut iroh::endpoint::SendStream,
    msg: &T,
) -> anyhow::Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = bytes.len() as u32;
    anyhow::ensure!(len <= MAX_MSG_SIZE, "message too large: {len} bytes");
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

/// Read a length-prefixed postcard message from an iroh RecvStream.
pub async fn read_msg<T: for<'de> Deserialize<'de>>(
    stream: &mut iroh::endpoint::RecvStream,
) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    anyhow::ensure!(len <= MAX_MSG_SIZE, "message too large: {len} bytes");
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

// ── Messages ───────────────────────────────────────────────────────────

/// Top-level message envelope sent over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Handshake(Handshake),
    Bitfield(Bitfield),
    Have(Have),
    Request(ChunkRequest),
    Invoice(ChunkInvoice),
    PaymentProof(PaymentProof),
    Chunk(ChunkData),
    Cancel(Cancel),
    Reject(Reject),
}

/// First message on every connection. Establishes protocol version
/// and declares which content the peer is interested in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub version: u8,
    /// SHA-256 of the encrypted content (H(E)) this session is about.
    pub encrypted_hash: [u8; 32],
    /// Peer's Lightning node pubkey (hex, for payment routing).
    pub lightning_pubkey: String,
}

impl Handshake {
    pub const CURRENT_VERSION: u8 = 1;

    pub fn new(encrypted_hash: [u8; 32], lightning_pubkey: String) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            encrypted_hash,
            lightning_pubkey,
        }
    }
}

/// Seeder's chunk availability for the content identified in the handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bitfield {
    /// One bit per chunk; bit[i]=1 means the seeder has encrypted chunk E_i.
    /// Packed as big-endian bytes: ceil(chunk_count / 8) bytes.
    pub bits: Vec<u8>,
    pub chunk_count: u32,
    pub chunk_size: u32,
    /// Encrypted Merkle root — so the buyer can verify chunks.
    pub encrypted_root: [u8; 32],
}

impl Bitfield {
    pub fn has_chunk(&self, index: u32) -> bool {
        let byte_idx = (index / 8) as usize;
        let bit_idx = 7 - (index % 8);
        self.bits
            .get(byte_idx)
            .is_some_and(|b| b & (1 << bit_idx) != 0)
    }

    pub fn set_chunk(&mut self, index: u32) {
        let byte_idx = (index / 8) as usize;
        let bit_idx = 7 - (index % 8);
        if byte_idx < self.bits.len() {
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    pub fn from_bools(available: &[bool], chunk_size: u32, encrypted_root: [u8; 32]) -> Self {
        let chunk_count = available.len() as u32;
        let byte_count = (chunk_count as usize).div_ceil(8);
        let mut bits = vec![0u8; byte_count];
        for (i, &has) in available.iter().enumerate() {
            if has {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                bits[byte_idx] |= 1 << bit_idx;
            }
        }
        Self {
            bits,
            chunk_count,
            chunk_size,
            encrypted_root,
        }
    }
}

/// Notification that a seeder just acquired a new chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Have {
    pub chunk_index: u32,
}

/// Buyer requests chunks from a seeder. One REQUEST per batch payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    /// Indices of chunks the buyer wants.
    pub indices: Vec<u32>,
}

/// Seeder responds with a Lightning invoice for the requested chunks.
/// Preimage = K_S (transport key). Paying reveals K_S, buyer uses it
/// to unwrap all chunks in this batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInvoice {
    /// BOLT11 invoice string.
    pub bolt11: String,
    /// Total amount in millisatoshis.
    pub amount_msat: u64,
    /// Number of chunks covered by this invoice.
    pub chunk_count: u32,
}

/// Buyer proves payment by revealing the preimage (= K_S).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProof {
    /// The Lightning preimage (32 bytes). This IS the transport key K_S.
    pub preimage: [u8; 32],
}

/// A wrapped (transport-encrypted) chunk plus its Merkle proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkData {
    pub chunk_index: u32,
    /// W_i = AES-256-CTR(E_i, K_S, nonce=i) — transport-encrypted chunk.
    pub data: Vec<u8>,
    /// Merkle proof siblings for verifying against encrypted_root.
    pub proof: Vec<ProofNode>,
}

/// Single node in a Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: [u8; 32],
    /// true = sibling is on the left, false = right.
    pub is_left: bool,
}

/// Buyer cancels pending chunk requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cancel {
    pub indices: Vec<u32>,
}

/// Seeder rejects a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reject {
    pub reason: RejectReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectReason {
    Overloaded,
    ChunksUnavailable,
    InvalidRequest,
    PaymentRequired,
}
