//! Buyer-side P2P client: connects to seeders, exchanges bitfields,
//! requests chunks, pays invoices, downloads chunk data.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use tracing::{debug, info, warn};

use crate::wire::*;

/// Receives verified chunks during download. Implementations decide where
/// data goes (RAM, disk, etc.).
pub trait DownloadSink: Send + Sync + 'static {
    fn write_chunk(&self, index: u32, data: &[u8]) -> Result<()>;
    fn on_progress(&self, received: u32, total: u32) {
        let _ = (received, total);
    }
}

/// Writes each chunk to `{dir}/{index}.bin`, keeping memory bounded.
pub struct DiskSink {
    dir: PathBuf,
}

impl DiskSink {
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn chunk_path(&self, index: u32) -> PathBuf {
        self.dir.join(format!("{index}.bin"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Read chunks back from disk in order and concatenate.
    pub fn reassemble(&self, count: u32) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        for i in 0..count {
            let p = self.chunk_path(i);
            let chunk = std::fs::read(&p)
                .with_context(|| format!("reading chunk {} from {}", i, p.display()))?;
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
}

impl DownloadSink for DiskSink {
    fn write_chunk(&self, index: u32, data: &[u8]) -> Result<()> {
        std::fs::write(self.chunk_path(index), data)?;
        Ok(())
    }
}

/// Collects chunks in memory (original behavior, for small files and tests).
pub struct MemorySink {
    chunks: std::sync::Mutex<Vec<(u32, Vec<u8>)>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self {
            chunks: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn into_chunks(self) -> Vec<(u32, Vec<u8>)> {
        self.chunks.into_inner().unwrap()
    }
}

impl DownloadSink for MemorySink {
    fn write_chunk(&self, index: u32, data: &[u8]) -> Result<()> {
        self.chunks.lock().unwrap().push((index, data.to_vec()));
        Ok(())
    }
}

/// Result of a successful chunk download session.
#[derive(Debug)]
pub struct DownloadResult {
    /// The downloaded chunks, indexed by chunk_index.
    /// Empty when using a sink -- chunks were written there instead.
    pub chunks: Vec<(u32, Vec<u8>)>,
    /// Total amount paid in millisatoshis.
    pub total_paid_msat: u64,
    /// Number of chunks received.
    pub chunks_received: u32,
}

/// Trait the buyer's application implements for Lightning payments.
pub trait PaymentHandler: Send + Sync + 'static {
    /// Pay a BOLT11 invoice. Returns the preimage on success.
    fn pay_invoice(&self, bolt11: &str) -> Result<[u8; 32]>;
}

/// Buyer P2P client for downloading chunks from a single seeder.
pub struct BuyerClient {
    endpoint: Endpoint,
    ln_pubkey: String,
}

impl BuyerClient {
    pub fn new(endpoint: Endpoint, ln_pubkey: String) -> Self {
        Self {
            endpoint,
            ln_pubkey,
        }
    }

    /// Connect to a seeder and download the specified chunks into memory.
    /// For large files, prefer `download_to_sink` with a `DiskSink`.
    pub async fn download(
        &self,
        seeder_addr: EndpointAddr,
        encrypted_hash: [u8; 32],
        desired_indices: &[u32],
        payment: std::sync::Arc<dyn PaymentHandler>,
        expected_encrypted_root: Option<[u8; 32]>,
    ) -> Result<DownloadResult> {
        let sink = std::sync::Arc::new(MemorySink::new());
        let mut result = self
            .download_to_sink(
                seeder_addr,
                encrypted_hash,
                desired_indices,
                payment,
                expected_encrypted_root,
                sink.clone(),
            )
            .await?;
        let sink = std::sync::Arc::try_unwrap(sink)
            .map_err(|_| anyhow::anyhow!("sink still referenced"))?;
        result.chunks = sink.into_chunks();
        Ok(result)
    }

    /// Connect to a seeder and download the specified chunks, writing each
    /// verified chunk to `sink` as it arrives. Keeps memory bounded.
    ///
    /// Flow:
    /// 1. HANDSHAKE -> receive BITFIELD
    /// 2. REQUEST(indices) -> receive INVOICE
    /// 3. Pay invoice off-band -> PAYMENT_PROOF(preimage)
    /// 4. Receive CHUNK messages (each Merkle-verified, written to sink)
    pub async fn download_to_sink(
        &self,
        seeder_addr: EndpointAddr,
        encrypted_hash: [u8; 32],
        desired_indices: &[u32],
        payment: std::sync::Arc<dyn PaymentHandler>,
        expected_encrypted_root: Option<[u8; 32]>,
        sink: std::sync::Arc<dyn DownloadSink>,
    ) -> Result<DownloadResult> {
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.endpoint.connect(seeder_addr, crate::CONDUIT_ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("P2P connect timed out after 15s"))?
        .context("connecting to seeder")?;

        info!(hash = hex::encode(encrypted_hash), "connected to seeder");

        self.run_session(
            conn,
            encrypted_hash,
            desired_indices,
            payment,
            expected_encrypted_root,
            sink,
        )
        .await
    }

    async fn run_session(
        &self,
        conn: Connection,
        encrypted_hash: [u8; 32],
        desired_indices: &[u32],
        payment: std::sync::Arc<dyn PaymentHandler>,
        expected_encrypted_root: Option<[u8; 32]>,
        sink: std::sync::Arc<dyn DownloadSink>,
    ) -> Result<DownloadResult> {
        let (mut send, mut recv) = conn.open_bi().await?;

        write_msg(
            &mut send,
            &Message::Handshake(Handshake::new(encrypted_hash, self.ln_pubkey.clone())),
        )
        .await?;

        let bitfield: Bitfield = match read_msg(&mut recv).await? {
            Message::Bitfield(bf) => bf,
            Message::Reject(r) => anyhow::bail!("seeder rejected: {:?}", r.reason),
            other => anyhow::bail!(
                "expected Bitfield, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        debug!(
            chunk_count = bitfield.chunk_count,
            chunk_size = bitfield.chunk_size,
            "received bitfield"
        );

        let encrypted_root = bitfield.encrypted_root;

        if let Some(expected) = expected_encrypted_root {
            if encrypted_root != expected {
                anyhow::bail!(
                    "seeder encrypted_root mismatch: expected {}, got {} -- possible MITM",
                    hex::encode(expected),
                    hex::encode(encrypted_root)
                );
            }
            info!("encrypted_root matches registry expectation");
        }

        let available: Vec<u32> = desired_indices
            .iter()
            .filter(|&&i| bitfield.has_chunk(i))
            .copied()
            .collect();

        if available.is_empty() {
            anyhow::bail!("seeder has none of the requested chunks");
        }

        let unavailable: Vec<u32> = desired_indices
            .iter()
            .filter(|&&i| !bitfield.has_chunk(i))
            .copied()
            .collect();
        if !unavailable.is_empty() {
            warn!(
                ?unavailable,
                "seeder missing some chunks, requesting only available ones"
            );
        }

        write_msg(
            &mut send,
            &Message::Request(ChunkRequest {
                indices: available.clone(),
            }),
        )
        .await?;

        let invoice = match read_msg(&mut recv).await? {
            Message::Invoice(inv) => inv,
            Message::Reject(r) => anyhow::bail!("seeder rejected request: {:?}", r.reason),
            other => anyhow::bail!("expected Invoice, got {:?}", std::mem::discriminant(&other)),
        };

        info!(
            amount_msat = invoice.amount_msat,
            chunk_count = invoice.chunk_count,
            "received invoice, paying"
        );

        let bolt11_owned = invoice.bolt11.clone();
        let payment_clone = payment.clone();
        let preimage =
            tokio::task::spawn_blocking(move || payment_clone.pay_invoice(&bolt11_owned))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?
                .context("paying invoice")?;

        write_msg(&mut send, &Message::PaymentProof(PaymentProof { preimage })).await?;

        let mut received = 0u32;

        while received < invoice.chunk_count {
            let per_chunk_timeout = std::time::Duration::from_secs(60);
            let msg = tokio::time::timeout(per_chunk_timeout, read_msg(&mut recv))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "timed out waiting for chunk {}/{} (received {} so far)",
                        received + 1,
                        invoice.chunk_count,
                        received
                    )
                })?;
            match msg? {
                Message::Chunk(chunk) => {
                    let merkle_proof = conduit_core::merkle::MerkleProof {
                        siblings: chunk
                            .proof
                            .iter()
                            .map(|pn| (pn.hash, pn.is_left))
                            .collect(),
                    };
                    if !merkle_proof.verify(
                        &chunk.data,
                        chunk.chunk_index as usize,
                        &encrypted_root,
                    ) {
                        warn!(
                            index = chunk.chunk_index,
                            "Merkle proof FAILED -- rejecting chunk"
                        );
                        anyhow::bail!(
                            "chunk {} failed Merkle verification (source may be malicious)",
                            chunk.chunk_index
                        );
                    }
                    debug!(
                        index = chunk.chunk_index,
                        size = chunk.data.len(),
                        "chunk verified"
                    );
                    sink.write_chunk(chunk.chunk_index, &chunk.data)?;
                    received += 1;
                    sink.on_progress(received, invoice.chunk_count);
                }
                Message::Reject(r) => {
                    anyhow::bail!(
                        "seeder rejected mid-transfer: {:?} (received {}/{})",
                        r.reason,
                        received,
                        invoice.chunk_count
                    );
                }
                other => {
                    warn!(
                        "unexpected message during transfer: {:?}",
                        std::mem::discriminant(&other)
                    );
                }
            }
        }

        send.finish()?;
        conn.close(0u8.into(), b"done");

        info!(
            chunks_received = received,
            total_paid_msat = invoice.amount_msat,
            "download complete — all chunks Merkle-verified"
        );

        Ok(DownloadResult {
            chunks: Vec::new(),
            total_paid_msat: invoice.amount_msat,
            chunks_received: received,
        })
    }
}

/// Multi-seeder parallel download orchestrator.
///
/// Given a set of seeders and desired chunks, distributes chunk requests
/// across seeders (preferring seeders that have unique chunks), downloads
/// in parallel, and reassembles.
pub struct MultiSourceDownloader {
    endpoint: Endpoint,
    ln_pubkey: String,
}

impl MultiSourceDownloader {
    pub fn new(endpoint: Endpoint, ln_pubkey: String) -> Self {
        Self {
            endpoint,
            ln_pubkey,
        }
    }

    /// Probe multiple seeders for their bitfields without downloading.
    pub async fn probe_seeders(
        &self,
        seeders: &[EndpointAddr],
        encrypted_hash: [u8; 32],
    ) -> Vec<(EndpointAddr, Bitfield)> {
        let mut results = Vec::new();

        for addr in seeders {
            match self.probe_one(addr.clone(), encrypted_hash).await {
                Ok(bf) => results.push((addr.clone(), bf)),
                Err(e) => warn!("failed to probe seeder: {e}"),
            }
        }

        results
    }

    async fn probe_one(&self, addr: EndpointAddr, encrypted_hash: [u8; 32]) -> Result<Bitfield> {
        let conn = self.endpoint.connect(addr, crate::CONDUIT_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        write_msg(
            &mut send,
            &Message::Handshake(Handshake::new(encrypted_hash, self.ln_pubkey.clone())),
        )
        .await?;

        let bf = match read_msg(&mut recv).await? {
            Message::Bitfield(bf) => bf,
            _ => anyhow::bail!("expected Bitfield"),
        };

        send.finish()?;
        conn.close(0u8.into(), b"probed");
        Ok(bf)
    }
}
