//! Buyer-side P2P client: connects to seeders, exchanges bitfields,
//! requests chunks, pays invoices, downloads chunk data.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr};
use tracing::{debug, info, warn};

use crate::wire::*;

/// Result of a successful chunk download session.
pub struct DownloadResult {
    /// The downloaded chunks, indexed by chunk_index.
    pub chunks: Vec<(u32, Vec<u8>)>,
    /// Total amount paid in millisatoshis.
    pub total_paid_msat: u64,
}

/// Trait the buyer's application implements for Lightning payments.
pub trait PaymentHandler: Send + Sync {
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

    /// Connect to a seeder and download the specified chunks.
    ///
    /// Flow:
    /// 1. HANDSHAKE → receive BITFIELD
    /// 2. REQUEST(indices) → receive INVOICE
    /// 3. Pay invoice off-band → PAYMENT_PROOF(preimage)
    /// 4. Receive CHUNK messages
    pub async fn download(
        &self,
        seeder_addr: EndpointAddr,
        encrypted_hash: [u8; 32],
        desired_indices: &[u32],
        payment: &dyn PaymentHandler,
    ) -> Result<DownloadResult> {
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.endpoint.connect(seeder_addr, crate::CONDUIT_ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("P2P connect timed out after 15s"))?
        .context("connecting to seeder")?;

        info!(hash = hex::encode(encrypted_hash), "connected to seeder");

        self.run_session(conn, encrypted_hash, desired_indices, payment)
            .await
    }

    async fn run_session(
        &self,
        conn: Connection,
        encrypted_hash: [u8; 32],
        desired_indices: &[u32],
        payment: &dyn PaymentHandler,
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

        let preimage = payment
            .pay_invoice(&invoice.bolt11)
            .context("paying invoice")?;

        write_msg(&mut send, &Message::PaymentProof(PaymentProof { preimage })).await?;

        let mut chunks = Vec::with_capacity(available.len());
        let mut received = 0u32;

        while received < invoice.chunk_count {
            match read_msg(&mut recv).await? {
                Message::Chunk(chunk) => {
                    debug!(
                        index = chunk.chunk_index,
                        size = chunk.data.len(),
                        "received chunk"
                    );
                    chunks.push((chunk.chunk_index, chunk.data));
                    received += 1;
                }
                Message::Reject(r) => {
                    anyhow::bail!("seeder rejected mid-transfer: {:?}", r.reason);
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
            chunks_received = chunks.len(),
            total_paid_msat = invoice.amount_msat,
            "download complete"
        );

        Ok(DownloadResult {
            chunks,
            total_paid_msat: invoice.amount_msat,
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
