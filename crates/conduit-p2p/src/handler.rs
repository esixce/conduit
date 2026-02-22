//! Seeder-side protocol handler: accepts incoming buyer connections,
//! responds to chunk requests with Lightning invoices and chunk data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tracing::{debug, info, warn};

use crate::wire::*;

/// Trait that the application layer implements to provide chunk data
/// and Lightning invoicing. This decouples `conduit-p2p` from
/// `conduit-setup`'s internal state.
pub trait ChunkStore: Send + Sync + std::fmt::Debug + 'static {
    /// Returns the encrypted chunk data for a given content hash and chunk index.
    fn get_chunk(&self, encrypted_hash: &[u8; 32], index: u32) -> Option<Vec<u8>>;

    /// Returns the Merkle proof for a given chunk.
    fn get_proof(&self, encrypted_hash: &[u8; 32], index: u32) -> Option<Vec<ProofNode>>;

    /// Returns the bitfield (which chunks are available) for a content hash.
    fn get_bitfield(&self, encrypted_hash: &[u8; 32]) -> Option<Bitfield>;

    /// Generate a BOLT11 invoice for the given chunks.
    /// Returns (bolt11_string, amount_msat).
    fn create_invoice(
        &self,
        encrypted_hash: &[u8; 32],
        chunk_indices: &[u32],
        buyer_ln_pubkey: &str,
    ) -> Result<(String, u64)>;

    /// Verify that a payment preimage is valid for a pending invoice.
    /// Returns true if the payment was received.
    fn verify_payment(&self, encrypted_hash: &[u8; 32], preimage: &[u8; 32]) -> bool;
}

/// The iroh ProtocolHandler that serves the Conduit chunk protocol.
#[derive(Clone, Debug)]
pub struct ChunkProtocol {
    store: Arc<dyn ChunkStore>,
    /// Track active sessions: (encrypted_hash) -> session state.
    sessions: Arc<Mutex<HashMap<[u8; 32], SessionState>>>,
}

#[derive(Debug)]
struct SessionState {
    pending_indices: Vec<u32>,
    invoice_issued: bool,
}

impl ChunkProtocol {
    pub fn new(store: Arc<dyn ChunkStore>) -> Self {
        Self {
            store,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn handle_connection(&self, conn: Connection) -> Result<()> {
        let (mut send, mut recv) = conn.accept_bi().await?;

        let handshake: Message = read_msg(&mut recv).await.context("reading handshake")?;

        let (encrypted_hash, buyer_ln) = match handshake {
            Message::Handshake(h) => {
                if h.version != Handshake::CURRENT_VERSION {
                    write_msg(
                        &mut send,
                        &Message::Reject(Reject {
                            reason: RejectReason::InvalidRequest,
                        }),
                    )
                    .await?;
                    send.finish()?;
                    anyhow::bail!("unsupported protocol version: {}", h.version);
                }
                (h.encrypted_hash, h.lightning_pubkey)
            }
            _ => {
                write_msg(
                    &mut send,
                    &Message::Reject(Reject {
                        reason: RejectReason::InvalidRequest,
                    }),
                )
                .await?;
                send.finish()?;
                anyhow::bail!(
                    "expected Handshake, got {:?}",
                    std::mem::discriminant(&handshake)
                );
            }
        };

        info!(
            hash = hex::encode(encrypted_hash),
            "buyer connected for content"
        );

        let bitfield = self
            .store
            .get_bitfield(&encrypted_hash)
            .context("content not found")?;
        write_msg(&mut send, &Message::Bitfield(bitfield)).await?;

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(
                encrypted_hash,
                SessionState {
                    pending_indices: Vec::new(),
                    invoice_issued: false,
                },
            );
        }

        loop {
            let msg: Message = match read_msg(&mut recv).await {
                Ok(m) => m,
                Err(_) => {
                    debug!("buyer disconnected");
                    break;
                }
            };

            match msg {
                Message::Request(req) => {
                    debug!(count = req.indices.len(), "chunk request received");

                    let all_available = req
                        .indices
                        .iter()
                        .all(|&i| self.store.get_chunk(&encrypted_hash, i).is_some());
                    if !all_available {
                        write_msg(
                            &mut send,
                            &Message::Reject(Reject {
                                reason: RejectReason::ChunksUnavailable,
                            }),
                        )
                        .await?;
                        continue;
                    }

                    match self
                        .store
                        .create_invoice(&encrypted_hash, &req.indices, &buyer_ln)
                    {
                        Ok((bolt11, amount_msat)) => {
                            {
                                let mut sessions = self.sessions.lock().unwrap();
                                if let Some(s) = sessions.get_mut(&encrypted_hash) {
                                    s.pending_indices = req.indices.clone();
                                    s.invoice_issued = true;
                                }
                            }
                            write_msg(
                                &mut send,
                                &Message::Invoice(ChunkInvoice {
                                    bolt11,
                                    amount_msat,
                                    chunk_count: req.indices.len() as u32,
                                }),
                            )
                            .await?;
                        }
                        Err(e) => {
                            warn!("invoice creation failed: {e}");
                            write_msg(
                                &mut send,
                                &Message::Reject(Reject {
                                    reason: RejectReason::PaymentRequired,
                                }),
                            )
                            .await?;
                        }
                    }
                }

                Message::PaymentProof(proof) => {
                    if !self.store.verify_payment(&encrypted_hash, &proof.preimage) {
                        write_msg(
                            &mut send,
                            &Message::Reject(Reject {
                                reason: RejectReason::PaymentRequired,
                            }),
                        )
                        .await?;
                        continue;
                    }

                    info!("payment verified, sending chunks");

                    let indices = {
                        let sessions = self.sessions.lock().unwrap();
                        sessions
                            .get(&encrypted_hash)
                            .map(|s| s.pending_indices.clone())
                            .unwrap_or_default()
                    };

                    for &idx in &indices {
                        let store = self.store.clone();
                        let hash = encrypted_hash;
                        let chunk_result = tokio::task::spawn_blocking(move || {
                            let data = store.get_chunk(&hash, idx);
                            let proof = store.get_proof(&hash, idx).unwrap_or_default();
                            data.map(|d| (d, proof))
                        })
                        .await
                        .context("spawn_blocking for chunk read")?;

                        let (data, proof_nodes) = match chunk_result {
                            Some(pair) => pair,
                            None => continue,
                        };

                        write_msg(
                            &mut send,
                            &Message::Chunk(ChunkData {
                                chunk_index: idx,
                                data,
                                proof: proof_nodes,
                            }),
                        )
                        .await?;
                    }

                    {
                        let mut sessions = self.sessions.lock().unwrap();
                        if let Some(s) = sessions.get_mut(&encrypted_hash) {
                            s.pending_indices.clear();
                            s.invoice_issued = false;
                        }
                    }
                }

                Message::Cancel(_) => {
                    debug!("buyer cancelled request");
                    let mut sessions = self.sessions.lock().unwrap();
                    if let Some(s) = sessions.get_mut(&encrypted_hash) {
                        s.pending_indices.clear();
                        s.invoice_issued = false;
                    }
                }

                _ => {
                    warn!("unexpected message from buyer");
                }
            }
        }

        {
            self.sessions.lock().unwrap().remove(&encrypted_hash);
        }
        Ok(())
    }
}

impl ProtocolHandler for ChunkProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        if let Err(e) = self.handle_connection(connection).await {
            warn!("connection handler error: {e:#}");
        }
        Ok(())
    }
}
