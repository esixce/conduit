> *"You never change things by fighting the existing reality. To change something, build a new model that makes the existing model obsolete."* — Buckminster Fuller

# Conduit

**Trustless content distribution with Lightning micropayments and Proxy Re-Encryption.**

Conduit is a peer-to-peer system where paying a Lightning invoice atomically
reveals the decryption key for digital content. Creators encrypt once; buyers
pay twice — once for the key (via PRE), once for the chunks (via P2P transport).
No intermediaries. No trust. Cryptographic verification at every layer.

## How it works

```
Creator                                Buyer
--------                               -----
1. Encrypt file with AES key K
2. Build Merkle tree over chunks
3. Publish encrypted chunks + metadata

   ── Payment 1: Content Key (PRE) ──

4. Creator generates re-encryption       1. Generate BLS keypair
   key  rk = f(sk_c, pk_b)              2. Send pk_b to creator
5. Create invoice:                       3. Pay Lightning invoice
   hash = SHA-256(rk)
              ─── HTLC settles ───
              ─── rk is revealed ──
                                         4. Recover AES key via PRE
                                            K = re-decrypt(rk, sk_b, ciphertext)

   ── Payment 2: Chunk Transport (P2P) ──

6. Seeder/creator serves chunks          5. Download encrypted chunks via
   over iroh QUIC                           iroh QUIC (eMule ICS selection)
                                         6. Verify each chunk against Merkle root
                                         7. Decrypt with recovered key K
                                         8. Verify plaintext hash
```

The payment and the key exchange are the same operation — the HTLC preimage
**is** the re-encryption key.

## Status

**Active development on custom signet.** 10-node testnet with automated
GitHub Actions deployment. PRE purchases, P2P chunk transport with Merkle
verification, ad-subsidized content, and a browser dashboard are all working.

## Quick start

```bash
cargo build --release -p conduit-setup
```

## Workspace

| Crate | What it does |
|-------|-------------|
| `conduit-core` | Encryption, hashing, Merkle trees, PRE primitives, LDK invoice/payment logic |
| `conduit-setup` | Unified node binary — CLI, HTTP API, buy/sell flows, SSE console, P2P orchestration |
| `conduit-p2p` | iroh-based QUIC transport — chunked file transfer with Merkle proofs |

### `conduit-setup` module structure

```
src/
├── main.rs          Entry point, router, startup
├── state.rs         Shared application state (AppState)
├── cli.rs           CLI argument parsing
├── catalog.rs       Content catalog management
├── events.rs        SSE event broadcasting
├── console.rs       Browser console helpers
├── sell.rs          Creator sell flow
├── buy/
│   ├── pre.rs       PRE buy flow (key recovery + P2P download)
│   ├── direct.rs    Direct purchase flow
│   ├── chunked.rs   eMule ICS chunk planning
│   ├── multisource.rs  Multi-source download orchestration
│   ├── ad.rs        Ad-subsidized purchase
│   └── simple.rs    Simple single-source buy
└── handlers/
    ├── pre.rs       /api/pre-purchase endpoint
    ├── chunks.rs    Chunk serving (seek-based I/O)
    ├── p2p.rs       P2P download endpoints
    ├── wallet.rs    Wallet/balance endpoints
    ├── content.rs   Content management endpoints
    ├── sse.rs       Server-Sent Events
    ├── tee.rs       TEE attestation
    ├── advertiser.rs  Advertiser role endpoints
    └── campaigns.rs   Ad campaign management
```

## Deployment

Push to `main` triggers GitHub Actions: build on ubuntu x86_64, SCP binary
to all target nodes, `systemctl restart`. See `deploy/` for service files
and `.github/workflows/` for the pipeline.

## Related repos

| Repo | Purpose |
|------|---------|
| [`conduitp2p/conduit-registry`](https://github.com/conduitp2p/conduit-registry) | Content discovery registry (SQLite + Axum) |
| [`conduitp2p/conduit-ui`](https://github.com/conduitp2p/conduit-ui) | Web dashboard served by every node |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
