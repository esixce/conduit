> *"You never change things by fighting the existing reality. To change something, build a new model that makes the existing model obsolete."* — Buckminster Fuller

# Conduit

**Trustless content distribution with Lightning micropayments.**

Conduit is a peer-to-peer system where paying a Lightning invoice atomically
reveals the decryption key for digital content. No intermediaries. No trust.
The HTLC preimage IS the AES-256 key.

## How it works

```
Creator                                 Buyer
--------                                -----
1. Encrypt file with key K
2. Create invoice: hash = SHA-256(K)
3. Publish encrypted file
                                        1. Obtain encrypted file
                                        2. Pay Lightning invoice
              ---- HTLC settles ----
              ---- K is revealed  ----
                                        3. Decrypt with K
                                        4. Verify file integrity
```

The payment and the key exchange are the same operation. You can't pay without
getting the key. You can't get the key without paying.

## Status

**Early development.** Working atomic exchange between a creator and buyer
on custom signet, with a real-time browser console for observing the swap.

## Quick start

```bash
cargo build --release -p conduit-setup
```

## Workspace

| Crate | What it does |
|-------|-------------|
| `conduit-core` | Encryption, hashing, LDK invoice/payment logic |
| `conduit-setup` | CLI for sell/buy commands + embedded web console |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
