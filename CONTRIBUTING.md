# Contributing to Conduit

Thank you for your interest in contributing to Conduit. This project handles
real money (Bitcoin/Lightning) and real cryptographic keys. Every change must
meet a high bar of correctness.

## Ground Rules

### 1. No merges without CI green

Every pull request must pass the full CI pipeline before merge:

- `cargo test --workspace` -- all tests pass
- `cargo clippy --workspace -- -D warnings` -- zero warnings
- `cargo fmt --check` -- code is formatted

No exceptions. No "I'll fix it in the next PR."

### 2. Cryptographic code requires expert review

Any change that touches the following modules requires review from a
contributor who understands the security proofs in `docs/09_security_proofs.tex`:

- `conduit-core/src/encrypt.rs` -- AES-256-CTR encryption
- `conduit-core/src/verify.rs` -- SHA-256 integrity verification
- `conduit-core/src/invoice.rs` -- HTLC preimage / payment hash construction

**What counts as a crypto change:**
- Modifying encryption, decryption, hashing, or key derivation logic
- Changing IV derivation or key generation
- Altering the preimage-to-payment-hash relationship
- Modifying how keys are stored, transmitted, or revealed

If your PR touches these paths, tag it with the `crypto-review` label.

### 3. Dependency updates require audit

Supply chain attacks are a real threat in cryptographic software.

- **Adding a new dependency:** Explain why it's needed and why alternatives
  were rejected. Prefer crates from the RustCrypto, LDK, or BDK ecosystems.
- **Updating an existing dependency:** Review the changelog for breaking
  changes or security advisories. Link the diff.
- **No wildcards in Cargo.toml.** Pin to major.minor at minimum.
- Run `cargo audit` before submitting dependency changes.

### 4. Protocol-breaking changes need an RFC

Any change that alters the wire protocol, invoice format, encryption scheme,
or payment flow must go through a discussion process first:

1. Open a GitHub issue with the `rfc` label.
2. Describe: what changes, why, migration path, security implications.
3. Allow at least 7 days for discussion.
4. Summarize the decision in the issue before implementing.

Examples of protocol-breaking changes:
- Changing the IV derivation formula
- Altering the HTLC preimage construction
- Modifying the content hash scheme
- Adding or removing fields from the exchange protocol

### 5. Keep the security proofs current

If your change affects any assumption in `docs/09_security_proofs.tex`,
you must update the proofs or demonstrate that they still hold. Don't
merge code that invalidates a proof without updating it.

## Development Setup

```bash
# Clone and build
git clone <repo-url>
cd conduit
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting and lints
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

### Testing on Signet

The MVP uses Mutinynet signet (30-second blocks). See
`docs/mvp/07_signet_setup.md` for the full setup guide.

## Pull Request Process

1. **Branch from `main`.** Use descriptive branch names:
   `feature/multi-channel`, `fix/iv-derivation`, `docs/update-proofs`.

2. **Write tests.** If you're adding functionality, add tests. If you're
   fixing a bug, add a test that reproduces it first.

3. **Keep PRs focused.** One logical change per PR. Don't bundle unrelated
   fixes.

4. **Write a clear description.** Explain *what* changed and *why*. Link
   related issues.

5. **Respond to review.** Address all comments before requesting re-review.

## Code Style

- Follow `rustfmt` defaults (run `cargo fmt`).
- Use `/// doc comments` on all public items.
- Error types use `thiserror`. No `unwrap()` in library code.
- Module-level doc comments (`//!`) explain the purpose of each file.

## License

By contributing to Conduit, you agree that your contributions will be
licensed under both the MIT License and Apache License 2.0, at the
choice of the user. See `LICENSE-MIT` and `LICENSE-APACHE`.
