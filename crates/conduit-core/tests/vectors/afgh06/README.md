# AFGH06 Test Vectors

Hand-computed test vectors for the AFGH06 proxy re-encryption scheme on BLS12-381.

No standard test vectors exist for AFGH06. These vectors use small, known scalar
values (e.g., 7, 11, 3) as keys and nonces to produce deterministic, pinned outputs.

## Vector structure

Each vector specifies:
- `sk_creator`, `sk_buyer` — small known scalars
- `k` — encryption nonce (small known scalar)
- `m` — known 32-byte AES key
- Expected intermediate values (c1, c2, rk, etc.)
- Expected final recovered `m` (must equal input)

## Cross-validation

Reference implementations for AFGH06:
- JS:  https://github.com/nguyentb/afgh-pre
- C:   https://github.com/lubux/afgh-pre-relic
- C++: https://isi.jhu.edu/~mgreen/prl/

These use symmetric pairings (Type-I). Our implementation uses the asymmetric
BLS12-381 pairing (Type-III), so intermediate values differ. The algebraic
properties (round-trip correctness, bilinear cancellation) are the same.
