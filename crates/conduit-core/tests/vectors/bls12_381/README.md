# BLS12-381 Test Vectors

These tests validate the BLS12-381 primitive operations used by the PRE module.

Rather than importing external YAML/JSON vectors from `ethereum/bls12-381-tests`,
we validate mathematical properties directly. This is more robust because:

1. **Generator validity** — G1 and G2 generators are on the curve and not identity
2. **Scalar multiplication** — associativity, identity element
3. **Pairing bilinearity** — `e(a*P, b*Q) = e(P, Q)^(a*b)`
4. **Pairing non-degeneracy** — `e(G1, G2) != identity` (GT)
5. **Serialization round-trip** — compress/decompress for G1 and G2

The zkcrypto `bls12_381` crate is independently audited and tested against the
Ethereum 2.0 specification. Our tests verify that our usage of the crate is correct.

## External reference

If needed, the full Ethereum test suite is at:
- https://github.com/ethereum/bls12-381-tests
- https://eips.ethereum.org/EIPS/eip-2537 (EIP-2537 test vectors)
