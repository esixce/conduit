//! SHA-256 file integrity verification for Conduit content exchange.
//!
//! The creator publishes `SHA-256(plaintext)` alongside the encrypted file.
//! After payment reveals the decryption key, the buyer decrypts and verifies
//! the hash to confirm content integrity. See `docs/mvp/03_verify.md`.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hash of a byte slice.
/// Returns the 32-byte hash.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verify that data matches an expected hash.
/// Returns `true` if `SHA-256(data) == expected_hash`.
pub fn verify_hash(data: &[u8], expected_hash: &[u8; 32]) -> bool {
    sha256_hash(data) == *expected_hash
}

/// Compute the SHA-256 hash and return it as a hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_hash(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Conduit-level tests
    // ---------------------------------------------------------------

    #[test]
    fn test_verify_matches() {
        let data = b"test content";
        let hash = sha256_hash(data);
        assert!(verify_hash(data, &hash));
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let data = b"original";
        let hash = sha256_hash(data);
        assert!(!verify_hash(b"tampered", &hash));
    }

    // ---------------------------------------------------------------
    // NIST FIPS 180-4 SHA-256 test vectors
    //
    // Official known-answer tests from the Secure Hash Standard.
    // Source: https://csrc.nist.gov/pubs/fips/180-4/final
    // Additional vectors: https://www.di-mgt.com.au/sha_testvectors.html
    //
    // These verify our SHA-256 wrapper produces bit-exact NIST output.
    // ---------------------------------------------------------------

    #[test]
    fn test_nist_sha256_empty_string() {
        // SHA-256("") -- the empty message
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_nist_sha256_abc() {
        // FIPS 180-4, Section B.1: SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_nist_sha256_two_block_message() {
        // FIPS 180-4, Section B.2: SHA-256("abcdbcde...nopq") -- 448-bit message
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_nist_sha256_long_message() {
        // FIPS 180-4, Section B.3: SHA-256("a" repeated 1,000,000 times)
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&input),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // ---------------------------------------------------------------
    // Edge-case and boundary-condition tests
    // ---------------------------------------------------------------

    #[test]
    fn test_sha256_hex_format() {
        let hex_str = sha256_hex(b"test");
        assert_eq!(hex_str.len(), 64, "SHA-256 hex must be 64 characters");
        assert!(
            hex_str.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "SHA-256 hex must be lowercase hex [0-9a-f]"
        );
    }

    #[test]
    fn test_single_bit_flip_rejects() {
        let data = b"data".to_vec();
        let hash = sha256_hash(&data);
        // Flip the least-significant bit of the first byte
        let mut flipped = data.clone();
        flipped[0] ^= 1;
        assert!(
            !verify_hash(&flipped, &hash),
            "A single-bit flip must invalidate the hash"
        );
    }

    #[test]
    fn test_different_data_different_hash() {
        let h1 = sha256_hash(b"alpha");
        let h2 = sha256_hash(b"bravo");
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }
}
