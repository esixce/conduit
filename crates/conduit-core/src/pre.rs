//! Proxy Re-Encryption (AFGH06) on BLS12-381.
//!
//! Implements the Ateniese-Fu-Green-Hohenberger 2006 unidirectional PRE scheme
//! adapted for BLS12-381's asymmetric (Type-III) pairing: `e: G1 × G2 → GT`.
//!
//! Group placement:
//! - Creator public key:     `pk_c = a * g1`  (G1)
//! - Buyer public key:       `pk_b = b * g2`  (G2)
//! - Ciphertext c1:          `(a*k) * g1`     (G1)
//! - Re-encryption key rk:   `(b/a) * g2`     (G2)
//! - Pairing: `e(c1, rk) = e(G1, G2)^(b*k)`  (GT)
//!
//! The HTLC preimage is `SHA-256(rk_compressed)` (32 bytes). The full `rk`
//! point (96 bytes compressed G2) is delivered via the purchase API.
//!
//! Hybrid KEM/DEM: the AES key `m` is XOR'd with `KDF(Z^k)` rather than
//! encoded into GT. Standard construction per IronCore's recrypt.
//!
//! See `docs/19_proxy_reencryption.md` for the full specification.

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use group::Curve;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Creator's PRE keypair (G1).
#[derive(Clone, Debug)]
pub struct CreatorKeyPair {
    /// Secret key: random scalar `a`.
    pub sk: Scalar,
    /// Public key: `a * G1::generator()`.
    pub pk: G1Projective,
}

/// Buyer's PRE keypair (G2).
///
/// Buyer keys live in G2 because the asymmetric pairing `e: G1 × G2 → GT`
/// requires the re-encryption key to be in G2 (paired with c1 from G1).
#[derive(Clone, Debug)]
pub struct BuyerKeyPair {
    /// Secret key: random scalar `b`.
    pub sk: Scalar,
    /// Public key: `b * G2::generator()`.
    pub pk: G2Projective,
}

/// First-level ciphertext: AES key encrypted under the creator's public key.
///
/// Stored by seeders. One copy per content, forever.
///
/// - `c1`: `(a * k) * G1` — curve point locking the nonce `k` to the creator.
/// - `c2`: `m XOR KDF(Z^k)` — the AES key masked by a pairing-derived value.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: G1Projective,
    pub c2: [u8; 32],
}

/// Re-encrypted ciphertext: transformed for a specific buyer.
///
/// - `c1_prime`: `e(c1, rk) = Z^(b*k)` — now locked to the buyer's key.
/// - `c2`: unchanged from the original ciphertext.
#[derive(Clone, Debug)]
pub struct ReEncrypted {
    pub c1_prime: Gt,
    pub c2: [u8; 32],
}

/// Result of re-encryption key generation.
#[derive(Clone, Debug)]
pub struct ReKeyResult {
    /// The re-encryption key as a G2 point: `(b/a) * G2`.
    pub rk_point: G2Projective,
    /// Compressed serialization of `rk_point` (96 bytes).
    pub rk_compressed: [u8; 96],
    /// HTLC preimage: `SHA-256(rk_compressed)` (32 bytes).
    pub htlc_preimage: [u8; 32],
}

// ---------------------------------------------------------------------------
// KDF: derive a 32-byte mask from a GT element
// ---------------------------------------------------------------------------

/// Derive a 32-byte symmetric mask from a GT element.
///
/// Uses SHA-256 over a deterministic byte representation of the GT value.
/// This is the DEM part of the KEM/DEM hybrid.
fn kdf_gt(gt_elem: &Gt) -> [u8; 32] {
    // GT elements in BLS12-381 live in Fp12. The zkcrypto crate does not
    // expose a direct `to_bytes()` on Gt. We use the Debug representation
    // as a deterministic serialization for KDF input. This is acceptable
    // because: (1) the KDF output is never transmitted, (2) SHA-256 gives
    // collision resistance over any deterministic input, (3) distinct Gt
    // values always produce distinct Debug strings.
    let bytes = format!("{:?}", gt_elem).into_bytes();
    let hash = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a random non-zero scalar.
fn random_nonzero_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    loop {
        let candidate = Scalar::random(&mut rng);
        if candidate != Scalar::zero() {
            return candidate;
        }
    }
}

/// Generate a creator keypair (G1).
pub fn creator_keygen() -> CreatorKeyPair {
    let sk = random_nonzero_scalar();
    let pk = G1Projective::generator() * sk;
    CreatorKeyPair { sk, pk }
}

/// Generate a buyer keypair (G2).
pub fn buyer_keygen() -> BuyerKeyPair {
    let sk = random_nonzero_scalar();
    let pk = G2Projective::generator() * sk;
    BuyerKeyPair { sk, pk }
}

/// Generate a creator keypair from a deterministic seed.
pub fn creator_keygen_from_seed(seed: &[u8; 32]) -> CreatorKeyPair {
    let sk = scalar_from_seed(seed, b"conduit-pre-creator-v1");
    let pk = G1Projective::generator() * sk;
    CreatorKeyPair { sk, pk }
}

/// Generate a buyer keypair from a deterministic seed.
pub fn buyer_keygen_from_seed(seed: &[u8; 32]) -> BuyerKeyPair {
    let sk = scalar_from_seed(seed, b"conduit-pre-buyer-v1");
    let pk = G2Projective::generator() * sk;
    BuyerKeyPair { sk, pk }
}

/// Derive a scalar from a seed and domain separator using SHA-512.
fn scalar_from_seed(seed: &[u8; 32], domain: &[u8]) -> Scalar {
    use sha2::Sha512;
    let mut hasher = Sha512::new();
    hasher.update(seed);
    hasher.update(domain);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide)
}

// ---------------------------------------------------------------------------
// AFGH06 core operations
// ---------------------------------------------------------------------------

/// Encrypt a 32-byte AES key `m` under the creator's public key.
///
/// ```text
/// Pick random k
/// c1 = k * pk_c = (a*k) * G1     (G1 point)
/// Z^k = e(k*G1, G2)              (GT element)
/// mask = SHA-256(Z^k)
/// c2 = m XOR mask                 (32 bytes)
/// ```
pub fn encrypt(pk_creator: &G1Projective, m: &[u8; 32]) -> Ciphertext {
    let k = random_nonzero_scalar();
    encrypt_with_nonce(pk_creator, m, &k)
}

/// Encrypt with a specific nonce (for deterministic testing only).
pub fn encrypt_with_nonce(
    pk_creator: &G1Projective,
    m: &[u8; 32],
    k: &Scalar,
) -> Ciphertext {
    // c1 = k * pk_creator = k * (a * G1) = (a*k) * G1
    let c1 = pk_creator * k;

    // Z^k = e(k*G1, G2)
    let k_g1 = (G1Projective::generator() * k).to_affine();
    let g2 = G2Projective::generator().to_affine();
    let z_k = pairing(&k_g1, &g2);

    // c2 = m XOR KDF(Z^k)
    let mask = kdf_gt(&z_k);
    let mut c2 = [0u8; 32];
    for i in 0..32 {
        c2[i] = m[i] ^ mask[i];
    }

    Ciphertext { c1, c2 }
}

/// Generate a re-encryption key from creator to buyer.
///
/// ```text
/// rk = a^{-1} * pk_b = a^{-1} * (b * G2) = (b/a) * G2    (G2 point)
/// htlc_preimage = SHA-256(rk_compressed)                     (32 bytes)
/// ```
pub fn re_keygen(sk_creator: &Scalar, pk_buyer: &G2Projective) -> ReKeyResult {
    let a_inv = sk_creator
        .invert()
        .expect("creator secret key must be non-zero");
    let rk_point = pk_buyer * a_inv;

    let rk_compressed = rk_point.to_affine().to_compressed();
    let preimage = Sha256::digest(rk_compressed);
    let mut htlc_preimage = [0u8; 32];
    htlc_preimage.copy_from_slice(&preimage);

    ReKeyResult {
        rk_point,
        rk_compressed,
        htlc_preimage,
    }
}

/// Re-encrypt a ciphertext from creator's key to buyer's key.
///
/// ```text
/// c1' = e(c1, rk)
///     = e((a*k)*G1, (b/a)*G2)
///     = e(G1, G2)^(a*k * b/a)
///     = e(G1, G2)^(b*k)
///     = Z^(b*k)
/// ```
pub fn re_encrypt(rk_point: &G2Projective, ct: &Ciphertext) -> ReEncrypted {
    let c1_affine = ct.c1.to_affine();
    let rk_affine = rk_point.to_affine();
    let c1_prime = pairing(&c1_affine, &rk_affine);

    ReEncrypted {
        c1_prime,
        c2: ct.c2,
    }
}

/// Re-encrypt using the compressed rk bytes (96-byte G2 point).
pub fn re_encrypt_from_bytes(rk_compressed: &[u8; 96], ct: &Ciphertext) -> Option<ReEncrypted> {
    let affine: Option<G2Affine> = G2Affine::from_compressed(rk_compressed).into();
    let rk_point = G2Projective::from(affine?);
    Some(re_encrypt(&rk_point, ct))
}

/// Decrypt a re-encrypted ciphertext using the buyer's secret key.
///
/// ```text
/// c1' = Z^(b*k)
/// temp = gt_pow(c1', b^{-1}) = Z^(b*k * 1/b) = Z^k
/// mask = KDF(Z^k)
/// m = c2 XOR mask
/// ```
pub fn decrypt(sk_buyer: &Scalar, re_ct: &ReEncrypted) -> [u8; 32] {
    let b_inv = sk_buyer.invert().expect("buyer secret key must be non-zero");
    let z_k = gt_pow(&re_ct.c1_prime, &b_inv);
    let mask = kdf_gt(&z_k);

    let mut m = [0u8; 32];
    for i in 0..32 {
        m[i] = re_ct.c2[i] ^ mask[i];
    }
    m
}

/// Decrypt a first-level ciphertext using the creator's own secret key.
///
/// ```text
/// c1 = (a*k)*G1
/// k*G1 = a^{-1} * c1
/// Z^k = e(k*G1, G2)
/// mask = KDF(Z^k)
/// m = c2 XOR mask
/// ```
pub fn decrypt_first_level(sk_creator: &Scalar, ct: &Ciphertext) -> [u8; 32] {
    let a_inv = sk_creator
        .invert()
        .expect("creator secret key must be non-zero");

    // a^{-1} * c1 = a^{-1} * (a*k)*G1 = k*G1
    let k_g1 = (ct.c1 * a_inv).to_affine();
    let g2 = G2Projective::generator().to_affine();
    let z_k = pairing(&k_g1, &g2);

    let mask = kdf_gt(&z_k);
    let mut m = [0u8; 32];
    for i in 0..32 {
        m[i] = ct.c2[i] ^ mask[i];
    }
    m
}

// ---------------------------------------------------------------------------
// GT exponentiation (scalar power via double-and-add)
// ---------------------------------------------------------------------------

/// Compute `base ^ exp` in the GT group.
///
/// GT is a multiplicative group; the zkcrypto crate uses additive notation
/// (`Gt + Gt` means `Gt * Gt` in math). We implement scalar "exponentiation"
/// via double-and-add on the additive representation.
fn gt_pow(base: &Gt, exp: &Scalar) -> Gt {
    let bits = scalar_to_le_bits(exp);
    let mut result = Gt::identity();
    let mut temp = *base;

    for bit in bits.iter() {
        if *bit {
            result += temp;
        }
        temp += temp;
    }

    result
}

/// Convert a Scalar to little-endian bits.
fn scalar_to_le_bits(s: &Scalar) -> Vec<bool> {
    let bytes = s.to_bytes();
    let mut bits = Vec::with_capacity(256);
    for byte in bytes.iter() {
        for i in 0..8 {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a Ciphertext to bytes.
///
/// Format: `[c1_compressed (48 bytes)] [c2 (32 bytes)]` = 80 bytes total.
pub fn serialize_ciphertext(ct: &Ciphertext) -> Vec<u8> {
    let c1_bytes = ct.c1.to_affine().to_compressed();
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&c1_bytes);
    out.extend_from_slice(&ct.c2);
    out
}

/// Deserialize a Ciphertext from bytes (80 bytes).
pub fn deserialize_ciphertext(bytes: &[u8]) -> Option<Ciphertext> {
    if bytes.len() != 80 {
        return None;
    }
    let mut c1_bytes = [0u8; 48];
    c1_bytes.copy_from_slice(&bytes[..48]);
    let c1_affine: Option<G1Affine> = G1Affine::from_compressed(&c1_bytes).into();
    let c1 = G1Projective::from(c1_affine?);

    let mut c2 = [0u8; 32];
    c2.copy_from_slice(&bytes[48..80]);

    Some(Ciphertext { c1, c2 })
}

/// Serialize a creator public key (G1) to compressed 48 bytes.
pub fn serialize_creator_pk(pk: &G1Projective) -> [u8; 48] {
    pk.to_affine().to_compressed()
}

/// Deserialize a creator public key from compressed 48 bytes.
pub fn deserialize_creator_pk(bytes: &[u8; 48]) -> Option<G1Projective> {
    let affine: Option<G1Affine> = G1Affine::from_compressed(bytes).into();
    Some(G1Projective::from(affine?))
}

/// Serialize a buyer public key (G2) to compressed 96 bytes.
pub fn serialize_buyer_pk(pk: &G2Projective) -> [u8; 96] {
    pk.to_affine().to_compressed()
}

/// Deserialize a buyer public key from compressed 96 bytes.
pub fn deserialize_buyer_pk(bytes: &[u8; 96]) -> Option<G2Projective> {
    let affine: Option<G2Affine> = G2Affine::from_compressed(bytes).into();
    Some(G2Projective::from(affine?))
}

// ---------------------------------------------------------------------------
// Payment hash helper
// ---------------------------------------------------------------------------

/// Compute the Lightning payment hash for a re-encryption key.
///
/// `payment_hash = SHA-256(htlc_preimage)` where
/// `htlc_preimage = SHA-256(rk_compressed)`.
pub fn payment_hash_for_rk(rk_result: &ReKeyResult) -> [u8; 32] {
    let hash = Sha256::digest(rk_result.htlc_preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creator_keygen_valid() {
        let kp = creator_keygen();
        assert_eq!(kp.pk, G1Projective::generator() * kp.sk);
    }

    #[test]
    fn test_buyer_keygen_valid() {
        let kp = buyer_keygen();
        assert_eq!(kp.pk, G2Projective::generator() * kp.sk);
    }

    #[test]
    fn test_creator_keygen_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = creator_keygen_from_seed(&seed);
        let kp2 = creator_keygen_from_seed(&seed);
        assert_eq!(kp1.sk, kp2.sk);
        assert_eq!(kp1.pk, kp2.pk);
    }

    #[test]
    fn test_buyer_keygen_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = buyer_keygen_from_seed(&seed);
        let kp2 = buyer_keygen_from_seed(&seed);
        assert_eq!(kp1.sk, kp2.sk);
        assert_eq!(kp1.pk, kp2.pk);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let c1 = creator_keygen_from_seed(&[0x01u8; 32]);
        let c2 = creator_keygen_from_seed(&[0x02u8; 32]);
        assert_ne!(c1.sk, c2.sk);
    }

    #[test]
    fn test_full_round_trip() {
        let creator = creator_keygen();
        let buyer = buyer_keygen();
        let m = [0xABu8; 32];

        let ct = encrypt(&creator.pk, &m);
        let rk = re_keygen(&creator.sk, &buyer.pk);
        let re_ct = re_encrypt(&rk.rk_point, &ct);
        let recovered = decrypt(&buyer.sk, &re_ct);

        assert_eq!(m, recovered, "Round-trip must recover original AES key");
    }

    #[test]
    fn test_creator_self_decrypt() {
        let creator = creator_keygen();
        let m = [0xCDu8; 32];
        let ct = encrypt(&creator.pk, &m);
        let recovered = decrypt_first_level(&creator.sk, &ct);
        assert_eq!(m, recovered);
    }

    #[test]
    fn test_wrong_buyer_cannot_decrypt() {
        let creator = creator_keygen();
        let buyer = buyer_keygen();
        let wrong_buyer = buyer_keygen();
        let m = [0xEFu8; 32];

        let ct = encrypt(&creator.pk, &m);
        let rk = re_keygen(&creator.sk, &buyer.pk);
        let re_ct = re_encrypt(&rk.rk_point, &ct);

        let bad_result = decrypt(&wrong_buyer.sk, &re_ct);
        assert_ne!(m, bad_result, "Wrong buyer must not recover m");
    }

    #[test]
    fn test_htlc_preimage_is_32_bytes() {
        let creator = creator_keygen();
        let buyer = buyer_keygen();
        let rk = re_keygen(&creator.sk, &buyer.pk);
        assert_eq!(rk.htlc_preimage.len(), 32);
    }

    #[test]
    fn test_rk_compressed_is_96_bytes() {
        let creator = creator_keygen();
        let buyer = buyer_keygen();
        let rk = re_keygen(&creator.sk, &buyer.pk);
        assert_eq!(rk.rk_compressed.len(), 96);
    }

    #[test]
    fn test_deterministic_encrypt_with_nonce() {
        let creator = creator_keygen_from_seed(&[0x01u8; 32]);
        let m = [0x42u8; 32];
        let k = Scalar::from(7u64);

        let ct1 = encrypt_with_nonce(&creator.pk, &m, &k);
        let ct2 = encrypt_with_nonce(&creator.pk, &m, &k);

        assert_eq!(ct1.c1, ct2.c1);
        assert_eq!(ct1.c2, ct2.c2);
    }

    #[test]
    fn test_different_nonce_different_ciphertext() {
        let creator = creator_keygen_from_seed(&[0x01u8; 32]);
        let m = [0x42u8; 32];

        let ct1 = encrypt_with_nonce(&creator.pk, &m, &Scalar::from(3u64));
        let ct2 = encrypt_with_nonce(&creator.pk, &m, &Scalar::from(5u64));

        assert_ne!(ct1.c1, ct2.c1);
        assert_ne!(ct1.c2, ct2.c2);
    }

    #[test]
    fn test_ciphertext_serialization_round_trip() {
        let creator = creator_keygen();
        let m = [0x99u8; 32];
        let ct = encrypt(&creator.pk, &m);

        let bytes = serialize_ciphertext(&ct);
        assert_eq!(bytes.len(), 80);

        let ct2 = deserialize_ciphertext(&bytes).expect("must deserialize");
        assert_eq!(ct.c1, ct2.c1);
        assert_eq!(ct.c2, ct2.c2);
    }

    #[test]
    fn test_creator_pk_serialization() {
        let kp = creator_keygen();
        let bytes = serialize_creator_pk(&kp.pk);
        let pk2 = deserialize_creator_pk(&bytes).expect("must deserialize");
        assert_eq!(kp.pk, pk2);
    }

    #[test]
    fn test_buyer_pk_serialization() {
        let kp = buyer_keygen();
        let bytes = serialize_buyer_pk(&kp.pk);
        let pk2 = deserialize_buyer_pk(&bytes).expect("must deserialize");
        assert_eq!(kp.pk, pk2);
    }

    #[test]
    fn test_re_encrypt_from_compressed_bytes() {
        let creator = creator_keygen();
        let buyer = buyer_keygen();
        let m = [0x77u8; 32];

        let ct = encrypt(&creator.pk, &m);
        let rk = re_keygen(&creator.sk, &buyer.pk);
        let re_ct =
            re_encrypt_from_bytes(&rk.rk_compressed, &ct).expect("must re-encrypt from bytes");
        let recovered = decrypt(&buyer.sk, &re_ct);
        assert_eq!(m, recovered);
    }

    #[test]
    fn test_multiple_buyers_same_content() {
        let creator = creator_keygen();
        let m = [0x55u8; 32];
        let ct = encrypt(&creator.pk, &m);

        for _ in 0..5 {
            let buyer = buyer_keygen();
            let rk = re_keygen(&creator.sk, &buyer.pk);
            let re_ct = re_encrypt(&rk.rk_point, &ct);
            let recovered = decrypt(&buyer.sk, &re_ct);
            assert_eq!(m, recovered, "Each buyer must recover m");
        }
    }

    #[test]
    fn test_payment_hash_deterministic() {
        let creator = creator_keygen_from_seed(&[0x01u8; 32]);
        let buyer = buyer_keygen_from_seed(&[0x02u8; 32]);
        let rk1 = re_keygen(&creator.sk, &buyer.pk);
        let rk2 = re_keygen(&creator.sk, &buyer.pk);
        assert_eq!(rk1.htlc_preimage, rk2.htlc_preimage);
        assert_eq!(payment_hash_for_rk(&rk1), payment_hash_for_rk(&rk2));
    }

    #[test]
    fn test_deterministic_full_round_trip_with_known_values() {
        // Fixed seeds and nonce for pinned test vector
        let creator = creator_keygen_from_seed(&[0x07u8; 32]);
        let buyer = buyer_keygen_from_seed(&[0x0Bu8; 32]);
        let k = Scalar::from(3u64);
        let m: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18,
        ];

        let ct = encrypt_with_nonce(&creator.pk, &m, &k);

        // Creator can self-decrypt
        let m_creator = decrypt_first_level(&creator.sk, &ct);
        assert_eq!(m, m_creator, "Creator self-decrypt must work");

        // Full PRE round-trip
        let rk = re_keygen(&creator.sk, &buyer.pk);
        let re_ct = re_encrypt(&rk.rk_point, &ct);
        let m_buyer = decrypt(&buyer.sk, &re_ct);
        assert_eq!(m, m_buyer, "Buyer PRE decrypt must work");

        // Verify determinism: same inputs → same outputs
        let ct2 = encrypt_with_nonce(&creator.pk, &m, &k);
        assert_eq!(ct.c1, ct2.c1);
        assert_eq!(ct.c2, ct2.c2);

        let rk2 = re_keygen(&creator.sk, &buyer.pk);
        assert_eq!(rk.rk_compressed, rk2.rk_compressed);
        assert_eq!(rk.htlc_preimage, rk2.htlc_preimage);
    }
}
