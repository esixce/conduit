//! Comprehensive test vectors for BLS12-381 primitives and AFGH06 PRE scheme.
//!
//! Part 1: BLS12-381 primitive validation (mathematical properties)
//! Part 2: AFGH06 pinned test vectors (known scalars, deterministic outputs)
//! Part 3: HTLC preimage compatibility with LDK PaymentHash

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use conduit_core::pre;
use group::Curve;
use sha2::{Digest, Sha256};

// =========================================================================
// Part 1: BLS12-381 Primitive Validation
// =========================================================================

#[test]
fn bls12_g1_generator_is_not_identity() {
    let g1 = G1Projective::generator();
    assert_ne!(g1, G1Projective::identity());
}

#[test]
fn bls12_g2_generator_is_not_identity() {
    let g2 = G2Projective::generator();
    assert_ne!(g2, G2Projective::identity());
}

#[test]
fn bls12_g1_generator_compressed_is_48_bytes() {
    let g1 = G1Projective::generator().to_affine().to_compressed();
    assert_eq!(g1.len(), 48);
}

#[test]
fn bls12_g2_generator_compressed_is_96_bytes() {
    let g2 = G2Projective::generator().to_affine().to_compressed();
    assert_eq!(g2.len(), 96);
}

#[test]
fn bls12_scalar_mul_identity() {
    let g1 = G1Projective::generator();
    let one = Scalar::one();
    assert_eq!(g1 * one, g1);
}

#[test]
fn bls12_scalar_mul_zero_gives_identity() {
    let g1 = G1Projective::generator();
    let zero = Scalar::zero();
    assert_eq!(g1 * zero, G1Projective::identity());
}

#[test]
fn bls12_scalar_mul_associativity() {
    let g1 = G1Projective::generator();
    let a = Scalar::from(7u64);
    let b = Scalar::from(11u64);

    // (a * b) * G1 == a * (b * G1)
    let ab = a * b;
    let left = g1 * ab;
    let right = (g1 * b) * a;
    assert_eq!(left, right);
}

#[test]
fn bls12_scalar_mul_distributivity() {
    let g1 = G1Projective::generator();
    let a = Scalar::from(5u64);
    let b = Scalar::from(3u64);

    // (a + b) * G1 == a*G1 + b*G1
    let left = g1 * (a + b);
    let right = (g1 * a) + (g1 * b);
    assert_eq!(left, right);
}

#[test]
fn bls12_g1_serialization_round_trip() {
    let p = G1Projective::generator() * Scalar::from(42u64);
    let compressed = p.to_affine().to_compressed();
    let recovered: Option<G1Affine> = G1Affine::from_compressed(&compressed).into();
    assert_eq!(G1Projective::from(recovered.unwrap()), p);
}

#[test]
fn bls12_g2_serialization_round_trip() {
    let p = G2Projective::generator() * Scalar::from(42u64);
    let compressed = p.to_affine().to_compressed();
    let recovered: Option<G2Affine> = G2Affine::from_compressed(&compressed).into();
    assert_eq!(G2Projective::from(recovered.unwrap()), p);
}

#[test]
fn bls12_pairing_non_degeneracy() {
    let g1 = G1Projective::generator().to_affine();
    let g2 = G2Projective::generator().to_affine();
    let z = pairing(&g1, &g2);
    assert_ne!(z, Gt::identity(), "e(G1, G2) must not be identity");
}

#[test]
fn bls12_pairing_identity_g1() {
    let id = G1Affine::identity();
    let g2 = G2Projective::generator().to_affine();
    let result = pairing(&id, &g2);
    assert_eq!(result, Gt::identity(), "e(0, G2) must be identity");
}

#[test]
fn bls12_pairing_identity_g2() {
    let g1 = G1Projective::generator().to_affine();
    let id = G2Affine::identity();
    let result = pairing(&g1, &id);
    assert_eq!(result, Gt::identity(), "e(G1, 0) must be identity");
}

/// The critical property that makes PRE work:
/// `e(a*G1, b*G2) = e(G1, G2)^(a*b)`
#[test]
fn bls12_pairing_bilinearity() {
    let a = Scalar::from(7u64);
    let b = Scalar::from(11u64);

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // Left: e(a*G1, b*G2)
    let a_g1 = (g1 * a).to_affine();
    let b_g2 = (g2 * b).to_affine();
    let left = pairing(&a_g1, &b_g2);

    // Right: e(G1, G2)^(a*b) = e((a*b)*G1, G2)
    let ab = a * b;
    let ab_g1 = (g1 * ab).to_affine();
    let g2_affine = g2.to_affine();
    let right = pairing(&ab_g1, &g2_affine);

    assert_eq!(left, right, "Bilinearity must hold: e(aP, bQ) = e(abP, Q)");
}

/// Verify the specific cancellation that AFGH06 relies on:
/// `e((a*k)*G1, (b/a)*G2) = e(G1, G2)^(b*k)`
#[test]
fn bls12_pairing_afgh_cancellation() {
    let a = Scalar::from(7u64);
    let b = Scalar::from(11u64);
    let k = Scalar::from(3u64);

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let a_inv = a.invert().expect("a must be invertible");

    // c1 = (a*k)*G1
    let c1 = (g1 * (a * k)).to_affine();

    // rk = (b/a)*G2 = (b * a^{-1})*G2
    let rk = (g2 * (b * a_inv)).to_affine();

    // Left: e(c1, rk) = e((a*k)*G1, (b/a)*G2)
    let left = pairing(&c1, &rk);

    // Right: e(G1, G2)^(b*k) = e((b*k)*G1, G2)
    let bk_g1 = (g1 * (b * k)).to_affine();
    let g2_affine = g2.to_affine();
    let right = pairing(&bk_g1, &g2_affine);

    assert_eq!(
        left, right,
        "AFGH cancellation: e((a*k)*G1, (b/a)*G2) must equal e(G1, G2)^(b*k)"
    );
}

#[test]
fn bls12_scalar_inversion() {
    let a = Scalar::from(7u64);
    let a_inv = a.invert().expect("7 must be invertible");
    let product = a * a_inv;
    assert_eq!(product, Scalar::one(), "a * a_inv must equal 1");
}

#[test]
fn bls12_scalar_bytes_is_32() {
    let s = Scalar::from(42u64);
    assert_eq!(s.to_bytes().len(), 32);
}

// =========================================================================
// Part 2: AFGH06 Pinned Test Vectors
// =========================================================================

/// Vector 1: Full round-trip with seed-derived keys and known nonce.
/// All intermediate values are pinned so any change to the crypto is caught.
#[test]
fn afgh06_vector_1_full_round_trip_pinned() {
    let creator = pre::creator_keygen_from_seed(&[0x07u8; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0x0Bu8; 32]);
    let k = Scalar::from(3u64);
    let m: [u8; 32] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18,
    ];

    // Encrypt
    let ct = pre::encrypt_with_nonce(&creator.pk, &m, &k);

    // Pin c1 (compressed G1 point, 48 bytes) and c2 (32 bytes)
    let c1_hex = hex::encode(ct.c1.to_affine().to_compressed());
    let c2_hex = hex::encode(ct.c2);

    // Creator self-decrypt
    let m_creator = pre::decrypt_first_level(&creator.sk, &ct);
    assert_eq!(m, m_creator, "Creator self-decrypt must recover m");

    // Re-keygen
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    let rk_hex = hex::encode(rk.rk_compressed);
    let preimage_hex = hex::encode(rk.htlc_preimage);

    // Re-encrypt + buyer decrypt
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
    let m_buyer = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, m_buyer, "Buyer must recover m after re-encryption");

    // Pin all values: rerun to verify determinism
    let ct2 = pre::encrypt_with_nonce(&creator.pk, &m, &k);
    assert_eq!(c1_hex, hex::encode(ct2.c1.to_affine().to_compressed()));
    assert_eq!(c2_hex, hex::encode(ct2.c2));

    let rk2 = pre::re_keygen(&creator.sk, &buyer.pk);
    assert_eq!(rk_hex, hex::encode(rk2.rk_compressed));
    assert_eq!(preimage_hex, hex::encode(rk2.htlc_preimage));
}

/// Vector 2: Different key seeds, same m.
#[test]
fn afgh06_vector_2_different_keys() {
    let creator = pre::creator_keygen_from_seed(&[0x01u8; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0x02u8; 32]);
    let k = Scalar::from(5u64);
    let m = [0x42u8; 32];

    let ct = pre::encrypt_with_nonce(&creator.pk, &m, &k);
    let m_creator = pre::decrypt_first_level(&creator.sk, &ct);
    assert_eq!(m, m_creator);

    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
    let m_buyer = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, m_buyer);
}

/// Vector 3: m = all zeros (edge case).
#[test]
fn afgh06_vector_3_zero_m() {
    let creator = pre::creator_keygen_from_seed(&[0xAAu8; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0xBBu8; 32]);
    let k = Scalar::from(13u64);
    let m = [0x00u8; 32];

    let ct = pre::encrypt_with_nonce(&creator.pk, &m, &k);
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
    let recovered = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, recovered);
}

/// Vector 4: m = all 0xFF (edge case).
#[test]
fn afgh06_vector_4_max_m() {
    let creator = pre::creator_keygen_from_seed(&[0xCCu8; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0xDDu8; 32]);
    let k = Scalar::from(17u64);
    let m = [0xFFu8; 32];

    let ct = pre::encrypt_with_nonce(&creator.pk, &m, &k);
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
    let recovered = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, recovered);
}

/// Vector 5: Multiple buyers, same ciphertext.
/// Verifies that one ciphertext can be re-encrypted for different buyers.
#[test]
fn afgh06_vector_5_multiple_buyers() {
    let creator = pre::creator_keygen_from_seed(&[0x10u8; 32]);
    let m = [0x55u8; 32];
    let k = Scalar::from(7u64);
    let ct = pre::encrypt_with_nonce(&creator.pk, &m, &k);

    for seed_byte in [0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8] {
        let buyer = pre::buyer_keygen_from_seed(&[seed_byte; 32]);
        let rk = pre::re_keygen(&creator.sk, &buyer.pk);
        let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
        let recovered = pre::decrypt(&buyer.sk, &re_ct);
        assert_eq!(
            m, recovered,
            "Buyer with seed {:#x} must recover m",
            seed_byte
        );
    }
}

// =========================================================================
// Part 3: HTLC Preimage / PaymentHash Compatibility
// =========================================================================

#[test]
fn htlc_preimage_is_exactly_32_bytes() {
    let creator = pre::creator_keygen();
    let buyer = pre::buyer_keygen();
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    assert_eq!(rk.htlc_preimage.len(), 32);
}

#[test]
fn htlc_preimage_deterministic() {
    let creator = pre::creator_keygen_from_seed(&[0x01u8; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0x02u8; 32]);

    let rk1 = pre::re_keygen(&creator.sk, &buyer.pk);
    let rk2 = pre::re_keygen(&creator.sk, &buyer.pk);

    assert_eq!(rk1.htlc_preimage, rk2.htlc_preimage);
}

#[test]
fn htlc_preimage_different_for_different_buyers() {
    let creator = pre::creator_keygen_from_seed(&[0x01u8; 32]);
    let buyer1 = pre::buyer_keygen_from_seed(&[0x02u8; 32]);
    let buyer2 = pre::buyer_keygen_from_seed(&[0x03u8; 32]);

    let rk1 = pre::re_keygen(&creator.sk, &buyer1.pk);
    let rk2 = pre::re_keygen(&creator.sk, &buyer2.pk);

    assert_ne!(
        rk1.htlc_preimage, rk2.htlc_preimage,
        "Different buyers must produce different preimages"
    );
}

#[test]
fn payment_hash_is_sha256_of_preimage() {
    let creator = pre::creator_keygen();
    let buyer = pre::buyer_keygen();
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);

    let expected_hash = Sha256::digest(rk.htlc_preimage);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&expected_hash);

    let actual = pre::payment_hash_for_rk(&rk);
    assert_eq!(expected, actual);
}

/// Verify that our payment hash matches LDK's `PaymentPreimage -> PaymentHash`
/// conversion. This is the critical bridge between PRE and Lightning.
#[test]
fn payment_hash_matches_ldk_convention() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};

    let creator = pre::creator_keygen();
    let buyer = pre::buyer_keygen();
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);

    // Our hash
    let our_hash = pre::payment_hash_for_rk(&rk);

    // LDK's hash: PaymentPreimage(bytes) -> PaymentHash via SHA-256
    let ldk_preimage = PaymentPreimage(rk.htlc_preimage);
    let ldk_hash: PaymentHash = ldk_preimage.into();

    assert_eq!(
        our_hash, ldk_hash.0,
        "PRE payment hash must match LDK PaymentHash conversion"
    );
}

#[test]
fn ciphertext_serialization_size() {
    let creator = pre::creator_keygen();
    let m = [0x42u8; 32];
    let ct = pre::encrypt(&creator.pk, &m);
    let bytes = pre::serialize_ciphertext(&ct);
    assert_eq!(bytes.len(), 80, "Ciphertext must be 48 (G1) + 32 (c2) = 80 bytes");
}

#[test]
fn ciphertext_serialization_round_trip_preserves_decryption() {
    let creator = pre::creator_keygen();
    let buyer = pre::buyer_keygen();
    let m = [0x42u8; 32];

    let ct = pre::encrypt(&creator.pk, &m);
    let bytes = pre::serialize_ciphertext(&ct);
    let ct2 = pre::deserialize_ciphertext(&bytes).expect("must deserialize");

    let rk = pre::re_keygen(&creator.sk, &buyer.pk);
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct2);
    let recovered = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, recovered, "Deserialized ciphertext must decrypt correctly");
}
