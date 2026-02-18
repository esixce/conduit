//! End-to-end PRE integration tests.
//!
//! These tests simulate the full Creator → Seeder → Buyer flow at the
//! crypto + serialization level, exercising every code path that would
//! run during a real PRE purchase on signet.
//!
//! No Lightning node or network is needed — the tests validate that:
//! 1. Creator encrypts content key `m` under their PRE public key
//! 2. PRE ciphertext serializes to the catalog format (hex strings)
//! 3. Creator computes rk for a buyer and produces a valid HTLC preimage
//! 4. Seeder deserializes the ciphertext and rk, re-encrypts
//! 5. Buyer decrypts to recover `m`
//! 6. Buyer uses `m` to decrypt actual AES-CTR encrypted content
//! 7. Decrypted content matches the original plaintext
//!
//! For the live signet test (requires deployed nodes), see:
//!   `scripts/test-pre-signet.sh`

use conduit_core::{encrypt, pre, verify};
use sha2::{Digest, Sha256};

/// Simulate the full PRE purchase flow as it would happen across
/// Creator, Seeder, and Buyer nodes.
#[test]
fn e2e_pre_full_purchase_flow() {
    // ================================================================
    // SETUP: same as what happens at node startup
    // ================================================================

    // Creator derives their PRE keypair from their storage seed
    let creator_seed = [0x07u8; 32];
    let creator_kp = pre::creator_keygen_from_seed(&creator_seed);

    // Buyer generates their PRE keypair
    let buyer_seed = [0x0Bu8; 32];
    let buyer_kp = pre::buyer_keygen_from_seed(&buyer_seed);

    // ================================================================
    // STEP 1: Creator registers content (handle_register)
    // ================================================================

    // Creator has plaintext content
    let plaintext = b"This is the premium content that buyers pay for.";

    // Creator generates AES key and encrypts
    let m = encrypt::generate_key(); // random 32-byte AES key
    let ciphertext = encrypt::encrypt(plaintext, &m, 0); // AES-CTR encrypt

    // Creator encrypts `m` under their PRE public key (AFGH06)
    let pre_ct = pre::encrypt(&creator_kp.pk, &m);

    // Creator serializes PRE ciphertext for catalog storage
    let ct_bytes = pre::serialize_ciphertext(&pre_ct);
    let pre_c1_hex = hex::encode(&ct_bytes[..48]);
    let pre_c2_hex = hex::encode(&ct_bytes[48..]);
    let pre_pk_creator_hex = hex::encode(pre::serialize_creator_pk(&creator_kp.pk));

    // Verify catalog fields have correct sizes
    assert_eq!(pre_c1_hex.len(), 96, "c1 hex must be 96 chars (48 bytes)");
    assert_eq!(pre_c2_hex.len(), 64, "c2 hex must be 64 chars (32 bytes)");
    assert_eq!(
        pre_pk_creator_hex.len(),
        96,
        "pk hex must be 96 chars (48 bytes)"
    );

    // Creator verifies they can self-decrypt
    let m_self = pre::decrypt_first_level(&creator_kp.sk, &pre_ct);
    assert_eq!(m, m_self, "Creator self-decrypt must recover m");

    // ================================================================
    // STEP 2: Buyer initiates purchase (POST /api/pre-purchase)
    // ================================================================

    // Buyer serializes their G2 public key
    let buyer_pk_hex = hex::encode(pre::serialize_buyer_pk(&buyer_kp.pk));
    assert_eq!(buyer_pk_hex.len(), 192, "buyer G2 pk hex must be 192 chars");

    // Creator receives buyer_pk and computes re-encryption key
    let buyer_pk_bytes = {
        let decoded = hex::decode(&buyer_pk_hex).unwrap();
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&decoded);
        arr
    };
    let buyer_pk = pre::deserialize_buyer_pk(&buyer_pk_bytes).expect("valid buyer pk");
    let rk = pre::re_keygen(&creator_kp.sk, &buyer_pk);

    // Creator creates invoice with PRE preimage
    let htlc_preimage = rk.htlc_preimage;
    let payment_hash = {
        let h = Sha256::digest(htlc_preimage);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h);
        out
    };

    // Verify HTLC preimage is 32 bytes
    assert_eq!(htlc_preimage.len(), 32);
    // Verify payment hash matches what LDK would compute
    assert_eq!(payment_hash, pre::payment_hash_for_rk(&rk));

    // Creator returns: bolt11, rk_compressed_hex, PRE ciphertext
    let rk_compressed_hex = hex::encode(rk.rk_compressed);

    // ================================================================
    // STEP 3: Buyer pays Lightning invoice
    //         (simulated — in real flow, LDK reveals htlc_preimage)
    // ================================================================

    // After payment, buyer has: htlc_preimage (revealed by HTLC)
    // Buyer already has: rk_compressed_hex (from purchase response)
    let _buyer_received_preimage = htlc_preimage;

    // ================================================================
    // STEP 4: Buyer sends rk to Seeder for re-encryption
    // ================================================================

    // Seeder deserializes the PRE ciphertext from catalog
    let seeder_ct = {
        let c1_bytes = hex::decode(&pre_c1_hex).unwrap();
        let c2_bytes = hex::decode(&pre_c2_hex).unwrap();
        let mut full = Vec::new();
        full.extend_from_slice(&c1_bytes);
        full.extend_from_slice(&c2_bytes);
        pre::deserialize_ciphertext(&full).expect("valid ciphertext from catalog")
    };

    // Seeder deserializes the re-encryption key from buyer
    let seeder_rk_bytes = {
        let decoded = hex::decode(&rk_compressed_hex).unwrap();
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&decoded);
        arr
    };

    // Seeder performs re-encryption
    let re_ct = pre::re_encrypt_from_bytes(&seeder_rk_bytes, &seeder_ct)
        .expect("re-encryption must succeed");

    // ================================================================
    // STEP 5: Buyer decrypts re-encrypted ciphertext
    // ================================================================

    let m_recovered = pre::decrypt(&buyer_kp.sk, &re_ct);

    // THE CRITICAL ASSERTION: buyer recovers the original AES key
    assert_eq!(
        m, m_recovered,
        "Buyer must recover the exact AES key after PRE round-trip"
    );

    // ================================================================
    // STEP 6: Buyer uses recovered key to decrypt AES content
    // ================================================================

    let decrypted = encrypt::decrypt(&ciphertext, &m_recovered, 0);
    assert_eq!(
        plaintext.as_slice(),
        decrypted.as_slice(),
        "Decrypted content must match original plaintext"
    );

    // ================================================================
    // STEP 7: Buyer verifies content hash
    // ================================================================

    let content_hash = verify::sha256_hash(plaintext);
    let decrypted_hash = verify::sha256_hash(&decrypted);
    assert_eq!(
        content_hash, decrypted_hash,
        "Content hash must match after decrypt"
    );
}

/// Test that a wrong buyer cannot decrypt even if they intercept
/// the re-encrypted ciphertext.
#[test]
fn e2e_pre_wrong_buyer_fails() {
    let creator = pre::creator_keygen_from_seed(&[0x01u8; 32]);
    let legit_buyer = pre::buyer_keygen_from_seed(&[0x02u8; 32]);
    let attacker = pre::buyer_keygen_from_seed(&[0x03u8; 32]);

    let m = encrypt::generate_key();
    let ct = pre::encrypt(&creator.pk, &m);

    // Creator issues rk for legit buyer
    let rk = pre::re_keygen(&creator.sk, &legit_buyer.pk);
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct);

    // Attacker intercepts re_ct and tries to decrypt with their own key
    let bad_m = pre::decrypt(&attacker.sk, &re_ct);
    assert_ne!(m, bad_m, "Attacker must NOT recover m");

    // Legit buyer CAN decrypt
    let good_m = pre::decrypt(&legit_buyer.sk, &re_ct);
    assert_eq!(m, good_m, "Legit buyer must recover m");
}

/// Test that each buyer gets a unique rk and HTLC preimage,
/// but all recover the same AES key from the same ciphertext.
#[test]
fn e2e_pre_multiple_buyers_same_content() {
    let creator = pre::creator_keygen_from_seed(&[0x10u8; 32]);
    let m = encrypt::generate_key();
    let ct = pre::encrypt(&creator.pk, &m);

    let mut preimages = Vec::new();

    for i in 0u8..5 {
        let buyer = pre::buyer_keygen_from_seed(&[0x20 + i; 32]);
        let rk = pre::re_keygen(&creator.sk, &buyer.pk);

        // Each buyer gets a unique preimage
        assert!(
            !preimages.contains(&rk.htlc_preimage),
            "Each buyer must get a unique HTLC preimage"
        );
        preimages.push(rk.htlc_preimage);

        // Re-encrypt and decrypt
        let re_ct = pre::re_encrypt(&rk.rk_point, &ct);
        let recovered = pre::decrypt(&buyer.sk, &re_ct);
        assert_eq!(m, recovered, "Buyer {} must recover m", i);
    }
}

/// Test the full flow with chunked content (multi-chunk file).
#[test]
fn e2e_pre_chunked_content() {
    use conduit_core::chunk;

    let creator = pre::creator_keygen_from_seed(&[0xAA; 32]);
    let buyer = pre::buyer_keygen_from_seed(&[0xBB; 32]);

    // Create a file large enough to produce multiple chunks
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    let m = encrypt::generate_key();

    // Chunk and encrypt (same as handle_register)
    let cs = chunk::select_chunk_size(plaintext.len());
    let (plain_chunks, meta) = chunk::split(&plaintext, cs);
    assert!(meta.count > 1, "Must produce multiple chunks");

    // Encrypt each chunk
    let enc_chunks: Vec<Vec<u8>> = plain_chunks
        .iter()
        .enumerate()
        .map(|(i, c)| encrypt::encrypt(c, &m, i as u64))
        .collect();

    // PRE encrypt the AES key
    let pre_ct = pre::encrypt(&creator.pk, &m);

    // Serialize to catalog format
    let ct_bytes = pre::serialize_ciphertext(&pre_ct);
    let ct_restored = pre::deserialize_ciphertext(&ct_bytes).unwrap();

    // Buyer purchases: creator generates rk
    let rk = pre::re_keygen(&creator.sk, &buyer.pk);

    // Seeder re-encrypts
    let re_ct = pre::re_encrypt(&rk.rk_point, &ct_restored);

    // Buyer decrypts PRE to get m
    let m_recovered = pre::decrypt(&buyer.sk, &re_ct);
    assert_eq!(m, m_recovered);

    // Buyer decrypts each chunk
    let dec_chunks: Vec<Vec<u8>> = enc_chunks
        .iter()
        .enumerate()
        .map(|(i, c)| encrypt::decrypt(c, &m_recovered, i as u64))
        .collect();

    // Reassemble and verify
    let decrypted: Vec<u8> = dec_chunks.into_iter().flatten().collect();
    // Trim to original size (last chunk may be padded)
    let decrypted = &decrypted[..plaintext.len()];
    assert_eq!(
        plaintext.as_slice(),
        decrypted,
        "Chunked content must match after PRE decrypt"
    );
}

/// Test catalog serialization round-trip (JSON, as stored on disk).
#[test]
fn e2e_pre_catalog_json_round_trip() {
    let creator = pre::creator_keygen_from_seed(&[0xCC; 32]);
    let m = [0x42u8; 32];
    let ct = pre::encrypt(&creator.pk, &m);

    let ct_bytes = pre::serialize_ciphertext(&ct);
    let c1_hex = hex::encode(&ct_bytes[..48]);
    let c2_hex = hex::encode(&ct_bytes[48..]);
    let pk_hex = hex::encode(pre::serialize_creator_pk(&creator.pk));

    // Simulate JSON catalog entry
    let json = serde_json::json!({
        "pre_c1_hex": c1_hex,
        "pre_c2_hex": c2_hex,
        "pre_pk_creator_hex": pk_hex,
    });

    // Deserialize back
    let c1_restored = hex::decode(json["pre_c1_hex"].as_str().unwrap()).unwrap();
    let c2_restored = hex::decode(json["pre_c2_hex"].as_str().unwrap()).unwrap();

    let mut full = Vec::new();
    full.extend_from_slice(&c1_restored);
    full.extend_from_slice(&c2_restored);

    let ct_restored = pre::deserialize_ciphertext(&full).expect("must deserialize from JSON hex");

    // Creator can still self-decrypt after catalog round-trip
    let m_recovered = pre::decrypt_first_level(&creator.sk, &ct_restored);
    assert_eq!(m, m_recovered);
}
