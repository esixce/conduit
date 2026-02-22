//! Purchase receipt verification for Conduit.
//!
//! A "receipt" is the persisted artifacts of a PRE purchase exchange.  The
//! cryptographic binding chain:
//!
//! ```text
//! bolt11 (creator-signed invoice)
//!   └─ contains payment_hash
//!        └─ SHA-256(preimage) == payment_hash   (buyer holds preimage)
//!
//! bolt11 description: "conduit:pre:{content_hash}:{buyer_pk_hex}:{price}"
//!   └─ signed by creator's LN node
//!
//! rk_compressed binds algebraically to buyer's PRE pubkey
//!   └─ creator can verify:  a * rk == pk_buyer
//!
//! Layer 2 listing signature binds content_hash + price to creator identity
//! ```
//!
//! No separate receipt signing ceremony is needed.  The exchange IS the receipt.

use serde::{Deserialize, Serialize};

use crate::verify;

/// A persisted purchase receipt (JSON on disk).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub version: u32,
    pub content_hash: String,
    pub encrypted_hash: String,
    pub encrypted_root: String,
    pub buyer_pk_hex: String,
    pub buyer_ln_pubkey: String,
    pub creator_pubkey: String,
    pub creator_signature: String,
    pub bolt11: String,
    pub payment_hash: String,
    pub preimage: String,
    pub rk_compressed_hex: String,
    pub price_sats: u64,
    pub file_name: String,
    pub timestamp: u64,
}

/// Result of receipt verification.
#[derive(Clone, Debug)]
pub struct VerifyResult {
    pub valid: bool,
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

/// Load a receipt from a JSON file.
pub fn load(path: &std::path::Path) -> Result<Receipt, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("invalid receipt JSON: {e}"))
}

/// Load all receipts from a directory.
pub fn load_all(dir: &std::path::Path) -> Vec<Receipt> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut receipts = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(r) = load(&path) {
                receipts.push(r);
            }
        }
    }
    receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    receipts
}

/// Verify a receipt's cryptographic integrity.
///
/// Checks performed:
/// 1. `SHA-256(preimage) == payment_hash`  (preimage proves payment)
/// 2. bolt11 description matches `conduit:pre:{content_hash}:{buyer_pk}:{price}`
/// 3. bolt11 payment_hash matches the receipt's payment_hash
/// 4. Layer 2 listing signature is present
pub fn verify(receipt: &Receipt) -> VerifyResult {
    let mut checks = Vec::new();

    // 1. Preimage → payment_hash
    let preimage_ok = if let Ok(preimage_bytes) = hex::decode(&receipt.preimage) {
        let computed = verify::sha256_hex(&preimage_bytes);
        let ok = computed == receipt.payment_hash;
        checks.push(Check {
            name: "preimage_hash",
            passed: ok,
            detail: if ok {
                "SHA-256(preimage) matches payment_hash".into()
            } else {
                format!(
                    "mismatch: SHA-256(preimage)={computed}, payment_hash={}",
                    receipt.payment_hash
                )
            },
        });
        ok
    } else {
        checks.push(Check {
            name: "preimage_hash",
            passed: false,
            detail: "preimage is not valid hex".into(),
        });
        false
    };

    // 2. bolt11 description binding
    let expected_desc = format!(
        "conduit:pre:{}:{}:{}",
        receipt.content_hash, receipt.buyer_pk_hex, receipt.price_sats
    );
    let desc_ok = {
        use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
        match receipt.bolt11.parse::<Bolt11Invoice>() {
            Ok(inv) => {
                let actual_desc = match inv.description() {
                    Bolt11InvoiceDescriptionRef::Direct(d) => d.to_string(),
                    Bolt11InvoiceDescriptionRef::Hash(_) => String::new(),
                };
                let ok = actual_desc == expected_desc;
                checks.push(Check {
                    name: "bolt11_description",
                    passed: ok,
                    detail: if ok {
                        "bolt11 description binds content + buyer + price".into()
                    } else if actual_desc.starts_with("PRE:") {
                        format!(
                            "legacy description format (pre-receipt): \"{actual_desc}\""
                        )
                    } else {
                        format!(
                            "description mismatch: got \"{actual_desc}\", expected \"{expected_desc}\""
                        )
                    },
                });
                ok
            }
            Err(e) => {
                checks.push(Check {
                    name: "bolt11_description",
                    passed: false,
                    detail: format!("failed to parse bolt11: {e}"),
                });
                false
            }
        }
    };

    // 3. bolt11 payment_hash matches
    let ph_ok = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        match receipt.bolt11.parse::<Bolt11Invoice>() {
            Ok(inv) => {
                let bolt11_hash = hex::encode(inv.payment_hash().as_ref() as &[u8]);
                let ok = bolt11_hash == receipt.payment_hash;
                checks.push(Check {
                    name: "bolt11_payment_hash",
                    passed: ok,
                    detail: if ok {
                        "bolt11 payment_hash matches receipt".into()
                    } else {
                        format!(
                            "mismatch: bolt11={bolt11_hash}, receipt={}",
                            receipt.payment_hash
                        )
                    },
                });
                ok
            }
            Err(_) => {
                checks.push(Check {
                    name: "bolt11_payment_hash",
                    passed: false,
                    detail: "bolt11 parse failed".into(),
                });
                false
            }
        }
    };

    // 4. Layer 2 creator signature present
    let sig_ok = !receipt.creator_signature.is_empty();
    checks.push(Check {
        name: "creator_signature",
        passed: sig_ok,
        detail: if sig_ok {
            "Layer 2 creator signature present".into()
        } else {
            "no creator signature (legacy purchase)".into()
        },
    });

    let valid = preimage_ok && desc_ok && ph_ok;
    VerifyResult { valid, checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_receipt() -> Receipt {
        Receipt {
            version: 1,
            content_hash: "abc123".into(),
            encrypted_hash: "def456".into(),
            encrypted_root: "".into(),
            buyer_pk_hex: "aabbcc".into(),
            buyer_ln_pubkey: "02deadbeef".into(),
            creator_pubkey: "03cafebabe".into(),
            creator_signature: "".into(),
            bolt11: "".into(),
            payment_hash: "".into(),
            preimage: "".into(),
            rk_compressed_hex: "".into(),
            price_sats: 5,
            file_name: "test.txt".into(),
            timestamp: 0,
        }
    }

    #[test]
    fn preimage_hash_check_valid() {
        let preimage_bytes = [0x42u8; 32];
        let preimage_hex = hex::encode(preimage_bytes);
        let payment_hash = verify::sha256_hex(&preimage_bytes);
        let mut r = dummy_receipt();
        r.preimage = preimage_hex;
        r.payment_hash = payment_hash;

        let result = verify(&r);
        let check = result.checks.iter().find(|c| c.name == "preimage_hash").unwrap();
        assert!(check.passed, "preimage_hash should pass: {}", check.detail);
    }

    #[test]
    fn preimage_hash_check_invalid() {
        let mut r = dummy_receipt();
        r.preimage = hex::encode([0x42u8; 32]);
        r.payment_hash = hex::encode([0x00u8; 32]);

        let result = verify(&r);
        let check = result.checks.iter().find(|c| c.name == "preimage_hash").unwrap();
        assert!(!check.passed, "preimage_hash should fail on mismatch");
    }
}
