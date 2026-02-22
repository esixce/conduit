// ---------------------------------------------------------------------------
// Ad-subsidized sell: HOLD-AND-CLAIM-TOGETHER
//
// Waits for BOTH Invoice 1 (K, from buyer) and Invoice 2 (K_ad, from
// advertiser) HTLCs to arrive before claiming either. This guarantees
// the creator never reveals K unless the advertiser's payment is locked in.
//
// Trust analysis:
//   - Buyer:      Risks ~15s of time watching the ad. Acceptable.
//   - Advertiser: Trusts the buyer's app displayed the ad (attestation).
//   - Creator:    TRUSTLESS — holds K until both HTLCs are pending.
//   - If Invoice 2 never arrives (advertiser doesn't pay), the creator
//     lets Invoice 1 expire. The buyer's 1 sat is returned. No content
//     is delivered. Nobody loses money.
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use conduit_core::{invoice, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};

use crate::events::*;

pub fn handle_ad_sell_hold_and_claim(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    key_k: &[u8; 32],    // Invoice 1 preimage: content key K
    key_k_ad: &[u8; 32], // Invoice 2 preimage: random K_ad
) {
    let role = "creator";

    // Compute payment hashes
    let hash_k = PaymentHash(verify::sha256_hash(key_k));
    let hash_k_ad = PaymentHash(verify::sha256_hash(key_k_ad));

    // Register for events on BOTH payment hashes
    let rx_k = router.register(hash_k);
    let rx_k_ad = router.register(hash_k_ad);

    emitter.emit( role, "AD_HOLD_WAITING", serde_json::json!({
        "message": "Waiting for BOTH Invoice 1 (buyer) and Invoice 2 (advertiser) HTLCs before claiming either",
        "buyer_payment_hash": hex::encode(hash_k.0),
        "ad_payment_hash": hex::encode(hash_k_ad.0),
    }));

    // Track which HTLCs have arrived
    let mut buyer_htlc: Option<u64> = None; // amount_msat when arrived
    let mut ad_htlc: Option<u64> = None; // amount_msat when arrived

    // Poll both receivers. We use try_recv with a short sleep to multiplex
    // two channels without blocking on either one forever.
    loop {
        // Check for Invoice 1 (buyer, K)
        if buyer_htlc.is_none() {
            if let Ok(Event::PaymentClaimable {
                claimable_amount_msat,
                ..
            }) = rx_k.try_recv()
            {
                emitter.emit(
                    role,
                    "AD_HTLC_BUYER_ARRIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash_k.0),
                        "amount_msat": claimable_amount_msat,
                        "message": "Buyer's HTLC arrived — HOLDING until advertiser's HTLC also arrives",
                    }),
                );
                buyer_htlc = Some(claimable_amount_msat);
            }
        }

        // Check for Invoice 2 (advertiser, K_ad)
        if ad_htlc.is_none() {
            if let Ok(Event::PaymentClaimable {
                claimable_amount_msat,
                ..
            }) = rx_k_ad.try_recv()
            {
                emitter.emit(
                    role,
                    "AD_HTLC_ADVERTISER_ARRIVED",
                    serde_json::json!({
                        "payment_hash": hex::encode(hash_k_ad.0),
                        "amount_msat": claimable_amount_msat,
                        "message": "Advertiser's HTLC arrived — HOLDING until buyer's HTLC also arrives",
                    }),
                );
                ad_htlc = Some(claimable_amount_msat);
            }
        }

        // If BOTH have arrived, claim both and break
        if let (Some(buyer_amt), Some(ad_amt)) = (buyer_htlc, ad_htlc) {
            emitter.emit(
                role,
                "AD_BOTH_HTLCS_READY",
                serde_json::json!({
                    "message": "BOTH HTLCs arrived — claiming both now",
                    "buyer_amount_msat": buyer_amt,
                    "ad_amount_msat": ad_amt,
                }),
            );

            // Claim Invoice 2 first (K_ad, meaningless) — order doesn't
            // matter since both HTLCs are already locked in, but claiming
            // the advertiser's payment first is a nice convention.
            invoice::claim_payment(node, key_k_ad, ad_amt)
                .expect("Failed to claim advertiser payment");
            emitter.emit(
                role,
                "AD_CLAIMED_ADVERTISER",
                serde_json::json!({
                    "preimage": hex::encode(key_k_ad),
                    "amount_msat": ad_amt,
                    "message": "Advertiser payment claimed (K_ad revealed — meaningless)",
                }),
            );

            // Claim Invoice 1 (K, the content key) — buyer learns K
            invoice::claim_payment(node, key_k, buyer_amt).expect("Failed to claim buyer payment");
            emitter.emit(
                role,
                "AD_CLAIMED_BUYER",
                serde_json::json!({
                    "preimage": hex::encode(key_k),
                    "amount_msat": buyer_amt,
                    "message": "Buyer payment claimed (K revealed — buyer can now decrypt content)",
                }),
            );

            break;
        }

        // Brief sleep to avoid busy-waiting
        thread::sleep(Duration::from_millis(100));
    }

    // Wait for PaymentReceived confirmations for both
    let mut k_confirmed = false;
    let mut k_ad_confirmed = false;
    while !k_confirmed || !k_ad_confirmed {
        if !k_confirmed {
            if let Ok(Event::PaymentReceived { amount_msat, .. }) = rx_k.try_recv() {
                emitter.emit(
                    role,
                    "AD_PAYMENT_CONFIRMED_BUYER",
                    serde_json::json!({
                        "amount_msat": amount_msat,
                        "message": "Buyer payment fully settled",
                    }),
                );
                k_confirmed = true;
            }
        }
        if !k_ad_confirmed {
            if let Ok(Event::PaymentReceived { amount_msat, .. }) = rx_k_ad.try_recv() {
                emitter.emit(
                    role,
                    "AD_PAYMENT_CONFIRMED_ADVERTISER",
                    serde_json::json!({
                        "amount_msat": amount_msat,
                        "message": "Advertiser payment fully settled",
                    }),
                );
                k_ad_confirmed = true;
            }
        }
        if !k_confirmed || !k_ad_confirmed {
            thread::sleep(Duration::from_millis(100));
        }
    }

    emitter.emit(
        role,
        "AD_SALE_COMPLETE",
        serde_json::json!({
            "message": "Ad-subsidized sale complete — both payments settled trustlessly",
        }),
    );

    router.unregister(&hash_k);
    router.unregister(&hash_k_ad);
}

