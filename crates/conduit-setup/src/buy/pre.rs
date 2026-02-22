// ---------------------------------------------------------------------------
// buy-pre command
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use conduit_core::{chunk, encrypt, invoice, pre, verify};
use ldk_node::lightning_types::payment::PaymentHash;
use ldk_node::{Event, Node};
use ldk_node::payment::{PaymentDirection, PaymentKind, PaymentStatus};

use crate::events::*;

/// Helper macro: emit BUY_ERROR and return early on failure.
macro_rules! pre_bail {
    ($emitter:expr, $msg:expr) => {{
        $emitter.emit(
            "buyer",
            "BUY_ERROR",
            serde_json::json!({ "message": $msg }),
        );
        eprintln!("PRE buy error: {}", $msg);
        return;
    }};
}

#[allow(clippy::too_many_arguments)]
pub fn handle_buy_pre(
    node: &Arc<Node>,
    emitter: &ConsoleEmitter,
    router: &Arc<EventRouter>,
    _storage_dir: &str,
    buyer_kp: &pre::BuyerKeyPair,
    creator_url: &str,
    content_hash: &str,
    seeder_url: Option<&str>,
    output_path: &str,
    p2p_node: Option<Arc<conduit_p2p::node::P2pNode>>,
    p2p_runtime_handle: Option<tokio::runtime::Handle>,
    source_mode: &str,
    registry_url: Option<&str>,
) {
    let role = "buyer";
    let buyer_pk_hex = hex::encode(pre::serialize_buyer_pk(&buyer_kp.pk));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    emitter.emit(
        role,
        "PRE_BUY_START",
        serde_json::json!({
            "creator_url": creator_url,
            "content_hash": content_hash,
            "buyer_pk_hex": &buyer_pk_hex,
        }),
    );
    println!("=== BUY-PRE ===");
    println!("Creator: {}", creator_url);
    println!("Content: {}", content_hash);

    // 1. Call creator's /api/pre-purchase/{content_hash} with buyer pk
    let purchase_url = format!(
        "{}/api/pre-purchase/{}",
        creator_url.trim_end_matches('/'),
        content_hash
    );
    let resp = match client
        .post(&purchase_url)
        .json(&serde_json::json!({ "buyer_pk_hex": buyer_pk_hex }))
        .send()
    {
        Ok(r) => r,
        Err(e) => pre_bail!(emitter, format!("Failed to contact creator: {}", e)),
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        pre_bail!(emitter, format!("Creator returned {} — {}", status, body));
    }

    let purchase_resp: serde_json::Value = match resp.json() {
        Ok(v) => v,
        Err(e) => pre_bail!(emitter, format!("Invalid JSON from creator: {}", e)),
    };

    let bolt11 = match purchase_resp["bolt11"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing bolt11"),
    };
    let rk_compressed_hex = match purchase_resp["rk_compressed_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing rk_compressed_hex"),
    };
    let pre_c1_hex = match purchase_resp["pre_c1_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(
            emitter,
            "Creator response missing pre_c1_hex (content may not be PRE-enabled)"
        ),
    };
    let pre_c2_hex = match purchase_resp["pre_c2_hex"].as_str() {
        Some(s) => s.to_string(),
        None => pre_bail!(emitter, "Creator response missing pre_c2_hex"),
    };
    let price_sats = purchase_resp["price_sats"].as_u64().unwrap_or(0);
    let enc_hash = purchase_resp["encrypted_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let encrypted_root_hex = purchase_resp["encrypted_root"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let expected_encrypted_root: Option<[u8; 32]> = if encrypted_root_hex.len() == 64 {
        hex::decode(&encrypted_root_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
    } else {
        None
    };

    emitter.emit(
        role,
        "PRE_PURCHASE_RECEIVED",
        serde_json::json!({
            "bolt11_len": bolt11.len(),
            "rk_len": rk_compressed_hex.len(),
            "price_sats": price_sats,
            "encrypted_hash": &enc_hash,
        }),
    );
    println!("Invoice received ({} sats)", price_sats);

    // 2. Countdown
    for i in (1..=3).rev() {
        emitter.emit(
            role,
            "COUNTDOWN",
            serde_json::json!({
                "seconds": i,
                "message": format!("Paying PRE invoice in {}...", i),
            }),
        );
        thread::sleep(Duration::from_secs(1));
    }

    // 3. Pay the Lightning invoice (with retry + DuplicatePayment recovery)
    //
    // Register the event listener BEFORE sending payment to avoid a race
    // where PaymentSuccessful fires before we start listening (direct
    // channels settle in <1s).
    let pre_payment_hash = {
        use ldk_node::lightning_invoice::Bolt11Invoice;
        let inv: Bolt11Invoice = bolt11.parse().expect("Invalid bolt11 in PRE flow");
        let h: &[u8] = inv.payment_hash().as_ref();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(h);
        arr
    };
    let target_hash = PaymentHash(pre_payment_hash);
    let rx = router.register(target_hash);

    emitter.emit(
        role,
        "PAYING_INVOICE",
        serde_json::json!({ "bolt11": &bolt11 }),
    );

    let hash_bytes = match invoice::pay_invoice_with_retry(node, &bolt11, 3, Duration::from_secs(3))
    {
        Ok(h) => h,
        Err(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("DuplicatePayment") {
                eprintln!("[buy-pre] DuplicatePayment — looking up preimage from history");
                emitter.emit(
                    role,
                    "PRE_ALREADY_PAID",
                    serde_json::json!({
                        "message": "DuplicatePayment — looking up preimage from history...",
                    }),
                );

                let target = PaymentHash(pre_payment_hash);
                let mut found_preimage: Option<[u8; 32]> = None;
                for p in node.list_payments_with_filter(|p| {
                    p.direction == PaymentDirection::Outbound
                        && p.status == PaymentStatus::Succeeded
                }) {
                    if let PaymentKind::Bolt11 {
                        hash,
                        preimage: Some(pre),
                        ..
                    } = &p.kind
                    {
                        if *hash == target {
                            found_preimage = Some(pre.0);
                            break;
                        }
                    }
                }

                match found_preimage {
                    Some(_preimage) => {
                        emitter.emit(
                            role,
                            "PRE_PAYMENT_CONFIRMED",
                            serde_json::json!({
                                "payment_hash": hex::encode(pre_payment_hash),
                                "message": "PRE payment recovered from history.",
                            }),
                        );
                        pre_payment_hash
                    }
                    None => {
                        router.unregister(&target_hash);
                        pre_bail!(
                            emitter,
                            "DuplicatePayment but preimage not found in history. Try again (new invoice will have a unique hash)."
                        );
                    }
                }
            } else {
                router.unregister(&target_hash);
                let usable_channels: Vec<String> = node
                    .list_channels()
                    .iter()
                    .filter(|c| c.is_usable)
                    .map(|c| {
                        format!(
                            "{}… out={}",
                            &c.counterparty_node_id.to_string()[..16],
                            c.outbound_capacity_msat / 1000
                        )
                    })
                    .collect();
                eprintln!(
                    "[buy-pre] payment failed after retries: {} | usable channels: {:?}",
                    err_str, usable_channels
                );
                emitter.emit(
                    role,
                    "BUY_ERROR",
                    serde_json::json!({
                        "message": format!("Failed to pay invoice: {}", err_str),
                        "usable_channels": usable_channels,
                    }),
                );
                return;
            }
        }
    };

    emitter.emit(
        role,
        "PAYMENT_SENT",
        serde_json::json!({
            "payment_hash": hex::encode(hash_bytes),
            "message": "HTLC in flight — PRE payment routing...",
        }),
    );

    // 4. Wait for payment confirmation (rx was registered before send)
    loop {
        let event = match rx.recv() {
            Ok(e) => e,
            Err(_) => {
                router.unregister(&target_hash);
                pre_bail!(emitter, "Event router dropped");
            }
        };
        match event {
            Event::PaymentSuccessful {
                payment_hash,
                payment_preimage: Some(preimage),
                fee_paid_msat,
                ..
            } => {
                emitter.emit(
                    role,
                    "PRE_PAYMENT_CONFIRMED",
                    serde_json::json!({
                        "payment_hash": hex::encode(payment_hash.0),
                        "preimage": hex::encode(preimage.0),
                        "fee_msat": fee_paid_msat,
                        "message": "PRE payment confirmed.",
                    }),
                );
                println!(
                    "Payment confirmed (fee: {} msat)",
                    fee_paid_msat.unwrap_or(0)
                );
                break;
            }
            Event::PaymentFailed { reason, .. } => {
                emitter.emit(
                    role,
                    "PAYMENT_FAILED",
                    serde_json::json!({
                        "payment_hash": hex::encode(target_hash.0),
                        "reason": format!("{:?}", reason),
                    }),
                );
                router.unregister(&target_hash);
                return;
            }
            _ => {}
        }
    }
    router.unregister(&target_hash);

    // 5. Recover AES key m via PRE decryption
    let m = match pre::buyer_decrypt_from_hex(
        &buyer_kp.sk,
        &pre_c1_hex,
        &pre_c2_hex,
        &rk_compressed_hex,
    ) {
        Some(m) => m,
        None => pre_bail!(emitter, "PRE decryption failed — invalid ciphertext or key"),
    };

    emitter.emit(
        role,
        "PRE_KEY_RECOVERED",
        serde_json::json!({
            "m_hex": hex::encode(m),
            "message": "AES key m recovered via PRE.",
        }),
    );
    println!("AES key recovered via PRE");

    // 6. Download encrypted chunks — ICS multi-source or single-source fallback
    let ics_result = if source_mode == "smart" {
        use crate::buy::multisource;
        emitter.emit(
            role,
            "ICS_MODE",
            serde_json::json!({ "message": "Using ICS multi-source download" }),
        );
        multisource::ics_download(&client, registry_url, creator_url, content_hash, emitter)
    } else {
        None
    };

    let all_enc_data = if let Some((data, _count, mode)) = ics_result {
        emitter.emit(
            role,
            "CHUNKS_DOWNLOADED",
            serde_json::json!({
                "total_bytes": data.len(),
                "ics_mode": mode.label(),
                "message": format!("ICS {} download complete ({} bytes)", mode.label(), data.len()),
            }),
        );
        data
    } else {
        // Single-source fallback (creator-only, specific seeder, or ICS unavailable)
        let chunk_source = if source_mode == "creator" || source_mode == "smart" {
            seeder_url.unwrap_or(creator_url)
        } else {
            // source_mode is a specific seeder URL
            if source_mode.contains(':') {
                source_mode
            } else {
                seeder_url.unwrap_or(creator_url)
            }
        };

    // Try P2P download first if we have an iroh node and the source supports it
    let p2p_result = if let Some(ref p2p) = p2p_node {
        let p2p_info_url = format!("{}/api/p2p-info", chunk_source.trim_end_matches('/'));
        match client.get(&p2p_info_url).send() {
            Ok(r) => match r.json::<serde_json::Value>() {
                Ok(info) if info["enabled"].as_bool() == Some(true) => {
                    let remote_node_id = info["node_id"].as_str().unwrap_or("").to_string();
                    let direct_addrs: Vec<String> = info["direct_addrs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let relay_urls: Vec<String> = info["relay_urls"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    emitter.emit(
                        role,
                        "P2P_CONNECTING",
                        serde_json::json!({
                            "remote_node_id": &remote_node_id,
                            "direct_addrs": &direct_addrs,
                            "relay_urls": &relay_urls,
                            "message": format!("Connecting to seeder via P2P (iroh QUIC)... addrs={}", direct_addrs.join(", ")),
                        }),
                    );
                    eprintln!(
                        "P2P: connecting to seeder {} addrs={:?} relays={:?}",
                        &remote_node_id[..16.min(remote_node_id.len())],
                        &direct_addrs,
                        &relay_urls
                    );

                    // Build EndpointAddr with the public key, direct IP addrs, and relay URLs
                    // so iroh can connect directly instead of relying on slow DHT discovery.
                    let addr_parse_result: Result<conduit_p2p::iroh::EndpointAddr, String> =
                        (|| {
                            let pk = remote_node_id
                                .parse::<conduit_p2p::iroh::PublicKey>()
                                .map_err(|e| format!("PublicKey parse: {e}"))?;
                            let mut addr = conduit_p2p::iroh::EndpointAddr::from(pk);
                            for s in &direct_addrs {
                                if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
                                    addr = addr.with_ip_addr(sa);
                                }
                            }
                            for u in &relay_urls {
                                if let Ok(ru) = u.parse::<conduit_p2p::iroh::RelayUrl>() {
                                    addr = addr.with_relay_url(ru);
                                }
                            }
                            Ok(addr)
                        })();

                    match addr_parse_result {
                        Ok(addr) => {
                            let ep = p2p.endpoint().clone();
                            let enc_hash_bytes = hex::decode(&enc_hash).ok().and_then(|b| {
                                if b.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&b);
                                    Some(arr)
                                } else {
                                    None
                                }
                            });

                            match enc_hash_bytes {
                                Some(hash_bytes) => {
                                    let ln_pk = node.node_id().to_string();
                                    let buyer_client =
                                        conduit_p2p::client::BuyerClient::new(ep, ln_pk);
                                    // Fetch catalog to know chunk count
                                    let catalog_url = format!(
                                        "{}/api/catalog",
                                        chunk_source.trim_end_matches('/')
                                    );
                                    let cat_resp = client
                                        .get(&catalog_url)
                                        .send()
                                        .ok()
                                        .and_then(|r| r.json::<serde_json::Value>().ok());
                                    let num_chunks = cat_resp
                                        .as_ref()
                                        .and_then(|cat| {
                                            let items = cat
                                                .as_array()
                                                .or_else(|| cat["items"].as_array())?;
                                            let entry = items.iter().find(|e| {
                                                e["content_hash"].as_str() == Some(content_hash)
                                                    || e["encrypted_hash"].as_str()
                                                        == Some(content_hash)
                                            })?;
                                            entry["chunk_count"]
                                                .as_u64()
                                                .or_else(|| entry["total_chunks"].as_u64())
                                        })
                                        .unwrap_or(1)
                                        as u32;

                                    let indices: Vec<u32> = (0..num_chunks).collect();
                                    struct LdkPaymentHandler {
                                        node: Arc<Node>,
                                        router: Arc<EventRouter>,
                                    }
                                    impl conduit_p2p::client::PaymentHandler for LdkPaymentHandler {
                                        fn pay_invoice(
                                            &self,
                                            bolt11: &str,
                                        ) -> anyhow::Result<[u8; 32]>
                                        {
                                            use ldk_node::lightning_invoice::Bolt11Invoice;
                                            eprintln!("[LdkPaymentHandler] pay_invoice called, bolt11 len={}", bolt11.len());

                                            let inv: Bolt11Invoice = bolt11.parse()
                                                .map_err(|e: ldk_node::lightning_invoice::ParseOrSemanticError| {
                                                    eprintln!("[LdkPaymentHandler] bad bolt11 parse: {e}");
                                                    anyhow::anyhow!("bad bolt11: {e}")
                                                })?;

                                            let payee = inv.recover_payee_pub_key();
                                            let amt = inv.amount_milli_satoshis().unwrap_or(0);
                                            let h: &[u8] = inv.payment_hash().as_ref();
                                            let mut hash = [0u8; 32];
                                            hash.copy_from_slice(h);
                                            let target = PaymentHash(hash);

                                            eprintln!(
                                                "[LdkPaymentHandler] invoice: payee={}, amt_msat={}, payment_hash={}",
                                                payee, amt, hex::encode(hash)
                                            );

                                            let channels = self.node.list_channels();
                                            let usable = channels.iter().filter(|c| c.is_usable).count();
                                            let to_payee = channels.iter().find(|c| {
                                                c.counterparty_node_id.to_string() == payee.to_string()
                                            });
                                            eprintln!(
                                                "[LdkPaymentHandler] channels: total={}, usable={}, direct_to_payee={}",
                                                channels.len(),
                                                usable,
                                                if let Some(ch) = &to_payee {
                                                    format!("yes (outbound={}msat, usable={})", ch.outbound_capacity_msat, ch.is_usable)
                                                } else {
                                                    "no".to_string()
                                                }
                                            );

                                            let rx = self.router.register(target);
                                            eprintln!("[LdkPaymentHandler] registered EventRouter listener for {}", hex::encode(hash));

                                            eprintln!("[LdkPaymentHandler] calling invoice::pay_invoice...");
                                            let pay_start = std::time::Instant::now();
                                            let pay_result = invoice::pay_invoice(&self.node, bolt11)
                                                .map_err(|e| {
                                                    eprintln!("[LdkPaymentHandler] pay_invoice FAILED after {}ms: {e}", pay_start.elapsed().as_millis());
                                                    self.router.unregister(&target);
                                                    anyhow::anyhow!("{e}")
                                                });
                                            let _payment_hash = pay_result?;
                                            eprintln!("[LdkPaymentHandler] pay_invoice sent in {}ms, waiting for event...", pay_start.elapsed().as_millis());

                                            let wait_start = std::time::Instant::now();
                                            loop {
                                                let event = rx.recv().map_err(|_| {
                                                    eprintln!("[LdkPaymentHandler] event router channel dropped after {}ms", wait_start.elapsed().as_millis());
                                                    anyhow::anyhow!("event router dropped")
                                                })?;
                                                match event {
                                                    Event::PaymentSuccessful {
                                                        payment_preimage: Some(pre),
                                                        ..
                                                    } => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] PaymentSuccessful with preimage in {}ms",
                                                            wait_start.elapsed().as_millis()
                                                        );
                                                        self.router.unregister(&target);
                                                        return Ok(pre.0);
                                                    }
                                                    Event::PaymentFailed { reason, .. } => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] PaymentFailed after {}ms: {:?}",
                                                            wait_start.elapsed().as_millis(), reason
                                                        );
                                                        self.router.unregister(&target);
                                                        return Err(anyhow::anyhow!(
                                                            "P2P chunk payment failed: {:?}",
                                                            reason
                                                        ));
                                                    }
                                                    other => {
                                                        eprintln!(
                                                            "[LdkPaymentHandler] ignoring event {:?} after {}ms",
                                                            std::mem::discriminant(&other),
                                                            wait_start.elapsed().as_millis()
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    let payment_handler: std::sync::Arc<
                                        dyn conduit_p2p::client::PaymentHandler,
                                    > = std::sync::Arc::new(LdkPaymentHandler {
                                        node: Arc::clone(node),
                                        router: Arc::clone(router),
                                    });

                                    let p2p_rt = p2p_runtime_handle.as_ref().expect(
                                        "P2P runtime handle must exist when p2p_node is Some",
                                    );
                                    let (download_tx, download_rx) =
                                        std::sync::mpsc::sync_channel::<
                                            anyhow::Result<conduit_p2p::client::DownloadResult>,
                                        >(1);
                                    let indices_owned = indices.clone();
                                    let num_indices = indices_owned.len();
                                    eprintln!("[P2P-BUY] spawning download: {} chunks, hash={}", num_indices, hex::encode(hash_bytes));
                                    let dl_start = std::time::Instant::now();
                                    p2p_rt.spawn(async move {
                                        eprintln!("[P2P-BUY] download task started on P2P runtime");
                                        let result = buyer_client
                                            .download(
                                                addr,
                                                hash_bytes,
                                                &indices_owned,
                                                payment_handler,
                                                expected_encrypted_root,
                                            )
                                            .await;
                                        match &result {
                                            Ok(r) => eprintln!("[P2P-BUY] download completed: {} chunks, {}msat", r.chunks.len(), r.total_paid_msat),
                                            Err(e) => eprintln!("[P2P-BUY] download failed: {e:#}"),
                                        }
                                        let _ = download_tx.send(result);
                                    });
                                    match download_rx.recv().unwrap_or_else(|_| {
                                        eprintln!("[P2P-BUY] download channel dropped after {}ms", dl_start.elapsed().as_millis());
                                        Err(anyhow::anyhow!("P2P download task dropped"))
                                    }) {
                                        Ok(result) => {
                                            emitter.emit(
                                                role,
                                                "P2P_DOWNLOAD_COMPLETE",
                                                serde_json::json!({
                                                    "chunks": result.chunks.len(),
                                                    "total_bytes": result.chunks.iter().map(|(_, d)| d.len()).sum::<usize>(),
                                                    "message": "Chunks downloaded via P2P!",
                                                }),
                                            );
                                            println!(
                                                "P2P: downloaded {} chunks",
                                                result.chunks.len()
                                            );
                                            let mut sorted = result.chunks;
                                            sorted.sort_by_key(|(idx, _)| *idx);
                                            let data: Vec<u8> =
                                                sorted.into_iter().flat_map(|(_, d)| d).collect();
                                            Some(data)
                                        }
                                        Err(e) => {
                                            emitter.emit(
                                                role,
                                                "P2P_DOWNLOAD_FAILED",
                                                serde_json::json!({
                                                    "error": format!("{}", e),
                                                    "message": "P2P download failed, falling back to HTTP.",
                                                }),
                                            );
                                            println!(
                                                "P2P: download failed ({}), falling back to HTTP",
                                                e
                                            );
                                            None
                                        }
                                    }
                                }
                                None => None,
                            }
                        }
                        Err(e) => {
                            eprintln!("P2P: address parse failed: {e}");
                            None
                        }
                    }
                }
                _ => None,
            },
            Err(_) => None,
        }
    } else {
        None
    };

    if let Some(data) = p2p_result {
        data
    } else {
        pre_bail!(emitter, "P2P download failed and HTTP fallback is disabled. Ensure the source supports P2P (iroh QUIC).");

        // ----- HTTP fallback preserved as dead code for future re-enablement -----
        #[allow(unreachable_code)]
        {
        let catalog_url = format!("{}/api/catalog", chunk_source.trim_end_matches('/'));
        let catalog_json: serde_json::Value = match client.get(&catalog_url).send() {
            Ok(r) => match r.json() {
                Ok(v) => v,
                Err(e) => pre_bail!(emitter, format!("Invalid catalog JSON: {}", e)),
            },
            Err(e) => pre_bail!(
                emitter,
                format!("Failed to fetch catalog from {}: {}", chunk_source, e)
            ),
        };

        let catalog_items: Vec<serde_json::Value> = if let Some(arr) = catalog_json.as_array() {
            arr.clone()
        } else if let Some(arr) = catalog_json["items"].as_array() {
            arr.clone()
        } else {
            pre_bail!(emitter, "Catalog response has no items array");
        };

        let entry = match catalog_items.iter().find(|e| {
            e["content_hash"].as_str() == Some(content_hash)
                || e["encrypted_hash"].as_str() == Some(content_hash)
        }) {
            Some(e) => e.clone(),
            None => pre_bail!(
                emitter,
                format!(
                    "Content {} not found in catalog at {}",
                    content_hash, chunk_source
                )
            ),
        };

        let num_chunks = entry["chunk_count"]
            .as_u64()
            .or_else(|| entry["total_chunks"].as_u64())
            .unwrap_or(1) as usize;
        let enc_hash_str = entry["encrypted_hash"]
            .as_str()
            .unwrap_or(content_hash)
            .to_string();

        emitter.emit(
            role,
            "DOWNLOADING_CHUNKS",
            serde_json::json!({
                "source": chunk_source,
                "chunks": num_chunks,
                "encrypted_hash": &enc_hash_str,
            }),
        );
        println!(
            "HTTP: downloading {} chunks from {}...",
            num_chunks, chunk_source
        );

        let mut data = Vec::new();
        for i in 0..num_chunks {
            let chunk_url = format!(
                "{}/api/chunks/{}/{}",
                chunk_source.trim_end_matches('/'),
                enc_hash_str,
                i
            );
            match client.get(&chunk_url).send() {
                Ok(r) => {
                    if !r.status().is_success() {
                        pre_bail!(
                            emitter,
                            format!("Chunk {}: HTTP {} from {}", i, r.status(), chunk_url)
                        );
                    }
                    match r.bytes() {
                        Ok(bytes) => {
                            data.extend_from_slice(&bytes);
                            emitter.emit(
                                role,
                                "CHUNK_PROGRESS",
                                serde_json::json!({
                                    "current": i + 1,
                                    "total": num_chunks,
                                    "bytes": bytes.len(),
                                }),
                            );
                        }
                        Err(e) => pre_bail!(emitter, format!("Chunk {} read error: {}", i, e)),
                    }
                }
                Err(e) => pre_bail!(emitter, format!("Failed to download chunk {}: {}", i, e)),
            }
        }
        data
        }
    }
    }; // end single-source fallback / ICS branch

    println!(
        "Downloaded {} bytes",
        all_enc_data.len(),
    );

    // 7. Decrypt per-chunk with recovered AES key m
    let cs = chunk::select_chunk_size(all_enc_data.len());
    let (enc_chunks, _meta) = chunk::split(&all_enc_data, cs);
    let decrypted: Vec<u8> = enc_chunks
        .iter()
        .enumerate()
        .flat_map(|(i, c)| encrypt::decrypt(c, &m, i as u64))
        .collect();
    emitter.emit(
        role,
        "CONTENT_DECRYPTED",
        serde_json::json!({
            "bytes": decrypted.len(),
            "chunks": enc_chunks.len(),
            "message": "Decrypted using PRE-recovered AES key.",
        }),
    );

    // 8. Verify content hash
    let actual_hash = verify::sha256_hash(&decrypted);
    let matches = hex::encode(actual_hash) == content_hash;
    emitter.emit(
        role,
        "HASH_VERIFIED",
        serde_json::json!({
            "matches": matches,
            "expected": content_hash,
            "actual": hex::encode(actual_hash),
        }),
    );
    if !matches {
        eprintln!(
            "WARNING: Content hash mismatch. Expected {} got {}",
            content_hash,
            hex::encode(actual_hash)
        );
    }

    // 9. Write output
    if let Err(e) = std::fs::write(output_path, &decrypted) {
        pre_bail!(emitter, format!("Failed to write file: {}", e));
    }
    emitter.emit(
        role,
        "FILE_SAVED",
        serde_json::json!({
            "path": output_path,
            "bytes": decrypted.len(),
            "message": "PRE atomic content exchange complete.",
        }),
    );
    println!();
    println!("=== BUY-PRE COMPLETE ===");
    println!(
        "Decrypted file: {} ({} bytes)",
        output_path,
        decrypted.len()
    );
}

