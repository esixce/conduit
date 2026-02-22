use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use conduit_core::chunk;
use conduit_core::merkle::MerkleTree;
use conduit_core::verify;

use super::state::{CatalogEntry, RegistryInfo};

pub fn catalog_path(storage_dir: &str) -> String {
    format!("{}/catalog.json", storage_dir)
}

pub fn load_catalog(storage_dir: &str) -> Vec<CatalogEntry> {
    let path = catalog_path(storage_dir);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse catalog {}: {}", path, e);
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

pub fn save_catalog(storage_dir: &str, catalog: &[CatalogEntry]) {
    let path = catalog_path(storage_dir);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(catalog).expect("Failed to serialize catalog");
    std::fs::write(&path, json).expect("Failed to write catalog");
    println!("Catalog saved: {} ({} entries)", path, catalog.len());
}

// ---------------------------------------------------------------------------
// Trusted manufacturers list — creator-local trust decisions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedManufacturer {
    pub pk_hex: String,
    pub name: String,
    #[serde(default)]
    pub added_at: String,
}

pub fn trust_list_path(storage_dir: &str) -> String {
    format!("{}/trusted_manufacturers.json", storage_dir)
}

pub fn load_trust_list(storage_dir: &str) -> Vec<TrustedManufacturer> {
    let path = trust_list_path(storage_dir);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse trust list {}: {}", path, e);
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

pub fn save_trust_list(storage_dir: &str, list: &[TrustedManufacturer]) {
    let path = trust_list_path(storage_dir);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(list).expect("Failed to serialize trust list");
    std::fs::write(&path, json).expect("Failed to write trust list");
    println!("Trust list saved: {} ({} entries)", path, list.len());
}

/// Startup migration: recompute chunk metadata for legacy seeder catalog entries
/// that have chunk_count == 0 but have an encrypted file on disk.
pub fn migrate_legacy_chunks(storage_dir: &str, catalog: &mut [CatalogEntry]) {
    let mut migrated = 0usize;
    for entry in catalog.iter_mut() {
        if entry.chunk_count > 0 || entry.enc_file_path.is_empty() {
            continue;
        }
        let encrypted = match std::fs::read(&entry.enc_file_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "migrate_legacy_chunks: skip {} — cannot read {}: {}",
                    entry.file_name, entry.enc_file_path, e
                );
                continue;
            }
        };
        let cs = chunk::select_chunk_size(encrypted.len());
        let (enc_chunks, meta) = chunk::split(&encrypted, cs);
        let enc_tree = MerkleTree::from_chunks(&enc_chunks);

        entry.chunk_size = meta.chunk_size;
        entry.chunk_count = meta.count;
        entry.encrypted_root = hex::encode(enc_tree.root());
        migrated += 1;
        println!(
            "migrate_legacy_chunks: {} → {} chunks (size {})",
            entry.file_name, meta.count, meta.chunk_size
        );
    }
    if migrated > 0 {
        save_catalog(storage_dir, catalog);
        println!(
            "Migrated {} legacy catalog entries with chunk metadata.",
            migrated
        );
    }
}

/// Startup resync: for each seeder catalog entry, check the registry listing.
/// If the creator re-published (new K → new encrypted_hash), re-fetch the
/// encrypted file from the creator and replace the stale catalog entry.
pub fn resync_stale_seeds(
    storage_dir: &str,
    catalog: &Arc<std::sync::Mutex<Vec<CatalogEntry>>>,
    registry_info: &RegistryInfo,
) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // 1. Fetch all listings from registry
    let listings_url = format!("{}/api/listings", registry_info.url);
    let listings: Vec<serde_json::Value> = match client
        .get(&listings_url)
        .send()
        .and_then(|r| r.json::<serde_json::Value>())
    {
        Ok(data) => {
            let items = data["items"]
                .as_array()
                .or_else(|| data.as_array())
                .cloned()
                .unwrap_or_default();
            items
        }
        Err(e) => {
            eprintln!("resync_stale_seeds: failed to fetch listings: {}", e);
            return;
        }
    };

    println!(
        "resync_stale_seeds: {} listings in registry",
        listings.len()
    );

    // 2. For each listing, check if we have a seeder entry by file_name
    for listing in &listings {
        let listing_file = listing["file_name"].as_str().unwrap_or("");
        let listing_enc_hash = listing["encrypted_hash"].as_str().unwrap_or("");
        let creator_addr = listing["creator_address"].as_str().unwrap_or("");
        if listing_file.is_empty() || listing_enc_hash.is_empty() || creator_addr.is_empty() {
            continue;
        }

        // Check if our catalog has this file_name with a DIFFERENT encrypted_hash
        let stale = {
            let cat = catalog.lock().unwrap();
            cat.iter().any(|e| {
                e.file_name == listing_file
                    && !e.encrypted_hash.is_empty()
                    && e.content_hash.is_empty()  // seeder entry (not creator)
                    && e.encrypted_hash != listing_enc_hash
            })
        };

        if !stale {
            continue;
        }

        println!(
            "resync_stale_seeds: {} has stale encrypted_hash, re-fetching from creator {}",
            listing_file, creator_addr
        );

        // 3. Fetch the new encrypted file from creator
        let enc_filename = format!("{}.enc", listing_file);
        let creator_base = if creator_addr.starts_with("http") {
            creator_addr.to_string()
        } else {
            format!("http://{}", creator_addr)
        };
        let enc_url = format!("{}/api/enc/{}", creator_base, enc_filename);
        let enc_data = match client.get(&enc_url).send().and_then(|r| r.bytes()) {
            Ok(b) => b.to_vec(),
            Err(e) => {
                eprintln!(
                    "resync_stale_seeds: failed to fetch {} from {}: {}",
                    enc_filename, enc_url, e
                );
                continue;
            }
        };

        // Verify the downloaded file's hash matches the listing
        let actual_hash = hex::encode(verify::sha256_hash(&enc_data));
        if actual_hash != listing_enc_hash {
            eprintln!(
                "resync_stale_seeds: hash mismatch for {} — expected {} got {}",
                listing_file, listing_enc_hash, actual_hash
            );
            continue;
        }

        // 4. Save the new encrypted file to disk
        let enc_path = format!("{}/{}", storage_dir, enc_filename);
        if let Err(e) = std::fs::write(&enc_path, &enc_data) {
            eprintln!("resync_stale_seeds: failed to write {}: {}", enc_path, e);
            continue;
        }

        // 5. Compute chunk metadata
        let cs = chunk::select_chunk_size(enc_data.len());
        let (enc_chunks, meta) = chunk::split(&enc_data, cs);
        let enc_tree = MerkleTree::from_chunks(&enc_chunks);

        // 6. Remove old entry and insert new one
        let transport_price = {
            let mut cat = catalog.lock().unwrap();
            let old_tp = cat
                .iter()
                .find(|e| e.file_name == listing_file && e.content_hash.is_empty())
                .map(|e| e.transport_price)
                .unwrap_or(5);
            cat.retain(|e| !(e.file_name == listing_file && e.content_hash.is_empty()));
            old_tp
        };

        let registered_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        let entry = CatalogEntry {
            content_hash: String::new(),
            file_name: listing_file.to_string(),
            file_path: String::new(),
            enc_file_path: enc_path.clone(),
            key_hex: String::new(),
            price_sats: 0,
            encrypted_hash: listing_enc_hash.to_string(),
            size_bytes: enc_data.len() as u64,
            registered_at: registered_at.clone(),
            transport_price,
            chunk_size: meta.chunk_size,
            chunk_count: meta.count,
            plaintext_root: String::new(),
            encrypted_root: hex::encode(enc_tree.root()),
            chunks_held: Vec::new(),
            pre_c1_hex: String::new(),
            pre_c2_hex: String::new(),
            pre_pk_creator_hex: String::new(),
            playback_policy: "open".to_string(),
        };

        {
            let mut cat = catalog.lock().unwrap();
            cat.push(entry);
            save_catalog(storage_dir, &cat);
        }

        // 7. Re-announce to registry
        let body = serde_json::json!({
            "encrypted_hash": listing_enc_hash,
            "seeder_pubkey": &registry_info.node_pubkey,
            "seeder_address": &registry_info.http_address,
            "seeder_ln_address": &registry_info.ln_address,
            "seeder_alias": &registry_info.node_alias,
            "transport_price": transport_price,
            "chunk_count": meta.count,
            "chunks_held": Vec::<usize>::new(),
            "announced_at": &registered_at,
        });
        let url = format!("{}/api/seeders", registry_info.url);
        match client.post(&url).json(&body).send() {
            Ok(resp) => println!(
                "resync_stale_seeds: {} reseeded & announced ({})",
                listing_file,
                resp.status()
            ),
            Err(e) => eprintln!(
                "resync_stale_seeds: announce failed for {}: {}",
                listing_file, e
            ),
        }
    }
}
