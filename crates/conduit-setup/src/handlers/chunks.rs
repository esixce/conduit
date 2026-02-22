// ---------------------------------------------------------------------------
// A4: Chunk-level HTTP endpoints
// ---------------------------------------------------------------------------

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};

use conduit_core::{chunk, merkle::MerkleTree};

use crate::state::*;

/// Helper: find a catalog entry by encrypted_hash and return it with chunk metadata.
pub fn find_entry_with_chunks(
    state: &AppState,
    encrypted_hash: &str,
) -> Option<(CatalogEntry, Vec<Vec<u8>>, usize)> {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    let entry = entry?;

    let encrypted = std::fs::read(&entry.enc_file_path).ok()?;
    let cs = if entry.chunk_size > 0 {
        entry.chunk_size
    } else {
        chunk::select_chunk_size(encrypted.len())
    };
    let (enc_chunks, _meta) = chunk::split(&encrypted, cs);
    Some((entry, enc_chunks, cs))
}

/// GET /api/chunks/{encrypted_hash}/meta
/// Returns chunk count, chunk size, Merkle roots, file size.
pub async fn chunk_meta_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    match entry {
        Some(e) => Json(serde_json::json!({
            "encrypted_hash": e.encrypted_hash,
            "chunk_count": e.chunk_count,
            "chunk_size": e.chunk_size,
            "size_bytes": e.size_bytes,
            "encrypted_root": e.encrypted_root,
            "plaintext_root": e.plaintext_root,
            "content_hash": e.content_hash,
        }))
        .into_response(),
        None => (StatusCode::NOT_FOUND, "content not found").into_response(),
    }
}

/// Read a single chunk from an encrypted file using seek, avoiding loading the
/// entire file into memory. Returns the chunk bytes and total chunk count.
fn read_single_chunk(
    enc_file_path: &str,
    chunk_size: usize,
    index: usize,
) -> Option<(Vec<u8>, usize)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(enc_file_path).ok()?;
    let file_len = f.metadata().ok()?.len() as usize;
    let cs = if chunk_size > 0 {
        chunk_size
    } else {
        chunk::select_chunk_size(file_len)
    };
    let total_chunks = (file_len + cs - 1) / cs;
    if index >= total_chunks {
        return None;
    }
    let offset = index * cs;
    let len = cs.min(file_len - offset);
    f.seek(SeekFrom::Start(offset as u64)).ok()?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf).ok()?;
    Some((buf, total_chunks))
}

/// GET /api/chunks/{encrypted_hash}/{index}
/// Serves a single encrypted chunk E_i using seek-based I/O (reads only 1 chunk,
/// not the entire file).
pub async fn chunk_data_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    let entry = match entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, "content not found").into_response(),
    };
    if !entry.chunks_held.is_empty() && !entry.chunks_held.contains(&index) {
        return (StatusCode::NOT_FOUND, "seeder does not hold this chunk").into_response();
    }
    match read_single_chunk(&entry.enc_file_path, entry.chunk_size, index) {
        Some((data, total)) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("x-chunk-index", &index.to_string()),
                ("x-chunk-count", &total.to_string()),
            ],
            data,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "chunk index out of range").into_response(),
    }
}

/// GET /api/chunks/{encrypted_hash}/proof/{index}
/// Returns a Merkle inclusion proof for chunk i against the encrypted Merkle root.
pub async fn chunk_proof_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let result = find_entry_with_chunks(&state, &encrypted_hash);
    match result {
        Some((entry, enc_chunks, _cs)) => {
            if index >= enc_chunks.len() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": "chunk index out of range"
                    })),
                )
                    .into_response();
            }
            let tree = MerkleTree::from_chunks(&enc_chunks);
            let proof = tree.proof(index);
            let leaf_hash = hex::encode(tree.leaf_hash_at(index));
            Json(serde_json::json!({
                "index": index,
                "leaf_hash": leaf_hash,
                "proof": proof.to_json(),
                "encrypted_root": entry.encrypted_root,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "content not found"
            })),
        )
            .into_response(),
    }
}

/// GET /api/chunks/{encrypted_hash}/bitfield
/// Returns which chunks this node has. Empty chunks_held means "all".
pub async fn chunk_bitfield_handler(
    State(state): State<AppState>,
    AxumPath(encrypted_hash): AxumPath<String>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    match entry {
        Some(e) => {
            let total = if e.chunk_count > 0 { e.chunk_count } else { 1 };
            let bitfield: Vec<bool> = if e.chunks_held.is_empty() {
                // Empty = has all chunks
                vec![true; total]
            } else {
                (0..total).map(|i| e.chunks_held.contains(&i)).collect()
            };
            Json(serde_json::json!({
                "encrypted_hash": e.encrypted_hash,
                "chunk_count": total,
                "bitfield": bitfield,
                "chunks_held": if e.chunks_held.is_empty() {
                    (0..total).collect::<Vec<usize>>()
                } else {
                    e.chunks_held.clone()
                },
            }))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, "content not found").into_response(),
    }
}

/// GET /api/wrapped-chunks/{encrypted_hash}/{index}
/// Serves a previously wrapped chunk W_i from the wrapped_chunks directory.
pub async fn wrapped_chunk_handler(
    State(state): State<AppState>,
    AxumPath((encrypted_hash, index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    let entry = {
        let cat = state.catalog.lock().unwrap();
        cat.iter()
            .find(|e| e.encrypted_hash == encrypted_hash)
            .cloned()
    };
    let entry = match entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, "content not found").into_response(),
    };

    let chunk_path = format!("{}.wrapped_chunks/{}", entry.enc_file_path, index);
    match std::fs::read(&chunk_path) {
        Ok(data) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("x-chunk-index", &index.to_string()),
            ],
            data,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "wrapped chunk not found (request transport-invoice first)",
        )
            .into_response(),
    }
}

