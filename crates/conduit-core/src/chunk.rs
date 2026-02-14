//! File chunking for P2P distribution.
//!
//! Splits files into fixed-size chunks for parallel multi-source download.
//! Each chunk becomes a leaf in the Merkle tree and is encrypted with a
//! chunk-index-specific IV (see [`crate::encrypt::derive_iv`]).
//!
//! Design: [`docs/02_p2p_distribution.md`], Section 2.

/// Default chunk size: 256 KB.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Minimum chunk size: 64 KB (for files < 1 MB).
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size: 1 MB (for files > 1 GB).
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Metadata for a chunked file.
#[derive(Debug, Clone)]
pub struct ChunkMeta {
    /// Number of chunks.
    pub count: usize,
    /// Chunk size in bytes (all chunks except possibly the last).
    pub chunk_size: usize,
    /// Original file size in bytes (before any padding).
    pub original_size: usize,
}

/// Select an appropriate chunk size for a file of the given length.
///
/// - Files < 1 MB use 64 KB chunks (finer granularity for small files).
/// - Files > 1 GB use 1 MB chunks (fewer chunks, less overhead).
/// - Everything else uses the 256 KB default.
pub fn select_chunk_size(file_size: usize) -> usize {
    if file_size < 1_000_000 {
        MIN_CHUNK_SIZE
    } else if file_size > 1_000_000_000 {
        MAX_CHUNK_SIZE
    } else {
        DEFAULT_CHUNK_SIZE
    }
}

/// Split `data` into fixed-size chunks.
///
/// Returns the list of chunks and metadata. The last chunk may be shorter
/// than `chunk_size` -- no padding is applied here (padding is the caller's
/// responsibility if needed for encryption alignment).
///
/// If `data` is empty, returns a single empty chunk so the Merkle tree
/// always has at least one leaf.
pub fn split(data: &[u8], chunk_size: usize) -> (Vec<Vec<u8>>, ChunkMeta) {
    assert!(chunk_size > 0, "chunk_size must be > 0");

    if data.is_empty() {
        return (
            vec![vec![]],
            ChunkMeta {
                count: 1,
                chunk_size,
                original_size: 0,
            },
        );
    }

    let chunks: Vec<Vec<u8>> = data.chunks(chunk_size).map(|c| c.to_vec()).collect();
    let count = chunks.len();

    (
        chunks,
        ChunkMeta {
            count,
            chunk_size,
            original_size: data.len(),
        },
    )
}

/// Reassemble chunks back into the original data.
///
/// `original_size` is used to strip any trailing padding from the last
/// chunk.
pub fn reassemble(chunks: &[Vec<u8>], original_size: usize) -> Vec<u8> {
    let mut data: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    data.truncate(original_size);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_chunk_size_small() {
        assert_eq!(select_chunk_size(500_000), MIN_CHUNK_SIZE);
    }

    #[test]
    fn test_select_chunk_size_medium() {
        assert_eq!(select_chunk_size(50_000_000), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn test_select_chunk_size_large() {
        assert_eq!(select_chunk_size(2_000_000_000), MAX_CHUNK_SIZE);
    }

    #[test]
    fn test_split_empty() {
        let (chunks, meta) = split(b"", 256);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_empty());
        assert_eq!(meta.count, 1);
        assert_eq!(meta.original_size, 0);
    }

    #[test]
    fn test_split_exact_multiple() {
        let data = vec![0xAB; 1024];
        let (chunks, meta) = split(&data, 256);
        assert_eq!(chunks.len(), 4);
        assert_eq!(meta.count, 4);
        assert_eq!(meta.original_size, 1024);
        for chunk in &chunks {
            assert_eq!(chunk.len(), 256);
        }
    }

    #[test]
    fn test_split_remainder() {
        let data = vec![0xCD; 700];
        let (chunks, meta) = split(&data, 256);
        assert_eq!(chunks.len(), 3); // 256 + 256 + 188
        assert_eq!(meta.count, 3);
        assert_eq!(meta.original_size, 700);
        assert_eq!(chunks[0].len(), 256);
        assert_eq!(chunks[1].len(), 256);
        assert_eq!(chunks[2].len(), 188);
    }

    #[test]
    fn test_split_single_chunk() {
        let data = vec![0xEF; 100];
        let (chunks, meta) = split(&data, 256);
        assert_eq!(chunks.len(), 1);
        assert_eq!(meta.count, 1);
        assert_eq!(chunks[0].len(), 100);
    }

    #[test]
    fn test_reassemble_exact() {
        let data = vec![0xAB; 1024];
        let (chunks, meta) = split(&data, 256);
        let reassembled = reassemble(&chunks, meta.original_size);
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_remainder() {
        let data: Vec<u8> = (0..700).map(|i| (i % 256) as u8).collect();
        let (chunks, meta) = split(&data, 256);
        let reassembled = reassemble(&chunks, meta.original_size);
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_round_trip_various_sizes() {
        for size in [0, 1, 255, 256, 257, 512, 1000, 65536, 65537] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let chunk_size = if size < 512 { 64 } else { 256 };
            let (chunks, meta) = split(&data, chunk_size);
            let reassembled = reassemble(&chunks, meta.original_size);
            assert_eq!(reassembled, data, "Round-trip failed for size {}", size);
        }
    }

    #[test]
    #[should_panic(expected = "chunk_size must be > 0")]
    fn test_split_zero_chunk_size() {
        split(b"data", 0);
    }
}
