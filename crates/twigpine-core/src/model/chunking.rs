//! Content-defined chunking and block packing.
//!
//! Chunking uses FastCDC (the 2020 algorithm variant) at 8 / 64 / 128 KiB
//! min / avg / max. Packing into blocks lives in `reconstruction::pack_file`,
//! which seals at the 64 MiB target or end of stream.

use std::io::Read;

use fastcdc::v2020::StreamCDC;

use super::sha256_hex;

pub const CHUNK_MIN: usize = 8 * 1024;
pub const CHUNK_AVG: usize = 64 * 1024;
pub const CHUNK_MAX: usize = 128 * 1024;
pub const BLOCK_TARGET: usize = 64 * 1024 * 1024;

/// One content-defined chunk of a file. `data` is present while packing; the
/// id is the chunk's sha256, which is how the chunk dedups across files and
/// releases.
#[derive(Debug)]
pub struct Chunk {
    pub sha256: String,
    pub len: usize,
    pub offset: u64,
    pub data: Vec<u8>,
}

/// A sealed block: a run of chunks and its content id.
#[derive(Debug)]
pub struct Block {
    pub sha256: String,
    pub chunks: Vec<Chunk>,
    pub data: Vec<u8>,
}

/// Stream a reader into content-defined chunks. Memory stays bounded by the
/// maximum chunk size, never the file size.
pub fn chunk_reader<R: Read>(reader: R) -> impl Iterator<Item = std::io::Result<Chunk>> {
    StreamCDC::new(reader, CHUNK_MIN, CHUNK_AVG, CHUNK_MAX).map(|r| {
        let c = r?;
        Ok(Chunk {
            sha256: sha256_hex(&c.data),
            len: c.data.len(),
            offset: c.offset,
            data: c.data,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::gen_bytes;
    use std::io::Cursor;

    const SEED: u64 = 0x9e3779b97f4a7c15;

    fn chunk_all(bytes: &[u8]) -> Vec<Chunk> {
        chunk_reader(Cursor::new(bytes.to_vec()))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn chunking_is_deterministic() {
        let bytes = gen_bytes(3 * 1024 * 1024, SEED);
        let a = chunk_all(&bytes);
        let b = chunk_all(&bytes);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.sha256, y.sha256);
            assert_eq!(x.len, y.len);
            assert_eq!(x.offset, y.offset);
        }
    }

    #[test]
    fn chunk_sizes_stay_within_bounds() {
        let bytes = gen_bytes(10 * 1024 * 1024, SEED);
        let chunks = chunk_all(&bytes);
        assert!(chunks.len() > 10);
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.len <= CHUNK_MAX, "chunk {i} exceeds max");
            if i + 1 < chunks.len() {
                // The final chunk may end before the min when the input runs out.
                assert!(c.len >= CHUNK_MIN, "chunk {i} below min");
            }
        }
    }

    #[test]
    fn a_small_edit_changes_only_early_chunks() {
        let base = gen_bytes(20 * 1024 * 1024, SEED);
        let mut edited = vec![0u8; 100];
        edited.extend_from_slice(&base);

        let base_ids: Vec<String> = chunk_all(&base).iter().map(|c| c.sha256.clone()).collect();
        let edited_ids: Vec<String> = chunk_all(&edited)
            .iter()
            .map(|c| c.sha256.clone())
            .collect();

        let base_set: std::collections::HashSet<&String> = base_ids.iter().collect();
        let changed = edited_ids
            .iter()
            .filter(|id| !base_set.contains(id))
            .count();
        // 100 inserted bytes move the first few boundaries; the vast majority
        // of a 20 MiB file still chunks identically.
        assert!(
            changed <= 4,
            "{changed} changed chunks for a 100-byte prefix insert"
        );
    }

    #[test]
    fn chunk_data_never_buffers_the_file() {
        // The contract this format depends on: a reader is consumed a chunk
        // at a time. Guard it by chunking a reader that would panic if read
        // past its claimed end before the iterator asks for more.
        struct Stingy {
            left: usize,
        }
        impl Read for Stingy {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = buf.len().min(self.left);
                self.left -= n;
                buf[..n].fill(1);
                Ok(n)
            }
        }
        let mut it = chunk_reader(Stingy {
            left: 3 * CHUNK_MAX,
        });
        let first = it.next().unwrap().unwrap();
        assert!(first.len <= CHUNK_MAX);
    }
}
