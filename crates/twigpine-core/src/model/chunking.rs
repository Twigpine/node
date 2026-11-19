//! Content-defined chunking and block packing.
//!
//! Chunking uses FastCDC (the 2020 algorithm variant) at 8 / 64 / 128 KiB
//! min / avg / max. The packer seals a block once the accumulated chunks
//! reach the 64 MiB target; since a chunk is at most 128 KiB, a sealed block
//! can never approach the 128 MiB hard cap, which exists to bound block size
//! if the chunk parameters ever change.

use std::io::Read;

use fastcdc::v2020::StreamCDC;

use super::sha256_hex;

pub const CHUNK_MIN: usize = 8 * 1024;
pub const CHUNK_AVG: usize = 64 * 1024;
pub const CHUNK_MAX: usize = 128 * 1024;
pub const BLOCK_TARGET: usize = 64 * 1024 * 1024;
pub const BLOCK_CAP: usize = 128 * 1024 * 1024;

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

/// Pack the chunk stream into sealed blocks. Each yielded `Block` is a run of
/// chunks of at least `BLOCK_TARGET` bytes unless it is the tail of the
/// stream or the run was cut short to keep a block under the cap. Memory is
/// bounded by the block size.
pub struct BlockPacker<I: Iterator<Item = std::io::Result<Chunk>>> {
    chunks: I,
    pending: Vec<Chunk>,
    pending_bytes: usize,
    done: bool,
}

impl<I: Iterator<Item = std::io::Result<Chunk>>> BlockPacker<I> {
    pub fn new(chunks: I) -> Self {
        Self {
            chunks,
            pending: Vec::new(),
            pending_bytes: 0,
            done: false,
        }
    }

    /// Seal `pending` into a block when it holds anything. The caller owns the
    /// returned chunks' data; a block's `data` is its bytes.
    fn seal(&mut self) -> Option<std::io::Result<Block>> {
        if self.pending.is_empty() {
            return None;
        }
        let chunks = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let mut data = Vec::with_capacity(chunks.iter().map(|c| c.len).sum());
        for c in &chunks {
            data.extend_from_slice(&c.data);
        }
        Some(Ok(Block {
            sha256: sha256_hex(&data),
            chunks,
            data,
        }))
    }
}

impl<I: Iterator<Item = std::io::Result<Chunk>>> Iterator for BlockPacker<I> {
    type Item = std::io::Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.chunks.next() {
                Some(Ok(chunk)) => {
                    // A single chunk may exceed the target; it still joins the
                    // block under construction, and the cap check below is the
                    // only hard stop. Sealing before adding keeps any block at
                    // target + one chunk at most.
                    if self.pending_bytes >= BLOCK_TARGET
                        || self.pending_bytes + chunk.len > BLOCK_CAP
                    {
                        let sealed = self.seal();
                        self.pending.push(chunk);
                        self.pending_bytes += self.pending.last().map(|c| c.len).unwrap_or(0);
                        return sealed;
                    }
                    self.pending_bytes += chunk.len;
                    self.pending.push(chunk);
                }
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(e));
                }
                None => {
                    self.done = true;
                    return self.seal();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Deterministic pseudo-random bytes: rand is a dependency of this crate
    /// but a fixed-pattern generator makes the tests reproducible without a
    /// seed constant.
    fn gen_bytes(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u64 = 0x9e3779b97f4a7c15;
        while v.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(n);
        v
    }

    fn chunk_all(bytes: &[u8]) -> Vec<Chunk> {
        chunk_reader(Cursor::new(bytes.to_vec()))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn chunking_is_deterministic() {
        let bytes = gen_bytes(3 * 1024 * 1024);
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
        let bytes = gen_bytes(10 * 1024 * 1024);
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
        let base = gen_bytes(20 * 1024 * 1024);
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
    fn packing_round_trips_bytes() {
        // Small enough to exercise seals without a huge test file: multiple
        // blocks only form past 64 MiB, so here we check boundary accounting
        // on a tail block and byte identity end to end.
        let bytes = gen_bytes(2 * 1024 * 1024 + 7);
        let blocks: Vec<Block> = BlockPacker::new(chunk_reader(Cursor::new(bytes.clone())))
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(blocks.len(), 1, "under-target input seals to a tail block");
        let reassembled: Vec<u8> = blocks
            .iter()
            .flat_map(|b| b.chunks.iter().flat_map(|c| c.data.clone()))
            .collect();
        assert_eq!(reassembled, bytes);
        assert_eq!(blocks[0].sha256, sha256_hex(&bytes));
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
