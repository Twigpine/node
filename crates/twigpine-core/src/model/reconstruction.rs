//! The reconstruction object: versioned JSON mapping each chunk-stored file
//! to the block terms that rebuild it.
//!
//! A term names a block by its sha256 and a half-open range of that block's
//! chunk list; a file is its terms in order. Each block's own entry lists
//! every chunk's sha256 and length, so byte offsets inside a block are prefix
//! sums and the format carries no redundant offset column.
//!
//! The schema string is part of the signed surface: a reader rejects a tag it
//! does not know rather than guessing at a later layout.

use std::collections::HashMap;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::chunking::{chunk_reader, Block, BLOCK_TARGET};
use super::{sha256_hex, RECONSTRUCTION_SCHEMA_V1};

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("unsupported reconstruction schema {0:?}")]
    UnknownSchema(String),
    #[error("invalid reconstruction: {0}")]
    Invalid(String),
    #[error("hash mismatch: {0}")]
    HashMismatch(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Term {
    /// sha256 of the block this term reads from.
    pub block: String,
    /// Half-open index range into that block's `chunks` list.
    pub chunk_start: u32,
    pub chunk_end: u32,
    /// File bytes this term contributes: the sum of its chunks' lengths.
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub terms: Vec<Term>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkMeta {
    pub sha256: String,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockEntry {
    pub sha256: String,
    pub size: u64,
    pub chunks: Vec<ChunkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reconstruction {
    pub schema: String,
    pub files: Vec<FileEntry>,
    pub blocks: Vec<BlockEntry>,
}

impl Reconstruction {
    pub fn new() -> Self {
        Self {
            schema: RECONSTRUCTION_SCHEMA_V1.to_string(),
            files: Vec::new(),
            blocks: Vec::new(),
        }
    }

    /// Parse and validate a stored object. Unknown schema tags are refused:
    /// misreading a later layout silently is worse than failing.
    pub fn parse(bytes: &[u8]) -> Result<Self, ModelError> {
        let this: Reconstruction = serde_json::from_slice(bytes)?;
        if this.schema != RECONSTRUCTION_SCHEMA_V1 {
            return Err(ModelError::UnknownSchema(this.schema));
        }
        this.validate()?;
        Ok(this)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ModelError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Structural sanity: terms index real blocks, chunk ranges are ordered,
    /// and each file's terms sum to its declared size.
    pub fn validate(&self) -> Result<(), ModelError> {
        let blocks: HashMap<&str, &BlockEntry> =
            self.blocks.iter().map(|b| (b.sha256.as_str(), b)).collect();
        for file in &self.files {
            let mut total = 0u64;
            for term in &file.terms {
                if term.chunk_start >= term.chunk_end {
                    return Err(ModelError::Invalid(format!(
                        "{}: empty chunk range in term for block {}",
                        file.path, term.block
                    )));
                }
                let block = blocks.get(term.block.as_str()).ok_or_else(|| {
                    ModelError::Invalid(format!(
                        "{}: term names unknown block {}",
                        file.path, term.block
                    ))
                })?;
                if term.chunk_end as usize > block.chunks.len() {
                    return Err(ModelError::Invalid(format!(
                        "{}: chunk range {}..{} exceeds block {} with {} chunks",
                        file.path,
                        term.chunk_start,
                        term.chunk_end,
                        term.block,
                        block.chunks.len()
                    )));
                }
                let span: u64 = block.chunks[term.chunk_start as usize..term.chunk_end as usize]
                    .iter()
                    .map(|c| c.len)
                    .sum();
                if span != term.length {
                    return Err(ModelError::Invalid(format!(
                        "{}: term length {span} != declared {}",
                        file.path, term.length
                    )));
                }
                total += term.length;
            }
            if total != file.size {
                return Err(ModelError::Invalid(format!(
                    "{}: terms cover {total} bytes, file declares {}",
                    file.path, file.size
                )));
            }
        }
        Ok(())
    }

    fn block_index(&self) -> HashMap<&str, &BlockEntry> {
        self.blocks.iter().map(|b| (b.sha256.as_str(), b)).collect()
    }
}

impl Default for Reconstruction {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunk-sha lookup over prior reconstruction objects, the dedup surface:
/// a chunk whose hash a prior release already stored can be referenced by
/// term instead of re-uploaded.
#[derive(Default)]
pub struct DedupIndex {
    /// chunk sha256 -> (block sha256, chunk index inside that block)
    by_chunk: HashMap<String, (String, u32)>,
}

impl DedupIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_reconstructions(priors: &[&Reconstruction]) -> Self {
        let mut idx = Self::new();
        for rec in priors {
            idx.add(rec);
        }
        idx
    }

    pub fn add(&mut self, rec: &Reconstruction) {
        for block in &rec.blocks {
            for (i, chunk) in block.chunks.iter().enumerate() {
                // First writer wins: two priors carrying the same chunk are
                // interchangeable, so keep the earliest.
                idx_insert(
                    &mut self.by_chunk,
                    chunk.sha256.clone(),
                    (block.sha256.clone(), i as u32),
                );
            }
        }
    }
}

fn idx_insert(map: &mut HashMap<String, (String, u32)>, k: String, v: (String, u32)) {
    map.entry(k).or_insert(v);
}

/// Seal a staged run of new chunks into one block and append its term and
/// block-table entry.
fn seal_staged(
    staged: &mut Vec<crate::model::chunking::Chunk>,
    terms: &mut Vec<Term>,
    block_entries: &mut Vec<BlockEntry>,
    new_blocks: &mut Vec<Block>,
) {
    if staged.is_empty() {
        return;
    }
    let chunks = std::mem::take(staged);
    let mut data = Vec::with_capacity(chunks.iter().map(|c| c.len).sum::<usize>());
    for c in &chunks {
        data.extend_from_slice(&c.data);
    }
    let block = Block {
        sha256: sha256_hex(&data),
        chunks,
        data,
    };
    terms.push(Term {
        block: block.sha256.clone(),
        chunk_start: 0,
        chunk_end: block.chunks.len() as u32,
        length: block.data.len() as u64,
    });
    block_entries.push(BlockEntry {
        sha256: block.sha256.clone(),
        size: block.data.len() as u64,
        chunks: block
            .chunks
            .iter()
            .map(|c| ChunkMeta {
                sha256: c.sha256.clone(),
                len: c.len as u64,
            })
            .collect(),
    });
    new_blocks.push(block);
}

/// What `pack_file` produced: the file's entry, the new blocks to store and
/// upload, and the block entries the reconstruction object must carry.
pub struct PackedFile {
    pub file: FileEntry,
    pub new_blocks: Vec<Block>,
    pub block_entries: Vec<BlockEntry>,
}

/// Chunk and pack one file, reusing terms for chunks a prior reconstruction
/// already holds (`dedup`). `path` is the repo-relative path recorded in the
/// entry.
pub fn pack_file<R: Read>(
    path: &str,
    reader: R,
    dedup: &DedupIndex,
) -> std::io::Result<PackedFile> {
    let mut file_hasher = sha2::Sha256::new();
    use sha2::Digest;

    let mut terms: Vec<Term> = Vec::new();
    let mut new_blocks: Vec<Block> = Vec::new();
    let mut block_entries: Vec<BlockEntry> = Vec::new();
    // Chunks not found in `dedup`, staged until the staging run seals into a
    // block (at the target size, on a reused-chunk boundary, or at EOF).
    let mut staged: Vec<crate::model::chunking::Chunk> = Vec::new();
    let mut staged_bytes: usize = 0;
    let mut file_size: u64 = 0;

    for chunk in chunk_reader(reader) {
        let chunk = chunk?;
        file_hasher.update(&chunk.data);
        file_size += chunk.len as u64;
        if let Some((block_sha, idx)) = dedup.by_chunk.get(&chunk.sha256) {
            seal_staged(&mut staged, &mut terms, &mut block_entries, &mut new_blocks);
            // Extend the previous term when it already reads the chunk before
            // this one in the same block: a shared run stays a single term.
            match terms.last_mut() {
                Some(t) if t.block == *block_sha && t.chunk_end == *idx => {
                    t.chunk_end = idx + 1;
                    t.length += chunk.len as u64;
                }
                _ => terms.push(Term {
                    block: block_sha.clone(),
                    chunk_start: *idx,
                    chunk_end: idx + 1,
                    length: chunk.len as u64,
                }),
            }
        } else {
            staged_bytes += chunk.len;
            staged.push(chunk);
            if staged_bytes >= BLOCK_TARGET {
                seal_staged(&mut staged, &mut terms, &mut block_entries, &mut new_blocks);
            }
        }
    }
    seal_staged(&mut staged, &mut terms, &mut block_entries, &mut new_blocks);

    let file = FileEntry {
        path: path.to_string(),
        size: file_size,
        sha256: hex::encode(file_hasher.finalize()),
        terms,
    };
    Ok(PackedFile {
        file,
        new_blocks,
        block_entries,
    })
}

/// Byte-range mapping: which slices of which blocks serve file bytes
/// `[start, end_exclusive)`. Each slice is a contiguous run of whole or
/// clipped chunks inside one block.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockSlice {
    pub block: String,
    /// Byte offset of the slice inside the block's chunk bytes.
    pub offset: u64,
    pub len: u64,
}

pub fn map_file_range(
    file: &FileEntry,
    rec: &Reconstruction,
    start: u64,
    end_exclusive: u64,
) -> Result<Vec<BlockSlice>, ModelError> {
    if start > end_exclusive || end_exclusive > file.size {
        return Err(ModelError::Invalid(format!(
            "range {start}..{end_exclusive} outside {} bytes of {}",
            file.size, file.path
        )));
    }
    let blocks = rec.block_index();
    let mut out: Vec<BlockSlice> = Vec::new();
    let mut cursor = 0u64;
    for term in &file.terms {
        let block = blocks
            .get(term.block.as_str())
            .ok_or_else(|| ModelError::Invalid(format!("unknown block {}", term.block)))?;
        let term_end = cursor + term.length;
        if term_end <= start || cursor >= end_exclusive {
            cursor = term_end;
            continue;
        }
        // Byte offset of each chunk inside the block, as a prefix sum.
        let mut block_off = 0u64;
        for (i, chunk) in block.chunks.iter().enumerate() {
            block_off += chunk.len;
            if i < term.chunk_start as usize {
                continue;
            }
            if i >= term.chunk_end as usize {
                break;
            }
            // This chunk covers file bytes [chunk_lo, chunk_hi).
            let chunk_hi = cursor + chunk.len;
            let chunk_lo = cursor;
            cursor = chunk_hi;
            let s = start.max(chunk_lo);
            let e = end_exclusive.min(chunk_hi);
            if s < e {
                let off = block_off - chunk.len + (s - chunk_lo);
                match out.last_mut() {
                    // Adjacent slices in the same block merge into one read.
                    Some(slice) if slice.block == term.block && slice.offset + slice.len == off => {
                        let slice: &mut BlockSlice = slice;
                        slice.len += e - s;
                    }
                    _ => out.push(BlockSlice {
                        block: term.block.clone(),
                        offset: off,
                        len: e - s,
                    }),
                }
            }
        }
        cursor = term_end;
    }
    Ok(out)
}

/// Rebuild a file's bytes from its terms, verifying every chunk's hash and
/// the whole-file digest. `fetch` returns a block's bytes by id (a
/// BlockStore range read or a cache hit on the caller's side).
pub fn rebuild_file<W: Write>(
    file: &FileEntry,
    rec: &Reconstruction,
    fetch: &mut dyn FnMut(&str) -> std::io::Result<Vec<u8>>,
    out: &mut W,
) -> Result<u64, ModelError> {
    use sha2::Digest;
    let blocks = rec.block_index();
    let mut file_hasher = sha2::Sha256::new();
    let mut written = 0u64;
    for term in &file.terms {
        let block = blocks
            .get(term.block.as_str())
            .ok_or_else(|| ModelError::Invalid(format!("unknown block {}", term.block)))?;
        let bytes = fetch(&term.block)?;
        if sha256_hex(&bytes) != term.block {
            return Err(ModelError::HashMismatch(format!(
                "block {} content does not hash to its id",
                term.block
            )));
        }
        let mut off = 0usize;
        for (i, chunk) in block.chunks.iter().enumerate() {
            let next = off + chunk.len as usize;
            if i >= term.chunk_start as usize && i < term.chunk_end as usize {
                let data = bytes.get(off..next).ok_or_else(|| {
                    ModelError::Invalid(format!(
                        "block {} shorter than its chunk table",
                        term.block
                    ))
                })?;
                if sha256_hex(data) != chunk.sha256 {
                    return Err(ModelError::HashMismatch(format!(
                        "chunk {} in block {}",
                        chunk.sha256, term.block
                    )));
                }
                out.write_all(data)?;
                file_hasher.update(data);
                written += chunk.len;
            }
            off = next;
        }
    }
    if written != file.size {
        return Err(ModelError::Invalid(format!(
            "{}: rebuilt {written} bytes, declared {}",
            file.path, file.size
        )));
    }
    let digest = hex::encode(file_hasher.finalize());
    if digest != file.sha256 {
        return Err(ModelError::HashMismatch(format!(
            "{}: rebuilt bytes do not hash to the manifest id",
            file.path
        )));
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn gen_bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x = seed;
        while v.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(n);
        v
    }

    fn pack(path: &str, bytes: &[u8]) -> (Reconstruction, PackedFile) {
        let dedup = DedupIndex::new();
        let packed = pack_file(path, Cursor::new(bytes.to_vec()), &dedup).unwrap();
        let mut rec = Reconstruction::new();
        rec.files.push(packed.file.clone());
        rec.blocks.extend(packed.block_entries.clone());
        (rec, packed)
    }

    #[test]
    fn pack_then_rebuild_is_byte_identical() {
        let bytes = gen_bytes(3 * 1024 * 1024 + 13, 7);
        let (rec, packed) = pack("model.safetensors", &bytes);
        rec.validate().unwrap();
        let store: HashMap<String, Vec<u8>> = packed
            .new_blocks
            .iter()
            .map(|b| (b.sha256.clone(), b.data.clone()))
            .collect();
        let mut out = Vec::new();
        let n = rebuild_file(
            &packed.file,
            &rec,
            &mut |id| Ok(store.get(id).cloned().expect("block")),
            &mut out,
        )
        .unwrap();
        assert_eq!(n as usize, bytes.len());
        assert_eq!(out, bytes);
    }

    #[test]
    fn reconstruction_round_trips_json_and_rejects_unknown_schema() {
        let bytes = gen_bytes(600_000, 11);
        let (rec, _) = pack("weights.bin", &bytes);
        let parsed = Reconstruction::parse(&rec.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, rec);

        let mut bad = rec.clone();
        bad.schema = "gitlawb/model-reconstruction/v99".to_string();
        assert!(matches!(
            Reconstruction::parse(&bad.to_bytes().unwrap()),
            Err(ModelError::UnknownSchema(_))
        ));
    }

    #[test]
    fn dedup_reuses_prior_chunks_without_new_blocks() {
        // A fine-tune sharing most of the base's bytes: only the changed
        // chunks seal into new blocks, the rest become terms into the prior
        // reconstruction's blocks.
        let base = gen_bytes(4 * 1024 * 1024, 23);
        let (base_rec, base_packed) = pack("base.safetensors", &base);
        assert_eq!(base_packed.new_blocks.len(), 1);

        let mut tuned = base.clone();
        // Overwrite a 300 KiB region in the middle: FastCDC boundaries
        // resync within a few chunks.
        for b in tuned.iter_mut().skip(2 * 1024 * 1024).take(300 * 1024) {
            *b = b.wrapping_add(1);
        }

        let dedup = DedupIndex::from_reconstructions(&[&base_rec]);
        let packed = pack_file("tuned.safetensors", Cursor::new(tuned.clone()), &dedup).unwrap();
        let mut rec = Reconstruction::new();
        // The block table carries prior blocks too: terms point at them, so
        // the object must list them for offsets to resolve.
        rec.blocks.extend(base_rec.blocks.iter().cloned());
        rec.blocks.extend(packed.block_entries.clone());
        rec.files.push(packed.file.clone());
        rec.validate().unwrap();

        let reused_chunks: usize = packed
            .file
            .terms
            .iter()
            .filter(|t| t.block == base_rec.blocks[0].sha256)
            .map(|t| (t.chunk_end - t.chunk_start) as usize)
            .sum();
        let total_chunks: usize = packed
            .file
            .terms
            .iter()
            .map(|t| (t.chunk_end - t.chunk_start) as usize)
            .sum();
        assert!(
            reused_chunks * 10 >= total_chunks * 8,
            "expected most chunks reused, got {reused_chunks}/{total_chunks}"
        );
        assert!(
            packed.new_blocks.len() <= 1,
            "changed chunks should seal into at most one new block"
        );

        let store: HashMap<String, Vec<u8>> = base_packed
            .new_blocks
            .iter()
            .chain(packed.new_blocks.iter())
            .map(|b| (b.sha256.clone(), b.data.clone()))
            .collect();
        let mut out = Vec::new();
        rebuild_file(
            &packed.file,
            &rec,
            &mut |id| Ok(store.get(id).cloned().expect("block")),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, tuned);
    }

    #[test]
    fn range_mapping_hits_the_middle_of_a_block() {
        // Build a 10-chunk block synthetically so the middle-subrange case is
        // exact, not dependent on where FastCDC happens to cut.
        let chunk_bytes: Vec<Vec<u8>> = (0..10)
            .map(|i| gen_bytes(100 + i * 10, i as u64 + 1))
            .collect();
        let chunks: Vec<ChunkMeta> = chunk_bytes
            .iter()
            .map(|c| ChunkMeta {
                sha256: sha256_hex(c),
                len: c.len() as u64,
            })
            .collect();
        let block_data: Vec<u8> = chunk_bytes.concat();
        let block_sha = sha256_hex(&block_data);
        // A file whose whole content is one term referencing chunks 3..6 of
        // a 10-chunk block: the shape dedup produces when a prior release
        // already stored the surrounding chunks.
        let term_len: u64 = chunks[3..6].iter().map(|c| c.len).sum();
        let prefix: u64 = chunks[..3].iter().map(|c| c.len).sum();
        let file_bytes: Vec<u8> = chunk_bytes[3..6].concat();
        let file = FileEntry {
            path: "f".into(),
            size: term_len,
            sha256: sha256_hex(&file_bytes),
            terms: vec![Term {
                block: block_sha.clone(),
                chunk_start: 3,
                chunk_end: 6,
                length: term_len,
            }],
        };
        let rec = Reconstruction {
            schema: RECONSTRUCTION_SCHEMA_V1.into(),
            files: vec![file.clone()],
            blocks: vec![BlockEntry {
                sha256: block_sha.clone(),
                size: block_data.len() as u64,
                chunks,
            }],
        };
        rec.validate().unwrap();

        // A middle range of the file maps to the middle of the block: the
        // slice offset includes the prefix sum of chunks 0..3 that the term
        // skips.
        let want = file.size - 10;
        let slices = map_file_range(&file, &rec, 10, want).unwrap();
        let served: u64 = slices.iter().map(|s| s.len).sum();
        assert_eq!(served, want - 10);
        assert_eq!(slices[0].offset, prefix + 10);
        // And the served bytes equal the file bytes.
        let mut got = Vec::new();
        for s in &slices {
            got.extend_from_slice(&block_data[s.offset as usize..(s.offset + s.len) as usize]);
        }
        assert_eq!(got, file_bytes[10..want as usize]);
    }

    #[test]
    fn rebuild_rejects_a_corrupt_block() {
        let bytes = gen_bytes(300_000, 31);
        let (rec, packed) = pack("f", &bytes);
        let mut out = Vec::new();
        let err =
            rebuild_file(&packed.file, &rec, &mut |_id| Ok(vec![0u8; 16]), &mut out).unwrap_err();
        assert!(matches!(err, ModelError::HashMismatch(_)));
    }
}
