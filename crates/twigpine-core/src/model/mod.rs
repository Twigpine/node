//! Model hosting formats shared by the node and the CLI: content-defined
//! chunking, block packing, the reconstruction object, and the signed
//! release manifest.
//!
//! Files are split by content, not by size: chunk boundaries land where the
//! bytes say they land, so appending or editing part of a weight file leaves
//! every other chunk identical. Chunks are the dedup unit; blocks (sequences
//! of chunks sealed near a target size) are the storage unit. Both are named
//! by the sha256 of their bytes, computed by whoever holds them and
//! recomputed by the node on receipt.

pub(crate) use crate::cid::sha256_hex;

pub mod chunking;
pub mod manifest;
pub mod reconstruction;

/// The schema tag carried by the reconstruction object defined here. Unknown
/// tags are rejected on parse so a reader never silently misreads a later
/// format.
pub const RECONSTRUCTION_SCHEMA_V1: &str = "gitlawb/model-reconstruction/v1";

/// Deterministic pseudo-random bytes for tests: `rand` is a dependency of
/// this crate, but a fixed-pattern generator keeps the tests reproducible.
#[cfg(test)]
pub(crate) fn gen_bytes(n: usize, seed: u64) -> Vec<u8> {
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
