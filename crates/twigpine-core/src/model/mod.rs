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

pub mod chunking;
pub mod reconstruction;

/// The schema tag carried by the reconstruction object defined here. Unknown
/// tags are rejected on parse so a reader never silently misreads a later
/// format.
pub const RECONSTRUCTION_SCHEMA_V1: &str = "gitlawb/model-reconstruction/v1";

/// Lowercase hex sha256 of some bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}
