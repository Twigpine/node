//! Open-weight model hosting: upload sessions, release claims, verification,
//! and reclamation. Feature-gated by `model_hosting_enabled`; the routes are
//! mounted only when `state.block_store` is `Some`, and every handler
//! re-checks it.
//!
//! All SQL lives in `crate::db::model_queries` as typed `Db` methods; the
//! free functions here are the store read helpers the handlers and workers
//! share.

pub mod claim;
pub mod durability;
pub mod serve;
pub mod sweep;
pub mod verify;

use std::sync::Arc;

use crate::db::model_queries::ModelRelease;
use crate::error::AppError;
use crate::state::AppState;

pub(crate) use crate::db::model_queries::ts_now;

/// Transport + store hard cap on one block (KTD1: 64 MiB target, 128 MiB cap).
pub const MAX_BLOCK_BYTES: u64 = 128 * 1024 * 1024;

/// Advisory-lock key serializing claim admission: the "one verifying release
/// per publisher" check and the quota reservations are check-then-act, so the
/// lock is what makes them safe under racing claims.
pub(crate) const CLAIM_LOCK_KEY: i64 = 0x6D6F64656C636C61; // "modelcla"

/// Paths inside a release commit: the signed manifest and its detached
/// signature. One definition shared by the claim reader, the HF surface,
/// and the durability jobs so a path change cannot split writers from
/// readers.
pub(crate) const RELEASE_MANIFEST_PATH: &str = ".twigpine/model-release.json";
pub(crate) const RELEASE_SIG_PATH: &str = ".twigpine/model-release.sig";

pub type ReleaseRow = ModelRelease;

pub async fn read_range(
    store: &Arc<dyn crate::blockstore::BlockStore>,
    sha: &str,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, crate::blockstore::BlockStoreError> {
    use futures::StreamExt;
    let id = crate::blockstore::BlockId::parse(sha)
        .map_err(|e| crate::blockstore::BlockStoreError::Backend(e.to_string()))?;
    let end = start
        .checked_add(len)
        .ok_or(crate::blockstore::BlockStoreError::OutOfRange)?;
    let mut stream = store.get_range(&id, start, end).await?;
    let mut out = Vec::with_capacity(len.min(1 << 22) as usize);
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

pub async fn read_block(
    store: &Arc<dyn crate::blockstore::BlockStore>,
    sha: &str,
    size: u64,
) -> Result<Vec<u8>, crate::blockstore::BlockStoreError> {
    read_range(store, sha, 0, size).await
}

/// The set of blocks a manifest references: the reconstruction object itself
/// (stored as its own content block) plus every data block the parsed
/// reconstruction names. The reconstruction object is read from the block
/// store and validated before its block table is trusted.
pub async fn referenced_blocks(
    state: &AppState,
    manifest: &twigpine_core::model::manifest::Manifest,
) -> Result<Vec<String>, AppError> {
    use twigpine_core::model::reconstruction::Reconstruction;
    let Some(rec_ref) = &manifest.reconstruction else {
        return Ok(Vec::new());
    };
    let store = state
        .block_store
        .clone()
        .ok_or_else(|| AppError::NotFound("model hosting is not enabled".into()))?;
    let bytes = read_block(&store, &rec_ref.sha256, rec_ref.size)
        .await
        .map_err(|e| AppError::BadRequest(format!("reconstruction object unreadable: {e}")))?;
    let rec = Reconstruction::parse(&bytes)
        .map_err(|e| AppError::BadRequest(format!("reconstruction object invalid: {e}")))?;
    let mut out = vec![rec_ref.sha256.clone()];
    for b in &rec.blocks {
        out.push(b.sha256.clone());
    }
    Ok(out)
}
