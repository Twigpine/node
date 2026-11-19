//! Open-weight model hosting: upload sessions, release claims, verification,
//! and reclamation. Feature-gated by `model_hosting_enabled`; the routes are
//! mounted only when `state.block_store` is `Some`, and every handler
//! re-checks it.
//!
//! All SQL lives in `crate::db::model_queries` as typed `Db` methods; the
//! free functions here are the thin `&Db`-taking seams the handlers and
//! workers share.

pub mod claim;
pub mod sweep;
pub mod verify;

use std::sync::Arc;

use crate::db::model_queries::{ModelRelease, ModelSession};
use crate::db::Db;
use crate::error::AppError;
use crate::state::AppState;

/// Transport + store hard cap on one block (KTD1: 64 MiB target, 128 MiB cap).
pub const MAX_BLOCK_BYTES: u64 = 128 * 1024 * 1024;

/// Advisory-lock key serializing claim admission: the "one verifying release
/// per publisher" check and the quota reservations are check-then-act, so the
/// lock is what makes them safe under racing claims.
pub(crate) const CLAIM_LOCK_KEY: i64 = 0x6D6F64656C636C61; // "modelcla"

pub type SessionRow = ModelSession;
pub type ReleaseRow = ModelRelease;

/// rfc3339 UTC `secs` from now: the repo's TEXT timestamp convention.
pub fn ts_from_now(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

pub fn ts_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// 256-bit random session id, hex-encoded: the bearer capability for block
/// PUTs. Anyone holding it may append blocks to the session it names, so it
/// is never logged or returned to anyone but its creator.
pub fn new_session_id() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub async fn open_session(
    db: &Db,
    owner_did: &str,
    repo_id: &str,
    ttl_secs: u64,
) -> Result<SessionRow, AppError> {
    Ok(db.model_open_session(owner_did, repo_id, ttl_secs).await?)
}

pub async fn load_session(db: &Db, id: &str) -> Result<Option<SessionRow>, AppError> {
    Ok(db.model_load_session(id).await?)
}

/// Atomically admit `claimed` bytes against the caller's per-identity
/// open-session cap and the node-wide quota (claimed quota plus every open
/// session's bytes), sliding the session's expiry forward in the same
/// update. Returns the post-update row when admitted, `None` when the
/// session is closed, expired, or the admission would exceed a cap; the
/// caller re-checks the session to pick the honest denial.
pub async fn admit_bytes(
    db: &Db,
    session_id: &str,
    claimed: i64,
    ttl_secs: u64,
    session_cap: i64,
    node_cap: i64,
) -> Result<Option<SessionRow>, AppError> {
    Ok(db
        .model_admit_bytes(session_id, claimed, ttl_secs, session_cap, node_cap)
        .await?)
}

/// Refund a previously admitted charge when the store or the bookkeeping
/// fails. Best-effort under races; an expired session frees the bytes anyway.
pub async fn refund_bytes(db: &Db, session_id: &str, bytes: i64) -> Result<(), AppError> {
    db.model_refund_bytes(session_id, bytes).await?;
    Ok(())
}

/// Book the stored block against the session inside one transaction. Returns
/// `true` when this PUT was a duplicate within the session (the admission
/// credit was refunded).
pub async fn record_block(
    db: &Db,
    session_id: &str,
    block_sha: &str,
    size: u64,
    admitted: i64,
) -> Result<bool, AppError> {
    Ok(db
        .model_record_block(session_id, block_sha, size, admitted)
        .await?)
}

pub async fn release_by_commit(
    db: &Db,
    repo_id: &str,
    commit: &str,
) -> Result<Option<ReleaseRow>, AppError> {
    Ok(db.model_release_by_commit(repo_id, commit).await?)
}

pub async fn release_by_id(db: &Db, id: i64) -> Result<Option<ReleaseRow>, AppError> {
    Ok(db.model_release_by_id(id).await?)
}

/// sha256 of the manifest bytes, as hex.
pub fn manifest_sha256(manifest_bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(manifest_bytes))
}

/// Collect `len` bytes of a stored object starting at `start`.
pub async fn read_range(
    store: &Arc<dyn crate::blockstore::BlockStore>,
    sha: &str,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, crate::blockstore::BlockStoreError> {
    use futures::StreamExt;
    let id = crate::blockstore::BlockId::parse(sha)
        .map_err(|e| crate::blockstore::BlockStoreError::Backend(e.to_string()))?;
    let mut stream = store.get_range(&id, start, start + len).await?;
    let mut out = Vec::with_capacity(len.min(1 << 22) as usize);
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

/// Collect a stored object's whole body via a range read.
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
