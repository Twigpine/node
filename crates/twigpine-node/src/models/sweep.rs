//! Reclamation: expire upload sessions, drop their block links, mark blocks
//! unreferenced, and delete unreferenced blocks after the unclaimed grace
//! period. Blocks referenced by a live release or an open session survive.
//! The claim path locks block rows (`FOR UPDATE`) before referencing them,
//! and the sweep's delete candidate is re-checked inside its own
//! transaction, so a claim in flight can never lose a block mid-reference.

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Default)]
pub struct SweepStats {
    pub sessions_expired: u64,
    pub blocks_marked: u64,
    pub blocks_deleted: u64,
}

/// One sweep pass. Exposed for tests; the worker calls it on a tick.
pub async fn sweep_once(state: &AppState) -> Result<SweepStats, AppError> {
    let db = &state.db;
    let mut stats = SweepStats::default();

    // Expire sessions past TTL, then drop their block links: an expired
    // session no longer confers liveness.
    let expired = db.model_expire_sessions().await?;
    stats.sessions_expired = expired.len() as u64;
    for sid in &expired {
        db.model_drop_session_blocks(sid).await?;
    }

    // Re-mark liveness both ways: blocks that lost every live reference get
    // an unreferenced_since stamp; blocks that regained one clear theirs.
    stats.blocks_marked = db.model_remark_liveness().await?;

    // Delete blocks past the grace period. The store object goes first so a
    // crash leaves a dangling row (an honest "missing" at next claim) rather
    // than an untracked object the sweep can never find again.
    let grace = state.config.model_unclaimed_ttl_secs as i64;
    let stale = db.model_stale_blocks(grace, 128).await?;
    let Some(store) = state.block_store.clone() else {
        return Ok(stats);
    };
    for sha in stale {
        // Re-check liveness under the row lock the claim path also takes,
        // held across the store delete so a racing claim blocks rather than
        // wins a reference to an object we just removed.
        let mut tx = db.model_begin().await?;
        if !db.model_tx_block_still_dead(&mut tx, &sha).await? {
            tx.commit().await?;
            continue;
        }
        let Ok(id) = crate::blockstore::BlockId::parse(&sha) else {
            tx.commit().await?;
            continue;
        };
        match store.delete(&id).await {
            Ok(()) | Err(crate::blockstore::BlockStoreError::NotFound) => {}
            Err(e) => {
                tracing::warn!("block {sha} store delete failed: {e}");
                tx.commit().await?;
                continue;
            }
        }
        db.model_tx_delete_block_row(&mut tx, &sha).await?;
        tx.commit().await?;
        stats.blocks_deleted += 1;
    }
    Ok(stats)
}

/// Periodic sweep; spawned once when model hosting is enabled and exits on
/// node shutdown.
pub async fn run_sweep_worker(state: AppState) {
    let mut shutdown_rx = state.subscribe_shutdown();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown_rx.changed() => return,
        }
        if let Err(e) = sweep_once(&state).await {
            tracing::warn!("model sweep failed: {e}");
        }
    }
}
