//! Durability outbox for published releases (KTD10, KTD13).
//!
//! Publishing a release enqueues one job per content object:
//! `pin_block` for every block the release references, `pin_manifest` and
//! `pin_reconstruction` for the git-resident objects, `pin_block_map` for
//! the sha256-to-provider-CID map, and `anchor` for the Irys release root.
//! Jobs are keyed `(release, kind, object)` so re-enqueueing is a no-op,
//! and the startup backfill inserts missing sets atomically.
//!
//! The worker drains pending jobs oldest-first under a batch budget. Each
//! pin re-checks the repository is still fully public and holds a
//! `PolicyFence` across the irreversible provider call, so a repo turned
//! private mid-drain stops every sibling job and the anchor never posts.
//! Provider CIDs are recorded in `provider_cid` beside `object_key`: the
//! sha256 stays the resolver key no matter what a provider answered.
//!
//! A failed job stays `pending` (attempts bumped) until `MAX_ATTEMPTS`,
//! then `failed`; an anchor outage therefore leaves the anchor pending
//! while local downloads keep serving. Nothing in this module gates the
//! read surface.

use std::time::Duration;

use crate::db::model_queries::DurabilityJob;
use crate::db::RepoRecord;
use crate::error::AppError;
use crate::ipfs_pin::PolicyFence;
use crate::models::claim::git_show;
use crate::state::AppState;

pub const KIND_BLOCK: &str = "pin_block";
pub const KIND_MANIFEST: &str = "pin_manifest";
pub const KIND_RECONSTRUCTION: &str = "pin_reconstruction";
pub const KIND_BLOCK_MAP: &str = "pin_block_map";
pub const KIND_ANCHOR: &str = "anchor";

/// Attempts before a job leaves the drain set as `failed`.
const MAX_ATTEMPTS: i32 = 8;
/// Jobs drained per worker pass; a larger backlog rolls to the next tick.
const DRAIN_BATCH: i64 = 32;
/// Releases one backfill pass enqueues for.
const BACKFILL_BATCH: i64 = 64;
/// Worker cadence. Short enough that a publish lands pins promptly, long
/// enough that an empty drain is cheap.
const TICK_SECS: u64 = 30;

use crate::models::{RELEASE_MANIFEST_PATH as MANIFEST_PATH, RELEASE_SIG_PATH as SIG_PATH};

/// Enqueue the full job set for one published release. Idempotent: the
/// `(release, kind, object)` unique key makes a second call insert
/// nothing, so the publish hook, a retry, and the startup backfill share
/// this entry point.
pub async fn enqueue_for_release(state: &AppState, release_id: i64) -> Result<(), AppError> {
    let Some(release) = state.db.model_release_by_id(release_id).await? else {
        return Ok(());
    };
    if release.state != "published" {
        return Ok(());
    }
    let block_shas = state.db.model_release_blocks(release_id).await?;
    let mut jobs: Vec<(&str, &str)> = block_shas
        .iter()
        .map(|sha| (KIND_BLOCK, sha.as_str()))
        .collect();
    jobs.push((KIND_MANIFEST, release.manifest_sha256.as_str()));
    let rec_sha = state.db.model_reconstruction_sha(release_id).await?;
    if let Some(sha) = rec_sha.as_deref() {
        jobs.push((KIND_RECONSTRUCTION, sha));
    }
    // Release-level jobs key on the commit: it scopes the row, nothing
    // resolves object bytes through it.
    jobs.push((KIND_BLOCK_MAP, release.commit_sha.as_str()));
    jobs.push((KIND_ANCHOR, release.commit_sha.as_str()));
    state.db.model_durability_enqueue(release_id, &jobs).await?;
    Ok(())
}

/// Startup/repair backfill: enqueue the full job set for every published
/// release that has none. The enqueue is one `INSERT ... ON CONFLICT DO
/// NOTHING` per release, so a crash mid-backfill leaves no partial set.
async fn backfill_missing(state: &AppState) -> Result<(), AppError> {
    for release_id in state
        .db
        .model_releases_missing_durability(BACKFILL_BATCH)
        .await?
    {
        enqueue_for_release(state, release_id).await?;
    }
    Ok(())
}

/// One worker pass: backfill, then drain a bounded batch of pending jobs.
/// Exposed for tests; the worker loop calls it every tick.
pub async fn durability_pass(state: &AppState) -> Result<(), AppError> {
    backfill_missing(state).await?;
    for job in state.db.model_durability_pending(DRAIN_BATCH).await? {
        process_job(state, &job).await?;
    }
    Ok(())
}

/// The durability worker: backfill, drain, tick. Exits on node shutdown.
pub async fn run_durability_worker(state: AppState) {
    let mut shutdown_rx = state.subscribe_shutdown();
    let mut interval = tokio::time::interval(Duration::from_secs(TICK_SECS));
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown_rx.changed() => return,
        }
        if let Err(e) = durability_pass(&state).await {
            tracing::warn!("model durability pass failed: {e}");
        }
    }
}

/// Whether the repo a release belongs to may still be published outbound:
/// fully public on the canonical predicate, and not quarantined. A `false`
/// means every pending job for the release stops and the anchor must never
/// post (KTD10: pins stop when publicity changes).
async fn still_publishable(state: &AppState, record: &RepoRecord) -> Result<bool, AppError> {
    if state.db.is_repo_quarantined(&record.id).await? {
        return Ok(false);
    }
    let rules = state.db.list_visibility_rules(&record.id).await?;
    Ok(crate::api::models::require_fully_public(record, &rules).is_ok())
}

/// Process one pending job. Errors are recorded (attempts bumped, failed
/// past `MAX_ATTEMPTS`) rather than propagated, so one wedged provider
/// cannot stall the drain behind it.
async fn process_job(state: &AppState, job: &DurabilityJob) -> Result<(), AppError> {
    let Some(release) = state.db.model_release_by_id(job.release_id).await? else {
        state
            .db
            .model_durability_mark_failed(job.id, "release row is gone")
            .await?;
        return Ok(());
    };
    if release.state != "published" {
        state
            .db
            .model_durability_mark_failed(job.id, "release is no longer published")
            .await?;
        return Ok(());
    }

    // A gated job waits for its inputs rather than erroring: the map waits
    // on the block pins, the anchor waits on everything else.
    match job.kind.as_str() {
        KIND_BLOCK_MAP => {
            let (pending, failed) = state
                .db
                .model_durability_kind_counts(job.release_id, KIND_BLOCK)
                .await?;
            if pending > 0 {
                return Ok(());
            }
            if failed > 0 {
                state
                    .db
                    .model_durability_mark_failed(
                        job.id,
                        "a block pin failed; the map would be incomplete",
                    )
                    .await?;
                return Ok(());
            }
        }
        KIND_ANCHOR => {
            let (pending, failed) = state
                .db
                .model_durability_other_counts(job.release_id, KIND_ANCHOR)
                .await?;
            if pending > 0 {
                return Ok(());
            }
            if failed > 0 {
                state
                    .db
                    .model_durability_mark_failed(
                        job.id,
                        "a pin job failed; the anchor would be incomplete",
                    )
                    .await?;
                return Ok(());
            }
        }
        _ => {}
    }

    let Some(record) = state.db.get_repo_by_id(&release.repo_id).await? else {
        state
            .db
            .model_durability_mark_failed(job.id, "repo row is gone")
            .await?;
        return Ok(());
    };
    if !still_publishable(state, &record).await? {
        state
            .db
            .model_durability_fail_pending(job.release_id, "repository is no longer fully public")
            .await?;
        return Ok(());
    }

    // The policy fence is checked immediately before the irreversible
    // provider call; a stale epoch re-runs the publicity check rather than
    // assuming the bump was publicity-shaped.
    let fence = PolicyFence::capture(&state.db, &release.repo_id).await;

    let result = execute_job(state, &release, job, fence.as_ref(), &record).await;
    match result {
        Ok(JobOutcome::Deferred) => Ok(()),
        Ok(JobOutcome::Done(cid)) => {
            state.db.model_durability_done(job.id, &cid).await?;
            Ok(())
        }
        Err(e) => {
            let attempts = state
                .db
                .model_durability_record_error(job.id, &e.to_string())
                .await?;
            if attempts >= MAX_ATTEMPTS {
                state
                    .db
                    .model_durability_mark_failed(job.id, &e.to_string())
                    .await?;
            }
            Ok(())
        }
    }
}

enum JobOutcome {
    /// The job's inputs are not ready yet; it stays pending untouched.
    Deferred,
    /// Provider work completed; the string is the recorded provider CID
    /// (or anchor tx id), never the resolver key.
    Done(String),
}

/// The policy epoch is still good; a stale one defers the job so the
/// publicity check re-runs before the provider call.
async fn fence_current(fence: Option<&PolicyFence>) -> bool {
    match fence {
        Some(f) => f.is_current().await,
        None => true,
    }
}

/// Run the job's own work. `fence` is the captured policy epoch, checked
/// right before each provider call.
async fn execute_job(
    state: &AppState,
    release: &crate::models::ReleaseRow,
    job: &DurabilityJob,
    fence: Option<&PolicyFence>,
    record: &RepoRecord,
) -> Result<JobOutcome, AppError> {
    match job.kind.as_str() {
        KIND_BLOCK | KIND_RECONSTRUCTION => {
            let store = state
                .block_store
                .clone()
                .ok_or_else(|| AppError::Internal(anyhow::anyhow!("no block store")))?;
            let id = crate::blockstore::BlockId::parse(&job.object_key)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("bad object key: {e}")))?;
            let len = store
                .size(&id)
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("block size lookup failed: {e}")))?
                .ok_or_else(|| {
                    AppError::Internal(anyhow::anyhow!(
                        "object {} is not in the block store",
                        job.object_key
                    ))
                })?;
            let bytes = crate::models::read_block(&store, &job.object_key, len)
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("block read failed: {e}")))?;
            pin_bytes(state, &job.object_key, &bytes, fence).await
        }
        KIND_MANIFEST => {
            let bytes = git_bytes(&state.git_bin, record, release, MANIFEST_PATH).await?;
            pin_bytes(state, &job.object_key, &bytes, fence).await
        }
        KIND_BLOCK_MAP => {
            let pairs = state
                .db
                .model_durability_done_cids(job.release_id, KIND_BLOCK)
                .await?;
            let blocks: serde_json::Map<String, serde_json::Value> = pairs
                .into_iter()
                .map(|(sha, cid)| (sha, serde_json::Value::String(cid)))
                .collect();
            // Git-stored files live in the commit, not the block store, so
            // nothing else ever pins them. Pin each here and index it by
            // its manifest sha256, or a fetch without this node can rebuild
            // every chunked file and still miss config.json.
            let manifest_bytes = git_bytes(&state.git_bin, record, release, MANIFEST_PATH).await?;
            let manifest = twigpine_core::model::manifest::Manifest::parse(&manifest_bytes)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("manifest parse: {e}")))?;
            let mut files = serde_json::Map::new();
            for file in manifest
                .files
                .iter()
                .filter(|f| f.storage == twigpine_core::model::manifest::StorageKind::Git)
            {
                let data = git_bytes(&state.git_bin, record, release, &file.path).await?;
                match pin_bytes(state, &file.sha256, &data, fence).await? {
                    JobOutcome::Done(cid) => {
                        files.insert(file.sha256.clone(), serde_json::Value::String(cid));
                    }
                    JobOutcome::Deferred => return Ok(JobOutcome::Deferred),
                }
            }
            let payload = serde_json::json!({
                "schema": "gitlawb/model-block-map/v1",
                "release": release.commit_sha,
                "blocks": blocks,
                "files": files,
            });
            let bytes = serde_json::to_vec(&payload)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("block map serialize: {e}")))?;
            pin_bytes(state, &job.object_key, &bytes, fence).await
        }
        KIND_ANCHOR => post_anchor(state, release, job, fence, record).await,
        other => Err(AppError::Internal(anyhow::anyhow!(
            "unknown durability job kind {other}"
        ))),
    }
}

/// Read a path out of the release commit (manifest, signature). A missing
/// object is a job error like a missing store block: retry until the
/// attempt budget fails it.
async fn git_bytes(
    git_bin: &str,
    record: &RepoRecord,
    release: &crate::models::ReleaseRow,
    path: &str,
) -> Result<Vec<u8>, AppError> {
    git_show(
        git_bin,
        std::path::Path::new(&record.disk_path),
        &release.commit_sha,
        path,
    )
    .await?
    .ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "release {} has no {path} at its commit",
            release.id
        ))
    })
}

/// Pin `data` under `object_key` on every configured provider (Kubo, then
/// Pinata), fenced. The fence is checked immediately before the first
/// upload so a publicity change between the job-top check and here cannot
/// push one more object out.
async fn pin_bytes(
    state: &AppState,
    object_key: &str,
    data: &[u8],
    fence: Option<&PolicyFence>,
) -> Result<JobOutcome, AppError> {
    if !fence_current(fence).await {
        return Ok(JobOutcome::Deferred);
    }
    let kubo = crate::ipfs_pin::pin_git_object(
        &state.config.ipfs_api,
        object_key,
        data,
        Some(Duration::from_secs(120)),
    )
    .await
    .map_err(AppError::Internal)?;
    // Pinata is the off-node copy: check the epoch again between providers
    // so a publicity flip mid-job cannot push content outbound that a flip
    // one second earlier would have stopped entirely.
    if !fence_current(fence).await {
        return Ok(JobOutcome::Deferred);
    }
    let pinata = crate::pinata::pin_model_object(
        &state.http_client,
        &state.config.pinata_upload_url,
        &state.config.pinata_jwt,
        object_key,
        data,
    )
    .await
    .map_err(AppError::Internal)?;
    // The recorded CID is provider metadata. Prefer Kubo's confirmed
    // answer, then Pinata's; when neither provider is configured the
    // locally computed raw CID still gives the map a real address (the
    // local store remains the canonical resolution path anyway).
    let cid = if !kubo.is_empty() {
        kubo
    } else if !pinata.is_empty() {
        pinata
    } else {
        twigpine_core::cid::Cid::from_git_object_bytes(data).to_string()
    };
    Ok(JobOutcome::Done(cid))
}

/// Gather the release root and post the Irys anchor. Disabled Irys is a
/// completed job, not an error: the operator configured no anchor tier,
/// and leaving the job pending forever would pin the whole drain set.
async fn post_anchor(
    state: &AppState,
    release: &crate::models::ReleaseRow,
    job: &DurabilityJob,
    fence: Option<&PolicyFence>,
    record: &RepoRecord,
) -> Result<JobOutcome, AppError> {
    if state.config.irys_url.is_empty() {
        return Ok(JobOutcome::Done(String::new()));
    }
    let manifest_cid = state
        .db
        .model_durability_done_cid(job.release_id, KIND_MANIFEST)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("manifest pin has no provider CID")))?;
    let block_map_cid = state
        .db
        .model_durability_done_cid(job.release_id, KIND_BLOCK_MAP)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("block map pin has no provider CID")))?;
    let (rec_sha, rec_cid) = match state.db.model_reconstruction_sha(job.release_id).await? {
        Some(sha) => {
            let cid = state
                .db
                .model_durability_done_cid(job.release_id, KIND_RECONSTRUCTION)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(anyhow::anyhow!("reconstruction pin has no provider CID"))
                })?;
            (Some(sha), Some(cid))
        }
        None => (None, None),
    };
    let signature = String::from_utf8(git_bytes(&state.git_bin, record, release, SIG_PATH).await?)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("model-release.sig is not utf-8")))?;

    if !fence_current(fence).await {
        return Ok(JobOutcome::Deferred);
    }
    let anchor = crate::arweave::ReleaseAnchor {
        repo: format!("{}/{}", record.owner_did, record.name),
        owner_did: record.owner_did.clone(),
        release_commit: release.commit_sha.clone(),
        manifest_sha256: release.manifest_sha256.clone(),
        manifest_cid,
        reconstruction_sha256: rec_sha,
        reconstruction_cid: rec_cid,
        block_map_cid,
        claim_signature: signature.trim().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        node_did: state.node_did.as_str().to_string(),
    };
    let tx =
        crate::arweave::anchor_model_release(&state.http_client, &state.config.irys_url, &anchor)
            .await
            .map_err(AppError::Internal)?;
    Ok(JobOutcome::Done(tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::blockstore::{BlockId, BlockStore};
    use crate::test_support::test_state_with;
    use futures::StreamExt as _;
    use twigpine_core::cid::sha256_hex;

    async fn put_block(store: &Arc<dyn BlockStore>, bytes: &[u8]) -> String {
        let sha = sha256_hex(bytes);
        let id = BlockId::parse(&sha).expect("id");
        let body = futures::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from(
            bytes.to_vec(),
        ))])
        .boxed();
        store.put_verified(&id, body, u64::MAX).await.expect("put");
        sha
    }

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A release commit carrying the manifest and its detached signature.
    fn make_release_git(dir: &std::path::Path, manifest: &[u8], sig: &str) -> String {
        git(dir, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(dir.join(".twigpine")).unwrap();
        std::fs::write(dir.join(".twigpine/model-release.json"), manifest).unwrap();
        std::fs::write(dir.join(".twigpine/model-release.sig"), sig).unwrap();
        git(dir, &["add", "-A"]);
        git(
            dir,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "-m",
                "rel",
            ],
        );
        git(dir, &["rev-parse", "HEAD"])
    }

    async fn seed_repo(db: &crate::db::Db, id: &str, public: bool, disk: &std::path::Path) {
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, is_public, default_branch,
                                created_at, updated_at, disk_path)
             VALUES ($1,'m','did:owner',$2,'main','t','t',$3)",
        )
        .bind(id)
        .bind(public)
        .bind(disk.to_str().unwrap())
        .execute(db.pool())
        .await
        .expect("seed repo");
    }

    async fn seed_block_row(db: &crate::db::Db, sha: &str, size: u64) {
        sqlx::query(
            "INSERT INTO model_blocks (sha256, size, created_at)
             VALUES ($1,$2,'t') ON CONFLICT DO NOTHING",
        )
        .bind(sha)
        .bind(size as i64)
        .execute(db.pool())
        .await
        .expect("seed block row");
    }

    /// A published release row, then links for each block sha.
    async fn seed_release(
        db: &crate::db::Db,
        repo_id: &str,
        commit: &str,
        state: &str,
        manifest_sha: &str,
        rec_sha: Option<&str>,
        block_shas: &[String],
    ) -> i64 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  reconstruction_sha256, claim_signature, claim_signature_input,
                  claim_signing_string, claim_body, created_at, published_at)
             VALUES ($1,$2,'main','did:owner',$3,$4,$5,'sig','input','signing',\
                     decode('00','hex'),'t','t')
             RETURNING id",
        )
        .bind(repo_id)
        .bind(commit)
        .bind(state)
        .bind(manifest_sha)
        .bind(rec_sha)
        .fetch_one(db.pool())
        .await
        .expect("seed release");
        for sha in block_shas {
            sqlx::query(
                "INSERT INTO model_release_blocks (release_id, block_sha256)
                 VALUES ($1,$2)",
            )
            .bind(id)
            .bind(sha)
            .execute(db.pool())
            .await
            .expect("link block");
        }
        id
    }

    /// Every pending job's (kind, object_key), for assertions.
    async fn pending_kinds(db: &crate::db::Db, release_id: i64) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT kind, object_key FROM model_durability_jobs
             WHERE release_id = $1 AND state = 'pending' ORDER BY id",
        )
        .bind(release_id)
        .fetch_all(db.pool())
        .await
        .expect("pending kinds")
    }

    async fn job_states(db: &crate::db::Db, release_id: i64) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT kind, state FROM model_durability_jobs
             WHERE release_id = $1 ORDER BY id",
        )
        .bind(release_id)
        .fetch_all(db.pool())
        .await
        .expect("job states")
    }

    /// Enqueue builds the whole job set for a published release and a
    /// repeat call inserts nothing.
    #[sqlx::test]
    async fn enqueue_full_set_idempotent(pool: sqlx::PgPool) {
        let state = test_state_with(pool.clone(), |_| {}).await;
        let dir = tempfile::tempdir().unwrap();
        seed_repo(&state.db, "r1", true, dir.path()).await;
        let b1 = sha256_hex(b"one");
        let b2 = sha256_hex(b"two");
        let rec = sha256_hex(b"rec");
        for (sha, n) in [(&b1, 3u64), (&b2, 3), (&rec, 3)] {
            seed_block_row(&state.db, sha, n).await;
        }
        let id = seed_release(
            &state.db,
            "r1",
            &"a".repeat(40),
            "published",
            &"b".repeat(64),
            Some(&rec),
            &[b1.clone(), b2.clone()],
        )
        .await;

        enqueue_for_release(&state, id).await.unwrap();
        enqueue_for_release(&state, id).await.unwrap();
        let jobs = pending_kinds(&state.db, id).await;
        let kinds: Vec<&str> = jobs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            kinds.len(),
            6,
            "two blocks + manifest + rec + map + anchor: {kinds:?}"
        );
        assert_eq!(kinds.iter().filter(|k| **k == KIND_BLOCK).count(), 2);
        for want in [
            KIND_MANIFEST,
            KIND_RECONSTRUCTION,
            KIND_BLOCK_MAP,
            KIND_ANCHOR,
        ] {
            assert!(kinds.contains(&want), "missing {want}: {kinds:?}");
        }

        // A non-published release enqueues nothing.
        let id2 = seed_release(
            &state.db,
            "r1",
            &"c".repeat(40),
            "verifying",
            &"d".repeat(64),
            None,
            &[],
        )
        .await;
        enqueue_for_release(&state, id2).await.unwrap();
        assert!(pending_kinds(&state.db, id2).await.is_empty());
    }

    /// The backfill enqueues published releases with no job rows and skips
    /// a verifying row entirely.
    #[sqlx::test]
    async fn backfill_enqueues_published_missing_only(pool: sqlx::PgPool) {
        let state = test_state_with(pool.clone(), |_| {}).await;
        let dir = tempfile::tempdir().unwrap();
        seed_repo(&state.db, "r1", true, dir.path()).await;
        let published = seed_release(
            &state.db,
            "r1",
            &"a".repeat(40),
            "published",
            &"b".repeat(64),
            None,
            &[],
        )
        .await;
        let verifying = seed_release(
            &state.db,
            "r1",
            &"c".repeat(40),
            "verifying",
            &"d".repeat(64),
            None,
            &[],
        )
        .await;
        backfill_missing(&state).await.unwrap();
        assert_eq!(pending_kinds(&state.db, published).await.len(), 3);
        assert!(pending_kinds(&state.db, verifying).await.is_empty());
    }

    /// A full drain on a mockito Kubo + Irys pins the block, the manifest,
    /// the block map, and posts the anchor only once every pin is done.
    #[sqlx::test]
    async fn drain_pins_maps_and_anchors(pool: sqlx::PgPool) {
        let mut kubo = mockito::Server::new_async().await;
        let mut irys = mockito::Server::new_async().await;

        let dir = tempfile::tempdir().unwrap();
        let block_dir = tempfile::tempdir().unwrap();
        let manifest = br#"{"schema":"gitlawb/model-release/v1","repo":"did:owner/m","publisher_did":"did:owner","license":"MIT","files":[]}"#.to_vec();
        let commit = make_release_git(dir.path(), &manifest, "sig");
        let manifest_sha = sha256_hex(&manifest);
        let block_bytes = b"BLOCKBYTES-durability".to_vec();

        let mut state = test_state_with(pool.clone(), |cfg| {
            cfg.ipfs_api = kubo.url();
            cfg.irys_url = irys.url();
        })
        .await;
        let store: Arc<dyn BlockStore> = Arc::new(
            crate::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf()).unwrap(),
        );
        state.block_store = Some(store.clone());

        let block_sha = put_block(&store, &block_bytes).await;
        seed_block_row(&state.db, &block_sha, block_bytes.len() as u64).await;
        seed_repo(&state.db, "r1", true, dir.path()).await;
        let release_id = seed_release(
            &state.db,
            "r1",
            &commit,
            "published",
            &manifest_sha,
            None,
            std::slice::from_ref(&block_sha),
        )
        .await;

        // Kubo answers each add with the CID the pin code computes locally,
        // matched on a marker byte sequence inside the multipart body.
        for (marker, data) in [
            ("BLOCKBYTES", &block_bytes),
            ("model-release/v1", &manifest),
        ] {
            kubo.mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .match_body(mockito::Matcher::Regex(marker.to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(data)
                ))
                .create_async()
                .await;
        }
        // The map body is generated inside execute_job; its CID is
        // computed the same way, from the serialized payload.
        let map_cid_holder = kubo
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .match_body(mockito::Matcher::Regex("model-block-map".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(|req| {
                // Answer the CID of whatever bytes were posted: mirrors
                // Kubo exactly, so the recorded cid is the confirmed one.
                let body: &[u8] = req.body().map(|b| b.as_slice()).unwrap_or(&[]);
                // multipart: strip to the raw object bytes between the
                // boundary preamble and the trailing boundary.
                let start = body
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(0);
                let end = body
                    .windows(2)
                    .rposition(|w| w == b"\r\n")
                    .unwrap_or(body.len());
                let object = &body[start..end];
                format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(object)
                )
                .into_bytes()
            })
            .create_async()
            .await;
        let irys_mock = irys
            .mock("POST", "/upload")
            .match_header(
                "x-irys-tags",
                mockito::Matcher::AllOf(vec![
                    mockito::Matcher::Regex("Schema:gitlawb/model-release-anchor/v1".to_string()),
                    mockito::Matcher::Regex(format!("Release-Commit:{commit}")),
                ]),
            )
            .match_body(mockito::Matcher::PartialJsonString(format!(
                r#"{{"release_commit":"{commit}"}}"#
            )))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TXDUR1"}"#)
            .create_async()
            .await;

        enqueue_for_release(&state, release_id).await.unwrap();
        // Gated jobs may defer inside one pass; a few passes is the
        // steady-state the worker converges to.
        for _ in 0..4 {
            durability_pass(&state).await.unwrap();
        }

        let states = job_states(&state.db, release_id).await;
        assert_eq!(states.len(), 4, "{states:?}");
        for (kind, st) in &states {
            assert_eq!(st, "done", "{kind} not done: {states:?}");
        }
        let tx = state
            .db
            .model_durability_done_cid(release_id, KIND_ANCHOR)
            .await
            .unwrap();
        assert_eq!(tx.as_deref(), Some("TXDUR1"));
        // The block pin recorded the provider CID beside the sha256 key.
        let block_cid = state
            .db
            .model_durability_done_cid(release_id, KIND_BLOCK)
            .await
            .unwrap()
            .expect("block cid");
        assert_eq!(
            block_cid,
            twigpine_core::cid::Cid::from_git_object_bytes(&block_bytes).to_string()
        );
        irys_mock.assert_async().await;
        map_cid_holder.assert_async().await;
    }

    /// A git-stored file never touches the block store, so only the map
    /// job pins it. The map must index it under `files` keyed by the
    /// manifest sha256 or an off-node fetch cannot rebuild it.
    #[sqlx::test]
    async fn block_map_indexes_git_files(pool: sqlx::PgPool) {
        let mut kubo = mockito::Server::new_async().await;
        let mut irys = mockito::Server::new_async().await;

        let dir = tempfile::tempdir().unwrap();
        let block_dir = tempfile::tempdir().unwrap();
        let config_bytes = br#"{"arch":"test-GITFILE"}"#.to_vec();
        let config_sha = sha256_hex(&config_bytes);
        std::fs::write(dir.path().join("config.json"), &config_bytes).unwrap();
        let manifest = format!(
            r#"{{"schema":"gitlawb/model-release/v1","repo":"did:owner/m","publisher_did":"did:owner","license":"MIT","files":[{{"path":"config.json","size":{},"sha256":"{config_sha}","format":"text","storage":"git"}}]}}"#,
            config_bytes.len()
        )
        .into_bytes();
        let commit = make_release_git(dir.path(), &manifest, "sig");
        let block_bytes = b"BLOCKBYTES-gitfiles".to_vec();

        let mut state = test_state_with(pool.clone(), |cfg| {
            cfg.ipfs_api = kubo.url();
            cfg.irys_url = irys.url();
        })
        .await;
        let store: Arc<dyn BlockStore> = Arc::new(
            crate::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf()).unwrap(),
        );
        state.block_store = Some(store.clone());

        let block_sha = put_block(&store, &block_bytes).await;
        seed_block_row(&state.db, &block_sha, block_bytes.len() as u64).await;
        seed_repo(&state.db, "r1", true, dir.path()).await;
        let release_id = seed_release(
            &state.db,
            "r1",
            &commit,
            "published",
            &sha256_hex(&manifest),
            None,
            std::slice::from_ref(&block_sha),
        )
        .await;

        for (marker, data) in [
            ("BLOCKBYTES", &block_bytes),
            ("model-release/v1", &manifest),
            ("GITFILE", &config_bytes),
        ] {
            kubo.mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .match_body(mockito::Matcher::Regex(marker.to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(data)
                ))
                .create_async()
                .await;
        }
        // Capture the map object the job posts so the `files` index can be
        // asserted directly, not through a second read of Kubo.
        let captured: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_in = captured.clone();
        kubo.mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .match_body(mockito::Matcher::Regex("model-block-map".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |req| {
                let body: &[u8] = req.body().map(|b| b.as_slice()).unwrap_or(&[]);
                let start = body
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(0);
                let end = body
                    .windows(2)
                    .rposition(|w| w == b"\r\n")
                    .unwrap_or(body.len());
                let object = body[start..end].to_vec();
                *captured_in.lock().unwrap() = object.clone();
                format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(&object)
                )
                .into_bytes()
            })
            .create_async()
            .await;
        irys.mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TXGIT"}"#)
            .create_async()
            .await;

        enqueue_for_release(&state, release_id).await.unwrap();
        for _ in 0..4 {
            durability_pass(&state).await.unwrap();
        }

        // The captured slice can carry multipart framing after the object;
        // parse the first complete JSON value rather than exact bounds.
        let map: serde_json::Value =
            serde_json::Deserializer::from_slice(&captured.lock().unwrap())
                .into_iter::<serde_json::Value>()
                .next()
                .expect("map body holds a value")
                .expect("map body parses");
        let expected_cid =
            twigpine_core::cid::Cid::from_git_object_bytes(&config_bytes).to_string();
        assert_eq!(
            map["files"][&config_sha].as_str(),
            Some(expected_cid.as_str()),
            "git-stored file must index into the map: {map}"
        );
        assert!(map["blocks"][&block_sha].is_string(), "blocks kept: {map}");
    }

    /// While a pin job is still pending, the map and anchor defer rather
    /// than posting incomplete addresses; once the object appears the next
    /// pass completes the chain.
    #[sqlx::test]
    async fn anchor_defers_until_pins_complete(pool: sqlx::PgPool) {
        let mut kubo = mockito::Server::new_async().await;
        let mut irys = mockito::Server::new_async().await;

        let dir = tempfile::tempdir().unwrap();
        let block_dir = tempfile::tempdir().unwrap();
        let manifest = br#"{"schema":"gitlawb/model-release/v1","repo":"did:owner/m","publisher_did":"did:owner","license":"MIT","files":[]}"#.to_vec();
        let commit = make_release_git(dir.path(), &manifest, "sig");
        let block_bytes = b"BLOCKBYTES-later".to_vec();
        let block_sha = sha256_hex(&block_bytes);

        let mut state = test_state_with(pool.clone(), |cfg| {
            cfg.ipfs_api = kubo.url();
            cfg.irys_url = irys.url();
        })
        .await;
        let store: Arc<dyn BlockStore> = Arc::new(
            crate::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf()).unwrap(),
        );
        state.block_store = Some(store.clone());

        seed_block_row(&state.db, &block_sha, block_bytes.len() as u64).await;
        seed_repo(&state.db, "r1", true, dir.path()).await;
        let release_id = seed_release(
            &state.db,
            "r1",
            &commit,
            "published",
            &sha256_hex(&manifest),
            None,
            std::slice::from_ref(&block_sha),
        )
        .await;

        for (marker, data) in [
            ("BLOCKBYTES", &block_bytes),
            ("model-release/v1", &manifest),
        ] {
            kubo.mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .match_body(mockito::Matcher::Regex(marker.to_string()))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(data)
                ))
                .create_async()
                .await;
        }
        kubo.mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .match_body(mockito::Matcher::Regex("model-block-map".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(|req| {
                let body: &[u8] = req.body().map(|b| b.as_slice()).unwrap_or(&[]);
                let start = body
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(0);
                let end = body
                    .windows(2)
                    .rposition(|w| w == b"\r\n")
                    .unwrap_or(body.len());
                let object = &body[start..end];
                format!(
                    r#"{{"Hash":"{}"}}"#,
                    twigpine_core::cid::Cid::from_git_object_bytes(object)
                )
                .into_bytes()
            })
            .create_async()
            .await;
        let irys_mock = irys
            .mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TXLATE"}"#)
            .expect(0)
            .create_async()
            .await;

        enqueue_for_release(&state, release_id).await.unwrap();
        // The block is NOT in the store: its pin errors, and the gated
        // jobs must not run ahead of it.
        durability_pass(&state).await.unwrap();
        let states = job_states(&state.db, release_id).await;
        assert_eq!(
            states.iter().filter(|(_, s)| s == "pending").count(),
            3,
            "block pin retries while map and anchor wait: {states:?}"
        );

        irys_mock.assert_async().await;

        // Now the object exists; the chain completes end to end.
        put_block(&store, &block_bytes).await;
        let irys_done = irys
            .mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TXLATE"}"#)
            .create_async()
            .await;
        for _ in 0..4 {
            durability_pass(&state).await.unwrap();
        }
        let states = job_states(&state.db, release_id).await;
        for (kind, st) in &states {
            assert_eq!(st, "done", "{kind} not done: {states:?}");
        }
        irys_done.assert_async().await;
    }

    /// A repo that stops being fully public fails every pending job for
    /// the release in one pass, and nothing reaches Irys.
    #[sqlx::test]
    async fn private_transition_fails_all_pending(pool: sqlx::PgPool) {
        let mut irys = mockito::Server::new_async().await;
        let dir = tempfile::tempdir().unwrap();
        let commit = make_release_git(dir.path(), b"{}", "sig");

        let mut state = test_state_with(pool.clone(), |cfg| {
            cfg.irys_url = irys.url();
        })
        .await;
        let block_dir = tempfile::tempdir().unwrap();
        state.block_store = Some(Arc::new(
            crate::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf()).unwrap(),
        ));

        seed_repo(&state.db, "r1", true, dir.path()).await;
        let release_id = seed_release(
            &state.db,
            "r1",
            &commit,
            "published",
            &"b".repeat(64),
            None,
            &[],
        )
        .await;
        enqueue_for_release(&state, release_id).await.unwrap();
        assert_eq!(pending_kinds(&state.db, release_id).await.len(), 3);

        let irys_mock = irys
            .mock("POST", "/upload")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        sqlx::query("UPDATE repos SET is_public = false WHERE id = 'r1'")
            .execute(state.db.pool())
            .await
            .unwrap();
        durability_pass(&state).await.unwrap();
        let states = job_states(&state.db, release_id).await;
        for (kind, st) in &states {
            assert_eq!(st, "failed", "{kind} should be failed: {states:?}");
        }
        irys_mock.assert_async().await;
    }
}
