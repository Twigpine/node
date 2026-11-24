//! Model-hosting queries. Timestamps follow the repo convention: rfc3339
//! text in TEXT columns, written and compared through the helpers here.

use sqlx::{Postgres, Transaction};

use super::{Db, Result};

pub(crate) fn ts_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn ts_from_now(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

#[derive(Debug, Clone)]
pub struct ModelSession {
    pub id: String,
    pub owner_did: String,
    pub repo_id: String,
    pub expires_at: String,
    pub bytes_received: i64,
    pub state: String,
}

type SessionTuple = (String, String, String, String, i64, String);

/// Global advisory key serializing block-byte admission across sessions
/// (see `model_admit_bytes`). Distinct from `CLAIM_LOCK_KEY` in
/// `crate::models`, which serializes claim admission.
pub(crate) const MODEL_ADMIT_LOCK: i64 = 0x6D6F64656C61646D; // "modeladm"

const SESSION_COLS: &str = "id, owner_did, repo_id, expires_at, bytes_received, state";

impl From<SessionTuple> for ModelSession {
    fn from(t: SessionTuple) -> Self {
        ModelSession {
            id: t.0,
            owner_did: t.1,
            repo_id: t.2,
            expires_at: t.3,
            bytes_received: t.4,
            state: t.5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelRelease {
    pub id: i64,
    pub repo_id: String,
    pub commit_sha: String,
    pub branch: String,
    pub publisher_did: String,
    pub state: String,
    pub manifest_sha256: String,
    pub failure_reason: Option<String>,
    pub created_at: String,
    pub published_at: Option<String>,
    pub request_digest: Option<String>,
}

#[allow(clippy::type_complexity)]
pub type ReleaseTuple = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

impl From<ReleaseTuple> for ModelRelease {
    fn from(t: ReleaseTuple) -> Self {
        ModelRelease {
            id: t.0,
            repo_id: t.1,
            commit_sha: t.2,
            branch: t.3,
            publisher_did: t.4,
            state: t.5,
            manifest_sha256: t.6,
            failure_reason: t.7,
            created_at: t.8,
            published_at: t.9,
            request_digest: t.10,
        }
    }
}

/// Result of [`Db::model_publish_if_public`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The release flipped to `published` inside the locked check.
    Published,
    /// The repo is gone, private, mirror-form, or now has visibility rules.
    NoLongerPublic,
    /// The release left `verifying` already (a concurrent verifier
    /// published it, or it was rejected); the caller must re-read the row
    /// before deciding what to unwind.
    NotVerifying,
}

pub const RELEASE_COLS: &str = "id, repo_id, commit_sha, branch, publisher_did, \
     state, manifest_sha256, failure_reason, created_at, published_at, \
     claim_request_digest";

/// Fields of the signed claim persisted on the release row (the status-claim
/// pattern: the row is the replay ledger).
pub struct ClaimPersist {
    pub signature: String,
    pub signature_input: String,
    pub signing_string: String,
    pub body: Vec<u8>,
    pub request_digest: String,
}

impl Db {
    pub async fn model_open_session(
        &self,
        owner_did: &str,
        repo_id: &str,
        ttl_secs: u64,
    ) -> Result<ModelSession> {
        let id = hex::encode(rand::random::<[u8; 32]>());
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "INSERT INTO model_upload_sessions
                 (id, owner_did, repo_id, created_at, expires_at, bytes_received, state)
             VALUES ($1, $2, $3, $4, $5, 0, 'open')
             RETURNING {SESSION_COLS}"
        ))
        .bind(&id)
        .bind(owner_did)
        .bind(repo_id)
        .bind(ts_now())
        .bind(ts_from_now(ttl_secs as i64))
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn model_load_session(&self, id: &str) -> Result<Option<ModelSession>> {
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "SELECT {SESSION_COLS} FROM model_upload_sessions WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Atomically admit `claimed` bytes against the caller's per-identity
    /// open-session cap and the node-wide quota, sliding expiry forward in
    /// the same update. `None` when the session is closed, expired, or a cap
    /// would be exceeded; the caller re-reads the session to pick the honest
    /// denial.
    pub async fn model_admit_bytes(
        &self,
        session_id: &str,
        claimed: i64,
        ttl_secs: u64,
        session_cap: i64,
        node_cap: i64,
    ) -> Result<Option<ModelSession>> {
        // Serialize admissions process-wide: the per-owner and node-wide cap
        // terms read other sessions' bytes_received, and two concurrent PUTs
        // on different sessions would otherwise admit against the same stale
        // sums. The critical section is one UPDATE, so the global key costs
        // nothing next to the upload itself.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MODEL_ADMIT_LOCK)
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "UPDATE model_upload_sessions s
             SET bytes_received = s.bytes_received + $1,
                 expires_at = $2
             WHERE s.id = $3
               AND s.state = 'open'
               AND s.expires_at > $4
               AND s.bytes_received + $1 + COALESCE((
                     SELECT SUM(o.bytes_received) FROM model_upload_sessions o
                     WHERE o.owner_did = s.owner_did AND o.state = 'open' AND o.id <> s.id
                       AND o.expires_at > $4
                   ), 0) <= $5
               AND COALESCE((SELECT SUM(q.bytes_used) FROM model_quota_usage q), 0)
                   + COALESCE((
                       SELECT SUM(o2.bytes_received) FROM model_upload_sessions o2
                       WHERE o2.state = 'open' AND o2.expires_at > $4
                     ), 0)
                   + $1 <= $6
             RETURNING {SESSION_COLS}"
        ))
        .bind(claimed)
        .bind(ts_from_now(ttl_secs as i64))
        .bind(session_id)
        .bind(ts_now())
        .bind(session_cap)
        .bind(node_cap)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(Into::into))
    }

    /// Refund an admitted charge when the store or the bookkeeping fails.
    /// Best-effort under races; an expired session frees the bytes anyway.
    pub async fn model_refund_bytes(&self, session_id: &str, bytes: i64) -> Result<()> {
        sqlx::query(
            "UPDATE model_upload_sessions
             SET bytes_received = GREATEST(bytes_received - $1, 0)
             WHERE id = $2",
        )
        .bind(bytes)
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Book the stored block against the session in one transaction. `true`
    /// when the admission credit was refunded: a duplicate within the
    /// session, or a block a verifying or published release of the session's
    /// own owner already carries. Claim authorizes that release's blocks
    /// without a session link and billed them at claim, so the block is
    /// neither charged nor linked here; a link would outlive the release and
    /// hold the block unbilled once it is rejected. Blocks carried by another
    /// publisher's release, or held only by other open sessions, are still
    /// charged and linked.
    pub async fn model_record_block(
        &self,
        session_id: &str,
        block_sha: &str,
        size: u64,
        admitted: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        // The own_release_carries read and the link insert must serialize
        // with claim's release-link insert: a repeat PUT that reads false
        // just before a claim moves the block would keep its charge and
        // double-count it. Same order as claim_release (advisory first,
        // then rows), so no deadlock is introduced.
        self.model_tx_advisory_lock(&mut tx, crate::models::CLAIM_LOCK_KEY)
            .await?;
        sqlx::query(
            "INSERT INTO model_blocks (sha256, size, created_at, unreferenced_since)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT (sha256) DO NOTHING",
        )
        .bind(block_sha)
        .bind(size as i64)
        .bind(ts_now())
        .execute(&mut *tx)
        .await?;
        let own_release_carries = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM model_release_blocks rb
                 JOIN model_releases r ON r.id = rb.release_id
                 JOIN model_upload_sessions s ON s.owner_did = r.publisher_did
                 WHERE rb.block_sha256 = $1 AND s.id = $2
                   AND r.state IN ('verifying', 'published'))",
        )
        .bind(block_sha)
        .bind(session_id)
        .fetch_one(&mut *tx)
        .await?;
        let linked = if own_release_carries {
            0
        } else {
            let rows = sqlx::query(
                "INSERT INTO model_session_blocks (session_id, block_sha256)
                 VALUES ($1, $2)
                 ON CONFLICT (session_id, block_sha256) DO NOTHING",
            )
            .bind(session_id)
            .bind(block_sha)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if rows > 0 {
                // A live link restarts the grace clock: keeping a stale
                // unreferenced_since would let the next sweep delete the
                // block on the old stamp the moment the link drops again.
                sqlx::query("UPDATE model_blocks SET unreferenced_since = NULL WHERE sha256 = $1")
                    .bind(block_sha)
                    .execute(&mut *tx)
                    .await?;
            }
            rows
        };
        let refund = linked == 0;
        if refund {
            sqlx::query(
                "UPDATE model_upload_sessions
                 SET bytes_received = GREATEST(bytes_received - $1, 0)
                 WHERE id = $2",
            )
            .bind(admitted)
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(refund)
    }

    /// Register a block row with no session link and no refund, so the sweep
    /// can reclaim an object whose write outcome is unknown once the grace
    /// period passes. Same insert as `model_record_block`.
    pub async fn model_register_unlinked_block(&self, sha: &str, size: u64) -> Result<()> {
        sqlx::query(
            "INSERT INTO model_blocks (sha256, size, created_at, unreferenced_since)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT (sha256) DO NOTHING",
        )
        .bind(sha)
        .bind(size as i64)
        .bind(ts_now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove one session link; `true` when a link row was deleted. The
    /// model_blocks row stays: the sweep tolerates a missing object.
    pub async fn model_unlink_session_block(&self, session_id: &str, sha: &str) -> Result<bool> {
        Ok(sqlx::query(
            "DELETE FROM model_session_blocks WHERE session_id = $1 AND block_sha256 = $2",
        )
        .bind(session_id)
        .bind(sha)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0)
    }

    /// Whether a `model_blocks` row exists for `sha`. A failed bookkeeping
    /// cleanup deletes a stored object only when no row references it, so a
    /// block a release or another session already carries is never removed
    /// from under it.
    pub async fn model_block_exists(&self, sha: &str) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM model_blocks WHERE sha256 = $1)",
        )
        .bind(sha)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn model_release_by_digest(&self, digest: &str) -> Result<Option<ModelRelease>> {
        let row = sqlx::query_as::<_, ReleaseTuple>(&format!(
            "SELECT {RELEASE_COLS} FROM model_releases WHERE claim_request_digest = $1"
        ))
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn model_release_by_commit(
        &self,
        repo_id: &str,
        commit: &str,
    ) -> Result<Option<ModelRelease>> {
        let row = sqlx::query_as::<_, ReleaseTuple>(&format!(
            "SELECT {RELEASE_COLS} FROM model_releases
             WHERE repo_id = $1 AND commit_sha = $2"
        ))
        .bind(repo_id)
        .bind(commit)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Ids of `verifying` releases stuck past `stale_secs`: the worker
    /// retries them forever today, so the sweep rejects them to un-wedge
    /// the publisher's one-verifying slot.
    pub async fn model_stale_verifying(&self, stale_secs: i64) -> Result<Vec<i64>> {
        Ok(sqlx::query_scalar(
            "SELECT id FROM model_releases
             WHERE state = 'verifying' AND created_at < $1",
        )
        .bind(ts_from_now(-stale_secs))
        .fetch_all(&self.pool)
        .await?)
    }

    /// The reconstruction object sha a release was claimed with, if any.
    /// The reconstruction GET serves by this stored ref: the manifest it
    /// names is immutable under the pinned commit and was verified at claim.
    pub async fn model_reconstruction_sha(&self, id: i64) -> Result<Option<String>> {
        Ok(sqlx::query_scalar::<_, Option<String>>(
            "SELECT reconstruction_sha256 FROM model_releases WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .flatten())
    }

    pub async fn model_release_by_id(&self, id: i64) -> Result<Option<ModelRelease>> {
        let row = sqlx::query_as::<_, ReleaseTuple>(&format!(
            "SELECT {RELEASE_COLS} FROM model_releases WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn model_begin(&self) -> Result<Transaction<'_, Postgres>> {
        Ok(self.pool.begin().await?)
    }

    // ── claim transaction steps ───────────────────────────────────────────

    pub async fn model_tx_advisory_lock(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        key: i64,
    ) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn model_tx_release_by_digest(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        digest: &str,
    ) -> Result<Option<ModelRelease>> {
        Ok(sqlx::query_as::<_, ReleaseTuple>(&format!(
            "SELECT {RELEASE_COLS} FROM model_releases WHERE claim_request_digest = $1"
        ))
        .bind(digest)
        .fetch_optional(&mut **tx)
        .await?
        .map(Into::into))
    }

    pub async fn model_tx_release_by_commit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        repo_id: &str,
        commit: &str,
    ) -> Result<Option<ModelRelease>> {
        Ok(sqlx::query_as::<_, ReleaseTuple>(&format!(
            "SELECT {RELEASE_COLS} FROM model_releases
             WHERE repo_id = $1 AND commit_sha = $2"
        ))
        .bind(repo_id)
        .bind(commit)
        .fetch_optional(&mut **tx)
        .await?
        .map(Into::into))
    }

    /// Lock and return the present subset of `shas` (`FOR UPDATE` so a
    /// racing sweep cannot delete a block mid-claim).
    pub async fn model_tx_lock_present_blocks(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        shas: &[String],
    ) -> Result<Vec<String>> {
        if shas.is_empty() {
            return Ok(Vec::new());
        }
        Ok(
            sqlx::query_scalar("SELECT sha256 FROM model_blocks WHERE sha256 = ANY($1) FOR UPDATE")
                .bind(shas)
                .fetch_all(&mut **tx)
                .await?,
        )
    }

    pub async fn model_tx_session_blocks(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner_did: &str,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT sb.block_sha256 FROM model_session_blocks sb
             JOIN model_upload_sessions s ON s.id = sb.session_id
             WHERE s.owner_did = $1 AND s.state = 'open' AND s.expires_at > $2",
        )
        .bind(owner_did)
        .bind(ts_now())
        .fetch_all(&mut **tx)
        .await?)
    }

    pub async fn model_tx_publisher_release_blocks(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        publisher_did: &str,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT rb.block_sha256 FROM model_release_blocks rb
             JOIN model_releases r ON r.id = rb.release_id
             WHERE r.publisher_did = $1 AND r.state IN ('verifying', 'published')",
        )
        .bind(publisher_did)
        .fetch_all(&mut **tx)
        .await?)
    }

    pub async fn model_tx_release_blocks_at_commit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        repo_id: &str,
        commit: &str,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT rb.block_sha256 FROM model_release_blocks rb
             JOIN model_releases r ON r.id = rb.release_id
             WHERE r.repo_id = $1 AND r.commit_sha = $2 AND r.state = 'published'",
        )
        .bind(repo_id)
        .bind(commit)
        .fetch_all(&mut **tx)
        .await?)
    }

    pub async fn model_tx_has_verifying(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        publisher_did: &str,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, Option<i64>>(
            "SELECT id FROM model_releases
             WHERE publisher_did = $1 AND state = 'verifying' LIMIT 1",
        )
        .bind(publisher_did)
        .fetch_optional(&mut **tx)
        .await?
        .is_some())
    }

    /// Bytes of `shas` not already referenced by any live release: the
    /// first-claimer-pays charge.
    pub async fn model_tx_unclaimed_bytes(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        shas: &[String],
    ) -> Result<i64> {
        if shas.is_empty() {
            return Ok(0);
        }
        // SUM over bigint returns numeric; cast back so the i64 decode holds.
        Ok(sqlx::query_scalar::<_, Option<i64>>(
            "SELECT SUM(b.size)::bigint FROM model_blocks b
             WHERE b.sha256 = ANY($1)
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks rb
                     JOIN model_releases r ON r.id = rb.release_id
                     WHERE rb.block_sha256 = b.sha256
                       AND r.state IN ('verifying', 'published'))",
        )
        .bind(shas)
        .fetch_one(&mut **tx)
        .await?
        .unwrap_or(0))
    }

    /// Atomic per-identity reservation; `None` when the cap would be
    /// exceeded. The cap applies on BOTH branches: a `WHERE` inside `DO
    /// UPDATE` alone would let a first-time DID insert any `delta`, since
    /// that clause never guards the insert attempt.
    pub async fn model_tx_reserve_quota(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        did: &str,
        delta: i64,
        cap: i64,
    ) -> Result<Option<i64>> {
        Ok(sqlx::query_scalar::<_, i64>(
            "INSERT INTO model_quota_usage (did, bytes_used)
             SELECT $1, $2 WHERE $2 <= $3
             ON CONFLICT (did) DO UPDATE
               SET bytes_used = model_quota_usage.bytes_used + $2
               WHERE model_quota_usage.bytes_used + $2 <= $3
             RETURNING bytes_used",
        )
        .bind(did)
        .bind(delta)
        .bind(cap)
        .fetch_optional(&mut **tx)
        .await?)
    }

    /// Node-wide used bytes: claimed quota plus every open session's bytes.
    pub async fn model_tx_node_used(&self, tx: &mut Transaction<'_, Postgres>) -> Result<i64> {
        // SUM over bigint returns numeric; cast back so the i64 decode holds.
        // A session past its wall-clock expiry is dead before the sweep
        // flips its state, so it does not count against the cap.
        Ok(sqlx::query_scalar::<_, Option<i64>>(
            "SELECT (COALESCE((SELECT SUM(bytes_used) FROM model_quota_usage), 0)
                  + COALESCE((SELECT SUM(bytes_received) FROM model_upload_sessions
                              WHERE state = 'open' AND expires_at > $1), 0))::bigint",
        )
        .bind(ts_now())
        .fetch_one(&mut **tx)
        .await?
        .unwrap_or(0))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn model_tx_insert_release(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        repo_id: &str,
        commit: &str,
        branch: &str,
        publisher_did: &str,
        manifest_sha256: &str,
        reconstruction_sha256: Option<&str>,
        claim: &ClaimPersist,
    ) -> Result<ModelRelease> {
        let row = sqlx::query_as::<_, ReleaseTuple>(&format!(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  reconstruction_sha256, claim_signature, claim_signature_input,
                  claim_signing_string, claim_body, claim_request_digest, created_at)
             VALUES ($1,$2,$3,$4,'verifying',$5,$6,$7,$8,$9,$10,$11,$12)
             RETURNING {RELEASE_COLS}"
        ))
        .bind(repo_id)
        .bind(commit)
        .bind(branch)
        .bind(publisher_did)
        .bind(manifest_sha256)
        .bind(reconstruction_sha256)
        .bind(&claim.signature)
        .bind(&claim.signature_input)
        .bind(&claim.signing_string)
        .bind(&claim.body)
        .bind(&claim.request_digest)
        .bind(ts_now())
        .fetch_one(&mut **tx)
        .await?;
        Ok(row.into())
    }

    /// Link `shas` to the release and drop them from the publisher's open
    /// sessions, so the same bytes stop counting twice node-wide. Batched:
    /// this runs inside the claim's advisory lock, so a manifest naming
    /// thousands of blocks must not pay two round trips per block.
    pub async fn model_tx_link_release_blocks(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        release_id: i64,
        publisher_did: &str,
        shas: &[String],
    ) -> Result<()> {
        if shas.is_empty() {
            return Ok(());
        }
        // The claimer pays for exactly the blocks model_tx_unclaimed_bytes
        // counted as new (no live release references them); blocks a live
        // release already carries keep their first payer. Runs before the
        // link insert below so this release's own rows do not mask the set.
        sqlx::query(
            "UPDATE model_blocks b SET payer_did = $2
             WHERE b.sha256 = ANY($1)
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks rb
                     JOIN model_releases r ON r.id = rb.release_id
                     WHERE rb.block_sha256 = b.sha256
                       AND r.state IN ('verifying', 'published'))",
        )
        .bind(shas)
        .bind(publisher_did)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO model_release_blocks (release_id, block_sha256)
             SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
        )
        .bind(release_id)
        .bind(shas)
        .execute(&mut **tx)
        .await?;
        // Same rule as the session-link insert: a live reference clears the
        // stale stamp so a later drop earns a fresh grace period.
        sqlx::query("UPDATE model_blocks SET unreferenced_since = NULL WHERE sha256 = ANY($1)")
            .bind(shas)
            .execute(&mut **tx)
            .await?;
        // The release now carries these blocks, so the sessions stop being
        // charged for exactly the bytes that moved. Subtracting the moved
        // set (rather than recounting links) preserves bytes admitted but
        // not yet recorded by a PUT still in flight.
        sqlx::query(
            "WITH moved AS (
                   DELETE FROM model_session_blocks sb
                   USING model_upload_sessions s
                   WHERE s.id = sb.session_id AND s.owner_did = $1
                     AND s.state = 'open' AND sb.block_sha256 = ANY($2)
                   RETURNING sb.session_id, sb.block_sha256
                 ), per_session AS (
                   SELECT m.session_id, COALESCE(SUM(b.size), 0)::bigint AS bytes
                   FROM moved m
                   JOIN model_blocks b ON b.sha256 = m.block_sha256
                   GROUP BY m.session_id
                 )
                 UPDATE model_upload_sessions s
                 SET bytes_received = GREATEST(s.bytes_received - ps.bytes, 0)
                 FROM per_session ps
                 WHERE ps.session_id = s.id",
        )
        .bind(publisher_did)
        .bind(shas)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    // ── verification ───────────────────────────────────────────────────────

    /// `false` when the release left `verifying` first (the stale-verify
    /// sweep rejected it mid-run); the caller then unwinds what it wrote.
    pub async fn model_mark_published(&self, release_id: i64) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE model_releases
             SET state = 'published', published_at = $2
             WHERE id = $1 AND state = 'verifying'",
        )
        .bind(release_id)
        .bind(ts_now())
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(done > 0)
    }

    /// Inside a claim transaction: the declared parent's repo is still fully
    /// public, taken FOR UPDATE so a visibility rule cannot commit between
    /// this check and the claim's commit.
    pub async fn model_tx_parent_still_public(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        repo_id: &str,
    ) -> Result<bool> {
        if repo_id.contains('/') {
            return Ok(false);
        }
        let is_public: Option<bool> =
            sqlx::query_scalar("SELECT is_public FROM repos WHERE id = $1 FOR UPDATE")
                .bind(repo_id)
                .fetch_optional(&mut **tx)
                .await?;
        if is_public != Some(true) {
            return Ok(false);
        }
        let has_rules: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM visibility_rules WHERE repo_id = $1)")
                .bind(repo_id)
                .fetch_one(&mut **tx)
                .await?;
        Ok(!has_rules)
    }

    /// Publish a verifying release only while its repo is still fully
    /// public. The repo row is taken FOR UPDATE, the same lock
    /// `set_visibility_rule` and `remove_visibility_rule` hold while they
    /// write a rule and bump the epoch, so a rule added mid-verify (after
    /// the handler-time publicity check) serializes: either it commits
    /// first and this returns `NoLongerPublic`, or it waits and sees the
    /// release already published.
    pub async fn model_publish_if_public(
        &self,
        release_id: i64,
        repo_id: &str,
    ) -> Result<PublishOutcome> {
        if repo_id.contains('/') {
            return Ok(PublishOutcome::NoLongerPublic);
        }
        let mut tx = self.pool.begin().await?;
        let is_public: Option<bool> =
            sqlx::query_scalar("SELECT is_public FROM repos WHERE id = $1 FOR UPDATE")
                .bind(repo_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(true) = is_public else {
            return Ok(PublishOutcome::NoLongerPublic);
        };
        let has_rules: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM visibility_rules WHERE repo_id = $1)")
                .bind(repo_id)
                .fetch_one(&mut *tx)
                .await?;
        if has_rules {
            return Ok(PublishOutcome::NoLongerPublic);
        }
        let done = sqlx::query(
            "UPDATE model_releases
             SET state = 'published', published_at = $2
             WHERE id = $1 AND state = 'verifying'",
        )
        .bind(release_id)
        .bind(ts_now())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(if done > 0 {
            PublishOutcome::Published
        } else {
            PublishOutcome::NotVerifying
        })
    }

    /// Reject: mark the release, drop its refs, and refund the publisher the
    /// bytes no other live release still references.
    pub async fn model_reject_release(&self, release_id: i64, reason: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // The refund's "no other live release references this block" test
        // and a concurrent claim's "not already claimed" test must agree;
        // the claim lock makes them serialize. Same order as claim_release
        // (advisory first, then rows), so no deadlock is introduced.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(crate::models::CLAIM_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let released: Option<(String,)> = sqlx::query_as(
            "UPDATE model_releases
             SET state = 'rejected', failure_reason = $2
             WHERE id = $1 AND state = 'verifying'
             RETURNING publisher_did",
        )
        .bind(release_id)
        .bind(reason)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((_publisher,)) = released else {
            tx.commit().await?;
            return Ok(());
        };
        self.model_release_refund_tx(&mut tx, release_id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Free the quota a release's blocks were charged under. Blocks no other
    /// live release references are released; each refunds to the DID that
    /// paid for it at claim (`model_blocks.payer_did`), falling back to this
    /// release's publisher for rows claimed before the column existed. The
    /// release's block links are dropped and the freed blocks' payer is
    /// cleared so nothing refunds them twice. Callers must hold
    /// `CLAIM_LOCK_KEY` inside the tx so the "no other live release" test
    /// serializes with claim's "not already claimed" test.
    pub async fn model_release_refund_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        release_id: i64,
    ) -> Result<()> {
        // SUM over bigint returns numeric; cast back so the i64 decode holds.
        let per_payer: Vec<(String, i64)> = sqlx::query_as(
            "SELECT COALESCE(b.payer_did, r.publisher_did) AS payer,
                    COALESCE(SUM(b.size), 0)::bigint AS bytes
             FROM model_blocks b
             JOIN model_release_blocks rb ON rb.block_sha256 = b.sha256
             JOIN model_releases r ON r.id = rb.release_id
             WHERE rb.release_id = $1
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks r2
                     JOIN model_releases r2r ON r2r.id = r2.release_id
                     WHERE r2.block_sha256 = b.sha256 AND r2.release_id <> $1
                       AND r2r.state IN ('verifying', 'published'))
             GROUP BY COALESCE(b.payer_did, r.publisher_did)",
        )
        .bind(release_id)
        .fetch_all(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE model_blocks b SET payer_did = NULL
             WHERE b.payer_did IS NOT NULL
               AND b.sha256 IN (
                     SELECT rb.block_sha256 FROM model_release_blocks rb
                     WHERE rb.release_id = $1)
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks r2
                     JOIN model_releases r2r ON r2r.id = r2.release_id
                     WHERE r2.block_sha256 = b.sha256 AND r2.release_id <> $1
                       AND r2r.state IN ('verifying', 'published'))",
        )
        .bind(release_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query("DELETE FROM model_release_blocks WHERE release_id = $1")
            .bind(release_id)
            .execute(&mut **tx)
            .await?;
        for (payer, bytes) in per_payer {
            sqlx::query(
                "UPDATE model_quota_usage SET bytes_used = GREATEST(bytes_used - $2, 0)
                 WHERE did = $1",
            )
            .bind(&payer)
            .bind(bytes)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    pub async fn model_verifying_ids(&self, limit: i64) -> Result<Vec<i64>> {
        Ok(sqlx::query_scalar(
            "SELECT id FROM model_releases WHERE state = 'verifying'
             ORDER BY created_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    // ── sweep ──────────────────────────────────────────────────────────────

    pub async fn model_expire_sessions(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "UPDATE model_upload_sessions SET state = 'expired'
             WHERE state = 'open' AND expires_at <= $1
             RETURNING id",
        )
        .bind(ts_now())
        .fetch_all(&self.pool)
        .await?)
    }

    /// Drop links under every expired session, not only the ids this pass
    /// expired: a failed DELETE must not strand links under sessions that
    /// are never re-selected.
    pub async fn model_drop_sessions_blocks(&self) -> Result<()> {
        sqlx::query(
            "DELETE FROM model_session_blocks sb
             USING model_upload_sessions s
             WHERE sb.session_id = s.id AND s.state = 'expired'",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Stamp `unreferenced_since` on blocks that lost every live reference,
    /// and clear it on blocks that regained one. Returns rows marked.
    pub async fn model_remark_liveness(&self) -> Result<u64> {
        let marked = sqlx::query(
            "UPDATE model_blocks b SET unreferenced_since = $1
             WHERE b.unreferenced_since IS NULL
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks rb
                     JOIN model_releases r ON r.id = rb.release_id
                     WHERE rb.block_sha256 = b.sha256
                       AND r.state IN ('verifying', 'published'))
               AND NOT EXISTS (
                     SELECT 1 FROM model_session_blocks sb
                     JOIN model_upload_sessions s ON s.id = sb.session_id
                     WHERE sb.block_sha256 = b.sha256 AND s.state = 'open')",
        )
        .bind(ts_now())
        .execute(&self.pool)
        .await?
        .rows_affected();
        sqlx::query(
            "UPDATE model_blocks b SET unreferenced_since = NULL
             WHERE b.unreferenced_since IS NOT NULL
               AND (EXISTS (
                     SELECT 1 FROM model_release_blocks rb
                     JOIN model_releases r ON r.id = rb.release_id
                     WHERE rb.block_sha256 = b.sha256
                       AND r.state IN ('verifying', 'published'))
                  OR EXISTS (
                     SELECT 1 FROM model_session_blocks sb
                     JOIN model_upload_sessions s ON s.id = sb.session_id
                     WHERE sb.block_sha256 = b.sha256 AND s.state = 'open'))",
        )
        .execute(&self.pool)
        .await?;
        Ok(marked)
    }

    pub async fn model_stale_blocks(&self, grace_secs: i64, limit: i64) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT sha256 FROM model_blocks
             WHERE unreferenced_since < $1
             LIMIT $2",
        )
        .bind(ts_from_now(-grace_secs))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Under the same row lock the claim path takes, confirm the block is
    /// still unreferenced. The caller keeps the transaction open across the
    /// store delete, then calls `model_tx_delete_block_row`.
    pub async fn model_tx_block_still_dead(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        sha: &str,
        grace_secs: i64,
    ) -> Result<bool> {
        // Lock the block row first. READ COMMITTED snapshots are taken per
        // statement, so folding the liveness subqueries into the locking
        // SELECT would evaluate them against the pre-lock snapshot and miss
        // a link committed while this statement waited.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM model_blocks WHERE sha256 = $1 FOR UPDATE)",
        )
        .bind(sha)
        .fetch_one(&mut **tx)
        .await?;
        if !exists {
            return Ok(true);
        }
        // The grace clock is re-checked too: a block re-marked after the
        // stale selection ran must earn its new grace period, not die on
        // the old one.
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT b.unreferenced_since IS NOT NULL
               AND b.unreferenced_since < $2
               AND NOT EXISTS (
                   SELECT 1 FROM model_release_blocks rb
                   JOIN model_releases r ON r.id = rb.release_id
                   WHERE rb.block_sha256 = $1
                     AND r.state IN ('verifying', 'published'))
             AND NOT EXISTS (
                   SELECT 1 FROM model_session_blocks sb
                   JOIN model_upload_sessions s ON s.id = sb.session_id
                   WHERE sb.block_sha256 = $1 AND s.state = 'open')
             FROM model_blocks b WHERE b.sha256 = $1",
        )
        .bind(sha)
        .bind(ts_from_now(-grace_secs))
        .fetch_one(&mut **tx)
        .await?)
    }

    pub async fn model_tx_delete_block_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        sha: &str,
    ) -> Result<()> {
        sqlx::query("DELETE FROM model_blocks WHERE sha256 = $1")
            .bind(sha)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn migrated(pool: sqlx::PgPool) -> Db {
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, is_public, default_branch,
                                created_at, updated_at, disk_path)
             VALUES ('r1', 'repo', 'did:owner', TRUE, 'main', 't', 't', '/r1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        db
    }

    #[sqlx::test]
    async fn admit_bytes_enforces_session_cap_and_slides_expiry(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db.model_open_session("did:owner", "r1", 60).await.unwrap();
        let first = db
            .model_admit_bytes(&s.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .expect("first admission");
        assert_eq!(first.bytes_received, 100);
        assert!(first.expires_at > s.expires_at);
        // Over the per-identity session cap: refused.
        assert!(db
            .model_admit_bytes(&s.id, 950, 3600, 1000, 10_000)
            .await
            .unwrap()
            .is_none());
        // Within the cap still admits.
        assert!(db
            .model_admit_bytes(&s.id, 900, 3600, 1000, 10_000)
            .await
            .unwrap()
            .is_some());
    }

    #[sqlx::test]
    async fn record_block_refunds_duplicate_within_session(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        let sha = "a".repeat(64);
        // First PUT: admit the block's bytes, then record the link.
        db.model_admit_bytes(&s.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .expect("first admission");
        assert!(!db.model_record_block(&s.id, &sha, 100, 100).await.unwrap());
        // Same block again: the second admission is charged then refunded
        // when the record sees the existing link.
        db.model_admit_bytes(&s.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .expect("second admission");
        assert!(db.model_record_block(&s.id, &sha, 100, 100).await.unwrap());
        let s2 = db.model_load_session(&s.id).await.unwrap().unwrap();
        assert_eq!(s2.bytes_received, 100);
    }

    #[sqlx::test]
    async fn a_relinked_block_loses_its_stale_stamp(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        let sha = "e".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at, unreferenced_since) VALUES ($1, 1, $2, $2)")
            .bind(&sha)
            .bind(ts_from_now(-7200))
            .execute(&pool)
            .await
            .unwrap();
        db.model_record_block(&s.id, &sha, 1, 1).await.unwrap();
        db.model_unlink_session_block(&s.id, &sha).await.unwrap();
        // Linked and dropped between sweeps: the old stamp is gone, so the
        // block is not immediately stale.
        assert!(!db
            .model_stale_blocks(3600, 10)
            .await
            .unwrap()
            .contains(&sha));
    }

    #[sqlx::test]
    async fn record_block_serializes_with_the_claim_lock(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        // A second Db over the same pool gets its own connection for the
        // blocked call.
        let db2 = Db::for_testing(pool.clone());
        let sid = s.id.clone();
        let mut tx = db.model_begin().await.unwrap();
        db.model_tx_advisory_lock(&mut tx, crate::models::CLAIM_LOCK_KEY)
            .await
            .unwrap();
        let mut handle = tokio::spawn(async move {
            db2.model_record_block(&sid, &"c".repeat(64), 100, 100)
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut handle)
                .await
                .is_err(),
            "model_record_block must wait for the claim lock"
        );
        tx.commit().await.unwrap();
        handle
            .await
            .expect("task joins")
            .expect("record_block completes");
    }

    #[sqlx::test]
    async fn expire_then_sweep_marks_and_deletes_dead_blocks(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        let sha = "b".repeat(64);
        db.model_record_block(&s.id, &sha, 100, 100).await.unwrap();

        // Blocks are born stamped; while the session is open, remarking
        // clears the stamp.
        db.model_remark_liveness().await.unwrap();
        let stamp: Option<String> =
            sqlx::query_scalar("SELECT unreferenced_since FROM model_blocks WHERE sha256 = $1")
                .bind(&sha)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(stamp.is_none());

        // Force the session expired and drop its links.
        sqlx::query("UPDATE model_upload_sessions SET expires_at = $1 WHERE id = $2")
            .bind("2000-01-01T00:00:00+00:00")
            .bind(&s.id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            db.model_expire_sessions().await.unwrap(),
            vec![s.id.clone()]
        );
        db.model_drop_sessions_blocks().await.unwrap();

        // The block is now unreferenced: marked, then deletable past grace.
        assert_eq!(db.model_remark_liveness().await.unwrap(), 1);
        sqlx::query("UPDATE model_blocks SET unreferenced_since = $1 WHERE sha256 = $2")
            .bind("2000-01-01T00:00:00+00:00")
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            db.model_stale_blocks(3600, 10).await.unwrap(),
            vec![sha.clone()]
        );
        let mut tx = db.model_begin().await.unwrap();
        assert!(db
            .model_tx_block_still_dead(&mut tx, &sha, 3600)
            .await
            .unwrap());
        db.model_tx_delete_block_row(&mut tx, &sha).await.unwrap();
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn a_remarked_block_earns_its_new_grace_period(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let sha = "f".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at, unreferenced_since) VALUES ($1, 1, $2, $2)")
            .bind(&sha)
            .bind(ts_from_now(-7200))
            .execute(&pool)
            .await
            .unwrap();
        // Selected while stale, then re-marked moments ago (as a racing
        // unmark/remark cycle would): the fresh stamp restarts the grace
        // clock and the block must not be deleted on the old one.
        let mut tx = db.model_begin().await.unwrap();
        assert!(db
            .model_tx_block_still_dead(&mut tx, &sha, 3600)
            .await
            .unwrap());
        sqlx::query("UPDATE model_blocks SET unreferenced_since = $1 WHERE sha256 = $2")
            .bind(ts_from_now(-10))
            .bind(&sha)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(!db
            .model_tx_block_still_dead(&mut tx, &sha, 3600)
            .await
            .unwrap());
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn caps_ignore_wall_clock_dead_open_sessions(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        // A same-owner peer and a different-owner peer each hold 900 bytes.
        let peer_same = db.model_open_session("did:owner", "r1", 60).await.unwrap();
        let peer_other = db.model_open_session("did:other", "r1", 60).await.unwrap();
        for s in [&peer_same, &peer_other] {
            db.model_admit_bytes(&s.id, 900, 3600, 10_000, 100_000)
                .await
                .unwrap()
                .expect("peer admission");
        }
        // Past the wall-clock TTL the rows still say 'open' until the sweep.
        sqlx::query("UPDATE model_upload_sessions SET expires_at = $1")
            .bind("2000-01-01T00:00:00+00:00")
            .execute(&pool)
            .await
            .unwrap();

        // Claim-side node total must not count the dead sessions.
        let mut tx = db.model_begin().await.unwrap();
        assert_eq!(db.model_tx_node_used(&mut tx).await.unwrap(), 0);
        tx.rollback().await.unwrap();

        // Per-owner term: the dead same-owner peer must not eat the cap.
        let live = db.model_open_session("did:owner", "r1", 60).await.unwrap();
        assert!(db
            .model_admit_bytes(&live.id, 200, 3600, 1000, 100_000)
            .await
            .unwrap()
            .is_some());
        // Node-wide term: both dead peers (1800) must not eat a 1000 cap.
        let live2 = db.model_open_session("did:third", "r1", 60).await.unwrap();
        assert!(db
            .model_admit_bytes(&live2.id, 200, 3600, 10_000, 1000)
            .await
            .unwrap()
            .is_some());
    }

    async fn seed_release_with_block(
        pool: &sqlx::PgPool,
        publisher: &str,
        state: &str,
        commit: &str,
        sha: &str,
    ) {
        sqlx::query(
            "INSERT INTO model_blocks (sha256, size, created_at) VALUES ($1, 100, 't')
             ON CONFLICT DO NOTHING",
        )
        .bind(sha)
        .execute(pool)
        .await
        .unwrap();
        let rid: i64 = sqlx::query_scalar(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, created_at)
             VALUES ('r1', $1, 'main', $3, $2, 'm', 's', 'i', 'ss', '\\x00', 't')
             RETURNING id",
        )
        .bind(commit)
        .bind(state)
        .bind(publisher)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO model_release_blocks (release_id, block_sha256) VALUES ($1, $2)")
            .bind(rid)
            .bind(sha)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn session_bytes(pool: &sqlx::PgPool, id: &str) -> i64 {
        sqlx::query_scalar("SELECT bytes_received FROM model_upload_sessions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test]
    async fn record_block_refunds_only_bytes_a_live_release_already_carries(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;

        // Block already carried by the owner's published release: claim
        // authorizes it without a link and billed it, so the PUT is free
        // and leaves no link behind to outlive the release.
        let carried = "d".repeat(64);
        seed_release_with_block(&pool, "did:owner", "published", "c1", &carried).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        db.model_admit_bytes(&s.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .model_record_block(&s.id, &carried, 100, 100)
            .await
            .unwrap());
        assert_eq!(session_bytes(&pool, &s.id).await, 0);
        let links: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM model_session_blocks WHERE session_id = $1")
                .bind(&s.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(links, 0);

        // Another publisher's published release bills its owner, not this
        // session, and the session needs the link to claim the block.
        let theirs = "9".repeat(64);
        seed_release_with_block(&pool, "did:other", "published", "c3", &theirs).await;
        db.model_admit_bytes(&s.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .unwrap();
        assert!(!db
            .model_record_block(&s.id, &theirs, 100, 100)
            .await
            .unwrap());
        assert_eq!(session_bytes(&pool, &s.id).await, 100);

        // Block only in a rejected release: nothing bills it, so the
        // session keeps the charge.
        let dead = "e".repeat(64);
        seed_release_with_block(&pool, "did:owner", "rejected", "c2", &dead).await;
        let s2 = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        db.model_admit_bytes(&s2.id, 100, 3600, 1000, 10_000)
            .await
            .unwrap()
            .unwrap();
        assert!(!db
            .model_record_block(&s2.id, &dead, 100, 100)
            .await
            .unwrap());
        assert_eq!(session_bytes(&pool, &s2.id).await, 100);

        // Block held only by another open session: that session is the
        // one billed, and a refund here would let a session pair hold
        // unbilled bytes once the first expires.
        let held = "f".repeat(64);
        let a = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        let b = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        for x in [&a, &b] {
            db.model_admit_bytes(&x.id, 100, 3600, 1000, 10_000)
                .await
                .unwrap()
                .unwrap();
        }
        assert!(!db.model_record_block(&a.id, &held, 100, 100).await.unwrap());
        assert!(!db.model_record_block(&b.id, &held, 100, 100).await.unwrap());
        assert_eq!(session_bytes(&pool, &b.id).await, 100);
    }

    #[sqlx::test]
    async fn session_blocks_ignore_expired_sessions(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let s = db
            .model_open_session("did:owner", "r1", 3600)
            .await
            .unwrap();
        let sha = "c".repeat(64);
        db.model_record_block(&s.id, &sha, 100, 100).await.unwrap();

        let mut tx = db.model_begin().await.unwrap();
        assert_eq!(
            db.model_tx_session_blocks(&mut tx, "did:owner")
                .await
                .unwrap(),
            vec![sha.clone()]
        );
        tx.rollback().await.unwrap();

        // Past the wall-clock TTL the row still says 'open' until the sweep
        // runs, yet the claim-side reachability set must already be empty.
        sqlx::query("UPDATE model_upload_sessions SET expires_at = $1 WHERE id = $2")
            .bind("2000-01-01T00:00:00+00:00")
            .bind(&s.id)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = db.model_begin().await.unwrap();
        assert!(db
            .model_tx_session_blocks(&mut tx, "did:owner")
            .await
            .unwrap()
            .is_empty());
        tx.rollback().await.unwrap();
    }

    #[sqlx::test]
    async fn reserve_quota_caps_first_and_later_claims(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        // First claim over cap: refused, and no row may be left behind.
        let mut tx = db.model_begin().await.unwrap();
        assert!(db
            .model_tx_reserve_quota(&mut tx, "did:owner", 2000, 1000)
            .await
            .unwrap()
            .is_none());
        tx.commit().await.unwrap();
        let row: Option<i64> =
            sqlx::query_scalar("SELECT bytes_used FROM model_quota_usage WHERE did = 'did:owner'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(row.is_none());
        // Within cap inserts, over-cap update refuses, within-cap update adds.
        let mut tx = db.model_begin().await.unwrap();
        assert_eq!(
            db.model_tx_reserve_quota(&mut tx, "did:owner", 600, 1000)
                .await
                .unwrap(),
            Some(600)
        );
        assert!(db
            .model_tx_reserve_quota(&mut tx, "did:owner", 500, 1000)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            db.model_tx_reserve_quota(&mut tx, "did:owner", 400, 1000)
                .await
                .unwrap(),
            Some(1000)
        );
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn release_blocks_keep_a_block_alive(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let sha = "c".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at) VALUES ($1, 5, 't')")
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, created_at)
             VALUES ('r1','c1','main','did:owner','published','m','s','i','ss','\\x00','t')
             RETURNING id",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rid: i64 = sqlx::query_scalar("SELECT id FROM model_releases WHERE repo_id = 'r1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO model_release_blocks (release_id, block_sha256) VALUES ($1,$2)")
            .bind(rid)
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        // Live release reference: the block never goes stale.
        assert_eq!(db.model_remark_liveness().await.unwrap(), 0);
        assert!(db.model_stale_blocks(-1, 10).await.unwrap().is_empty());
        let mut tx = db.model_begin().await.unwrap();
        assert!(!db
            .model_tx_block_still_dead(&mut tx, &sha, 3600)
            .await
            .unwrap());
        tx.commit().await.unwrap();
    }

    /// Run the claim transaction's charge path against `shas` (unclaimed
    /// bytes -> per-payer quota -> release insert -> block link/payer stamp)
    /// and return the release id. The HTTP and git halves of claim_release
    /// are not exercised here.
    async fn claim_as(db: &Db, publisher: &str, commit: &str, repo: &str, shas: &[String]) -> i64 {
        let mut tx = db.model_begin().await.unwrap();
        db.model_tx_advisory_lock(&mut tx, crate::models::CLAIM_LOCK_KEY)
            .await
            .unwrap();
        let new_bytes = db.model_tx_unclaimed_bytes(&mut tx, shas).await.unwrap();
        db.model_tx_reserve_quota(&mut tx, publisher, new_bytes, i64::MAX)
            .await
            .unwrap();
        let persist = ClaimPersist {
            signature: "s".into(),
            signature_input: "i".into(),
            signing_string: "ss".into(),
            body: vec![0],
            request_digest: format!("{publisher}-{commit}"),
        };
        let row = db
            .model_tx_insert_release(
                &mut tx, repo, commit, "main", publisher, "m", None, &persist,
            )
            .await
            .unwrap();
        db.model_tx_link_release_blocks(&mut tx, row.id, publisher, shas)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        row.id
    }

    async fn quota_used(pool: &sqlx::PgPool, did: &str) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(bytes_used, 0) FROM model_quota_usage WHERE did = $1")
            .bind(did)
            .fetch_optional(pool)
            .await
            .unwrap()
            .unwrap_or(0)
    }

    #[sqlx::test]
    async fn rejection_refunds_the_payer_not_the_release_publisher(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let sha = "a".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at) VALUES ($1, 100, 't')")
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        // A claims the block (pays 100); B's later claim is free.
        let ra = claim_as(&db, "did:a", "ca", "r1", std::slice::from_ref(&sha)).await;
        let rb = claim_as(&db, "did:b", "cb", "r1", std::slice::from_ref(&sha)).await;
        assert_eq!(quota_used(&pool, "did:a").await, 100);
        assert_eq!(quota_used(&pool, "did:b").await, 0);

        // Rejecting A's release first changes nothing: the block is still
        // carried by B's live release, so nothing is freed.
        db.model_reject_release(ra, "x").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 100);
        // Rejecting B's release then frees the block, and the refund goes
        // to the payer A, never to the rejected release's publisher B (who
        // was never charged).
        db.model_reject_release(rb, "x").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 0);
        assert_eq!(quota_used(&pool, "did:b").await, 0);
        // The payer stamp was cleared: a re-claim would charge anew, not
        // refund-into-reclaim.
        let payer: Option<String> =
            sqlx::query_scalar("SELECT payer_did FROM model_blocks WHERE sha256 = $1")
                .bind(&sha)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(payer, None);
    }

    #[sqlx::test]
    async fn free_claimer_rejection_first_keeps_the_payer_charge(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let sha = "b".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at) VALUES ($1, 100, 't')")
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        let ra = claim_as(&db, "did:a", "ca", "r1", std::slice::from_ref(&sha)).await;
        let rb = claim_as(&db, "did:b", "cb", "r1", std::slice::from_ref(&sha)).await;
        // B rejects first: still live under A, so nothing moves.
        db.model_reject_release(rb, "x").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 100);
        let payer: Option<String> =
            sqlx::query_scalar("SELECT payer_did FROM model_blocks WHERE sha256 = $1")
                .bind(&sha)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(payer.as_deref(), Some("did:a"));
        // Then A: freed, refunded.
        db.model_reject_release(ra, "x").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 0);
    }

    #[sqlx::test]
    async fn delete_repo_refunds_live_release_charges(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, is_public, default_branch,
                                created_at, updated_at, disk_path)
             VALUES ('r2', 'repo2', 'did:a', TRUE, 'main', 't', 't', '/r2')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let sha = "c".repeat(64);
        sqlx::query("INSERT INTO model_blocks (sha256, size, created_at) VALUES ($1, 100, 't')")
            .bind(&sha)
            .execute(&pool)
            .await
            .unwrap();
        // A publishes the block on r2 (payer A); B free-claims it on r1.
        let ra = claim_as(&db, "did:a", "ca", "r2", std::slice::from_ref(&sha)).await;
        sqlx::query("UPDATE model_releases SET state = 'published' WHERE id = $1")
            .bind(ra)
            .execute(&pool)
            .await
            .unwrap();
        claim_as(&db, "did:b", "cb", "r1", std::slice::from_ref(&sha)).await;
        assert_eq!(quota_used(&pool, "did:a").await, 100);

        // Deleting r1 must not touch A's charge: the block is still carried
        // by r2's live release.
        db.delete_repo_by_id("r1").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 100);
        // Deleting r2 frees it: the payer is refunded even though the
        // cascade also dropped the rows.
        db.delete_repo_by_id("r2").await.unwrap();
        assert_eq!(quota_used(&pool, "did:a").await, 0);
    }

    #[sqlx::test]
    async fn rejection_refunds_the_publisher_for_a_legacy_unpayered_block(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let sha = "d".repeat(64);
        seed_release_with_block(&pool, "did:c", "verifying", "cl", &sha).await;
        sqlx::query("INSERT INTO model_quota_usage (did, bytes_used) VALUES ('did:c', 100)")
            .execute(&pool)
            .await
            .unwrap();
        let rid: i64 = sqlx::query_scalar("SELECT id FROM model_releases WHERE commit_sha = 'cl'")
            .fetch_one(&pool)
            .await
            .unwrap();
        db.model_reject_release(rid, "x").await.unwrap();
        assert_eq!(quota_used(&pool, "did:c").await, 0);
    }

    async fn seed_verifying_release(pool: &sqlx::PgPool, commit: &str) -> i64 {
        // A distinct publisher per row: the one-verifying index is real.
        sqlx::query_scalar(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, created_at)
             VALUES ('r1', $1, 'main', 'did:' || $1, 'verifying', 'm', 's', 'i', 'ss', '\\x00', 't')
             RETURNING id",
        )
        .bind(commit)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    async fn publish_if_public_gates_on_the_locked_repo_state(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;

        // Public repo: the verifying release publishes.
        let rid = seed_verifying_release(&pool, "cp1").await;
        assert_eq!(
            db.model_publish_if_public(rid, "r1").await.unwrap(),
            PublishOutcome::Published
        );

        // A visibility rule appearing between the handler check and publish
        // flips the outcome to NoLongerPublic and the row stays verifying.
        sqlx::query(
            "INSERT INTO visibility_rules
                 (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
             VALUES ('v1', 'r1', '/x', 'withhold', '[]', 'did:owner', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rid2 = seed_verifying_release(&pool, "cp2").await;
        assert_eq!(
            db.model_publish_if_public(rid2, "r1").await.unwrap(),
            PublishOutcome::NoLongerPublic
        );
        let state: String = sqlx::query_scalar("SELECT state FROM model_releases WHERE id = $1")
            .bind(rid2)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "verifying");

        // With the rule gone the repo is fully public again: a row already
        // out of verifying is NotVerifying, not a re-publish.
        sqlx::query("DELETE FROM visibility_rules WHERE repo_id = 'r1'")
            .execute(&pool)
            .await
            .unwrap();
        let rid3 = seed_verifying_release(&pool, "cp3").await;
        sqlx::query("UPDATE model_releases SET state = 'published' WHERE id = $1")
            .bind(rid3)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            db.model_publish_if_public(rid3, "r1").await.unwrap(),
            PublishOutcome::NotVerifying
        );

        // A missing repo row is NoLongerPublic.
        let rid4 = seed_verifying_release(&pool, "cp4").await;
        assert_eq!(
            db.model_publish_if_public(rid4, "gone").await.unwrap(),
            PublishOutcome::NoLongerPublic
        );
    }

    #[sqlx::test]
    async fn parent_still_public_tracks_publicity_and_rules(pool: sqlx::PgPool) {
        let db = migrated(pool.clone()).await;
        let mut tx = pool.begin().await.unwrap();
        assert!(db
            .model_tx_parent_still_public(&mut tx, "r1")
            .await
            .unwrap());
        assert!(!db
            .model_tx_parent_still_public(&mut tx, "gone")
            .await
            .unwrap());
        assert!(!db
            .model_tx_parent_still_public(&mut tx, "a/b")
            .await
            .unwrap());
        tx.rollback().await.unwrap();

        sqlx::query(
            "INSERT INTO visibility_rules (id, repo_id, path_glob, mode, reader_dids,
                                           created_by, created_at)
             VALUES ('v1', 'r1', 'x/**', 'deny', '[]', 'did:owner', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(!db
            .model_tx_parent_still_public(&mut tx, "r1")
            .await
            .unwrap());
        tx.rollback().await.unwrap();

        sqlx::query("DELETE FROM visibility_rules WHERE repo_id = 'r1'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET is_public = FALSE WHERE id = 'r1'")
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(!db
            .model_tx_parent_still_public(&mut tx, "r1")
            .await
            .unwrap());
        tx.rollback().await.unwrap();
    }
}
