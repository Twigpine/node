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
                   ), 0) <= $5
               AND COALESCE((SELECT SUM(q.bytes_used) FROM model_quota_usage q), 0)
                   + COALESCE((
                       SELECT SUM(o2.bytes_received) FROM model_upload_sessions o2
                       WHERE o2.state = 'open'
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
        .fetch_optional(&self.pool)
        .await?;
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
    /// when this PUT was a duplicate within the session (the admission
    /// credit was refunded).
    pub async fn model_record_block(
        &self,
        session_id: &str,
        block_sha: &str,
        size: u64,
        admitted: i64,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
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
        let linked = sqlx::query(
            "INSERT INTO model_session_blocks (session_id, block_sha256)
             VALUES ($1, $2)
             ON CONFLICT (session_id, block_sha256) DO NOTHING",
        )
        .bind(session_id)
        .bind(block_sha)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if linked == 0 {
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
        Ok(linked == 0)
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
             WHERE s.owner_did = $1 AND s.state = 'open'",
        )
        .bind(owner_did)
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
        Ok(sqlx::query_scalar::<_, Option<i64>>(
            "SELECT (COALESCE((SELECT SUM(bytes_used) FROM model_quota_usage), 0)
                  + COALESCE((SELECT SUM(bytes_received) FROM model_upload_sessions
                              WHERE state = 'open'), 0))::bigint",
        )
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
        sqlx::query(
            "INSERT INTO model_release_blocks (release_id, block_sha256)
             SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
        )
        .bind(release_id)
        .bind(shas)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "DELETE FROM model_session_blocks sb
             USING model_upload_sessions s
             WHERE s.id = sb.session_id AND s.owner_did = $1
               AND s.state = 'open' AND sb.block_sha256 = ANY($2)",
        )
        .bind(publisher_did)
        .bind(shas)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn model_tx_recount_open_session_bytes(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner_did: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE model_upload_sessions s
             SET bytes_received = COALESCE((
                   SELECT SUM(b.size) FROM model_session_blocks sb
                   JOIN model_blocks b ON b.sha256 = sb.block_sha256
                   WHERE sb.session_id = s.id), 0)
             WHERE s.owner_did = $1 AND s.state = 'open'",
        )
        .bind(owner_did)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    // ── verification ───────────────────────────────────────────────────────

    pub async fn model_mark_published(&self, release_id: i64) -> Result<()> {
        sqlx::query(
            "UPDATE model_releases
             SET state = 'published', published_at = $2
             WHERE id = $1 AND state = 'verifying'",
        )
        .bind(release_id)
        .bind(ts_now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reject: mark the release, drop its refs, and refund the publisher the
    /// bytes no other live release still references.
    pub async fn model_reject_release(&self, release_id: i64, reason: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
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
        let Some((publisher,)) = released else {
            tx.commit().await?;
            return Ok(());
        };
        // SUM over bigint returns numeric; cast back so the i64 decode holds.
        let freed: i64 = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT COALESCE(SUM(b.size), 0)::bigint FROM model_blocks b
             JOIN model_release_blocks rb ON rb.block_sha256 = b.sha256
             WHERE rb.release_id = $1
               AND NOT EXISTS (
                     SELECT 1 FROM model_release_blocks r2
                     JOIN model_releases r ON r.id = r2.release_id
                     WHERE r2.block_sha256 = b.sha256 AND r2.release_id <> $1
                       AND r.state IN ('verifying', 'published'))",
        )
        .bind(release_id)
        .fetch_one(&mut *tx)
        .await?
        .unwrap_or(0);
        sqlx::query("DELETE FROM model_release_blocks WHERE release_id = $1")
            .bind(release_id)
            .execute(&mut *tx)
            .await?;
        if freed > 0 {
            sqlx::query(
                "UPDATE model_quota_usage SET bytes_used = GREATEST(bytes_used - $2, 0)
                 WHERE did = $1",
            )
            .bind(&publisher)
            .bind(freed)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
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

    pub async fn model_drop_sessions_blocks(&self, session_ids: &[String]) -> Result<()> {
        sqlx::query("DELETE FROM model_session_blocks WHERE session_id = ANY($1)")
            .bind(session_ids)
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
    ) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT NOT EXISTS (
                   SELECT 1 FROM model_release_blocks rb
                   JOIN model_releases r ON r.id = rb.release_id
                   WHERE rb.block_sha256 = $1
                     AND r.state IN ('verifying', 'published'))
             AND NOT EXISTS (
                   SELECT 1 FROM model_session_blocks sb
                   JOIN model_upload_sessions s ON s.id = sb.session_id
                   WHERE sb.block_sha256 = $1 AND s.state = 'open')
             FROM model_blocks b
             WHERE b.sha256 = $1 FOR UPDATE",
        )
        .bind(sha)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or(false))
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
        db.model_drop_sessions_blocks(std::slice::from_ref(&s.id))
            .await
            .unwrap();

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
        assert!(db.model_tx_block_still_dead(&mut tx, &sha).await.unwrap());
        db.model_tx_delete_block_row(&mut tx, &sha).await.unwrap();
        tx.commit().await.unwrap();
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
        assert!(!db.model_tx_block_still_dead(&mut tx, &sha).await.unwrap());
        tx.commit().await.unwrap();
    }
}
