//! Release verification: rebuild every chunk-stored file, hash it against
//! the manifest, check the declared format against detected bytes, and only
//! then mark the release published (and pin the hidden ref). Rejection frees
//! the quota reservation and drops the block refs.

use futures::StreamExt;
use sha2::Digest;
use std::io::Write;
use twigpine_core::model::manifest::{detect_format, StorageKind};
use twigpine_core::model::reconstruction::Reconstruction;

use crate::error::AppError;
use crate::state::AppState;

/// Sink hashing rebuilt bytes and keeping the head for format detection.
struct VerifySink {
    hasher: sha2::Sha256,
    head: Vec<u8>,
}

impl Write for VerifySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        if self.head.len() < 64 {
            let take = (64 - self.head.len()).min(buf.len());
            self.head.extend_from_slice(&buf[..take]);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Verify one release end to end. Idempotent: a release no longer in
/// `verifying` returns immediately.
pub async fn verify_release(state: &AppState, release_id: i64) -> Result<(), AppError> {
    let Some(release) = state.db.model_release_by_id(release_id).await? else {
        return Ok(());
    };
    if release.state != "verifying" {
        return Ok(());
    }

    // The repo must still be fully public: a repo turned private or given
    // visibility rules mid-verification never publishes.
    let record = state
        .db
        .get_repo_by_id(&release.repo_id)
        .await?
        .ok_or_else(|| AppError::NotFound("repo gone".into()))?;
    // mirror-rows-handled: a slash-form id fails closed in the condition
    // below; the vacuous pair never admits a mirror for publishing.
    let rules = state.db.list_visibility_rules(&record.id).await?;
    // A mirror row (slash-form id) has a vacuous publicity pair, so it can
    // never prove full publicity here either.
    if !record.is_public || !rules.is_empty() || record.id.contains('/') {
        return reject_release(state, release_id, "repository is no longer fully public").await;
    }

    let disk_path = std::path::PathBuf::from(&record.disk_path);
    let (manifest_bytes, manifest) = match super::claim::read_verified_manifest(
        &state.git_bin,
        &disk_path,
        &release.commit_sha,
        &record.owner_did,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // An internal failure (git spawn, IO) is transient: propagate so
            // the worker's bounded retry applies. Deterministic errors (a
            // bad signature, a missing file, malformed input) settle here.
            if matches!(e, AppError::Internal(_)) {
                return Err(e);
            }
            return reject_release(state, release_id, &format!("manifest re-check failed: {e}"))
                .await;
        }
    };
    if twigpine_core::cid::sha256_hex(&manifest_bytes) != release.manifest_sha256 {
        return reject_release(state, release_id, "manifest digest changed since claim").await;
    }

    let rec = match &manifest.reconstruction {
        Some(rec_ref) => {
            let store = state
                .block_store
                .clone()
                .ok_or_else(|| AppError::Internal(anyhow::anyhow!("block store gone")))?;
            let rec_bytes = match super::read_block(&store, &rec_ref.sha256, rec_ref.size).await {
                Ok(b) => b,
                Err(e) => {
                    return reject_release(
                        state,
                        release_id,
                        &format!("reconstruction object unreadable: {e}"),
                    )
                    .await;
                }
            };
            match Reconstruction::parse(&rec_bytes) {
                Ok(r) => Some(r),
                Err(e) => {
                    return reject_release(
                        state,
                        release_id,
                        &format!("reconstruction object invalid: {e}"),
                    )
                    .await;
                }
            }
        }
        None => None,
    };
    // An all-Git release legitimately carries no reconstruction object; a
    // manifest naming chunked files without one is self-contradictory.
    if rec.is_none()
        && manifest
            .files
            .iter()
            .any(|f| matches!(f.storage, StorageKind::Chunked))
    {
        return reject_release(
            state,
            release_id,
            "chunked files declared but the manifest has no reconstruction object",
        )
        .await;
    }

    // Commit ⊆ manifest: a committed file the manifest does not name as
    // git-stored slipped past the publish scan; refuse it rather than
    // release bytes the manifest never described.
    let tree = crate::git::store::run_git_bounded(
        &state.git_bin,
        &disk_path,
        &["ls-tree", "-rz", "--name-only", &release.commit_sha],
        b"",
        std::time::Duration::from_secs(30),
        "git ls-tree",
    )
    .await
    .map_err(AppError::Internal)?;
    // A failed ls-tree must not read as an empty tree: its stdout is only
    // trustworthy when the command succeeded.
    if !tree.status.success() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "git ls-tree failed: {}",
            String::from_utf8_lossy(&tree.stderr)
                .chars()
                .take(256)
                .collect::<String>()
        )));
    }
    let manifest_git_paths: std::collections::HashSet<&[u8]> = manifest
        .files
        .iter()
        .filter(|f| f.storage == StorageKind::Git)
        .map(|f| f.path.as_bytes())
        .collect();
    // -z, not line-splitting: with core.quotePath on, a non-ASCII path is
    // printed as escaped octal and could never match a manifest path.
    // Raw bytes: a lossy decode would let an invalid-UTF-8 name match a
    // manifest entry spelled with U+FFFD and skip the read and hash.
    for path in tree
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty() && !p.starts_with(b".twigpine/"))
    {
        if !manifest_git_paths.contains(path) {
            return reject_release(
                state,
                release_id,
                &format!(
                    "{} is committed but not in the manifest",
                    String::from_utf8_lossy(path)
                ),
            )
            .await;
        }
    }

    let rec_by_path: std::collections::HashMap<&str, _> = rec
        .as_ref()
        .map(|r| r.files.iter().map(|f| (f.path.as_str(), f)).collect())
        .unwrap_or_default();
    for file in &manifest.files {
        match file.storage {
            StorageKind::Chunked => {
                let Some(&entry) = rec_by_path.get(file.path.as_str()) else {
                    return reject_release(
                        state,
                        release_id,
                        &format!("reconstruction object has no entry for {}", file.path),
                    )
                    .await;
                };
                if entry.sha256 != file.sha256 || entry.size != file.size {
                    return reject_release(
                        state,
                        release_id,
                        &format!("{}: reconstruction disagrees with the manifest", file.path),
                    )
                    .await;
                }
                // Rebuild by ordered range reads, fully async: a sync walker
                // would force block_on, which has no reactor under the S3
                // backend. Blocks were hash-verified at write, so the
                // whole-file digest is the check that matters here.
                let rec = rec.as_ref().expect("entry implies rec");
                let slices = match twigpine_core::model::reconstruction::map_file_range(
                    entry, rec, 0, file.size,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return reject_release(
                            state,
                            release_id,
                            &format!("{}: rebuild failed: {e}", file.path),
                        )
                        .await;
                    }
                };
                let mut sink = VerifySink {
                    hasher: sha2::Sha256::new(),
                    head: Vec::new(),
                };
                // Ordered prefetch: `buffered` preserves order while
                // overlapping the store's per-slice round trips.
                let store = state
                    .block_store
                    .clone()
                    .ok_or_else(|| AppError::Internal(anyhow::anyhow!("block store gone")))?;
                let jobs = slices
                    .iter()
                    .map(|s| (s.block.clone(), s.offset, s.len))
                    .collect::<Vec<_>>();
                // Ordered prefetch: `buffered` preserves order while
                // overlapping the store's per-slice round trips. Consume
                // as slices land: collecting first would hold the whole
                // rebuilt file in memory.
                let mut fetched =
                    futures::stream::iter(jobs.into_iter().map(|(block, offset, len)| {
                        let store = store.clone();
                        async move { super::read_range(&store, &block, offset, len).await }
                    }))
                    .buffered(4);
                while let Some(bytes) = fetched.next().await {
                    let bytes = match bytes {
                        Ok(b) => b,
                        Err(e) => {
                            return reject_release(
                                state,
                                release_id,
                                &format!("{}: rebuild failed: {e}", file.path),
                            )
                            .await;
                        }
                    };
                    if sink.write_all(&bytes).is_err() {
                        return Err(AppError::Internal(anyhow::anyhow!("verify sink write")));
                    }
                }
                let digest = hex::encode(sink.hasher.finalize());
                if digest != file.sha256 {
                    return reject_release(
                        state,
                        release_id,
                        &format!("{}: rebuilt bytes hash to {digest}", file.path),
                    )
                    .await;
                }
                let detected = detect_format(&sink.head, &file.path);
                if detected != file.format {
                    return reject_release(
                        state,
                        release_id,
                        &format!(
                            "{}: declared format {:?} but bytes detect as {:?}",
                            file.path, file.format, detected
                        ),
                    )
                    .await;
                }
            }
            StorageKind::Git => {
                let spec = format!("{}:{}", release.commit_sha, file.path);
                match crate::git::store::run_git_blob_digest(
                    &state.git_bin,
                    &disk_path,
                    &spec,
                    std::time::Duration::from_secs(120),
                    64,
                )
                .await
                .map_err(AppError::Internal)?
                {
                    Some(blob) => {
                        if blob.sha256_hex != file.sha256 || blob.size != file.size {
                            return reject_release(
                                state,
                                release_id,
                                &format!("{}: git blob does not match the manifest", file.path),
                            )
                            .await;
                        }
                        let detected = detect_format(&blob.head, &file.path);
                        if detected != file.format {
                            return reject_release(
                                state,
                                release_id,
                                &format!(
                                    "{}: declared format {:?} but bytes detect as {:?}",
                                    file.path, file.format, detected
                                ),
                            )
                            .await;
                        }
                    }
                    None => {
                        return reject_release(
                            state,
                            release_id,
                            &format!("{}: not present in the claimed commit", file.path),
                        )
                        .await;
                    }
                }
            }
        }
    }

    // Publish: hidden ref first, then the state flip, so a crash leaves a
    // verifying row the worker retries rather than a dangling ref.
    write_release_ref(&state.git_bin, &disk_path, &release.commit_sha).await?;
    match state
        .db
        .model_publish_if_public(release_id, &release.repo_id)
        .await?
    {
        crate::db::model_queries::PublishOutcome::Published => {}
        crate::db::model_queries::PublishOutcome::NoLongerPublic => {
            reject_release(state, release_id, "repository is no longer fully public").await?;
        }
        crate::db::model_queries::PublishOutcome::NotVerifying => {
            // The row settled while this pass ran: a rejected release's ref
            // must go, but a concurrently published one owns its ref.
            let rejected = state
                .db
                .model_release_by_id(release_id)
                .await?
                .is_some_and(|r| r.state == "rejected");
            if rejected {
                remove_release_ref(&state.git_bin, &disk_path, &release.commit_sha).await;
            }
        }
    }
    Ok(())
}

/// Drop the hidden release ref written for `commit`. Best-effort like the
/// write it undoes: a failure leaves an advertised ref, which is a
/// leak of a commit, not a correctness wedge.
async fn remove_release_ref(git_bin: &str, disk_path: &std::path::Path, commit: &str) {
    let ref_name = format!("refs/gitlawb/releases/{commit}");
    let _ = crate::git::store::run_git_bounded(
        git_bin,
        disk_path,
        &["update-ref", "-d", &ref_name],
        b"",
        std::time::Duration::from_secs(30),
        "git update-ref",
    )
    .await;
}

/// `refs/gitlawb/releases/<commit>` -> the release commit itself: reachable,
/// so `gc` never prunes it, and hidden under the gitlawb ref namespace.
/// Idempotently add the release-ref hideRefs config: repos created before
/// the namespace existed only get it via the push-path prereq, which is
/// warn-and-proceed, so a failed write there would leave release commits
/// advertised to every clone.
async fn ensure_release_refs_hidden(
    git_bin: &str,
    disk_path: &std::path::Path,
) -> Result<(), AppError> {
    for &(key, value) in crate::git::store::HIDDEN_REFS
        .iter()
        .filter(|(_, v)| v.contains("releases/"))
    {
        let have = crate::git::store::run_git_bounded(
            git_bin,
            disk_path,
            &["config", "--get-all", key],
            b"",
            std::time::Duration::from_secs(30),
            "git config --get-all",
        )
        .await
        .map_err(AppError::Internal)?;
        if String::from_utf8_lossy(&have.stdout)
            .lines()
            .any(|l| l.trim() == value)
        {
            continue;
        }
        let out = crate::git::store::run_git_bounded(
            git_bin,
            disk_path,
            &["config", "--add", key, value],
            b"",
            std::time::Duration::from_secs(30),
            "git config --add",
        )
        .await
        .map_err(AppError::Internal)?;
        // A failed add (e.g. a stale config.lock) still reports Ok from
        // run_git_bounded; without this the release ref is written to a repo
        // that advertises it to every clone.
        if !out.status.success() {
            return Err(AppError::Internal(anyhow::anyhow!(
                "git config --add {key} failed: {}",
                String::from_utf8_lossy(&out.stderr)
                    .chars()
                    .take(256)
                    .collect::<String>()
            )));
        }
    }
    Ok(())
}

pub async fn write_release_ref(
    git_bin: &str,
    disk_path: &std::path::Path,
    commit: &str,
) -> Result<(), AppError> {
    ensure_release_refs_hidden(git_bin, disk_path).await?;
    let out = crate::git::store::run_git_bounded(
        git_bin,
        disk_path,
        &[
            "update-ref",
            &format!("refs/gitlawb/releases/{commit}"),
            commit,
        ],
        b"",
        std::time::Duration::from_secs(30),
        "git update-ref",
    )
    .await
    .map_err(AppError::Internal)?;
    if !out.status.success() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "git update-ref failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(256)
                .collect::<String>()
        )));
    }
    Ok(())
}

/// Reject a release: drop its block refs, release the quota it reserved for
/// blocks no other live release still references, and record the reason.
pub async fn reject_release(
    state: &AppState,
    release_id: i64,
    reason: &str,
) -> Result<(), AppError> {
    state.db.model_reject_release(release_id, reason).await?;
    tracing::info!(release_id, %reason, "model release rejected");
    // A rejected release must not keep its hidden pin: the ref may exist if
    // a pass wrote it and then errored before the state flip. Remove it only
    // when the row really settled as rejected, never for a published one.
    if let Some(release) = state.db.model_release_by_id(release_id).await? {
        if release.state == "rejected" {
            if let Some(record) = state.db.get_repo_by_id(&release.repo_id).await? {
                remove_release_ref(
                    &state.git_bin,
                    std::path::Path::new(&record.disk_path),
                    &release.commit_sha,
                )
                .await;
            }
        }
    }
    Ok(())
}

/// Poll for `verifying` releases and verify them in order. Spawned once per
/// node when model hosting is enabled; exits on node shutdown.
pub async fn run_verify_worker(state: AppState) {
    let mut shutdown_rx = state.subscribe_shutdown();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    // Consecutive verify_release errors per release id, reset on success and
    // on reject: the bound on retries a persistently broken release gets.
    let mut failures: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown_rx.changed() => return,
        }
        let ids = match state.db.model_verifying_ids(4).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("model verify worker query failed: {e}");
                continue;
            }
        };
        for id in &ids {
            match verify_release(&state, *id).await {
                Ok(()) => {
                    failures.remove(id);
                }
                Err(e) => {
                    tracing::warn!("model release {id} verification errored: {e}");
                    let n = failures.entry(*id).or_insert(0);
                    *n += 1;
                    // A persistent internal error would otherwise hold the
                    // publisher's one-verifying slot until the 6h stale
                    // sweep; a bounded run of errors rejects the row sooner.
                    if *n >= 5 {
                        if let Err(re) = reject_release(
                            &state,
                            *id,
                            &format!("verification failed repeatedly: {e}"),
                        )
                        .await
                        {
                            tracing::warn!(
                                "model release {id} reject after repeated failures failed: {re}"
                            );
                        }
                        failures.remove(id);
                    }
                }
            }
        }
        // Rows that left `verifying` by another path (publish, stale sweep)
        // carry no counter forward.
        failures.retain(|id, _| ids.contains(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twigpine_core::model::manifest::{
        FileFormat, Manifest, ManifestFile, StorageKind, MANIFEST_SCHEMA_V1,
    };

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

    /// A `verifying` release whose publish step fails every pass (a stale
    /// `config.lock` refuses the hideRefs `git config --add`) is rejected by
    /// the worker after a bounded run of errors, and the publisher's
    /// one-verifying slot is then free for a new claim.
    #[sqlx::test]
    async fn a_persistently_failing_verify_is_rejected_and_frees_the_claim_slot(
        pool: sqlx::PgPool,
    ) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let owner_did =
            twigpine_core::did::Did::from_verifying_key(&signing.verifying_key()).to_string();

        // A real commit: a.txt rides as a git-stored manifest file, so the
        // whole verify path runs and only the ref-pin step fails.
        let dir = tempfile::tempdir().expect("tempdir");
        git(dir.path(), &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(dir.path().join(".twigpine")).expect("mkdir");
        std::fs::write(dir.path().join("a.txt"), b"hello\n").expect("a.txt");
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            repo: format!("{}/model", crate::db::canonical_did(&owner_did)),
            publisher_did: owner_did.clone(),
            license: "mit".to_string(),
            parent: None,
            files: vec![ManifestFile {
                path: "a.txt".to_string(),
                size: 6,
                sha256: twigpine_core::cid::sha256_hex(b"hello\n"),
                format: FileFormat::Text,
                storage: StorageKind::Git,
            }],
            reconstruction: None,
        };
        let manifest_bytes = manifest.to_bytes().expect("manifest bytes");
        let sig = twigpine_core::model::manifest::sign(&signing, &manifest_bytes);
        std::fs::write(
            dir.path().join(".twigpine/model-release.json"),
            &manifest_bytes,
        )
        .expect("manifest");
        std::fs::write(dir.path().join(".twigpine/model-release.sig"), sig).expect("sig");
        git(dir.path(), &["add", "a.txt", ".twigpine"]);
        git(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "r1",
            ],
        );
        let commit = git(dir.path(), &["rev-parse", "HEAD"]);

        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, is_public, default_branch,
                                created_at, updated_at, disk_path)
             VALUES ('r1', 'model', $1, TRUE, 'main', $2, $2, $3)",
        )
        .bind(&owner_did)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(dir.path().to_str().expect("utf-8 path"))
        .execute(&pool)
        .await
        .expect("repo row");
        sqlx::query(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, claim_request_digest, created_at)
             VALUES ('r1', $1, 'main', $2, 'verifying', $3, 's', 'i', 'ss',
                     decode('00','hex'), 'd1', $4)
             RETURNING id",
        )
        .bind(&commit)
        .bind(&owner_did)
        .bind(twigpine_core::cid::sha256_hex(&manifest_bytes))
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&pool)
        .await
        .expect("release row");

        // A stale lock makes `git config --add` fail every pass; the pin
        // step then errors instead of writing an advertised release ref.
        std::fs::write(dir.path().join(".git/config.lock"), b"").expect("config.lock");

        let worker = tokio::spawn(run_verify_worker(state.clone()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let state_str = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM model_releases WHERE commit_sha = $1")
                    .bind(&commit)
                    .fetch_one(&pool)
                    .await
                    .expect("release state");
            if s != "verifying" {
                break s;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "release never settled"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        };
        worker.abort();
        assert_eq!(state_str, "rejected");
        let reason: String =
            sqlx::query_scalar("SELECT failure_reason FROM model_releases WHERE commit_sha = $1")
                .bind(&commit)
                .fetch_one(&pool)
                .await
                .expect("failure_reason");
        assert!(
            reason.contains("verification failed repeatedly"),
            "got: {reason}"
        );

        // The slot is free: a claim on a new commit is accepted.
        std::fs::write(dir.path().join("a.txt"), b"hello again\n").expect("a.txt v2");
        git(dir.path(), &["add", "a.txt"]);
        git(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "r2",
            ],
        );
        let commit2 = git(dir.path(), &["rev-parse", "HEAD"]);
        let record = state
            .db
            .get_repo_by_id("r1")
            .await
            .expect("repo read")
            .expect("repo row");
        let material = super::super::claim::ClaimMaterial {
            request_digest: "d2".to_string(),
            signature: "s".to_string(),
            signature_input: "i".to_string(),
            signing_string: "ss".to_string(),
            body: Vec::new(),
        };
        let row = super::super::claim::claim_release(
            &state, &record, &owner_did, &commit2, "main", &material,
        )
        .await
        .expect("claim after rejection is accepted");
        assert_eq!(row.state, "verifying");
    }

    /// One verifying release over a real repo holding `files`: the manifest
    /// names `manifest_paths` of them as git-stored; any committed file the
    /// manifest does not name is extra. Returns (state, release_id, commit).
    async fn verify_fixture(
        pool: &sqlx::PgPool,
        worktree: &std::path::Path,
        files: &[(&str, &[u8])],
        manifest_paths: &[&str],
    ) -> (crate::state::AppState, i64, String) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let owner_did =
            twigpine_core::did::Did::from_verifying_key(&signing.verifying_key()).to_string();
        git(worktree, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(worktree.join(".twigpine")).expect("mkdir");
        let mut entries = Vec::new();
        let mut add = vec![".twigpine".to_string()];
        for (path, bytes) in files {
            std::fs::write(worktree.join(path), bytes).expect("worktree file");
            add.push(path.to_string());
            entries.push(ManifestFile {
                path: path.to_string(),
                size: bytes.len() as u64,
                sha256: twigpine_core::cid::sha256_hex(bytes),
                format: FileFormat::Text,
                storage: StorageKind::Git,
            });
        }
        entries.retain(|f| manifest_paths.contains(&f.path.as_str()));
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            repo: format!("{}/model", crate::db::canonical_did(&owner_did)),
            publisher_did: owner_did.clone(),
            license: "mit".to_string(),
            parent: None,
            files: entries,
            reconstruction: None,
        };
        let manifest_bytes = manifest.to_bytes().expect("manifest bytes");
        let sig = twigpine_core::model::manifest::sign(&signing, &manifest_bytes);
        std::fs::write(
            worktree.join(".twigpine/model-release.json"),
            &manifest_bytes,
        )
        .expect("manifest");
        std::fs::write(worktree.join(".twigpine/model-release.sig"), sig).expect("sig");
        let add_refs: Vec<&str> = add.iter().map(String::as_str).collect();
        git(worktree, &[&["add"][..], &add_refs].concat());
        git(
            worktree,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "r1",
            ],
        );
        let commit = git(worktree, &["rev-parse", "HEAD"]);
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, is_public, default_branch,
                                created_at, updated_at, disk_path)
             VALUES ('r1', 'model', $1, TRUE, 'main', $2, $2, $3)",
        )
        .bind(&owner_did)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(worktree.to_str().expect("utf-8 path"))
        .execute(pool)
        .await
        .expect("repo row");
        let release_id: i64 = sqlx::query_scalar(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, claim_request_digest, created_at)
             VALUES ('r1', $1, 'main', $2, 'verifying', $3, 's', 'i', 'ss',
                     decode('00','hex'), 'd1', $4)
             RETURNING id",
        )
        .bind(&commit)
        .bind(&owner_did)
        .bind(twigpine_core::cid::sha256_hex(&manifest_bytes))
        .bind(chrono::Utc::now().to_rfc3339())
        .fetch_one(pool)
        .await
        .expect("release row");
        (state, release_id, commit)
    }

    async fn release_state(pool: &sqlx::PgPool, release_id: i64) -> (String, Option<String>) {
        sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT state, failure_reason FROM model_releases WHERE id = $1",
        )
        .bind(release_id)
        .fetch_one(pool)
        .await
        .expect("release row")
    }

    /// A nonzero `git ls-tree` must not read as an empty tree and publish:
    /// the failure propagates as Internal and the release stays `verifying`.
    #[sqlx::test]
    async fn a_failed_ls_tree_does_not_reach_publication(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut state, release_id, _commit) = verify_fixture(
            &pool,
            dir.path(),
            &[("a.txt", b"hi\n")],
            &["a.txt"],
        )
        .await;

        // A git shim that fails only `ls-tree`; everything else execs real git.
        let real_git = std::process::Command::new("which")
            .arg("git")
            .output()
            .expect("which git");
        let real_git = String::from_utf8(real_git.stdout).expect("utf-8");
        let shim = dir.path().join("fake-git");
        // Fails only the commit-listing `ls-tree -rz --name-only`; the
        // per-blob `ls-tree -z` probe and every other git call pass through,
        // so only the exit-status check under test can stop publication.
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = \"--name-only\" ]; then echo boom >&2; exit 129; fi; done\nexec {} \"$@\"\n",
                real_git.trim()
            ),
        )
        .expect("shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        state.git_bin = shim.to_str().expect("utf-8 path").to_string();

        let err = verify_release(&state, release_id)
            .await
            .expect_err("a failed ls-tree is internal, not empty");
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
        let (state_str, _) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "verifying");
    }

    /// A transient manifest read failure (git spawn) must propagate as
    /// Internal so the worker retries, leaving the release `verifying`; a
    /// deterministic failure like a rejected signature still rejects.
    #[sqlx::test]
    async fn an_internal_read_retries_but_a_bad_signature_rejects(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut state, release_id, _commit) =
            verify_fixture(&pool, dir.path(), &[("a.txt", b"hi\n")], &["a.txt"]).await;

        // Forced internal failure: the git binary cannot spawn.
        state.git_bin = "/nonexistent/git".to_string();
        let err = verify_release(&state, release_id)
            .await
            .expect_err("an internal read failure propagates");
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
        let (state_str, _) = release_state(&pool, release_id).await;
        assert_eq!(
            state_str, "verifying",
            "a retryable failure must not settle the row"
        );

        // A deterministic failure still rejects: a second commit carrying
        // a signature that does not verify. The first row stays `verifying`
        // (that is the point of the leg above), but the one-verifying-per-
        // publisher index admits no second row until it settles.
        sqlx::query("UPDATE model_releases SET state = 'rejected' WHERE id = $1")
            .bind(release_id)
            .execute(&pool)
            .await
            .expect("settle first row for leg two");
        state.git_bin = "git".to_string();
        std::fs::write(dir.path().join(".twigpine/model-release.sig"), "AAAA").expect("bad sig");
        git(dir.path(), &["add", ".twigpine/model-release.sig"]);
        git(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "r2",
            ],
        );
        let commit2 = git(dir.path(), &["rev-parse", "HEAD"]);
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let owner_did =
            twigpine_core::did::Did::from_verifying_key(&signing.verifying_key()).to_string();
        let manifest_sha = twigpine_core::cid::sha256_hex(
            &std::fs::read(dir.path().join(".twigpine/model-release.json")).expect("manifest"),
        );
        let release_id2: i64 = sqlx::query_scalar(
            "INSERT INTO model_releases
                 (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
                  claim_signature, claim_signature_input, claim_signing_string,
                  claim_body, claim_request_digest, created_at)
             VALUES ('r1', $1, 'main', $2, 'verifying', $3, 's', 'i', 'ss',
                     decode('00','hex'), 'd2', $4)
             RETURNING id",
        )
        .bind(&commit2)
        .bind(&owner_did)
        .bind(manifest_sha)
        .bind(chrono::Utc::now().to_rfc3339())
        .fetch_one(&pool)
        .await
        .expect("release row");
        verify_release(&state, release_id2)
            .await
            .expect("verify call");
        let (state_str, reason) = release_state(&pool, release_id2).await;
        assert_eq!(state_str, "rejected");
        assert!(reason
            .expect("failure_reason")
            .contains("manifest re-check failed"),);
    }

    /// A git-stored manifest file whose name needs quoting under
    /// core.quotePath (`README-é.md`) still verifies: ls-tree -z must not
    /// quote it into a phantom mismatch.
    #[sqlx::test]
    async fn a_non_ascii_git_file_verifies(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, release_id, _commit) = verify_fixture(
            &pool,
            dir.path(),
            &[("README-é.md", b"hi\n")],
            &["README-é.md"],
        )
        .await;
        verify_release(&state, release_id).await.expect("verify");
        let (state_str, _) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "published");
    }

    /// The same committed-but-unlisted check must still fire on a non-ASCII
    /// path the manifest does not name.
    #[sqlx::test]
    async fn an_unlisted_non_ascii_commit_is_still_rejected(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, release_id, _commit) = verify_fixture(
            &pool,
            dir.path(),
            &[("README-é.md", b"hi\n"), ("extra-é.bin", b"x")],
            &["README-é.md"],
        )
        .await;
        verify_release(&state, release_id)
            .await
            .expect("verify call");
        let (state_str, reason) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "rejected");
        let reason = reason.expect("failure_reason");
        assert!(
            reason.contains("committed but not in the manifest"),
            "{reason}"
        );
        assert!(reason.contains("extra-é.bin"), "{reason}");
    }
    async fn ref_exists(dir: &std::path::Path, commit: &str) -> bool {
        std::process::Command::new("git")
            .args(["show-ref", "--verify", "-q"])
            .arg(format!("refs/gitlawb/releases/{commit}"))
            .current_dir(dir)
            .status()
            .expect("git runs")
            .success()
    }

    /// Rejecting a release removes the hidden pin a failed pass left behind,
    /// and leaves the ref of a release that is actually published alone.
    #[sqlx::test]
    async fn rejecting_a_release_drops_its_pin_but_not_a_published_ones(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, release_id, commit) =
            verify_fixture(&pool, dir.path(), &[("a.txt", b"hi\n")], &["a.txt"]).await;
        write_release_ref(&state.git_bin, dir.path(), &commit)
            .await
            .expect("write ref");
        assert!(ref_exists(dir.path(), &commit).await);
        reject_release(&state, release_id, "test")
            .await
            .expect("reject");
        assert_eq!(release_state(&pool, release_id).await.0, "rejected");
        assert!(!ref_exists(dir.path(), &commit).await, "pin must be gone");

        sqlx::query("UPDATE model_releases SET state = 'published' WHERE id = $1")
            .bind(release_id)
            .execute(&pool)
            .await
            .expect("publish");
        write_release_ref(&state.git_bin, dir.path(), &commit)
            .await
            .expect("write ref");
        reject_release(&state, release_id, "late")
            .await
            .expect("no-op reject");
        assert_eq!(release_state(&pool, release_id).await.0, "published");
        assert!(
            ref_exists(dir.path(), &commit).await,
            "published keeps its pin"
        );
    }

    /// A git-stored file past the metadata read cap still verifies: the
    /// blob is hashed as a stream, never held whole.
    #[sqlx::test]
    async fn a_9_mib_git_file_verifies(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let big = vec![b'a'; 9 * 1024 * 1024];
        let (state, release_id, _commit) =
            verify_fixture(&pool, dir.path(), &[("big.txt", &big)], &["big.txt"]).await;
        verify_release(&state, release_id).await.expect("verify");
        let (state_str, reason) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "published", "{reason:?}");
    }

    #[sqlx::test]
    async fn a_9_mib_git_file_with_a_wrong_hash_is_rejected(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let big = vec![b'a'; 9 * 1024 * 1024];
        let (state, release_id, _commit) =
            verify_fixture(&pool, dir.path(), &[("big.txt", &big)], &["big.txt"]).await;
        // Rewrite the manifest with a wrong sha256 for the same file.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let raw = std::fs::read(dir.path().join(".twigpine/model-release.json")).expect("read");
        let mut manifest: Manifest = serde_json::from_slice(&raw).expect("manifest");
        manifest.files[0].sha256 = twigpine_core::cid::sha256_hex(b"other");
        let bytes = manifest.to_bytes().expect("bytes");
        let sig = twigpine_core::model::manifest::sign(&signing, &bytes);
        std::fs::write(dir.path().join(".twigpine/model-release.json"), &bytes).expect("m");
        std::fs::write(dir.path().join(".twigpine/model-release.sig"), sig).expect("s");
        git(dir.path(), &["add", ".twigpine"]);
        git(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--amend",
                "-m",
                "r1",
            ],
        );
        let commit = git(dir.path(), &["rev-parse", "HEAD"]);
        sqlx::query("UPDATE model_releases SET commit_sha = $1 WHERE id = $2")
            .bind(&commit)
            .bind(release_id)
            .execute(&pool)
            .await
            .expect("update");
        sqlx::query("UPDATE model_releases SET manifest_sha256 = $1 WHERE id = $2")
            .bind(twigpine_core::cid::sha256_hex(&bytes))
            .bind(release_id)
            .execute(&pool)
            .await
            .expect("update");
        verify_release(&state, release_id)
            .await
            .expect("verify call");
        let (state_str, reason) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "rejected", "{reason:?}");
        assert!(reason
            .expect("reason")
            .contains("git blob does not match the manifest"));
    }

    /// Distinct invalid-UTF-8 names must not collapse onto a manifest entry
    /// named with U+FFFD: the committed-subset check compares raw bytes.
    #[sqlx::test]
    async fn an_invalid_utf8_name_does_not_match_a_replacement_char_name(pool: sqlx::PgPool) {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let (state, release_id, _commit) = verify_fixture(
            &pool,
            dir.path(),
            &[("\u{FFFD}.bin", b"x")],
            &["\u{FFFD}.bin"],
        )
        .await;
        let bad = std::ffi::OsStr::from_bytes(b"\xFF.bin");
        std::fs::write(dir.path().join(bad), b"smuggled").expect("bad name");
        git(dir.path(), &["add", "-A"]);
        git(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--amend",
                "-m",
                "r1",
            ],
        );
        let commit = git(dir.path(), &["rev-parse", "HEAD"]);
        sqlx::query("UPDATE model_releases SET commit_sha = $1 WHERE id = $2")
            .bind(&commit)
            .bind(release_id)
            .execute(&pool)
            .await
            .expect("update");
        verify_release(&state, release_id)
            .await
            .expect("verify call");
        let (state_str, reason) = release_state(&pool, release_id).await;
        assert_eq!(state_str, "rejected", "{reason:?}");
        assert!(reason
            .expect("reason")
            .contains("committed but not in the manifest"));
    }
}
