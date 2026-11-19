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
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if !record.is_public || !rules.is_empty() {
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
        &["ls-tree", "-r", "--name-only", &release.commit_sha],
        b"",
        std::time::Duration::from_secs(30),
        "git ls-tree",
    )
    .await
    .map_err(AppError::Internal)?;
    let manifest_git_paths: std::collections::HashSet<&str> = manifest
        .files
        .iter()
        .filter(|f| f.storage == StorageKind::Git)
        .map(|f| f.path.as_str())
        .collect();
    for path in String::from_utf8_lossy(&tree.stdout)
        .lines()
        .filter(|p| !p.starts_with(".twigpine/"))
    {
        if !manifest_git_paths.contains(path) {
            return reject_release(
                state,
                release_id,
                &format!("{path} is committed but not in the manifest"),
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
                match super::claim::git_show(
                    &state.git_bin,
                    &disk_path,
                    &release.commit_sha,
                    &file.path,
                )
                .await
                {
                    Ok(Some(bytes)) => {
                        let got = twigpine_core::cid::sha256_hex(&bytes);
                        if got != file.sha256 || bytes.len() as u64 != file.size {
                            return reject_release(
                                state,
                                release_id,
                                &format!("{}: git blob does not match the manifest", file.path),
                            )
                            .await;
                        }
                        let detected = detect_format(&bytes[..bytes.len().min(64)], &file.path);
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
                    Ok(None) => {
                        return reject_release(
                            state,
                            release_id,
                            &format!("{}: not present in the claimed commit", file.path),
                        )
                        .await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    // Publish: hidden ref first, then the state flip, so a crash leaves a
    // verifying row the worker retries rather than a dangling ref.
    write_release_ref(&state.git_bin, &disk_path, &release.commit_sha).await?;
    if !state.db.model_mark_published(release_id).await? {
        // The stale-verify sweep rejected the row while this pass ran:
        // drop the ref just written so it does not advertise a rejected
        // commit.
        let ref_name = format!("refs/gitlawb/releases/{}", release.commit_sha);
        let _ = crate::git::store::run_git_bounded(
            &state.git_bin,
            &disk_path,
            &["update-ref", "-d", &ref_name],
            b"",
            std::time::Duration::from_secs(30),
            "git update-ref",
        )
        .await;
    }
    Ok(())
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
        crate::git::store::run_git_bounded(
            git_bin,
            disk_path,
            &["config", "--add", key, value],
            b"",
            std::time::Duration::from_secs(30),
            "git config --add",
        )
        .await
        .map_err(AppError::Internal)?;
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
    Ok(())
}

/// Poll for `verifying` releases and verify them in order. Spawned once per
/// node when model hosting is enabled; exits on node shutdown.
pub async fn run_verify_worker(state: AppState) {
    let mut shutdown_rx = state.subscribe_shutdown();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
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
        for id in ids {
            if let Err(e) = verify_release(&state, id).await {
                tracing::warn!("model release {id} verification errored: {e}");
            }
        }
    }
}
