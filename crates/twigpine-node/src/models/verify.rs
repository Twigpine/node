//! Release verification: rebuild every chunk-stored file, hash it against
//! the manifest, check the declared format against detected bytes, and only
//! then mark the release published (and pin the hidden ref). Rejection frees
//! the quota reservation and drops the block refs.

use sha2::Digest;
use std::io::Write;
use twigpine_core::model::manifest::{detect_format, StorageKind};
use twigpine_core::model::reconstruction::{rebuild_file, Reconstruction};

use crate::error::AppError;
use crate::state::AppState;

/// Sink hashing rebuilt bytes and keeping the head for format detection.
struct VerifySink {
    hasher: sha2::Sha256,
    head: Vec<u8>,
    digest: Option<String>,
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
    let Some(release) = super::release_by_id(&state.db, release_id).await? else {
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
    if super::manifest_sha256(&manifest_bytes) != release.manifest_sha256 {
        return reject_release(state, release_id, "manifest digest changed since claim").await;
    }

    let Some(rec_ref) = &manifest.reconstruction else {
        return reject_release(state, release_id, "manifest has no reconstruction object").await;
    };
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
    let rec = match Reconstruction::parse(&rec_bytes) {
        Ok(r) => r,
        Err(e) => {
            return reject_release(
                state,
                release_id,
                &format!("reconstruction object invalid: {e}"),
            )
            .await;
        }
    };

    for file in &manifest.files {
        match file.storage {
            StorageKind::Chunked => {
                let Some(entry) = rec.files.iter().find(|f| f.path == file.path).cloned() else {
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
                // The rebuild runs on the blocking pool: `rebuild_file` is a
                // sync walker over a range-fetch callback, and the store is
                // async. block_on inside spawn_blocking is honest — the
                // fetch itself is chunk-sized and bounded.
                let store2 = store.clone();
                let rec2 = rec.clone();
                let path = file.path.clone();
                let declared = file.format;
                let built = tokio::task::spawn_blocking(move || {
                    let mut sink = VerifySink {
                        hasher: sha2::Sha256::new(),
                        head: Vec::new(),
                        digest: None,
                    };
                    let mut fetch = |block: &str, off: u64, len: u64| -> std::io::Result<Vec<u8>> {
                        let store3 = store2.clone();
                        let block = block.to_string();
                        futures::executor::block_on(async move {
                            super::read_range(&store3, &block, off, len).await
                        })
                        .map_err(|e| std::io::Error::other(e.to_string()))
                    };
                    rebuild_file(&entry, &rec2, &mut fetch, &mut sink)?;
                    sink.digest = Some(hex::encode(sink.hasher.clone().finalize()));
                    Ok::<_, twigpine_core::model::reconstruction::ModelError>((
                        sink, path, declared,
                    ))
                })
                .await;
                let (sink, path, declared) = match built {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        return reject_release(
                            state,
                            release_id,
                            &format!("{}: rebuild failed: {e}", file.path),
                        )
                        .await;
                    }
                    Err(e) => return Err(AppError::Internal(e.into())),
                };
                if sink.digest.as_deref() != Some(file.sha256.as_str()) {
                    return reject_release(
                        state,
                        release_id,
                        &format!(
                            "{}: rebuilt bytes hash to {}",
                            path,
                            sink.digest.unwrap_or_default()
                        ),
                    )
                    .await;
                }
                let detected = detect_format(&sink.head, &path);
                if detected != declared {
                    return reject_release(
                        state,
                        release_id,
                        &format!(
                            "{path}: declared format {declared:?} but bytes detect as {detected:?}"
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
                        let got = hex::encode(sha2::Sha256::digest(&bytes));
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
    state.db.model_mark_published(release_id).await?;
    Ok(())
}

/// `refs/gitlawb/releases/<commit>` -> the release commit itself: reachable,
/// so `gc` never prunes it, and hidden under the gitlawb ref namespace.
pub async fn write_release_ref(
    git_bin: &str,
    disk_path: &std::path::Path,
    commit: &str,
) -> Result<(), AppError> {
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
/// node when model hosting is enabled.
pub async fn run_verify_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        interval.tick().await;
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
