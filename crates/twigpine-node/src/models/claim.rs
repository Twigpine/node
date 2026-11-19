//! Release claim: the commit point. The ordered checks from KTD5 run here;
//! the check-then-act tail (other-verifying probe, quota reservation, release
//! insert) runs inside one transaction under the claim advisory lock.

use twigpine_core::model::manifest::{Manifest, StorageKind};

use crate::db::model_queries::ClaimPersist;
use crate::db::RepoRecord;
use crate::error::AppError;
use crate::state::AppState;

use super::{ReleaseRow, CLAIM_LOCK_KEY};

/// Everything the handler verified about the signed request, threaded so the
/// release row is the replay ledger: a replayed claim resolves by request
/// digest to the original row instead of writing a second one.
pub struct ClaimMaterial {
    pub request_digest: String,
    pub signature: String,
    pub signature_input: String,
    pub signing_string: String,
    pub body: Vec<u8>,
}

fn bad_request(msg: impl Into<String>) -> AppError {
    AppError::BadRequest(msg.into())
}

pub(crate) async fn git_show(
    git_bin: &str,
    disk_path: &std::path::Path,
    commit: &str,
    path: &str,
) -> Result<Option<Vec<u8>>, AppError> {
    let spec = format!("{commit}:{path}");
    let out = crate::git::store::run_git_bounded(
        git_bin,
        disk_path,
        &["show", &spec],
        b"",
        std::time::Duration::from_secs(30),
        "git show",
    )
    .await
    .map_err(AppError::Internal)?;
    if out.status.success() {
        return Ok(Some(out.stdout));
    }
    match out.status.code() {
        // Path missing inside a real commit: honest absence.
        Some(128) => Ok(None),
        _ => Err(AppError::Internal(anyhow::anyhow!(
            "git show {spec} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(256)
                .collect::<String>()
        ))),
    }
}

pub async fn commit_exists(
    git_bin: &str,
    disk_path: &std::path::Path,
    sha: &str,
) -> Result<bool, AppError> {
    let out = crate::git::store::run_git_bounded(
        git_bin,
        disk_path,
        &["cat-file", "-e", &format!("{sha}^{{commit}}")],
        b"",
        std::time::Duration::from_secs(30),
        "git cat-file",
    )
    .await
    .map_err(AppError::Internal)?;
    Ok(out.status.success())
}

/// Read and anchor-verify the release manifest at `commit`. The verifying key
/// comes from the repo owner DID (the independent anchor), never the artifact.
pub(crate) async fn read_verified_manifest(
    git_bin: &str,
    disk_path: &std::path::Path,
    commit: &str,
    owner_did: &str,
) -> Result<(Vec<u8>, Manifest), AppError> {
    let manifest_bytes = git_show(git_bin, disk_path, commit, ".twigpine/model-release.json")
        .await?
        .ok_or_else(|| bad_request("commit carries no .twigpine/model-release.json"))?;
    let sig_text = git_show(git_bin, disk_path, commit, ".twigpine/model-release.sig")
        .await?
        .ok_or_else(|| bad_request("commit carries no .twigpine/model-release.sig"))?;
    let sig_text =
        String::from_utf8(sig_text).map_err(|_| bad_request("model-release.sig is not utf-8"))?;
    let did: twigpine_core::did::Did = crate::db::canonical_did(owner_did)
        .parse()
        .map_err(|_| bad_request("repo owner DID does not resolve"))?;
    let manifest = twigpine_core::model::manifest::verify(&manifest_bytes, &sig_text, &did)
        .map_err(|e| bad_request(format!("manifest signature rejected: {e}")))?;
    Ok((manifest_bytes, manifest))
}

/// Claim `commit` on `branch` as a model release. The handler has already
/// proven the feature flag, the owner gate, and full publicity; everything
/// from the manifest read down runs here.
pub async fn claim_release(
    state: &AppState,
    record: &RepoRecord,
    caller: &str,
    commit: &str,
    branch: &str,
    material: &ClaimMaterial,
) -> Result<ReleaseRow, AppError> {
    let db = &state.db;
    let disk_path = std::path::PathBuf::from(&record.disk_path);

    if !commit_exists(&state.git_bin, &disk_path, commit).await? {
        return Err(bad_request("commit not found in this repository"));
    }
    let (manifest_bytes, manifest) =
        read_verified_manifest(&state.git_bin, &disk_path, commit, &record.owner_did).await?;
    let expected_repo = format!(
        "{}/{}",
        crate::db::canonical_did(&record.owner_did),
        record.name
    );
    if manifest.repo != expected_repo {
        return Err(bad_request("manifest names a different repository"));
    }
    if manifest.reconstruction.is_none()
        && manifest
            .files
            .iter()
            .any(|f| matches!(f.storage, StorageKind::Chunked))
    {
        return Err(bad_request(
            "chunked files declared but the manifest has no reconstruction object",
        ));
    }
    let m_sha = twigpine_core::cid::sha256_hex(&manifest_bytes);
    let rec_sha = manifest.reconstruction.as_ref().map(|r| r.sha256.clone());
    let blocks = super::referenced_blocks(state, &manifest).await?;

    // Resolve the declared parent before the transaction: the repo lookup
    // uses its own pool connection and must not sit behind the global
    // advisory lock, where pool pressure would stall every claim.
    let parent = match &manifest.parent {
        None => None,
        Some(parent) => {
            let (powner, pname) = parent
                .repo
                .split_once('/')
                .ok_or_else(|| bad_request("declared parent repo is not owner/name"))?;
            // A parent only confers blocks while its repo is fully public:
            // a withdrawn parent cannot launder references.
            let (precord, prules) =
                crate::api::authorize_repo_read(state, powner, pname, Some(caller), "/").await?;
            if !precord.is_public || !prules.is_empty() {
                return Err(bad_request(
                    "declared parent's repo is no longer fully public",
                ));
            }
            Some((precord.id, parent.commit.clone()))
        }
    };

    let mut tx = db.model_begin().await?;
    db.model_tx_advisory_lock(&mut tx, CLAIM_LOCK_KEY).await?;

    // Replay by request digest, then idempotent re-claim by (repo, commit):
    // both return the original row.
    if let Some(existing) = db
        .model_tx_release_by_digest(&mut tx, &material.request_digest)
        .await?
    {
        tx.commit().await?;
        return Ok(existing);
    }
    if let Some(existing) = db
        .model_tx_release_by_commit(&mut tx, &record.id, commit)
        .await?
    {
        tx.commit().await?;
        return Ok(existing);
    }

    // Lock the referenced block rows so a racing sweep cannot delete one
    // mid-claim, and require each to exist.
    if !blocks.is_empty() {
        let present: std::collections::HashSet<String> = db
            .model_tx_lock_present_blocks(&mut tx, &blocks)
            .await?
            .into_iter()
            .collect();
        if let Some(missing) = blocks.iter().find(|b| !present.contains(b.as_str())) {
            return Err(bad_request(format!(
                "manifest references block {} which is not stored on this node",
                missing.get(..16).unwrap_or(missing)
            )));
        }
    }

    // Authorization: every referenced block must arrive through the caller's
    // open session, a live release of the caller's, or the declared parent.
    let caller_session_blocks: std::collections::HashSet<String> = db
        .model_tx_session_blocks(&mut tx, caller)
        .await?
        .into_iter()
        .collect();
    let caller_release_blocks: std::collections::HashSet<String> = db
        .model_tx_publisher_release_blocks(&mut tx, caller)
        .await?
        .into_iter()
        .collect();
    let parent_blocks: std::collections::HashSet<String> = match &parent {
        None => std::collections::HashSet::new(),
        Some((prepo_id, pcommit)) => {
            let rows = db
                .model_tx_release_blocks_at_commit(&mut tx, prepo_id, pcommit)
                .await?;
            if rows.is_empty() {
                return Err(bad_request(
                    "declared parent is not a published release on this node",
                ));
            }
            rows.into_iter().collect()
        }
    };
    for b in &blocks {
        let allowed = caller_session_blocks.contains(b)
            || caller_release_blocks.contains(b)
            || parent_blocks.contains(b);
        if !allowed {
            return Err(bad_request(format!(
                "block {} is not reachable through an open session, a prior \
                 release, or the declared parent",
                b.get(..16).unwrap_or(b)
            )));
        }
    }

    // One verifying release per publisher.
    if db.model_tx_has_verifying(&mut tx, caller).await? {
        return Err(AppError::Conflict(
            "another release is still verifying; wait for it to settle".into(),
        ));
    }

    // New bytes are the distinct blocks not already claimed by any live
    // release anywhere: first claimer pays, dedup stays free.
    let new_bytes = db.model_tx_unclaimed_bytes(&mut tx, &blocks).await?;

    // Per-identity quota, atomically.
    let did_cap = state.config.model_quota_bytes as i64;
    let admitted = db
        .model_tx_reserve_quota(&mut tx, caller, new_bytes, did_cap)
        .await?;
    if new_bytes > 0 && admitted.is_none() {
        return Err(bad_request(format!(
            "per-publisher model quota ({did_cap} bytes) would be exceeded"
        )));
    }

    let persist = ClaimPersist {
        signature: material.signature.clone(),
        signature_input: material.signature_input.clone(),
        signing_string: material.signing_string.clone(),
        body: material.body.clone(),
        request_digest: material.request_digest.clone(),
    };
    let row = db
        .model_tx_insert_release(
            &mut tx,
            &record.id,
            commit,
            branch,
            caller,
            &m_sha,
            rec_sha.as_deref(),
            &persist,
        )
        .await?;
    let release_id = row.id;

    // Claimed blocks leave the caller's open sessions' charge: the
    // release now carries them. This must precede the node-cap check or
    // the just-claimed bytes count twice (once under quota, once under
    // the sessions they still appear linked to).
    db.model_tx_link_release_blocks(&mut tx, release_id, caller, &blocks)
        .await?;

    // Node-wide quota in the same transaction: claimed bytes plus open
    // session bytes.
    let node_cap = state.config.model_node_quota_bytes as i64;
    let node_total = db.model_tx_node_used(&mut tx).await?;
    if node_total > node_cap {
        return Err(AppError::TooManyRequests(format!(
            "node model storage cap ({node_cap} bytes) would be exceeded"
        )));
    }

    tx.commit().await?;

    // Pin the commit under the hidden release ref now: between claim and
    // publish a force-push plus gc could drop the commit the verifier
    // needs. Best-effort; the publish path writes it again.
    if let Err(e) = super::verify::write_release_ref(&state.git_bin, &disk_path, commit).await {
        tracing::warn!(%commit, "release ref write at claim failed: {e}");
    }
    Ok(row)
}
