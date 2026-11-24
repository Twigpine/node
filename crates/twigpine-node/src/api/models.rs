//! Open-weight model hosting routes: signed upload-session open, unsigned
//! bearer-session block ingest, signed release claim, and the publisher
//! status reads. Mounted only when the operator enables model hosting; every
//! handler re-checks `state.block_store` so a disabled node answers the same
//! not-found as an unmounted route.

use axum::extract::{Path, Request, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;

use crate::api::{authorize_repo_read, require_repo_owner};
use crate::auth::{AuthenticatedDid, SignatureMaterial};
use crate::blockstore::{BlockId, BlockStoreError, PutOutcome};
use crate::db::{RepoRecord, VisibilityRule};
use crate::error::{AppError, Result};
use crate::models;
use crate::state::AppState;

/// `X-Twigpine-Model-Session`: the bearer credential on block PUTs. The
/// session id is a 256-bit random capability minted at session open; there
/// is no HTTP signature on the PUT because a 64 MiB signed body would have
/// to be buffered whole to verify.
pub const SESSION_HEADER: &str = "x-twigpine-model-session";

fn hosting_enabled(state: &AppState) -> Result<()> {
    if state.block_store.is_some() {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "model hosting is not enabled on this node".into(),
        ))
    }
}

/// Model hosting only serves fully public repositories: a private repo, or
/// a public one carrying any path-scoped visibility rule, refuses with a
/// clear 4xx rather than partially publishing.
fn require_fully_public(record: &RepoRecord, rules: &[VisibilityRule]) -> Result<()> {
    // A mirror row (slash-form id) carries a vacuous publicity pair: its
    // is_public is hardcoded true and rules never sync, so passing this
    // check on one means nothing. Mirrors are replication-managed, not
    // publishable; refuse them the same way as a gated canonical repo.
    if !record.is_public || !rules.is_empty() || record.id.contains('/') {
        return Err(AppError::BadRequest(
            "model hosting requires a fully public repository".into(),
        ));
    }
    Ok(())
}

/// POST `/api/v1/repos/{owner}/{repo}/models/sessions` — open an upload
/// session. Owner-only (a session writes bytes the owner is billed for) on a
/// fully public repo.
pub async fn open_model_session(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
    _body: Option<Json<serde_json::Value>>,
) -> Result<impl IntoResponse> {
    hosting_enabled(&state)?;
    let caller = &auth.0;
    let (record, rules) = authorize_repo_read(&state, &owner, &name, Some(caller), "/").await?;
    require_repo_owner(&record, caller)?;
    require_fully_public(&record, &rules)?;
    let session = state
        .db
        .model_open_session(caller, &record.id, state.config.model_session_ttl_secs)
        .await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "session_id": session.id,
            "expires_at": session.expires_at,
        })),
    ))
}

/// GET `/api/v1/repos/{owner}/{repo}/models/sessions/{id}` — owner-only
/// session status.
pub async fn get_model_session(
    State(state): State<AppState>,
    Path((owner, name, id)): Path<(String, String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
) -> Result<Json<serde_json::Value>> {
    hosting_enabled(&state)?;
    let caller = &auth.0;
    let (record, _rules) = authorize_repo_read(&state, &owner, &name, Some(caller), "/").await?;
    require_repo_owner(&record, caller)?;
    let session = state
        .db
        .model_load_session(&id)
        .await?
        .filter(|s| s.repo_id == record.id && s.expires_at > models::ts_now())
        .ok_or_else(|| AppError::NotFound("model upload session not found".into()))?;
    Ok(Json(json!({
        "session_id": session.id,
        "state": session.state,
        "bytes_received": session.bytes_received,
        "expires_at": session.expires_at,
    })))
}

/// PUT `/api/v1/repos/{owner}/{repo}/models/blocks/{sha256}` — stream one
/// content block under a session bearer. Unsigned by design (see
/// [`SESSION_HEADER`]); the gate resolves the session, then runs the repo
/// read check as the session's owner so a repo turned private or withheld
/// mid-upload stops accepting bytes.
pub async fn put_model_block(
    State(state): State<AppState>,
    Path((owner, name, sha)): Path<(String, String, String)>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<serde_json::Value>> {
    hosting_enabled(&state)?;
    let Some(session_id) = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return Err(AppError::Unauthorized(
            "a model block PUT requires the session header".into(),
        ));
    };
    let db = &state.db;
    let Some(session) = db.model_load_session(&session_id).await? else {
        return Err(AppError::NotFound("model upload session not found".into()));
    };
    // authorize_repo_read 404s a repo the session owner can no longer read;
    // the session-to-repo binding check below keeps foreign-session PUTs
    // indistinguishable from a missing session. The owner always reads their
    // own repo, so the fully-public check is what stops bytes landing on a
    // repo that turned private or gained visibility rules mid-upload.
    // mirror-rows-handled: sessions can only bind canonical repos (open
    // refuses slash ids); the id check below already makes a mirror row a
    // mismatch, and the explicit slash guard keeps the publicity pair from
    // being trusted on one.
    let (record, rules) =
        authorize_repo_read(&state, &owner, &name, Some(&session.owner_did), "/").await?;
    if session.repo_id != record.id
        || session.state != "open"
        || session.expires_at <= models::ts_now()
        || !record.is_public
        || !rules.is_empty()
        || record.id.contains('/')
    {
        return Err(AppError::NotFound("model upload session not found".into()));
    }
    let block_id =
        BlockId::parse(&sha).map_err(|e| AppError::BadRequest(format!("block id: {e}")))?;
    let declared: u64 = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError::BadRequest("Content-Length is required".into()))?;
    if declared == 0 || declared > models::MAX_BLOCK_BYTES {
        return Err(AppError::BadRequest(format!(
            "block bodies are 1..{} bytes",
            models::MAX_BLOCK_BYTES
        )));
    }

    // Admission before any byte is stored: the conditional update is the
    // atomic charge against both the per-identity session cap and the
    // node-wide quota, and it slides the session expiry in the same write.
    let session_cap = state.config.effective_model_max_session_bytes() as i64;
    let node_cap = state.config.model_node_quota_bytes as i64;
    let Some(_) = db
        .model_admit_bytes(
            &session.id,
            declared as i64,
            state.config.model_session_ttl_secs,
            session_cap,
            node_cap,
        )
        .await?
    else {
        // Not admitted: re-check whether the session died (404 hides the
        // session) or a cap refused (named quota).
        let session = db
            .model_load_session(&session_id)
            .await?
            .filter(|s| s.state == "open" && s.expires_at > models::ts_now());
        return match session {
            None => Err(AppError::NotFound("model upload session not found".into())),
            Some(_) => Err(AppError::TooManyRequests(format!(
                "the upload would exceed a model storage cap \
                 (session cap {session_cap} bytes, node cap {node_cap} bytes)"
            ))),
        };
    };

    let store = state.block_store.clone().expect("checked above");
    let stream = request
        .into_body()
        .into_data_stream()
        .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())));
    // The store write and its bookkeeping run in one spawned task whose
    // JoinHandle this handler awaits: a client that disconnects after
    // sending the body drops the handler future, and a bare await between
    // put_verified and model_record_block would strand a stored object with
    // no model_blocks row and no refund, which the sweep can never find
    // (its candidate list is model_blocks rows).
    let bookkeep_db = state.db.clone();
    let bookkeep_session = session.id.clone();
    let bookkeep_sha = sha.clone();
    let bookkeeping = tokio::spawn(async move {
        let outcome = match store
            .put_verified(&block_id, Box::pin(stream), models::MAX_BLOCK_BYTES)
            .await
        {
            Ok(o) => o,
            // Unknown outcome: probe once. Present continues as stored,
            // absent refunds, a failed probe quarantines (an unlinked row
            // so the sweep reclaims the object; the charge stays until the
            // session expires).
            Err(BlockStoreError::Unknown) => match store.size(&block_id).await {
                Ok(Some(_)) => PutOutcome::AlreadyPresent,
                Ok(None) => {
                    let _ = bookkeep_db
                        .model_refund_bytes(&bookkeep_session, declared as i64)
                        .await;
                    return Err(AppError::Conflict(
                        "the block was not stored; re-send it".into(),
                    ));
                }
                Err(_) => {
                    let _ = bookkeep_db
                        .model_register_unlinked_block(&bookkeep_sha, declared)
                        .await;
                    return Err(AppError::Conflict(
                        "the write's outcome is unknown; re-send the block".into(),
                    ));
                }
            },
            Err(e) => {
                let _ = bookkeep_db
                    .model_refund_bytes(&bookkeep_session, declared as i64)
                    .await;
                return Err(match e {
                    BlockStoreError::DigestMismatch => AppError::BadRequest(format!(
                        "block body does not hash to the named id {bookkeep_sha}"
                    )),
                    BlockStoreError::TooLarge(cap) => {
                        AppError::BadRequest(format!("block exceeds the {cap}-byte limit"))
                    }
                    BlockStoreError::Body(e) => {
                        AppError::BadRequest(format!("block body could not be read: {e}"))
                    }
                    other => {
                        AppError::Internal(anyhow::anyhow!("block store write failed: {other}"))
                    }
                });
            }
        };
        // Stored and AlreadyPresent both leave the bytes stored. On a tail
        // failure the admission is always refunded, but the object is
        // deleted only when this request stored it AND no model_blocks row
        // names it now: an already-present block, or one a row carries, is
        // shared and must survive.
        let size = match store.size(&block_id).await {
            Ok(Some(s)) => s,
            r => {
                let _ = bookkeep_db
                    .model_refund_bytes(&bookkeep_session, declared as i64)
                    .await;
                if outcome == PutOutcome::Stored
                    && !bookkeep_db
                        .model_block_exists(&bookkeep_sha)
                        .await
                        .unwrap_or(true)
                {
                    let _ = store.delete(&block_id).await;
                }
                return Err(match r {
                    Ok(None) => AppError::Internal(anyhow::anyhow!(
                        "block {bookkeep_sha} absent immediately after write"
                    )),
                    Err(e) => AppError::Internal(anyhow::anyhow!("block size lookup failed: {e}")),
                    Ok(Some(_)) => unreachable!(),
                });
            }
        };
        match bookkeep_db
            .model_record_block(&bookkeep_session, &bookkeep_sha, size, declared as i64)
            .await
        {
            // The committed link now shields the block from the sweep, so
            // this recheck cannot race it: if the object is gone (or
            // unverifiable) undo this request's link and fail closed.
            Ok(duplicate) => match store.size(&block_id).await {
                Ok(Some(_)) => Ok(duplicate),
                _ => {
                    // A duplicate request created no link: there is nothing
                    // of this request's to unlink or refund.
                    if !duplicate {
                        let unlinked = bookkeep_db
                            .model_unlink_session_block(&bookkeep_session, &bookkeep_sha)
                            .await
                            .unwrap_or(false);
                        if unlinked {
                            let _ = bookkeep_db
                                .model_refund_bytes(&bookkeep_session, declared as i64)
                                .await;
                        }
                    }
                    Err(AppError::Conflict(
                        "the block disappeared before it could be linked; re-send it".into(),
                    ))
                }
            },
            Err(e) => {
                let _ = bookkeep_db
                    .model_refund_bytes(&bookkeep_session, declared as i64)
                    .await;
                if outcome == PutOutcome::Stored
                    && !bookkeep_db
                        .model_block_exists(&bookkeep_sha)
                        .await
                        .unwrap_or(true)
                {
                    let _ = store.delete(&block_id).await;
                }
                Err(e.into())
            }
        }
    });
    let duplicate = bookkeeping.await.map_err(|e| {
        AppError::Internal(anyhow::anyhow!("upload bookkeeping task failed: {e}"))
    })??;
    let fresh = db.model_load_session(&session.id).await?;
    Ok(Json(json!({
        "received": fresh.as_ref().map(|s| s.bytes_received).unwrap_or(0),
        "duplicate": duplicate,
        "expires_at": fresh.map(|s| s.expires_at).unwrap_or_default(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ClaimBody {
    pub commit: String,
    pub branch: String,
}

fn release_view(r: &models::ReleaseRow) -> serde_json::Value {
    json!({
        "release_id": r.id,
        "commit": r.commit_sha,
        "branch": r.branch,
        "state": r.state,
        "manifest_sha256": r.manifest_sha256,
        "failure_reason": r.failure_reason,
        "created_at": r.created_at,
        "published_at": r.published_at,
    })
}

/// POST `/api/v1/repos/{owner}/{repo}/models/claims` — claim a pushed commit
/// as a model release. Runs the ordered KTD5 checks; a replay resolves to the
/// original row via the persisted request digest.
pub async fn claim_model_release(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    Extension(auth): Extension<AuthenticatedDid>,
    material: Option<Extension<SignatureMaterial>>,
    Json(body): Json<ClaimBody>,
) -> Result<Json<serde_json::Value>> {
    hosting_enabled(&state)?;
    let caller = &auth.0;
    let (record, rules) = authorize_repo_read(&state, &owner, &name, Some(caller), "/").await?;
    require_repo_owner(&record, caller)?;
    require_fully_public(&record, &rules)?;

    let Some(Extension(material)) = material else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "claim route is missing its signature material"
        )));
    };
    let Some(body_bytes) = material.body.clone() else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "claim route is missing its persisted request body"
        )));
    };
    crate::api::status::require_body_bound_signature(&material, &body_bytes)?;
    if body.commit.len() != 40 || !body.commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("commit must be a 40-hex sha".into()));
    }
    let material = models::claim::ClaimMaterial {
        request_digest: crate::api::status::request_digest(&material, &body_bytes),
        signature: material.signature,
        signature_input: material.signature_input,
        signing_string: material.signing_string,
        body: body_bytes.to_vec(),
    };
    let release = models::claim::claim_release(
        &state,
        &record,
        caller,
        &body.commit,
        &body.branch,
        &material,
    )
    .await?;
    Ok(Json(release_view(&release)))
}

/// GET `/api/v1/repos/{owner}/{repo}/models/releases/{commit}` — release
/// status. Same read gate as the repo's other listing surfaces: anonymous on
/// a public repo, 404 where the caller cannot read.
pub async fn get_model_release(
    State(state): State<AppState>,
    Path((owner, name, commit)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    hosting_enabled(&state)?;
    let caller = auth.map(|Extension(AuthenticatedDid(d))| d);
    let (record, _rules) =
        authorize_repo_read(&state, &owner, &name, caller.as_deref(), "/").await?;
    let release = state
        .db
        .model_release_by_commit(&record.id, &commit)
        .await?
        .ok_or_else(|| AppError::NotFound("model release not found".into()))?;
    Ok(Json(release_view(&release)))
}

/// GET `/api/v1/repos/{owner}/{repo}/models/releases/{commit}/reconstruction`
/// — the reconstruction object of a published release, for publisher-side
/// dedup (KTD6). The repo read gate applies, plus the current-public check:
/// once a repo stops being fully public it stops serving model objects,
/// owner included.
pub async fn get_model_reconstruction(
    State(state): State<AppState>,
    Path((owner, name, commit)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<impl IntoResponse> {
    hosting_enabled(&state)?;
    let caller = auth.map(|Extension(AuthenticatedDid(d))| d);
    // mirror-rows-handled: a mirror row (slash-form id) can never carry a
    // claimed release, and its publicity pair is vacuous, so it takes the
    // same 404 as a private repo.
    let (record, rules) =
        authorize_repo_read(&state, &owner, &name, caller.as_deref(), "/").await?;
    if !record.is_public || !rules.is_empty() || record.id.contains('/') {
        return Err(AppError::NotFound("model release not found".into()));
    }
    let release = state
        .db
        .model_release_by_commit(&record.id, &commit)
        .await?
        .filter(|r| r.state == "published")
        .ok_or_else(|| AppError::NotFound("model release not found".into()))?;
    // The stored reconstruction ref was bound when the release verified;
    // re-reading and re-verifying the manifest per GET is wasted work.
    let Some(sha) = state.db.model_reconstruction_sha(release.id).await? else {
        return Err(AppError::NotFound(
            "release has no reconstruction object".into(),
        ));
    };
    let store = state.block_store.clone().expect("checked above");
    // Only confirmed absence is a 404: an unparsable id, a proven-empty
    // size lookup, or the store's own NotFound. A backend failure is a
    // 500, never an existence-hiding 404.
    let id = BlockId::parse(&sha)
        .map_err(|_| AppError::NotFound("reconstruction object not stored".into()))?;
    let size = match store.size(&id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err(AppError::NotFound("reconstruction object not stored".into()));
        }
        Err(e) => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "reconstruction size lookup failed: {e}"
            )));
        }
    };
    // Stream the object straight into the response body: buffering the whole
    // reconstruction object per anonymous GET would be an uncapped read.
    let stream = store.get_range(&id, 0, size).await.map_err(|e| match e {
        BlockStoreError::NotFound => {
            AppError::NotFound("reconstruction object not stored".into())
        }
        other => AppError::Internal(anyhow::anyhow!("reconstruction read failed: {other}")),
    })?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        axum::body::Body::from_stream(stream),
    ))
}
