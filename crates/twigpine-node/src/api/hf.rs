//! Hugging Face-compatible model read surface (KTD8, KTD9).
//!
//! Endpoints:
//!   GET  /hf/api/models/{owner}/{repo}                 model info
//!   GET  /hf/api/models/{owner}/{repo}/revision/{rev}  revision info
//!   GET  /hf/api/models/{owner}/{repo}/tree/{rev}[/{path}]  file tree
//!   GET  /hf/api/models/{owner}/{repo}/refs            branch refs
//!   HEAD|GET /hf/{owner}/{repo}/resolve/{rev}/{*path}  file bytes
//!
//! Metadata comes from the newest published release row and its manifest,
//! never from arbitrary git history: a plain push after a release does not
//! move HF `main`. Publicity is checked before any release lookup, so a
//! private, mirrored, or rule-bearing repo answers the same 404 as a
//! missing one and releases never leak existence.
//!
//! HF bearer tokens are ignored: `Authorization: Bearer hf_...` carries no
//! signature headers, so the caller reads as anonymous and never gets a
//! 401 from the signature middleware.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde_json::json;
use twigpine_core::model::manifest::{FileFormat, Manifest, StorageKind};
use twigpine_core::model::reconstruction::Reconstruction;

use crate::api::authorize_repo_read;
use crate::api::models::require_fully_public;
use crate::auth::AuthenticatedDid;
use crate::blockstore::BlockStore;
use crate::db::{RepoRecord, VisibilityRule};
use crate::error::AppError;
use crate::models::claim::git_show;
use crate::models::serve::{self, RangeSpec};
use crate::models::ReleaseRow;
use crate::state::AppState;

/// Manifest and signature paths inside the release commit (the same paths
/// `models::claim` reads at claim time).
const MANIFEST_PATH: &str = ".twigpine/model-release.json";

const X_REPO_COMMIT: HeaderName = HeaderName::from_static("x-repo-commit");
const X_ERROR_CODE: HeaderName = HeaderName::from_static("x-error-code");

/// HF error body: `{"error": code}` with the code repeated in
/// `X-Error-Code`, the shape HF clients dispatch on.
fn hf_deny(status: StatusCode, code: &'static str) -> Response {
    let mut resp = (status, axum::Json(json!({"error": code}))).into_response();
    if let Ok(v) = HeaderValue::from_str(code) {
        resp.headers_mut().insert(X_ERROR_CODE, v);
    }
    resp
}

fn hosting_enabled(state: &AppState) -> Result<(), AppError> {
    if state.block_store.is_none() {
        return Err(AppError::NotFound("model hosting not enabled".into()));
    }
    Ok(())
}

/// The caller's DID, or `None` for anonymous. A bearer token is not a
/// signature header, so it never reaches here.
fn caller_did(auth: &Option<Extension<AuthenticatedDid>>) -> Option<&str> {
    auth.as_ref().map(|e| e.0 .0.as_str())
}

/// The second half of the read gate every HF handler runs (the
/// `authorize_repo_read` call itself stays inline in each handler so the
/// egress guard sees it): model hosting serves only a fully public repo,
/// and anything else answers the same bare 404 so release existence cannot
/// be inferred through the model surface.
fn require_fully_public_404(record: &RepoRecord, rules: &[VisibilityRule]) -> Result<(), AppError> {
    if require_fully_public(record, rules).is_err() {
        return Err(AppError::RepoNotFound(record.id.clone()));
    }
    Ok(())
}

/// Resolve the HF revision to a published release row.
///
/// A 40-hex rev is a commit pin. `main` resolves to the newest published
/// release recorded on `main`, then on the repo's git default branch (a
/// `master` default still serves HF `main`). Any other string is a branch
/// name resolving to its newest published release.
async fn release_for_rev(
    state: &AppState,
    record: &RepoRecord,
    rev: &str,
) -> Result<Option<ReleaseRow>, AppError> {
    let rev = rev.trim();
    if rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()) {
        let rel = state
            .db
            .model_release_by_commit(&record.id, rev)
            .await?
            .filter(|r| r.state == "published");
        return Ok(rel);
    }
    if rev == "main" {
        if let Some(rel) = state
            .db
            .model_release_for_branch(&record.id, "main")
            .await?
        {
            return Ok(Some(rel));
        }
        if record.default_branch != "main" {
            return Ok(state
                .db
                .model_release_for_branch(&record.id, &record.default_branch)
                .await?);
        }
        return Ok(None);
    }
    Ok(state.db.model_release_for_branch(&record.id, rev).await?)
}

/// The "no such revision" answer: `RepoNotFound` when the repo has no
/// published release at all, `RevisionNotFound` when releases exist but
/// none match `rev` (KTD8).
async fn revision_or_repo_not_found(
    state: &AppState,
    record: &RepoRecord,
) -> Result<Response, AppError> {
    Ok(
        if state.db.model_release_newest(&record.id).await?.is_none() {
            hf_deny(StatusCode::NOT_FOUND, "RepoNotFound")
        } else {
            hf_deny(StatusCode::NOT_FOUND, "RevisionNotFound")
        },
    )
}

/// Load and re-verify the manifest recorded for a published release. The
/// bytes' sha256 is checked against the release row, and the manifest
/// signature input was already bound to the repo owner DID at claim and
/// verification time, so nothing identity-shaped inside the artifact is
/// trusted here.
async fn load_manifest(
    state: &AppState,
    record: &RepoRecord,
    release: &ReleaseRow,
) -> Result<Manifest, AppError> {
    let disk = std::path::Path::new(&record.disk_path);
    let bytes = git_show(&state.git_bin, disk, &release.commit_sha, MANIFEST_PATH)
        .await?
        .ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "published release {} has no manifest at its commit",
                release.id
            ))
        })?;
    if twigpine_core::cid::sha256_hex(&bytes) != release.manifest_sha256 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "manifest sha mismatch for release {}",
            release.id
        )));
    }
    Manifest::parse(&bytes).map_err(|e| AppError::Internal(anyhow::anyhow!("manifest parse: {e}")))
}

fn siblings(manifest: &Manifest) -> serde_json::Value {
    serde_json::Value::Array(
        manifest
            .files
            .iter()
            .map(|f| {
                let mut o = json!({"rfilename": f.path});
                if f.format == FileFormat::Pickle {
                    o["unsafe"] = json!(true);
                }
                o
            })
            .collect(),
    )
}

fn model_info_json(
    record: &RepoRecord,
    release: &ReleaseRow,
    manifest: &Manifest,
) -> serde_json::Value {
    json!({
        "id": format!("{}/{}", record.owner_did, record.name),
        "modelId": format!("{}/{}", record.owner_did, record.name),
        "sha": release.commit_sha,
        "lastModified": release
            .published_at
            .clone()
            .unwrap_or_else(|| release.created_at.clone()),
        "private": false,
        "gated": false,
        "disabled": false,
        "siblings": siblings(manifest),
        "tags": [],
        "pipeline_tag": null,
        "downloads": 0,
        "likes": 0,
        "library_name": null,
    })
}

/// Manifest files under `prefix` as HF tree entries. `oid` is the file's
/// sha256; chunked files also carry an `lfs` block, and pickle entries an
/// `unsafe` marker, so an HF client knows exactly what it would pull down.
fn tree_entries(manifest: &Manifest, prefix: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for f in &manifest.files {
        if !f.path.starts_with(prefix) {
            continue;
        }
        let mut e = json!({
            "type": "file",
            "path": f.path,
            "size": f.size,
            "oid": f.sha256,
        });
        if f.storage == StorageKind::Chunked {
            e["lfs"] = json!({
                "oid": f.sha256,
                "size": f.size,
                "pointerSize": f.size,
            });
        }
        if f.format == FileFormat::Pickle {
            e["unsafe"] = json!(true);
        }
        out.push(e);
    }
    out
}

/// `GET /hf/api/models/{owner}/{repo}`, model info for the newest
/// published release (`sha` is the release commit, `siblings` the manifest
/// file list).
pub async fn hf_model_info(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    let Some(release) = state.db.model_release_newest(&record.id).await? else {
        return Ok(hf_deny(StatusCode::NOT_FOUND, "RepoNotFound"));
    };
    let manifest = load_manifest(&state, &record, &release).await?;
    Ok(axum::Json(model_info_json(&record, &release, &manifest)).into_response())
}

/// `GET /hf/api/models/{owner}/{repo}/revision/{rev}`, model info pinned
/// to one revision.
pub async fn hf_revision_info(
    State(state): State<AppState>,
    Path((owner, name, rev)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    let Some(release) = release_for_rev(&state, &record, &rev).await? else {
        return revision_or_repo_not_found(&state, &record).await;
    };
    let manifest = load_manifest(&state, &record, &release).await?;
    Ok(axum::Json(model_info_json(&record, &release, &manifest)).into_response())
}

/// `GET /hf/api/models/{owner}/{repo}/tree/{rev}`, flat file list for a
/// revision.
pub async fn hf_tree(
    State(state): State<AppState>,
    Path((owner, name, rev)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    tree_response(&state, &record, &rev, "").await
}

/// `GET /hf/api/models/{owner}/{repo}/tree/{rev}/{*path}`, file list for a
/// path prefix. HF treats a tree path as a directory prefix; entries are
/// flat paths regardless.
pub async fn hf_tree_path(
    State(state): State<AppState>,
    Path((owner, name, rev, path)): Path<(String, String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    let prefix = if path.ends_with('/') {
        path
    } else {
        format!("{path}/")
    };
    tree_response(&state, &record, &rev, &prefix).await
}

async fn tree_response(
    state: &AppState,
    record: &RepoRecord,
    rev: &str,
    prefix: &str,
) -> Result<Response, AppError> {
    let Some(release) = release_for_rev(state, record, rev).await? else {
        return revision_or_repo_not_found(state, record).await;
    };
    let manifest = load_manifest(state, record, &release).await?;
    Ok(axum::Json(serde_json::Value::Array(tree_entries(&manifest, prefix))).into_response())
}

/// `GET /hf/api/models/{owner}/{repo}/refs`: `main` names the newest
/// published release's commit regardless of the repo's git default branch.
/// The HF surface is defined by releases, so a repo with none answers the
/// same RepoNotFound as every other endpoint.
pub async fn hf_refs(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    let Some(release) = state.db.model_release_newest(&record.id).await? else {
        return Ok(hf_deny(StatusCode::NOT_FOUND, "RepoNotFound"));
    };
    let branches = vec![json!({"name": "main", "targetCommit": release.commit_sha})];
    Ok(axum::Json(json!({
        "branches": branches,
        "converts": [],
        "tags": [],
    }))
    .into_response())
}

/// `HEAD|GET /hf/{owner}/{repo}/resolve/{rev}/{*path}`, byte-exact,
/// resumable file bytes (KTD9). `X-Repo-Commit` is on every answer,
/// including `EntryNotFound`, so a client can always pin what it read.
pub async fn hf_resolve(
    State(state): State<AppState>,
    Path((owner, name, rev, path)): Path<(String, String, String, String)>,
    method: Method,
    headers: HeaderMap,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response, AppError> {
    hosting_enabled(&state)?;
    let caller = caller_did(&auth);
    let (record, rules) = authorize_repo_read(&state, &owner, &name, caller, "/").await?;
    require_fully_public_404(&record, &rules)?;
    let Some(release) = release_for_rev(&state, &record, &rev).await? else {
        return revision_or_repo_not_found(&state, &record).await;
    };
    let manifest = load_manifest(&state, &record, &release).await?;
    let Some(file) = manifest.files.iter().find(|f| f.path == path) else {
        let mut resp = hf_deny(StatusCode::NOT_FOUND, "EntryNotFound");
        resp.headers_mut().insert(
            X_REPO_COMMIT,
            HeaderValue::from_str(&release.commit_sha)
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        return Ok(resp);
    };

    let etag = format!("\"{}\"", file.sha256);

    // Conditional request: a client already holding this object (weak or
    // strong match, or `*`) gets a 304 with the same pinning headers, no
    // body and no store read.
    if let Some(cond) = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let hit = cond.trim() == "*"
            || cond.split(',').any(|t| {
                let t = t.trim();
                // If-None-Match compares weakly: strip an optional `W/`.
                let t = t.strip_prefix("W/").unwrap_or(t);
                t.trim_matches('"') == file.sha256
            });
        if hit {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            if let Ok(v) = HeaderValue::from_str(&etag) {
                resp.headers_mut().insert(ETAG, v);
            }
            if let Ok(v) = HeaderValue::from_str(&release.commit_sha) {
                resp.headers_mut().insert(X_REPO_COMMIT, v);
            }
            return Ok(resp);
        }
    }

    let range = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok());
    let if_range = headers
        .get(axum::http::header::IF_RANGE)
        .and_then(|v| v.to_str().ok());
    let spec = serve::resolve(range, if_range, &etag, file.size);
    let (status, _start, len) = match spec {
        RangeSpec::Full => (StatusCode::OK, 0u64, file.size),
        RangeSpec::Single { start, end_incl } => {
            (StatusCode::PARTIAL_CONTENT, start, end_incl - start + 1)
        }
        RangeSpec::Unsatisfiable => {
            let mut resp = hf_deny(StatusCode::RANGE_NOT_SATISFIABLE, "RangeNotSatisfiable");
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{}", file.size)) {
                resp.headers_mut().insert(CONTENT_RANGE, v);
            }
            resp.headers_mut().insert(
                X_REPO_COMMIT,
                HeaderValue::from_str(&release.commit_sha)
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            resp.headers_mut()
                .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            return Ok(resp);
        }
    };

    let mut out_headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&release.commit_sha) {
        out_headers.insert(X_REPO_COMMIT, v);
    }
    if let Ok(v) = HeaderValue::from_str(&etag) {
        out_headers.insert(ETAG, v);
    }
    out_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    out_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&len.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    out_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let RangeSpec::Single { start, end_incl } = spec {
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end_incl}/{}", file.size)) {
            out_headers.insert(CONTENT_RANGE, v);
        }
    }

    if method == Method::HEAD {
        // Headers mirror GET (including a ranged answer's 206/416) without
        // touching the store: a HEAD never opens a block stream.
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = status;
        resp.headers_mut().extend(out_headers);
        return Ok(resp);
    }

    let store: Arc<dyn BlockStore> = state
        .block_store
        .clone()
        .ok_or_else(|| AppError::NotFound("model hosting not enabled".into()))?;
    // Bound concurrent model downloads: a stalled reader upstream must not
    // starve every other consumer of the node.
    let _permit = state
        .model_download_semaphore
        .acquire()
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("download semaphore closed")))?;

    let body = match file.storage {
        StorageKind::Git => {
            // Git-stored files are under the chunking threshold, so one
            // blob read is bounded by definition; a ranged answer slices it.
            let bytes = git_show(
                &state.git_bin,
                std::path::Path::new(&record.disk_path),
                &release.commit_sha,
                &file.path,
            )
            .await?
            .ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "release {} file {} missing from git",
                    release.id,
                    file.path
                ))
            })?;
            match spec {
                RangeSpec::Full => Body::from(bytes),
                RangeSpec::Single { start, .. } => {
                    let s = (start as usize).min(bytes.len());
                    let e = (start as usize + len as usize).min(bytes.len());
                    Body::from(bytes[s..e].to_vec())
                }
                RangeSpec::Unsatisfiable => unreachable!("handled above"),
            }
        }
        StorageKind::Chunked => {
            let rec_ref = manifest.reconstruction.as_ref().ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!(
                    "release {} chunked file has no reconstruction ref",
                    release.id
                ))
            })?;
            let rec_bytes = crate::models::read_block(&store, &rec_ref.sha256, rec_ref.size)
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("reconstruction read: {e}")))?;
            let rec = Reconstruction::parse(&rec_bytes)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("reconstruction parse: {e}")))?;
            let entry = rec
                .files
                .iter()
                .find(|e| e.path == file.path)
                .ok_or_else(|| {
                    AppError::Internal(anyhow::anyhow!(
                        "reconstruction has no entry for {}",
                        file.path
                    ))
                })?;
            let (want_start, want_end) = match spec {
                RangeSpec::Full => (0u64, file.size),
                RangeSpec::Single { start, end_incl } => (start, end_incl + 1),
                RangeSpec::Unsatisfiable => unreachable!("handled above"),
            };
            let slices = twigpine_core::model::reconstruction::map_file_range(
                entry, &rec, want_start, want_end,
            )
            .map_err(|e| AppError::Internal(anyhow::anyhow!("range map: {e}")))?;
            Body::from_stream(serve::slices_stream(store, slices))
        }
    };

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().extend(out_headers);
    Ok(resp)
}
