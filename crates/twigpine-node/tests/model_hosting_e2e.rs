//! Model-hosting end-to-end (KTD15): a published release must rebuild
//! byte-identically with the node gone.
//!
//! The release is seeded honestly (git objects, block store, published
//! release row) rather than driven through the upload-session/claim/verify
//! pipeline, then the node's OWN durability worker is drained in-process
//! against an in-memory Kubo (`/api/v0/add`, `/ipfs/{cid}`) and an
//! in-memory Irys+Arweave (`/upload`, `/graphql`, `/{tx}`) on the same test
//! server. After the node is shut down, `twigpine_cli::model::fetch_model`
//! rebuilds the release from the providers alone, verifying the manifest
//! signature against the owner DID the test supplies out of band.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header::CONTENT_TYPE, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use twigpine_cli::model::{fetch_model, FetchArgs};
use twigpine_core::cid::sha256_hex;
use twigpine_core::identity::Keypair;
use twigpine_core::model::manifest::{
    self, FileFormat, Manifest, ManifestFile, ReconstructionRef, StorageKind, MANIFEST_SCHEMA_V1,
};
use twigpine_core::model::reconstruction::{
    BlockEntry, ChunkMeta, FileEntry, Reconstruction, Term,
};
use twigpine_node::models::durability::durability_pass;
use twigpine_node::test_harness::{spawn_node_with_args, TestNode};

// ── fake providers ─────────────────────────────────────────────────────────

/// One store serving three provider roles: Kubo (`POST /api/v0/add`,
/// `GET /ipfs/{cid}`), Irys (`POST /upload`), and the Arweave gateway
/// (`POST /graphql`, `GET /{tx}`). Objects are content-addressed the way the
/// node computes them, so a fetch reads back exactly what the durability
/// worker pinned.
#[derive(Clone, Default)]
struct Providers {
    ipfs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    arweave: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}

fn cid_of(bytes: &[u8]) -> String {
    twigpine_core::cid::Cid::from_git_object_bytes(bytes).to_string()
}

/// Pull the single file part out of a reqwest multipart/form-data body: one
/// part, its bytes bracketed by the header separator and the closing
/// boundary marker.
fn multipart_file(content_type: &str, body: &[u8]) -> Option<Vec<u8>> {
    let boundary = content_type.split("boundary=").nth(1)?.trim();
    let start = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)?;
    let mut marker = Vec::with_capacity(boundary.len() + 4);
    marker.extend_from_slice(b"\r\n--");
    marker.extend_from_slice(boundary.as_bytes());
    let end = body[start..]
        .windows(marker.len())
        .position(|w| w == marker.as_slice())
        .map(|i| start + i)?;
    Some(body[start..end].to_vec())
}

async fn kubo_add(
    State(p): State<Providers>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let bytes = multipart_file(ct, &body).ok_or(StatusCode::BAD_REQUEST)?;
    let cid = cid_of(&bytes);
    p.ipfs.lock().unwrap().insert(cid.clone(), bytes);
    // Kubo answers newline-delimited JSON; only `Hash` is read.
    Ok(format!("{{\"Hash\":\"{cid}\"}}\n").into_response())
}

async fn ipfs_get(
    State(p): State<Providers>,
    Path(cid): Path<String>,
) -> Result<Response, StatusCode> {
    match p.ipfs.lock().unwrap().get(&cid) {
        Some(bytes) => Ok(bytes.clone().into_response()),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn irys_upload(State(p): State<Providers>, body: Bytes) -> Response {
    let tx = format!("tx-{}", p.arweave.lock().unwrap().len() + 1);
    p.arweave.lock().unwrap().push((tx.clone(), body.to_vec()));
    json!({ "id": tx }).to_string().into_response()
}

async fn arweave_graphql(State(p): State<Providers>) -> Response {
    let edges: Vec<Value> = p
        .arweave
        .lock()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, (id, _))| {
            json!({
                "cursor": format!("cursor-{id}"),
                "node": { "id": id, "block": { "height": (i + 1) as u64 } },
            })
        })
        .collect();
    json!({
        "data": { "transactions": {
            "pageInfo": { "hasNextPage": false, "endCursor": null },
            "edges": edges,
        } }
    })
    .to_string()
    .into_response()
}

async fn arweave_tx(
    State(p): State<Providers>,
    Path(tx): Path<String>,
) -> Result<Response, StatusCode> {
    match p
        .arweave
        .lock()
        .unwrap()
        .iter()
        .find(|(id, _)| *id == tx)
        .map(|(_, b)| b.clone())
    {
        Some(bytes) => Ok(bytes.into_response()),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Bound URL of the running fake-provider server.
async fn spawn_providers() -> (Providers, String) {
    let p = Providers::default();
    let app = Router::new()
        .route("/api/v0/add", post(kubo_add))
        .route("/ipfs/{cid}", get(ipfs_get))
        .route("/upload", post(irys_upload))
        .route("/graphql", post(arweave_graphql))
        .route("/{tx}", get(arweave_tx))
        .with_state(p.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (p, format!("http://{addr}"))
}

// ── release fixture ────────────────────────────────────────────────────────

const REPO_NAME: &str = "tiny-weights";

struct ReleaseContent {
    commit: String,
    manifest_bytes: Vec<u8>,
    manifest_sha: String,
    rec_bytes: Vec<u8>,
    rec_sha: String,
    signature: String,
    /// block sha -> block bytes (data blocks only; the reconstruction
    /// object is a block too but seeded separately below).
    blocks: Vec<(String, Vec<u8>)>,
    /// manifest path -> expected bytes.
    files: Vec<(String, Vec<u8>)>,
}

fn build_release(owner: &Keypair, repo: &str) -> ReleaseContent {
    let readme = b"# tiny weights\n".to_vec();
    let c1 = b"chunk one of the weights".to_vec();
    let c2 = b"chunk two of the weights".to_vec();
    let c3 = b"chunk three lives in block two".to_vec();
    let model: Vec<u8> = [c1.as_slice(), &c2, &c3].concat();

    let block1: Vec<u8> = [c1.as_slice(), &c2].concat();
    let block2: Vec<u8> = c3.clone();
    let b1sha = sha256_hex(&block1);
    let b2sha = sha256_hex(&block2);

    let rec = Reconstruction {
        schema: "gitlawb/model-reconstruction/v1".to_string(),
        files: vec![FileEntry {
            path: "model.safetensors".to_string(),
            size: model.len() as u64,
            sha256: sha256_hex(&model),
            terms: vec![
                Term {
                    block: b1sha.clone(),
                    chunk_start: 0,
                    chunk_end: 2,
                    length: (c1.len() + c2.len()) as u64,
                },
                Term {
                    block: b2sha.clone(),
                    chunk_start: 0,
                    chunk_end: 1,
                    length: c3.len() as u64,
                },
            ],
        }],
        blocks: vec![
            BlockEntry {
                sha256: b1sha.clone(),
                size: block1.len() as u64,
                chunks: vec![
                    ChunkMeta {
                        sha256: sha256_hex(&c1),
                        len: c1.len() as u64,
                    },
                    ChunkMeta {
                        sha256: sha256_hex(&c2),
                        len: c2.len() as u64,
                    },
                ],
            },
            BlockEntry {
                sha256: b2sha.clone(),
                size: block2.len() as u64,
                chunks: vec![ChunkMeta {
                    sha256: sha256_hex(&c3),
                    len: c3.len() as u64,
                }],
            },
        ],
    };
    let rec_bytes = rec.to_bytes().unwrap();
    let rec_sha = sha256_hex(&rec_bytes);

    let manifest = Manifest {
        schema: MANIFEST_SCHEMA_V1.to_string(),
        repo: repo.to_string(),
        publisher_did: owner.did().to_string(),
        license: "apache-2.0".to_string(),
        parent: None,
        files: vec![
            ManifestFile {
                path: "README.md".to_string(),
                size: readme.len() as u64,
                sha256: sha256_hex(&readme),
                format: FileFormat::Text,
                storage: StorageKind::Git,
            },
            ManifestFile {
                path: "model.safetensors".to_string(),
                size: model.len() as u64,
                sha256: sha256_hex(&model),
                format: FileFormat::Safetensors,
                storage: StorageKind::Chunked,
            },
        ],
        reconstruction: Some(ReconstructionRef {
            sha256: rec_sha.clone(),
            size: rec_bytes.len() as u64,
        }),
    };
    let manifest_bytes = manifest.to_bytes().unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&owner.to_seed());
    let signature = manifest::sign(&signing, &manifest_bytes);

    ReleaseContent {
        commit: String::new(),
        manifest_sha: sha256_hex(&manifest_bytes),
        manifest_bytes,
        rec_bytes,
        rec_sha,
        signature,
        blocks: vec![(b1sha, block1), (b2sha, block2)],
        files: vec![
            ("README.md".to_string(), readme),
            ("model.safetensors".to_string(), model),
        ],
    }
}

/// Seed a published release honestly: git objects (manifest, signature,
/// git-stored files), block-store blocks, the published release row, and
/// release-block links. The claim/verify pipeline is bypassed; the
/// durability worker then does the real outbound work.
async fn seed_release(node: &TestNode, owner: &Keypair) -> (String, String, ReleaseContent) {
    let owner_did = owner.did().to_string();
    let repo = format!("{owner_did}/{REPO_NAME}");
    let repo_id = node.seed_repo(&owner_did, REPO_NAME, true).await;

    let mut rel = build_release(owner, &repo);
    let manifest_text = String::from_utf8(rel.manifest_bytes.clone()).unwrap();
    let files: Vec<(&str, &str)> = vec![
        (".twigpine/model-release.json", manifest_text.as_str()),
        (".twigpine/model-release.sig", rel.signature.as_str()),
        ("README.md", "# tiny weights\n"),
    ];
    let oids = node.seed_bare_repo(&owner_did, REPO_NAME, &files, "sha256");
    rel.commit = oids["HEAD"].clone();
    let git_dir = node.repo_git_dir(&owner_did, REPO_NAME);
    node.set_repo_disk_path(&repo_id, &git_dir).await;

    // The claim path links the reconstruction object sha alongside the data
    // blocks (models::referenced_blocks), so seed the same set.
    node.seed_model_block(&rel.rec_sha, &rel.rec_bytes).await;
    let release_id = node
        .seed_published_model_release(
            &repo_id,
            &rel.commit,
            &owner_did,
            &rel.manifest_sha,
            Some(&rel.rec_sha),
            &rel.signature,
        )
        .await;
    node.link_release_block(release_id, &rel.rec_sha).await;
    for (sha, bytes) in &rel.blocks {
        node.seed_model_block(sha, bytes).await;
        node.link_release_block(release_id, sha).await;
    }
    (repo, format!("{release_id}"), rel)
}

/// Drain the durability worker until no job is pending or failed.
async fn drain_durability(node: &TestNode) {
    for _ in 0..8 {
        durability_pass(node.state()).await.unwrap();
        let open: i64 =
            sqlx::query_scalar("SELECT count(*) FROM model_durability_jobs WHERE state <> 'done'")
                .fetch_one(node.state().db.pool())
                .await
                .unwrap();
        if open == 0 {
            return;
        }
    }
    let rows: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT kind, state, last_error FROM model_durability_jobs ORDER BY id")
            .fetch_all(node.state().db.pool())
            .await
            .unwrap();
    panic!("durability jobs did not drain: {rows:?}");
}

fn fetch_args(repo: &str, owner_did: &str, gateway: &str, out: &std::path::Path) -> FetchArgs {
    FetchArgs {
        repo: repo.to_string(),
        expect_did: owner_did.to_string(),
        revision: None,
        output: Some(out.to_path_buf()),
        arweave_gateway: gateway.to_string(),
        ipfs_gateway: gateway.to_string(),
    }
}

#[sqlx::test]
async fn published_release_rebuilds_without_the_node(pool: sqlx::PgPool) {
    let (providers, gateway) = spawn_providers().await;
    let node = spawn_node_with_args(
        pool,
        &[
            "--model-hosting-enabled",
            "--ipfs-api",
            gateway.as_str(),
            "--irys-url",
            gateway.as_str(),
        ],
    )
    .await;

    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let (repo, _release_id, rel) = seed_release(&node, &owner).await;
    drain_durability(&node).await;

    // The node's own work is done; the rest of this test must not consult it.
    node.shutdown().await;

    let out = tempfile::tempdir().unwrap();
    let report = fetch_model(&fetch_args(
        &repo,
        &owner_did,
        &gateway,
        &out.path().join("one"),
    ))
    .await
    .unwrap();
    assert_eq!(report.files, rel.files.len());
    assert_eq!(report.release_commit, rel.commit);
    assert_eq!(report.anchor_tx, "tx-1");
    for (path, want) in &rel.files {
        let got = std::fs::read(report.output_dir.join(path)).unwrap();
        assert_eq!(&got, want, "{path} did not rebuild byte-identically");
    }

    // A second self-signed anchor by an attacker keypair names its own DID:
    // it sorts newest but must be skipped when fetching with the real owner
    // DID (the anchor's own DID fields are never the verifying key).
    let attacker = Keypair::generate();
    let forged_manifest = Manifest {
        publisher_did: attacker.did().to_string(),
        ..serde_json::from_slice::<Manifest>(&rel.manifest_bytes).unwrap()
    };
    let forged_bytes = forged_manifest.to_bytes().unwrap();
    let forged_sig = manifest::sign(
        &ed25519_dalek::SigningKey::from_bytes(&attacker.to_seed()),
        &forged_bytes,
    );
    let forged_anchor = json!({
        "schema": "gitlawb/model-release-anchor/v1",
        "repo": repo,
        "owner_did": attacker.did().to_string(),
        "release_commit": rel.commit,
        "manifest_sha256": sha256_hex(&forged_bytes),
        "manifest_cid": cid_of(&forged_bytes),
        "reconstruction_sha256": rel.rec_sha,
        "reconstruction_cid": cid_of(&rel.rec_bytes),
        "block_map_cid": "bafy-anything",
        "claim_signature": forged_sig,
        "timestamp": "2026-11-19T00:00:00Z",
        "node_did": "did:key:z6Mkattacker-node",
    });
    providers
        .ipfs
        .lock()
        .unwrap()
        .insert(cid_of(&forged_bytes), forged_bytes);
    reqwest::Client::new()
        .post(format!("{gateway}/upload"))
        .body(forged_anchor.to_string())
        .send()
        .await
        .unwrap();

    let report = fetch_model(&fetch_args(
        &repo,
        &owner_did,
        &gateway,
        &out.path().join("two"),
    ))
    .await
    .unwrap();
    assert_eq!(
        report.anchor_tx, "tx-1",
        "the newer self-signed anchor must be skipped for the real one"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("tx-2")),
        "the skipped forged anchor should leave a warning: {:?}",
        report.warnings
    );

    // Tampered provider bytes must fail the fetch naming the block sha.
    let (block_sha, block_bytes) = &rel.blocks[0];
    let block_cid = cid_of(block_bytes);
    providers
        .ipfs
        .lock()
        .unwrap()
        .insert(block_cid, b"tampered block bytes".to_vec());
    let err = fetch_model(&fetch_args(
        &repo,
        &owner_did,
        &gateway,
        &out.path().join("three"),
    ))
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains(block_sha),
        "the tamper error should name block {block_sha}: {err}"
    );
}
