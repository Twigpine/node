//! HTTP-level coverage for the U5/U6/U7 model-hosting routes: the signed
//! session open and session status, the unsigned bearer block PUT, the signed
//! release claim (including its request-digest replay), and the read-gated
//! release status. The deny sweep already proves the hostile statuses; these
//! tests drive the happy paths and the handler-specific 4xxes the sweep rows
//! cannot express. Requires `--features test-harness`.

#[allow(dead_code)]
mod support;

use serde_json::{json, Value};
use support::bounded_client;
use support::signing::signed_request;

use twigpine_core::cid::sha256_hex;
use twigpine_core::http_sig::sign_request;
use twigpine_core::identity::Keypair;
use twigpine_node::blockstore::{BlockId, BlockStore};
use twigpine_node::test_harness::{spawn_node, spawn_node_with_store, FailOnceSizeStore, TestNode};

fn sessions_path(owner: &str, repo: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/models/sessions")
}

fn claims_path(owner: &str, repo: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/models/claims")
}

fn release_path(owner: &str, repo: &str, commit: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/models/releases/{commit}")
}

fn blocks_path(owner: &str, repo: &str, sha: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/models/blocks/{sha}")
}

fn put_block(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    session: Option<&str>,
    body: Vec<u8>,
) -> reqwest::RequestBuilder {
    let mut req = client.put(format!("{base_url}{path}")).body(body);
    if let Some(s) = session {
        req = req.header("x-twigpine-model-session", s);
    }
    req
}

/// An owner keypair plus the raw SigningKey the manifest format signs with;
/// both derive from one seed so the keypair's DID anchors the manifest.
fn owner_with_signing(seed: u8) -> (Keypair, ed25519_dalek::SigningKey) {
    let seed_bytes = [seed; 32];
    (
        Keypair::from_seed(&seed_bytes).expect("keypair"),
        ed25519_dalek::SigningKey::from_bytes(&seed_bytes),
    )
}

/// Build a git repo on disk containing one commit with a valid signed release
/// manifest, returning the commit sha. The claim route's `git cat-file` /
/// `git show` calls run against `repos.disk_path`, so the row must point here.
fn make_release_repo(dir: &std::path::Path, manifest: &[u8], sig: &str) -> String {
    let run = |args: &[&str]| {
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
    };
    run(&["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(dir.join(".twigpine")).expect("mkdir .twigpine");
    std::fs::write(dir.join(".twigpine/model-release.json"), manifest).expect("write manifest");
    std::fs::write(dir.join(".twigpine/model-release.sig"), sig).expect("write sig");
    run(&["add", "-A"]);
    run(&[
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "-m",
        "model release 1",
    ]);
    run(&["rev-parse", "HEAD"])
}

/// Point the seeded repo row at an on-disk git directory (seed_repo writes a
/// placeholder disk_path the claim route cannot read).
async fn set_disk_path(pool: &sqlx::PgPool, repo_id: &str, dir: &std::path::Path) {
    sqlx::query("UPDATE repos SET disk_path = $1 WHERE id = $2")
        .bind(dir.to_str().expect("utf-8 temp path"))
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("update disk_path");
}

async fn seed_open_session(node: &TestNode, repo_id: &str, owner_did: &str) -> String {
    let session_id = "s".repeat(64);
    node.seed_model_session(repo_id, &session_id, owner_did)
        .await;
    session_id
}

// ── POST /models/sessions ────────────────────────────────────────────────────

/// The owner opening a session on a fully public repo gets 201 and a
/// 64-hex session id plus an expiry.
#[sqlx::test]
async fn open_session_owner_created(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "model", true).await;

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &sessions_path(&owner_did, "model"),
        b"{}".to_vec(),
        &owner,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 201);
    let v: Value = resp.json().await.expect("session body");
    assert_eq!(
        v["session_id"].as_str().map(str::len),
        Some(64),
        "session id is a 256-bit hex bearer"
    );
    assert!(v["expires_at"].as_str().is_some());

    node.shutdown().await;
}

/// A mirror row with no canonical twin carries a vacuous publicity pair:
/// `is_public` is hardcoded true and rules never sync, so neither check may
/// admit it for publishing. Slash-form ids mark mirror rows (issue #244).
#[sqlx::test]
async fn mirror_repo_without_twin_cannot_publish(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO repos
             (id, name, owner_did, description, is_public, default_branch,
              created_at, updated_at, disk_path)
         VALUES ($1,'model',$2,'mirrored from peer',true,'main',$3,$3,'/tmp/mirror-model')",
    )
    .bind(format!("{owner_did}/model"))
    .bind(&owner_did)
    .bind(&now)
    .execute(&pool)
    .await
    .expect("mirror row seeds");

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &sessions_path(&owner_did, "model"),
        b"{}".to_vec(),
        &owner,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 400);

    let body = serde_json::to_vec(&json!({"commit": "0".repeat(40), "branch": "main"})).unwrap();
    let signed = sign_request(&owner, "POST", &claims_path(&owner_did, "model"), &body);
    let resp = client
        .post(format!(
            "{}{}",
            node.base_url,
            claims_path(&owner_did, "model")
        ))
        .header("content-digest", &signed.content_digest)
        .header("signature-input", &signed.signature_input)
        .header("signature", &signed.signature)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status().as_u16(), 400);

    node.shutdown().await;
}

/// A signed caller who is not the repo owner gets the owner gate's 403.
#[sqlx::test]
async fn open_session_non_owner_forbidden(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "model", true).await;

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &sessions_path(&owner_did, "model"),
        b"{}".to_vec(),
        &stranger,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 403);

    node.shutdown().await;
}

/// An unsigned request is stopped by the signature layer before any repo
/// lookup: 401.
#[sqlx::test]
async fn open_session_anon_unauthorized(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    node.seed_repo(&owner_did, "model", true).await;

    let resp = client
        .post(format!(
            "{}{}",
            node.base_url,
            sessions_path(&owner_did, "model")
        ))
        .body(b"{}".to_vec())
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status().as_u16(), 401);

    node.shutdown().await;
}

/// A private repo answers the read gate's existence-hiding 404 to a signed
/// non-reader, before the owner gate can fire.
#[sqlx::test]
async fn open_session_private_repo_hidden(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "model", false).await;

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &sessions_path(&owner_did, "model"),
        b"{}".to_vec(),
        &stranger,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404);

    node.shutdown().await;
}

/// A public repo carrying a path-scoped visibility rule is not "fully
/// public", so the session open refuses it with a named 400 rather than
/// partially publishing.
#[sqlx::test]
async fn open_session_repo_with_visibility_rule_rejected(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    node.withhold_path(&repo_id, "sub/**", &[], &owner_did)
        .await;

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &sessions_path(&owner_did, "model"),
        b"{}".to_vec(),
        &owner,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 400);
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("fully public"),
        "denial should name the fully-public requirement, got: {body}"
    );

    node.shutdown().await;
}

// ── GET /models/sessions/{id} ────────────────────────────────────────────────

/// The owner reads back an open session's state and byte counter.
#[sqlx::test]
async fn get_session_owner_reads_open(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = seed_open_session(&node, &repo_id, &owner_did).await;

    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &format!("{}/{}", sessions_path(&owner_did, "model"), session_id),
        Vec::new(),
        &owner,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("session body");
    assert_eq!(v["session_id"].as_str(), Some(session_id.as_str()));
    assert_eq!(v["state"].as_str(), Some("open"));

    node.shutdown().await;
}

/// A signed stranger reaches the owner gate on the session read: 403.
#[sqlx::test]
async fn get_session_non_owner_forbidden(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = seed_open_session(&node, &repo_id, &owner_did).await;

    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &format!("{}/{}", sessions_path(&owner_did, "model"), session_id),
        Vec::new(),
        &stranger,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 403);

    node.shutdown().await;
}

// ── PUT /models/blocks/{sha256} ──────────────────────────────────────────────

/// The unsigned PUT without the session header gets 401: the bearer
/// credential is absent, not invalid.
#[sqlx::test]
async fn put_block_without_session_header_unauthorized(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    node.seed_repo(&owner_did, "model", true).await;
    let sha = sha256_hex(b"block");

    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        None,
        b"block".to_vec(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 401);

    node.shutdown().await;
}

/// A session id that was never issued answers the same 404 as an expired or
/// foreign one: a bearer guess learns nothing about which part failed.
#[sqlx::test]
async fn put_block_bogus_session_not_found(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    node.seed_repo(&owner_did, "model", true).await;
    let body = b"block".to_vec();
    let sha = sha256_hex(&body);

    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&"f".repeat(64)),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404);

    node.shutdown().await;
}

/// A session bound to repo A does not upload into repo B: the
/// session-to-repo binding check answers 404.
#[sqlx::test]
async fn put_block_session_for_other_repo_not_found(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    let repo_a = node.seed_repo(&owner_did, "model-a", true).await;
    node.seed_repo(&owner_did, "model-b", true).await;
    let session_id = seed_open_session(&node, &repo_a, &owner_did).await;
    let body = b"block".to_vec();
    let sha = sha256_hex(&body);

    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model-b", &sha),
        Some(&session_id),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404);

    node.shutdown().await;
}

/// An open session whose expiry already passed answers 404; the PUT never
/// reaches the block store.
#[sqlx::test]
async fn put_block_expired_session_not_found(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = "e".repeat(64);
    node.seed_model_session(&repo_id, &session_id, &owner_did)
        .await;
    sqlx::query("UPDATE model_upload_sessions SET expires_at = $1 WHERE id = $2")
        .bind((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339())
        .bind(&session_id)
        .execute(&pool)
        .await
        .expect("backdate session expiry");
    let body = b"block".to_vec();
    let sha = sha256_hex(&body);

    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session_id),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404);

    node.shutdown().await;
}

#[sqlx::test]
async fn put_block_happy_path_duplicate_and_digest_mismatch(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = seed_open_session(&node, &repo_id, &owner_did).await;

    let body = b"the quick brown fox".to_vec();
    let sha = sha256_hex(&body);
    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session_id),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("block response");
    assert_eq!(v["duplicate"].as_bool(), Some(false));
    assert!(
        v["received"].as_i64().unwrap_or(0) >= body.len() as i64,
        "bytes_received should include this block: {v}"
    );

    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session_id),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("dup response");
    assert_eq!(v["duplicate"].as_bool(), Some(true));

    let wrong_sha = "0".repeat(64);
    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &wrong_sha),
        Some(&session_id),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 400, "digest mismatch is a 400");

    node.shutdown().await;
}

/// A bookkeeping failure on a PUT whose bytes the store already held (the
/// put reports AlreadyPresent) must not delete the shared object or its
/// model_blocks row, and must refund the second session's admission. The
/// fault seam fails the `size()` call inside the second PUT's bookkeeping
/// tail.
#[sqlx::test]
async fn put_block_failed_bookkeeping_keeps_shared_block(pool: sqlx::PgPool) {
    let repos_dir = tempfile::tempdir().expect("repos dir");
    let block_dir = tempfile::tempdir().expect("block dir");
    let inner: std::sync::Arc<dyn BlockStore> = std::sync::Arc::new(
        twigpine_node::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf())
            .expect("fs store"),
    );
    let failing = std::sync::Arc::new(FailOnceSizeStore::new(inner.clone()));
    let node = spawn_node_with_store(
        pool.clone(),
        repos_dir.path().to_path_buf(),
        failing.clone(),
    )
    .await;
    let client = bounded_client();
    let owner_did = Keypair::generate().did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let body = b"shared-block".to_vec();
    let sha = sha256_hex(&body);
    let block_id = BlockId::parse(&sha).expect("block id");

    // The first PUT stores the block and books it.
    let session1 = seed_open_session(&node, &repo_id, &owner_did).await;
    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session1),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    // The second PUT sees the stored object (AlreadyPresent), then the
    // injected size() failure lands in the bookkeeping tail.
    failing.fail_next_size();
    let session2 = "t".repeat(64);
    node.seed_model_session(&repo_id, &session2, &owner_did)
        .await;
    let resp = put_block(
        &client,
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session2),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 500);

    // The shared object and its model_blocks row survive; the failed
    // session's admission is refunded and it records no link.
    assert_eq!(
        inner.size(&block_id).await.expect("size"),
        Some(body.len() as u64),
        "shared block must not be deleted"
    );
    let block_row: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM model_blocks WHERE sha256 = $1)")
            .bind(&sha)
            .fetch_one(&pool)
            .await
            .expect("block row check");
    assert!(block_row, "model_blocks row must remain");
    let (received, linked): (i64, i64) = sqlx::query_as(
        "SELECT s.bytes_received,
                (SELECT COUNT(*) FROM model_session_blocks l
                  WHERE l.session_id = s.id AND l.block_sha256 = $2)
         FROM model_upload_sessions s WHERE s.id = $1",
    )
    .bind(&session2)
    .bind(&sha)
    .fetch_one(&pool)
    .await
    .expect("session state");
    assert_eq!(received, 0, "admission refunded");
    assert_eq!(linked, 0, "no session link recorded");

    node.shutdown().await;
}

/// Fault wrapper: `put_unknown` makes put_verified return Unknown (after the
/// real write when `Some(true)`); `size_err` fails every size(); `vanish`
/// deletes the object from the inner store on the first size() per digest
/// (the sweep winning between the pre-record check and the link commit).
#[derive(Default)]
struct FaultStore {
    inner: Option<std::sync::Arc<dyn BlockStore>>,
    put_unknown: Option<bool>,
    size_err: bool,
    vanish: bool,
    sized: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl FaultStore {
    fn inner(&self) -> &std::sync::Arc<dyn BlockStore> {
        self.inner.as_ref().expect("inner")
    }
}

#[async_trait::async_trait]
impl BlockStore for FaultStore {
    async fn put_verified(
        &self,
        id: &BlockId,
        body: futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>,
        max_len: u64,
    ) -> Result<twigpine_node::blockstore::PutOutcome, twigpine_node::blockstore::BlockStoreError>
    {
        match self.put_unknown {
            None => self.inner().put_verified(id, body, max_len).await,
            Some(write) => {
                if write {
                    self.inner().put_verified(id, body, max_len).await?;
                }
                Err(twigpine_node::blockstore::BlockStoreError::Unknown)
            }
        }
    }

    async fn get_range(
        &self,
        id: &BlockId,
        start: u64,
        end_exclusive: u64,
    ) -> Result<
        futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>,
        twigpine_node::blockstore::BlockStoreError,
    > {
        self.inner().get_range(id, start, end_exclusive).await
    }

    async fn size(
        &self,
        id: &BlockId,
    ) -> Result<Option<u64>, twigpine_node::blockstore::BlockStoreError> {
        if self.size_err {
            return Err(twigpine_node::blockstore::BlockStoreError::Backend(
                "injected size failure".into(),
            ));
        }
        let real = self.inner().size(id).await?;
        if self.vanish && self.sized.lock().unwrap().insert(id.as_str().to_string()) {
            self.inner().delete(id).await?;
        }
        Ok(real)
    }

    async fn delete(&self, id: &BlockId) -> Result<(), twigpine_node::blockstore::BlockStoreError> {
        self.inner().delete(id).await
    }

    fn backend_name(&self) -> &'static str {
        "fault"
    }
}

/// Spawn a node over a FaultStore, seed repo and session; returns what the
/// fault tests need.
async fn fault_node(
    pool: &sqlx::PgPool,
    fault: impl FnOnce(&mut FaultStore),
) -> (
    TestNode,
    std::sync::Arc<dyn BlockStore>,
    String,
    String,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let repos_dir = tempfile::tempdir().expect("repos dir");
    let block_dir = tempfile::tempdir().expect("block dir");
    let inner: std::sync::Arc<dyn BlockStore> = std::sync::Arc::new(
        twigpine_node::blockstore::fs::FsBlockStore::new(block_dir.path().to_path_buf())
            .expect("fs store"),
    );
    let mut store = FaultStore {
        inner: Some(inner.clone()),
        ..Default::default()
    };
    fault(&mut store);
    let node = spawn_node_with_store(
        pool.clone(),
        repos_dir.path().to_path_buf(),
        std::sync::Arc::new(store),
    )
    .await;
    let owner_did = Keypair::generate().did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session = seed_open_session(&node, &repo_id, &owner_did).await;
    (node, inner, owner_did, session, repos_dir, block_dir)
}

/// (bytes_received, link count, block row count) for a session and sha.
async fn session_block_state(pool: &sqlx::PgPool, session: &str, sha: &str) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT s.bytes_received,
                (SELECT COUNT(*) FROM model_session_blocks l
                  WHERE l.session_id = s.id AND l.block_sha256 = $2),
                (SELECT COUNT(*) FROM model_blocks b WHERE b.sha256 = $2)
         FROM model_upload_sessions s WHERE s.id = $1",
    )
    .bind(session)
    .bind(sha)
    .fetch_one(pool)
    .await
    .expect("session state")
}

/// Unknown write outcome, the probe finds the object: the PUT succeeds as if
/// stored, linked and still charged.
#[sqlx::test]
async fn put_block_unknown_outcome_object_present_succeeds(pool: sqlx::PgPool) {
    let (node, _inner, owner_did, session, _r, _b) =
        fault_node(&pool, |s| s.put_unknown = Some(true)).await;
    let body = b"unknown-present".to_vec();
    let sha = sha256_hex(&body);
    let resp = put_block(
        &bounded_client(),
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let (received, linked, rows) = session_block_state(&pool, &session, &sha).await;
    assert_eq!(received, body.len() as i64, "admission stays charged");
    assert_eq!((linked, rows), (1, 1));
    node.shutdown().await;
}

/// Unknown write outcome, the probe says absent: refund, 409, no row.
#[sqlx::test]
async fn put_block_unknown_outcome_object_absent_refunds(pool: sqlx::PgPool) {
    let (node, _inner, owner_did, session, _r, _b) =
        fault_node(&pool, |s| s.put_unknown = Some(false)).await;
    let body = b"unknown-absent".to_vec();
    let sha = sha256_hex(&body);
    let resp = put_block(
        &bounded_client(),
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 409);
    let (received, linked, rows) = session_block_state(&pool, &session, &sha).await;
    assert_eq!((received, linked, rows), (0, 0, 0));
    node.shutdown().await;
}

/// Unknown write outcome and the probe also errors: quarantine with an
/// unlinked row for the sweep, no refund, 409.
#[sqlx::test]
async fn put_block_unknown_outcome_probe_fails_quarantines(pool: sqlx::PgPool) {
    let (node, _inner, owner_did, session, _r, _b) = fault_node(&pool, |s| {
        s.put_unknown = Some(true);
        s.size_err = true;
    })
    .await;
    let body = b"unknown-quarantine".to_vec();
    let sha = sha256_hex(&body);
    let resp = put_block(
        &bounded_client(),
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session),
        body.clone(),
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 409);
    let (received, linked, rows) = session_block_state(&pool, &session, &sha).await;
    assert_eq!(received, body.len() as i64, "charge kept until expiry");
    assert_eq!((linked, rows), (0, 1));
    node.shutdown().await;
}

/// The object vanishes between the pre-record size() and the link commit
/// (the sweep winning): the PUT fails closed, unlinks and refunds.
#[sqlx::test]
async fn put_block_object_vanishing_before_link_fails_closed(pool: sqlx::PgPool) {
    let (node, inner, owner_did, session, _r, _b) = fault_node(&pool, |s| s.vanish = true).await;
    let body = b"vanishing-block".to_vec();
    let sha = sha256_hex(&body);
    let resp = put_block(
        &bounded_client(),
        &node.base_url,
        &blocks_path(&owner_did, "model", &sha),
        Some(&session),
        body,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 409);
    let (received, linked, _rows) = session_block_state(&pool, &session, &sha).await;
    assert_eq!((received, linked), (0, 0));
    let id = BlockId::parse(&sha).expect("block id");
    assert_eq!(inner.size(&id).await.expect("size"), None);
    node.shutdown().await;
}

/// A session bearer that declares a small Content-Length but streams a larger
/// valid block must not get the larger block stored under the small charge.
/// Both framing headers are sent so the body is read to EOF by chunked
/// framing while the handler still sees the understated length.
#[sqlx::test]
async fn put_block_understated_content_length_is_not_stored_under_small_charge(pool: sqlx::PgPool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let node = spawn_node(pool).await;
    let owner_did = Keypair::generate().did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = seed_open_session(&node, &repo_id, &owner_did).await;

    let body = vec![b'x'; 4096];
    let sha = sha256_hex(&body);
    let addr = node.base_url.trim_start_matches("http://").to_string();
    let mut sock = tokio::net::TcpStream::connect(&addr)
        .await
        .expect("connect");
    let head = format!(
        "PUT {} HTTP/1.1\r\nHost: {addr}\r\nx-twigpine-model-session: {session_id}\r\n\
         Content-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        blocks_path(&owner_did, "model", &sha)
    );
    sock.write_all(head.as_bytes()).await.expect("write head");
    sock.write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .await
        .expect("write chunk size");
    sock.write_all(&body).await.expect("write body");
    sock.write_all(b"\r\n0\r\n\r\n").await.expect("write end");
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw).await;
    let raw = String::from_utf8_lossy(&raw).to_string();
    let status_line = raw.lines().next().unwrap_or("").to_string();
    eprintln!("raw response: {raw}");
    assert!(
        !status_line.contains(" 200 "),
        "a block larger than its declared Content-Length must not be admitted: {status_line}"
    );

    node.shutdown().await;
}

/// An open session past its `expires_at` is dead on the status read too, so
/// the CLI resume path (which abandons a 404) does not keep a lapsed session.
#[sqlx::test]
async fn get_session_expired_open_session_not_found(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let kp = Keypair::generate();
    let owner_did = kp.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let session_id = "f".repeat(64);
    node.seed_model_session(&repo_id, &session_id, &owner_did)
        .await;
    let path = format!("{}/{session_id}", sessions_path(&owner_did, "model"));
    let live = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &path,
        Vec::new(),
        &kp,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(live.status().as_u16(), 200, "a live session reads as open");
    sqlx::query("UPDATE model_upload_sessions SET expires_at = $1 WHERE id = $2")
        .bind((chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339())
        .bind(&session_id)
        .execute(&pool)
        .await
        .expect("backdate session expiry");
    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &path,
        Vec::new(),
        &kp,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404, "a lapsed session is not found");

    node.shutdown().await;
}

// ── POST /models/claims ──────────────────────────────────────────────────────

/// A claim against a pushed commit carrying a signed manifest inserts the
/// release row; re-sending the identical signed request resolves to the same
/// release_id through the persisted request digest.
#[sqlx::test]
async fn claim_accepts_signed_manifest_and_replays_idempotently(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(7);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;

    let manifest = twigpine_core::model::manifest::Manifest {
        schema: twigpine_core::model::manifest::MANIFEST_SCHEMA_V1.to_string(),
        repo: format!("{owner_did}/model"),
        publisher_did: owner_did.clone(),
        license: "mit".to_string(),
        parent: None,
        files: vec![],
        reconstruction: None,
    };
    let manifest_bytes = manifest.to_bytes().expect("manifest bytes");
    let sig = twigpine_core::model::manifest::sign(&signing, &manifest_bytes);

    let dir = tempfile::tempdir().expect("tempdir");
    let commit = make_release_repo(dir.path(), &manifest_bytes, &sig);
    set_disk_path(&pool, &repo_id, dir.path()).await;

    let path = claims_path(&owner_did, "model");
    let body =
        serde_json::to_vec(&json!({"commit": commit, "branch": "main"})).expect("claim body");
    // Sign once, then send the identical request twice: the digest replay
    // resolves the second to the original row.
    let signed = sign_request(&owner, "POST", &path, &body);
    let send = |client: &reqwest::Client| {
        client
            .post(format!("{}{}", node.base_url, path))
            .header("content-digest", &signed.content_digest)
            .header("signature-input", &signed.signature_input)
            .header("signature", &signed.signature)
            .header("content-type", "application/json")
            .body(body.clone())
    };

    let resp = send(&client).send().await.expect("request sends");
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "claim body: {text}");
    let v: Value = serde_json::from_str(&text).expect("claim response");
    let release_id = v["release_id"].as_i64().expect("release_id");
    assert_eq!(v["commit"].as_str(), Some(commit.as_str()));
    assert_eq!(v["state"].as_str(), Some("verifying"));

    let resp = send(&client).send().await.expect("replay sends");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("replay response");
    assert_eq!(
        v["release_id"].as_i64(),
        Some(release_id),
        "a replayed claim must resolve to the original release row"
    );

    node.shutdown().await;
}

/// A claim naming a commit the repo does not hold is a 400, not a 404: the
/// repo exists and is readable; the commit is the bad input.
#[sqlx::test]
async fn claim_missing_commit_is_bad_request(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(8);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;

    // A real on-disk repo is needed for `git cat-file` to answer "missing"
    // rather than the spawn failing on a nonexistent path.
    let manifest = twigpine_core::model::manifest::Manifest {
        schema: twigpine_core::model::manifest::MANIFEST_SCHEMA_V1.to_string(),
        repo: format!("{owner_did}/model"),
        publisher_did: owner_did.clone(),
        license: "mit".to_string(),
        parent: None,
        files: vec![],
        reconstruction: None,
    };
    let manifest_bytes = manifest.to_bytes().expect("manifest bytes");
    let sig = twigpine_core::model::manifest::sign(&signing, &manifest_bytes);
    let dir = tempfile::tempdir().expect("tempdir");
    make_release_repo(dir.path(), &manifest_bytes, &sig);
    set_disk_path(&pool, &repo_id, dir.path()).await;

    let body = serde_json::to_vec(&json!({
        "commit": "b".repeat(40),
        "branch": "main",
    }))
    .expect("claim body");
    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &claims_path(&owner_did, "model"),
        body,
        &owner,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 400);
    let text = resp.text().await.unwrap_or_default();
    assert!(text.contains("commit not found"), "got: {text}");

    node.shutdown().await;
}

/// The owner gate on claims: a signed stranger is 403, an unsigned request is
/// 401 before the handler runs.
#[sqlx::test]
async fn claim_non_owner_forbidden_and_anon_unauthorized(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "model", true).await;
    let body = serde_json::to_vec(&json!({
        "commit": "a".repeat(40),
        "branch": "main",
    }))
    .expect("claim body");

    let resp = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &claims_path(&owner_did, "model"),
        body.clone(),
        &stranger,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 403);

    let resp = client
        .post(format!(
            "{}{}",
            node.base_url,
            claims_path(&owner_did, "model")
        ))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status().as_u16(), 401);

    node.shutdown().await;
}

// ── GET /models/releases/{sha} ───────────────────────────────────────────────

/// A seeded published release reads back its fields; an unknown commit is a
/// plain 404; a private repo's release is existence-hiding to a non-reader.
#[sqlx::test]
async fn release_get_published_unknown_and_private(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "model", true).await;
    let commit = "c".repeat(40);
    node.seed_model_release(&repo_id, &commit, &owner_did).await;

    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            release_path(&owner_did, "model", &commit)
        ))
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("release body");
    assert_eq!(v["commit"].as_str(), Some(commit.as_str()));
    assert_eq!(v["state"].as_str(), Some("published"));
    assert_eq!(v["branch"].as_str(), Some("main"));
    assert!(v["release_id"].as_i64().is_some());
    assert!(v["manifest_sha256"].as_str().is_some());

    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            release_path(&owner_did, "model", &"d".repeat(40))
        ))
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404, "unknown commit is a 404");

    // Private repo: a signed stranger gets the existence-hiding 404.
    let priv_repo = node.seed_repo(&owner_did, "model-priv", false).await;
    node.seed_model_release(&priv_repo, &commit, &owner_did)
        .await;
    let resp = signed_request(
        &client,
        reqwest::Method::GET,
        &node.base_url,
        &release_path(&owner_did, "model-priv", &commit),
        Vec::new(),
        &stranger,
    )
    .send()
    .await
    .expect("request sends");
    assert_eq!(resp.status().as_u16(), 404);

    node.shutdown().await;
}

/// The reconstruction GET and the claims POST hide a repo that is not fully
/// public: callers who fail the read gate (anonymous, stranger) get the same
/// 404 and none reach the store or the commit lookup. The owner can read the
/// repo but fails the fully-public requirement, so the claims POST answers
/// an explicit 400. The deny sweep cannot drive the hostile-only legs for
/// the reconstruction route, so they live here.
#[sqlx::test]
async fn reconstruction_and_claims_deny_on_private_repo(pool: sqlx::PgPool) {
    let node = spawn_node(pool).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "model", false).await;
    let commit = "c".repeat(40);
    let rec_path = format!(
        "{}/reconstruction",
        release_path(&owner_did, "model", &commit)
    );

    for (label, req) in [
        (
            "anon GET reconstruction",
            client.get(format!("{}{}", node.base_url, rec_path)),
        ),
        (
            "stranger GET reconstruction",
            signed_request(
                &client,
                reqwest::Method::GET,
                &node.base_url,
                &rec_path,
                Vec::new(),
                &stranger,
            ),
        ),
        (
            "owner GET reconstruction",
            signed_request(
                &client,
                reqwest::Method::GET,
                &node.base_url,
                &rec_path,
                Vec::new(),
                &owner,
            ),
        ),
        (
            "stranger POST claims",
            signed_request(
                &client,
                reqwest::Method::POST,
                &node.base_url,
                &claims_path(&owner_did, "model"),
                serde_json::to_vec(&serde_json::json!({
                    "commit": commit,
                    "branch": "main",
                }))
                .expect("claim body"),
                &stranger,
            )
            .header("content-type", "application/json"),
        ),
    ] {
        let resp = req.send().await.expect("request sends");
        assert_eq!(resp.status().as_u16(), 404, "{label}");
    }

    // The owner reads their own private repo, so the read gate passes and
    // the fully-public requirement denies with a 400 rather than a 404.
    let owner_claim = signed_request(
        &client,
        reqwest::Method::POST,
        &node.base_url,
        &claims_path(&owner_did, "model"),
        serde_json::to_vec(&serde_json::json!({
            "commit": commit,
            "branch": "main",
        }))
        .expect("claim body"),
        &owner,
    )
    .header("content-type", "application/json")
    .send()
    .await
    .expect("request sends");
    assert_eq!(owner_claim.status().as_u16(), 400, "owner POST claims");

    node.shutdown().await;
}
