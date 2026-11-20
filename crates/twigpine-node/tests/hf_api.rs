//! HTTP-level coverage for the HF-compatible read surface (U9/U10): model
//! info, revision, tree, refs, and the resumable resolve route. Each test
//! seeds a real on-disk release commit (signed manifest plus the git-stored
//! files) and, for chunked files, real blocks in the store through the
//! bearer PUT, so the routes read exactly what a published release would
//! serve. Requires `--features test-harness`.

#[allow(dead_code)]
mod support;

use serde_json::Value;
use support::bounded_client;
use support::signing::signed_request;

use twigpine_core::cid::sha256_hex;
use twigpine_core::identity::Keypair;
use twigpine_core::model::manifest::{
    FileFormat, Manifest, ManifestFile, ReconstructionRef, StorageKind, MANIFEST_SCHEMA_V1,
};
use twigpine_core::model::reconstruction::{
    BlockEntry, ChunkMeta, FileEntry, Reconstruction, Term,
};
use twigpine_core::model::RECONSTRUCTION_SCHEMA_V1;
use twigpine_node::test_harness::spawn_node;

fn owner_with_signing(seed: u8) -> (Keypair, ed25519_dalek::SigningKey) {
    let seed_bytes = [seed; 32];
    (
        Keypair::from_seed(&seed_bytes).expect("keypair"),
        ed25519_dalek::SigningKey::from_bytes(&seed_bytes),
    )
}

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
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

/// Build a git repo on disk containing one commit with the signed release
/// manifest, its signature, and the git-stored manifest files, returning
/// the release commit sha.
fn make_release_repo(
    dir: &std::path::Path,
    manifest: &[u8],
    sig: &str,
    git_files: &[(&str, &[u8])],
) -> String {
    run_git(dir, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(dir.join(".twigpine")).expect("mkdir .twigpine");
    std::fs::write(dir.join(".twigpine/model-release.json"), manifest).expect("write manifest");
    std::fs::write(dir.join(".twigpine/model-release.sig"), sig).expect("write sig");
    for (path, bytes) in git_files {
        let p = dir.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir file parent");
        }
        std::fs::write(&p, bytes).expect("write file");
    }
    run_git(dir, &["add", "-A"]);
    run_git(
        dir,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "model release 1",
        ],
    );
    run_git(dir, &["rev-parse", "HEAD"])
}

async fn set_disk_path(pool: &sqlx::PgPool, repo_id: &str, dir: &std::path::Path) {
    sqlx::query("UPDATE repos SET disk_path = $1 WHERE id = $2")
        .bind(dir.to_str().expect("utf-8 temp path"))
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("update disk_path");
}

/// Insert a published release row with the real manifest sha (the seeded
/// row `seed_model_release` pads the commit, which `load_manifest` would
/// correctly refuse). `branch` records which git branch the release came
/// from; `rec_sha` links the reconstruction object.
async fn seed_published_release(
    pool: &sqlx::PgPool,
    repo_id: &str,
    commit: &str,
    branch: &str,
    publisher_did: &str,
    manifest_sha: &str,
    rec_sha: Option<&str>,
    block_shas: &[String],
) -> i64 {
    let now = chrono::Utc::now().to_rfc3339();
    // created_at predates published_at so a test can tell which timestamp
    // the surface reports.
    let created = "2000-01-01T00:00:00Z".to_string();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO model_releases
             (repo_id, commit_sha, branch, publisher_did, state, manifest_sha256,
              reconstruction_sha256, claim_signature, claim_signature_input,
              claim_signing_string, claim_body, created_at, published_at)
         VALUES ($1,$2,$3,$4,'published',$5,$6,'sig','input','signing',\
                 decode('00','hex'),$7,$8)
         RETURNING id",
    )
    .bind(repo_id)
    .bind(commit)
    .bind(branch)
    .bind(publisher_did)
    .bind(manifest_sha)
    .bind(rec_sha)
    .bind(&created)
    .bind(&now)
    .fetch_one(pool)
    .await
    .expect("seed release");
    for sha in block_shas {
        sqlx::query(
            "INSERT INTO model_release_blocks (release_id, block_sha256)
             VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(sha)
        .execute(pool)
        .await
        .expect("link release block");
    }
    id
}

/// Everything a test needs to serve one published release.
struct Fixture {
    commit: String,
}

/// Build a repo dir + manifest + release row. `git_files` are committed
/// into the release; `chunked_files` is `(path, bytes)` split into
/// single-chunk blocks of `chunk_len` bytes, stored in the block store via
/// the bearer PUT (seeded session) and mapped by a real reconstruction
/// object.
async fn seed_release(
    node: &twigpine_node::test_harness::TestNode,
    pool: &sqlx::PgPool,
    owner_did: &str,
    signing: &ed25519_dalek::SigningKey,
    repo_id: &str,
    repo_name: &str,
    git_files: &[(&str, &[u8])],
    chunked_files: &[(&str, &[u8], usize)],
    branch: &str,
) -> Fixture {
    let client = bounded_client();
    // Upload the chunked blocks first so the reconstruction object can
    // name them; the rec object itself is stored as a block too.
    let session = "s".repeat(64);
    if !chunked_files.is_empty() {
        node.seed_model_session(repo_id, &session, owner_did).await;
    }
    let mut blocks: Vec<BlockEntry> = Vec::new();
    let mut rec_files: Vec<FileEntry> = Vec::new();
    let mut block_shas: Vec<String> = Vec::new();
    let mut files: Vec<(String, Vec<u8>, StorageKind, FileFormat)> = Vec::new();
    for (path, data, chunk_len) in chunked_files {
        // One chunk per block keeps the fixture simple while still
        // exercising multi-block ranges when the file spans blocks.
        let mut terms = Vec::new();
        for chunk in data.chunks(*chunk_len) {
            let sha = sha256_hex(chunk);
            let resp = client
                .put(format!(
                    "{}/api/v1/repos/{}/{}/models/blocks/{}",
                    node.base_url, owner_did, repo_name, sha
                ))
                .header("x-twigpine-model-session", &session)
                .body(chunk.to_vec())
                .send()
                .await
                .expect("block put");
            assert_eq!(resp.status().as_u16(), 200, "block put {path}");
            blocks.push(BlockEntry {
                sha256: sha.clone(),
                size: chunk.len() as u64,
                chunks: vec![ChunkMeta {
                    sha256: sha.clone(),
                    len: chunk.len() as u64,
                }],
            });
            block_shas.push(sha.clone());
            terms.push(Term {
                block: sha,
                chunk_start: 0,
                chunk_end: 1,
                length: chunk.len() as u64,
            });
        }
        rec_files.push(FileEntry {
            path: path.to_string(),
            size: data.len() as u64,
            sha256: sha256_hex(data),
            terms,
        });
        files.push((
            path.to_string(),
            data.to_vec(),
            StorageKind::Chunked,
            FileFormat::Safetensors,
        ));
    }
    let rec_bytes = Reconstruction {
        schema: RECONSTRUCTION_SCHEMA_V1.to_string(),
        files: rec_files,
        blocks,
    }
    .to_bytes()
    .expect("rec bytes");
    let rec_sha = if chunked_files.is_empty() {
        None
    } else {
        let sha = sha256_hex(&rec_bytes);
        let resp = client
            .put(format!(
                "{}/api/v1/repos/{}/{}/models/blocks/{}",
                node.base_url, owner_did, repo_name, sha
            ))
            .header("x-twigpine-model-session", &session)
            .body(rec_bytes.clone())
            .send()
            .await
            .expect("rec put");
        assert_eq!(resp.status().as_u16(), 200, "rec object put");
        block_shas.push(sha.clone());
        Some(sha)
    };

    for (path, data) in git_files {
        files.push((
            path.to_string(),
            data.to_vec(),
            StorageKind::Git,
            FileFormat::Text,
        ));
    }

    let manifest = Manifest {
        schema: MANIFEST_SCHEMA_V1.to_string(),
        repo: format!("{owner_did}/{repo_name}"),
        publisher_did: owner_did.to_string(),
        license: "mit".to_string(),
        parent: None,
        files: files
            .iter()
            .map(|(path, data, storage, format)| ManifestFile {
                path: path.clone(),
                size: data.len() as u64,
                sha256: sha256_hex(data),
                format: *format,
                storage: *storage,
            })
            .collect(),
        reconstruction: rec_sha.as_ref().map(|sha| ReconstructionRef {
            sha256: sha.clone(),
            size: rec_bytes.len() as u64,
        }),
    };
    let manifest_bytes = manifest.to_bytes().expect("manifest bytes");
    let manifest_sha = sha256_hex(&manifest_bytes);
    let sig = twigpine_core::model::manifest::sign(signing, &manifest_bytes);

    let dir = tempfile::tempdir().expect("tempdir");
    let git_files: Vec<(&str, &[u8])> = files
        .iter()
        .filter(|(_, _, s, _)| *s == StorageKind::Git)
        .map(|(p, d, _, _)| (p.as_str(), d.as_slice()))
        .collect();
    let commit = make_release_repo(dir.path(), &manifest_bytes, &sig, &git_files);
    set_disk_path(pool, repo_id, dir.path()).await;
    // Keep the tempdir alive past this function: the git dir must outlive
    // the test's HTTP calls.
    let _dir_path = dir.keep();

    seed_published_release(
        pool,
        repo_id,
        &commit,
        branch,
        owner_did,
        &manifest_sha,
        rec_sha.as_deref(),
        &block_shas,
    )
    .await;
    Fixture { commit }
}

fn info_path(owner: &str, repo: &str) -> String {
    format!("/hf/api/models/{owner}/{repo}")
}

fn rev_path(owner: &str, repo: &str, rev: &str) -> String {
    format!("/hf/api/models/{owner}/{repo}/revision/{rev}")
}

fn tree_path(owner: &str, repo: &str, rev: &str) -> String {
    format!("/hf/api/models/{owner}/{repo}/tree/{rev}")
}

fn refs_path(owner: &str, repo: &str) -> String {
    format!("/hf/api/models/{owner}/{repo}/refs")
}

fn resolve_path(owner: &str, repo: &str, rev: &str, path: &str) -> String {
    format!("/hf/{owner}/{repo}/resolve/{rev}/{path}")
}

const GIT_FILE: &[u8] = b"config: a small git-stored file";
const CHUNKED_FILE_CONTENTS: &[u8] = b"0123456789abcdef-weights-bytes-across-two-blocks";

/// One git-stored file plus one chunked file split at 16 bytes (three
/// blocks), so cross-block ranges are exercised.
#[sqlx::test]
async fn model_info_revision_tree_and_refs(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(21);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    let fx = seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[("weights.safetensors", CHUNKED_FILE_CONTENTS, 16)],
        "main",
    )
    .await;

    // Model info: sha is the release commit, siblings carry every manifest
    // file.
    let resp = client
        .get(format!("{}{}", node.base_url, info_path(&owner_did, "m")))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("model info json");
    assert_eq!(v["sha"].as_str(), Some(fx.commit.as_str()));
    let published_at: String =
        sqlx::query_scalar("SELECT published_at FROM model_releases WHERE repo_id = $1")
            .bind(&repo_id)
            .fetch_one(&pool)
            .await
            .expect("read published_at");
    assert_eq!(v["lastModified"].as_str(), Some(published_at.as_str()));
    let sibs: Vec<&str> = v["siblings"]
        .as_array()
        .expect("siblings")
        .iter()
        .filter_map(|s| s["rfilename"].as_str())
        .collect();
    assert_eq!(sibs.len(), 2);
    assert!(sibs.contains(&"config.json"));
    assert!(sibs.contains(&"weights.safetensors"));

    // Revision pinned by commit, and `main` resolving to the same release.
    for rev in [fx.commit.as_str(), "main"] {
        let resp = client
            .get(format!(
                "{}{}",
                node.base_url,
                rev_path(&owner_did, "m", rev)
            ))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 200, "rev {rev}");
        let v: Value = resp.json().await.expect("rev json");
        assert_eq!(v["sha"].as_str(), Some(fx.commit.as_str()));
    }

    // Unknown commit-shaped revision: 404 + X-Error-Code RevisionNotFound.
    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            rev_path(&owner_did, "m", &"9".repeat(40))
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(
        resp.headers()["x-error-code"].to_str().unwrap(),
        "RevisionNotFound"
    );

    // Tree: chunked file carries an lfs block, oid is the file sha256.
    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            tree_path(&owner_did, "m", "main")
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let entries: Vec<Value> = resp.json().await.expect("tree json");
    assert_eq!(entries.len(), 2);
    let chunked = entries
        .iter()
        .find(|e| e["path"].as_str() == Some("weights.safetensors"))
        .expect("chunked entry");
    assert_eq!(
        chunked["oid"].as_str(),
        Some(sha256_hex(CHUNKED_FILE_CONTENTS).as_str())
    );
    assert_eq!(
        chunked["lfs"]["size"].as_u64(),
        Some(CHUNKED_FILE_CONTENTS.len() as u64)
    );
    let git_entry = entries
        .iter()
        .find(|e| e["path"].as_str() == Some("config.json"))
        .expect("git entry");
    assert!(git_entry.get("lfs").is_none());

    // Refs: `main` names the release commit.
    let resp = client
        .get(format!("{}{}", node.base_url, refs_path(&owner_did, "m")))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.expect("refs json");
    assert_eq!(v["branches"][0]["name"].as_str(), Some("main"));
    assert_eq!(
        v["branches"][0]["targetCommit"].as_str(),
        Some(fx.commit.as_str())
    );

    node.shutdown().await;
}

/// A public repo with no release is RepoNotFound; a private repo is the
/// same 404 to anon and stranger; a bearer token is ignored (never 401).
#[sqlx::test]
async fn no_release_private_repo_and_bearer_token(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let owner = Keypair::generate();
    let stranger = Keypair::generate();
    let owner_did = owner.did().to_string();
    node.seed_repo(&owner_did, "m", true).await;

    for path in [
        info_path(&owner_did, "m"),
        refs_path(&owner_did, "m"),
        tree_path(&owner_did, "m", "main"),
    ] {
        let resp = client
            .get(format!("{}{}", node.base_url, path))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 404, "{path}");
        assert_eq!(
            resp.headers()["x-error-code"].to_str().unwrap(),
            "RepoNotFound",
            "{path}"
        );
    }

    // Bearer token is not a signature header: reads as anonymous, 200 or
    // the existence-hiding 404, never 401.
    let resp = client
        .get(format!("{}{}", node.base_url, info_path(&owner_did, "m")))
        .header("authorization", "Bearer hf_faketoken")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 404, "bearer token is ignored");

    // Private repo: anon and signed stranger get the same 404.
    node.seed_repo(&owner_did, "priv", false).await;
    for (label, req) in [
        (
            "anon",
            client.get(format!(
                "{}{}",
                node.base_url,
                info_path(&owner_did, "priv")
            )),
        ),
        (
            "stranger",
            signed_request(
                &client,
                reqwest::Method::GET,
                &node.base_url,
                &info_path(&owner_did, "priv"),
                Vec::new(),
                &stranger,
            ),
        ),
    ] {
        let resp = req.send().await.expect("send");
        assert_eq!(resp.status().as_u16(), 404, "{label}");
    }

    node.shutdown().await;
}

/// Pickle entries carry the unsafe marker in the tree (and siblings).
#[sqlx::test]
async fn pickle_entries_marked_unsafe(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(22);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    let pickle = b"pickle bytes".to_vec();
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA_V1.to_string(),
        repo: format!("{owner_did}/m"),
        publisher_did: owner_did.clone(),
        license: "mit".to_string(),
        parent: None,
        files: vec![ManifestFile {
            path: "model.pkl".to_string(),
            size: pickle.len() as u64,
            sha256: sha256_hex(&pickle),
            format: FileFormat::Pickle,
            storage: StorageKind::Git,
        }],
        reconstruction: None,
    };
    let manifest_bytes = manifest.to_bytes().unwrap();
    let sig = twigpine_core::model::manifest::sign(&signing, &manifest_bytes);
    let dir = tempfile::tempdir().unwrap();
    let commit = make_release_repo(dir.path(), &manifest_bytes, &sig, &[("model.pkl", &pickle)]);
    set_disk_path(&pool, &repo_id, dir.path()).await;
    seed_published_release(
        &pool,
        &repo_id,
        &commit,
        "main",
        &owner_did,
        &sha256_hex(&manifest_bytes),
        None,
        &[],
    )
    .await;

    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            tree_path(&owner_did, "m", "main")
        ))
        .send()
        .await
        .expect("send");
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries[0]["unsafe"].as_bool(), Some(true));

    // Model info marks the same file unsafe in siblings.
    let resp = client
        .get(format!("{}{}", node.base_url, info_path(&owner_did, "m")))
        .send()
        .await
        .expect("send");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["siblings"][0]["unsafe"].as_bool(), Some(true));

    node.shutdown().await;
}

/// A repo whose git default branch is `master` still serves HF `main`:
/// revision `main` resolves to the newest release on `master` and refs
/// reports it under `main`.
#[sqlx::test]
async fn master_default_branch_serves_hf_main(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(23);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    sqlx::query("UPDATE repos SET default_branch = 'master' WHERE id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .unwrap();
    let fx = seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[],
        "master",
    )
    .await;

    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            rev_path(&owner_did, "m", "main")
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["sha"].as_str(), Some(fx.commit.as_str()));

    let resp = client
        .get(format!("{}{}", node.base_url, refs_path(&owner_did, "m")))
        .send()
        .await
        .expect("send");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["branches"][0]["name"].as_str(), Some("main"));
    assert_eq!(
        v["branches"][0]["targetCommit"].as_str(),
        Some(fx.commit.as_str())
    );

    node.shutdown().await;
}

/// A plain git commit after the release does not move HF `main`: refs and
/// model info still name the release commit.
#[sqlx::test]
async fn later_commit_does_not_move_hf_main(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(24);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    let fx = seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[],
        "main",
    )
    .await;

    // A second, unrelated commit on the same on-disk repo.
    let record = sqlx::query_as::<_, (String,)>("SELECT disk_path FROM repos WHERE id = $1")
        .bind(&repo_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let dir = std::path::PathBuf::from(&record.0);
    std::fs::write(dir.join("later.txt"), b"not a release").unwrap();
    run_git(&dir, &["add", "-A"]);
    run_git(
        &dir,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "later",
        ],
    );
    let later = run_git(&dir, &["rev-parse", "HEAD"]);
    assert_ne!(later, fx.commit);

    for path in [info_path(&owner_did, "m"), refs_path(&owner_did, "m")] {
        let resp = client
            .get(format!("{}{}", node.base_url, path))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 200, "{path}");
        let v: Value = resp.json().await.unwrap();
        let sha = v["sha"]
            .as_str()
            .or_else(|| v["branches"][0]["targetCommit"].as_str());
        assert_eq!(sha, Some(fx.commit.as_str()), "{path} must pin the release");
    }

    node.shutdown().await;
}

/// Resolve: byte-exact full and ranged GET on a git-stored file, HEAD
/// headers, 416 bounds, stale If-Range, and the EntryNotFound shape.
#[sqlx::test]
async fn resolve_git_file_ranges_and_headers(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(25);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    let fx = seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[("weights.safetensors", CHUNKED_FILE_CONTENTS, 16)],
        "main",
    )
    .await;
    let path = resolve_path(&owner_did, "m", "main", "config.json");
    let etag = format!("\"{}\"", sha256_hex(GIT_FILE));

    // Full GET: exact bytes plus the pinned headers.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers()["x-repo-commit"].to_str().unwrap(), fx.commit);
    assert_eq!(resp.headers()["etag"].to_str().unwrap(), etag);
    assert_eq!(
        resp.headers()["content-length"].to_str().unwrap(),
        GIT_FILE.len().to_string()
    );
    assert_eq!(resp.headers()["accept-ranges"].to_str().unwrap(), "bytes");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), GIT_FILE);

    // HEAD: same headers, empty body.
    let resp = client
        .head(format!("{}{}", node.base_url, path))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()["content-length"].to_str().unwrap(),
        GIT_FILE.len().to_string()
    );
    assert_eq!(resp.headers()["x-repo-commit"].to_str().unwrap(), fx.commit);
    assert!(resp.bytes().await.unwrap().is_empty());

    // Open-ended range: 206 with a correct Content-Range and suffix bytes.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("range", "bytes=10-")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 206);
    assert_eq!(
        resp.headers()["content-range"].to_str().unwrap(),
        format!("bytes 10-{}/{}", GIT_FILE.len() - 1, GIT_FILE.len())
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &GIT_FILE[10..]);

    // Stale If-Range: full 200, not a partial.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("range", "bytes=10-")
        .header("if-range", "\"stale\"")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), GIT_FILE);

    // Out of bounds: 416 with `bytes */total`.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("range", "bytes=1000000-")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 416);
    assert_eq!(
        resp.headers()["content-range"].to_str().unwrap(),
        format!("bytes */{}", GIT_FILE.len())
    );

    // Missing file: 404 EntryNotFound with X-Repo-Commit.
    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            resolve_path(&owner_did, "m", "main", "absent.bin")
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(
        resp.headers()["x-error-code"].to_str().unwrap(),
        "EntryNotFound"
    );
    assert_eq!(resp.headers()["x-repo-commit"].to_str().unwrap(), fx.commit);

    // A client holding the object gets a 304: etag is the file sha256.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("if-none-match", &etag)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 304);
    assert_eq!(resp.headers()["etag"].to_str().unwrap(), etag);
    assert_eq!(resp.headers()["x-repo-commit"].to_str().unwrap(), fx.commit);
    // A mismatched validator does not short-circuit.
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("if-none-match", "\"stale\"")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);

    node.shutdown().await;
}

/// A chunked file streams exact bytes, and a range spanning its block
/// boundary returns contiguous correct bytes.
#[sqlx::test]
async fn resolve_chunked_file_full_and_cross_block_range(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(26);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[("weights.safetensors", CHUNKED_FILE_CONTENTS, 16)],
        "main",
    )
    .await;
    let path = resolve_path(&owner_did, "m", "main", "weights.safetensors");

    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), CHUNKED_FILE_CONTENTS);

    // A range spanning the first two 16-byte blocks (bytes 8..24).
    let resp = client
        .get(format!("{}{}", node.base_url, path))
        .header("range", "bytes=8-23")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 206);
    assert_eq!(
        resp.headers()["content-range"].to_str().unwrap(),
        format!("bytes 8-23/{}", CHUNKED_FILE_CONTENTS.len())
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &CHUNKED_FILE_CONTENTS[8..24]);

    node.shutdown().await;
}

/// After the repo turns private, anonymous HEAD and GET on resolve return
/// the existence-hiding 404.
#[sqlx::test]
async fn resolve_denies_after_repo_turns_private(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(27);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[("config.json", GIT_FILE)],
        &[],
        "main",
    )
    .await;
    sqlx::query("UPDATE repos SET is_public = false WHERE id = $1")
        .bind(&repo_id)
        .execute(&pool)
        .await
        .unwrap();

    let path = resolve_path(&owner_did, "m", "main", "config.json");
    for (label, req) in [
        ("HEAD", client.head(format!("{}{}", node.base_url, path))),
        ("GET", client.get(format!("{}{}", node.base_url, path))),
    ] {
        let resp = req.send().await.expect("send");
        assert_eq!(resp.status().as_u16(), 404, "{label}");
    }

    node.shutdown().await;
}

/// `/tree/{rev}/{path}` treats `path` as a directory prefix on a slash
/// boundary: `sub` lists `sub/*` and must not leak a sibling-prefix
/// `subdir/*` entry.
#[sqlx::test]
async fn tree_path_filters_on_slash_boundary(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, signing) = owner_with_signing(23);
    let owner_did = owner.did().to_string();
    let repo_id = node.seed_repo(&owner_did, "m", true).await;
    seed_release(
        &node,
        &pool,
        &owner_did,
        &signing,
        &repo_id,
        "m",
        &[
            ("sub/a.txt", b"a".as_ref()),
            ("sub/b.txt", b"b".as_ref()),
            ("subdir/c.txt", b"c".as_ref()),
        ],
        &[],
        "main",
    )
    .await;

    for suffix in ["sub", "sub/"] {
        let resp = client
            .get(format!(
                "{}{}/{}",
                node.base_url,
                tree_path(&owner_did, "m", "main"),
                suffix
            ))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 200, "{suffix}");
        let entries: Vec<Value> = resp.json().await.expect("tree json");
        let paths: Vec<&str> = entries.iter().filter_map(|e| e["path"].as_str()).collect();
        assert_eq!(paths, ["sub/a.txt", "sub/b.txt"], "{suffix}");
    }

    // The unprefixed tree still lists every file.
    let resp = client
        .get(format!(
            "{}{}",
            node.base_url,
            tree_path(&owner_did, "m", "main")
        ))
        .send()
        .await
        .expect("send");
    let entries: Vec<Value> = resp.json().await.expect("tree json");
    assert_eq!(entries.len(), 3);

    node.shutdown().await;
}

/// Every HF route answers the same existence-hiding 404 for a repo that is
/// private or carries visibility rules, anonymous or signed-stranger.
#[sqlx::test]
async fn all_routes_deny_private_and_ruled_repos(pool: sqlx::PgPool) {
    let node = spawn_node(pool.clone()).await;
    let client = bounded_client();
    let (owner, _signing) = owner_with_signing(24);
    let owner_did = owner.did().to_string();
    let (stranger, _) = owner_with_signing(25);

    node.seed_repo(&owner_did, "priv", false).await;
    let ruled_id = node.seed_repo(&owner_did, "ruled", true).await;
    sqlx::query(
        "INSERT INTO visibility_rules
             (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
         VALUES ('r1', $1, '/withheld/**', 'b', '[]', $2, '2000-01-01T00:00:00Z')",
    )
    .bind(&ruled_id)
    .bind(&owner_did)
    .execute(&pool)
    .await
    .expect("seed rule");

    for repo in ["priv", "ruled"] {
        let routes = [
            info_path(&owner_did, repo),
            rev_path(&owner_did, repo, "main"),
            tree_path(&owner_did, repo, "main"),
            format!("{}/sub", tree_path(&owner_did, repo, "main")),
            refs_path(&owner_did, repo),
            resolve_path(&owner_did, repo, "main", "config.json"),
        ];
        for route in routes {
            for (label, req) in [
                ("anon", client.get(format!("{}{}", node.base_url, route))),
                (
                    "stranger",
                    signed_request(
                        &client,
                        reqwest::Method::GET,
                        &node.base_url,
                        &route,
                        Vec::new(),
                        &stranger,
                    ),
                ),
            ] {
                let resp = req.send().await.expect("send");
                assert_eq!(resp.status().as_u16(), 404, "{repo} {route} {label}");
                // Denial must not echo whether a repo or release exists:
                // the body is the same not-found shape a missing repo gets.
                let body: Value = resp.json().await.expect("denial body");
                let text = body.to_string();
                assert!(
                    text.contains("repo_not_found") || text.contains("not_found"),
                    "{repo} {route} {label}: {body}"
                );
                assert!(
                    !text.contains("private") && !text.contains("forbidden"),
                    "{repo} {route} {label} leaked: {body}"
                );
            }
        }
    }

    node.shutdown().await;
}
