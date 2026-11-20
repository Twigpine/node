//! Integration tests for `twigpine model fetch` (KTD15): a mock Arweave
//! gateway serves anchor discovery pages and transaction bodies, a mock IPFS
//! gateway serves the manifest, reconstruction object, block map, and
//! content objects, and `fetch_model` has to rebuild byte-identical files
//! trusting nothing but the caller-supplied owner DID.

use std::collections::HashMap;

use serde_json::{json, Value};
use tempfile::TempDir;
use twigpine_cli::model::{fetch_model, FetchArgs};
use twigpine_core::cid::sha256_hex;
use twigpine_core::did::Did;
use twigpine_core::identity::Keypair;
use twigpine_core::model::manifest::{
    self, FileFormat, Manifest, ManifestFile, ReconstructionRef, StorageKind, MANIFEST_SCHEMA_V1,
};
use twigpine_core::model::reconstruction::{
    BlockEntry, ChunkMeta, FileEntry, Reconstruction, Term,
};

const COMMIT: &str = "aaaabbbbccccddddeeeeffff00001111";
const ANCHOR_SCHEMA: &str = "gitlawb/model-release-anchor/v1";
const BLOCK_MAP_SCHEMA: &str = "gitlawb/model-block-map/v1";

/// One whole release, served: a signed manifest over one git-stored file and
/// one chunked file spanning two content blocks.
struct Release {
    did: Did,
    signing: ed25519_dalek::SigningKey,
    manifest_bytes: Vec<u8>,
    rec_bytes: Vec<u8>,
    block_map: Value,
    /// CID -> bytes, exactly what the IPFS gateway serves.
    objects: HashMap<String, Vec<u8>>,
    /// Expected bytes per manifest path after the fetch.
    files: HashMap<String, Vec<u8>>,
}

fn signing_key(kp: &Keypair) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&kp.to_seed())
}

fn build_release(owner: &Keypair) -> Release {
    let repo = format!("{}/my-model", owner.did());

    let readme = b"# tiny test model\n".to_vec();
    let c1 = b"first weights chunk, pretend safetensors".to_vec();
    let c2 = b"second weights chunk follows it".to_vec();
    let c3 = b"third chunk lives in another block".to_vec();
    let model: Vec<u8> = [c1.as_slice(), &c2, &c3].concat();

    let block1: Vec<u8> = [c1.as_slice(), &c2].concat();
    let block2: Vec<u8> = c3.clone();
    let block1_sha = sha256_hex(&block1);
    let block2_sha = sha256_hex(&block2);

    let rec = Reconstruction {
        schema: "gitlawb/model-reconstruction/v1".to_string(),
        files: vec![FileEntry {
            path: "model.safetensors".to_string(),
            size: model.len() as u64,
            sha256: sha256_hex(&model),
            terms: vec![
                Term {
                    block: block1_sha.clone(),
                    chunk_start: 0,
                    chunk_end: 2,
                    length: (c1.len() + c2.len()) as u64,
                },
                Term {
                    block: block2_sha.clone(),
                    chunk_start: 0,
                    chunk_end: 1,
                    length: c3.len() as u64,
                },
            ],
        }],
        blocks: vec![
            BlockEntry {
                sha256: block1_sha.clone(),
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
                sha256: block2_sha.clone(),
                size: block2.len() as u64,
                chunks: vec![ChunkMeta {
                    sha256: sha256_hex(&c3),
                    len: c3.len() as u64,
                }],
            },
        ],
    };
    let rec_bytes = rec.to_bytes().unwrap();

    let manifest = Manifest {
        schema: MANIFEST_SCHEMA_V1.to_string(),
        repo: repo.clone(),
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
            sha256: sha256_hex(&rec_bytes),
            size: rec_bytes.len() as u64,
        }),
    };
    let manifest_bytes = manifest.to_bytes().unwrap();

    let block_map = json!({
        "schema": BLOCK_MAP_SCHEMA,
        "release": COMMIT,
        "blocks": {
            block1_sha: "bafy-block-1",
            block2_sha: "bafy-block-2",
        },
        "files": {
            sha256_hex(&readme): "bafy-readme",
        },
    });

    let mut objects = HashMap::new();
    objects.insert("bafy-manifest".to_string(), manifest_bytes.clone());
    objects.insert("bafy-rec".to_string(), rec_bytes.clone());
    objects.insert(
        "bafy-blockmap".to_string(),
        serde_json::to_vec(&block_map).unwrap(),
    );
    objects.insert("bafy-block-1".to_string(), block1);
    objects.insert("bafy-block-2".to_string(), block2);
    objects.insert("bafy-readme".to_string(), readme.clone());

    let mut files = HashMap::new();
    files.insert("README.md".to_string(), readme);
    files.insert("model.safetensors".to_string(), model);

    Release {
        did: owner.did(),
        signing: signing_key(owner),
        manifest_bytes,
        rec_bytes,
        block_map,
        objects,
        files,
    }
}

/// The anchor body as `anchor_model_release` posts it, signed by `signing`
/// and naming `owner_did` (which a hostile anchor can lie about).
fn anchor_json(
    release: &Release,
    owner_did: &Did,
    signing: &ed25519_dalek::SigningKey,
    rec_sha: &str,
) -> Value {
    json!({
        "schema": ANCHOR_SCHEMA,
        "repo": format!("{}/my-model", release.did),
        "owner_did": owner_did.to_string(),
        "release_commit": COMMIT,
        "manifest_sha256": sha256_hex(&release.manifest_bytes),
        "manifest_cid": "bafy-manifest",
        "reconstruction_sha256": rec_sha,
        "reconstruction_cid": "bafy-rec",
        "block_map_cid": "bafy-blockmap",
        "claim_signature": manifest::sign(signing, &release.manifest_bytes),
        "timestamp": "2026-11-19T00:00:00Z",
        "node_did": "did:key:z6Mknode",
    })
}

/// A GraphQL page holding the given (tx id, height) pairs, in edge order.
fn gql_page(edges: &[(&str, u64)]) -> Value {
    let edges: Vec<Value> = edges
        .iter()
        .map(|(id, height)| {
            json!({
                "cursor": format!("cursor-{id}"),
                "node": { "id": id, "block": { "height": height } },
            })
        })
        .collect();
    json!({
        "data": {
            "transactions": {
                "pageInfo": { "hasNextPage": false, "endCursor": null },
                "edges": edges,
            }
        }
    })
}

/// Mock both gateways on one server: `/graphql` + `/{tx}` are Arweave,
/// `/ipfs/{cid}` is IPFS. `anchors` is (tx id, body) in GraphQL edge order;
/// `objects` overrides which release objects actually get served.
async fn serve(
    anchors: &[(&str, Value)],
    objects: &HashMap<String, Vec<u8>>,
) -> mockito::ServerGuard {
    let mut server = mockito::Server::new_async().await;
    let edges: Vec<(&str, u64)> = anchors
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, 1000 - i as u64))
        .collect();
    server
        .mock("POST", "/graphql")
        .with_status(200)
        .with_body(gql_page(&edges).to_string())
        .create_async()
        .await;
    for (id, body) in anchors {
        server
            .mock("GET", format!("/{id}").as_str())
            .with_status(200)
            .with_body(body.to_string())
            .create_async()
            .await;
    }
    for (cid, bytes) in objects {
        server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(bytes.clone())
            .create_async()
            .await;
    }
    server
}

fn args(gateway: &str, did: &Did, output: &TempDir) -> FetchArgs {
    FetchArgs {
        repo: format!("{did}/my-model"),
        expect_did: did.to_string(),
        revision: None,
        output: Some(output.path().join("out")),
        arweave_gateway: gateway.to_string(),
        ipfs_gateway: gateway.to_string(),
    }
}

#[tokio::test]
async fn fetch_rebuilds_git_and_chunked_files_byte_identically() {
    let owner = Keypair::generate();
    let release = build_release(&owner);
    let rec_sha = sha256_hex(&release.rec_bytes);
    let anchor = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    let server = serve(&[("tx-good", anchor)], &release.objects).await;

    let out = TempDir::new().unwrap();
    let mut a = args(&server.url(), &release.did, &out);
    a.revision = Some(COMMIT.to_string());
    let report = fetch_model(&a).await.unwrap();

    assert_eq!(report.files, 2);
    assert_eq!(report.release_commit, COMMIT);
    assert_eq!(report.anchor_tx, "tx-good");
    for (path, want) in &release.files {
        let got = std::fs::read(report.output_dir.join(path)).unwrap();
        assert_eq!(&got, want, "{path} did not rebuild byte-identically");
    }
}

#[tokio::test]
async fn anchor_naming_a_different_owner_did_is_skipped() {
    let owner = Keypair::generate();
    let attacker = Keypair::generate();
    let release = build_release(&owner);
    let rec_sha = sha256_hex(&release.rec_bytes);
    // The attacker posts a self-signed anchor naming its own DID; fetching
    // with the real owner DID must skip it and use the owner's anchor.
    let forged = anchor_json(&release, &attacker.did(), &signing_key(&attacker), &rec_sha);
    let good = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    // The forged anchor sorts newest (first edge).
    let server = serve(
        &[("tx-forged", forged), ("tx-good", good)],
        &release.objects,
    )
    .await;

    let out = TempDir::new().unwrap();
    let report = fetch_model(&args(&server.url(), &release.did, &out))
        .await
        .unwrap();
    assert_eq!(report.anchor_tx, "tx-good");
    assert!(
        report.warnings.iter().any(|w| w.contains("tx-forged")),
        "the skipped anchor should leave a warning: {:?}",
        report.warnings
    );
    for (path, want) in &release.files {
        assert_eq!(
            &std::fs::read(report.output_dir.join(path)).unwrap(),
            want,
            "{path} did not rebuild byte-identically"
        );
    }
}

#[tokio::test]
async fn anchor_with_bad_manifest_signature_is_skipped() {
    let owner = Keypair::generate();
    let attacker = Keypair::generate();
    let release = build_release(&owner);
    let rec_sha = sha256_hex(&release.rec_bytes);
    // The anchor names the real owner DID (selection passes) but signs the
    // manifest with an attacker's key: verification has to reject it.
    let mut forged = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    forged["claim_signature"] = json!(manifest::sign(
        &signing_key(&attacker),
        &release.manifest_bytes
    ));
    let good = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    let server = serve(
        &[("tx-badsig", forged), ("tx-good", good)],
        &release.objects,
    )
    .await;

    let out = TempDir::new().unwrap();
    let report = fetch_model(&args(&server.url(), &release.did, &out))
        .await
        .unwrap();
    assert_eq!(report.anchor_tx, "tx-good");
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("tx-badsig") && w.contains("verification")),
        "the signature failure should be reported: {:?}",
        report.warnings
    );
}

#[tokio::test]
async fn no_verifying_anchor_fails_naming_repo_and_did() {
    let owner = Keypair::generate();
    let attacker = Keypair::generate();
    let release = build_release(&owner);
    let rec_sha = sha256_hex(&release.rec_bytes);
    let forged = anchor_json(&release, &attacker.did(), &signing_key(&attacker), &rec_sha);
    let server = serve(&[("tx-forged", forged)], &release.objects).await;

    let out = TempDir::new().unwrap();
    let err = fetch_model(&args(&server.url(), &release.did, &out))
        .await
        .unwrap_err();
    let msg = err.to_string();
    let repo = format!("{}/my-model", release.did);
    assert!(msg.contains(&repo), "error should name the repo: {msg}");
    assert!(
        msg.contains(&release.did.to_string()),
        "error should name the expected DID: {msg}"
    );
}

#[tokio::test]
async fn tampered_block_content_fails_naming_the_block() {
    let owner = Keypair::generate();
    let release = build_release(&owner);
    let rec_sha = sha256_hex(&release.rec_bytes);
    let anchor = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    let mut objects = release.objects.clone();
    objects.insert("bafy-block-1".to_string(), b"tampered bytes".to_vec());
    let server = serve(&[("tx-good", anchor)], &objects).await;

    let out = TempDir::new().unwrap();
    let err = fetch_model(&args(&server.url(), &release.did, &out))
        .await
        .unwrap_err();
    let block1 = release
        .block_map
        .pointer("/blocks")
        .and_then(|b| b.as_object())
        .and_then(|m| {
            m.iter()
                .find(|(_, cid)| cid.as_str() == Some("bafy-block-1"))
                .map(|(sha, _)| sha.clone())
        })
        .unwrap();
    let msg = err.to_string();
    assert!(
        msg.contains(&block1),
        "error should name the failing block {block1}: {msg}"
    );
}

#[tokio::test]
async fn manifest_path_traversal_is_refused() {
    let owner = Keypair::generate();
    let mut release = build_release(&owner);
    // Re-sign a manifest whose git file escapes the output directory.
    let mut manifest: Manifest = serde_json::from_slice(&release.manifest_bytes).unwrap();
    manifest.files[0].path = "../escape.txt".to_string();
    release.manifest_bytes = manifest.to_bytes().unwrap();
    release
        .objects
        .insert("bafy-manifest".to_string(), release.manifest_bytes.clone());
    let rec_sha = sha256_hex(&release.rec_bytes);
    let anchor = anchor_json(&release, &release.did, &release.signing, &rec_sha);
    let server = serve(&[("tx-good", anchor)], &release.objects).await;

    let out = TempDir::new().unwrap();
    let err = fetch_model(&args(&server.url(), &release.did, &out))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("relative path"));
    assert!(!out.path().join("escape.txt").exists());
}
