//! Arweave permanent anchoring via Irys.
//!
//! Every ref-update event (push) is anchored to Arweave through the Irys
//! network. The anchor payload is a small JSON object containing:
//!
//!   { repo, owner_did, ref_name, old_sha, new_sha, cid, timestamp, node_did }
//!
//! Irys allows free uploads for data < 100 KiB on both devnet and mainnet
//! (via Turbo). No wallet is required for payloads under the free threshold.
//!
//! Set `TWIGPINE_IRYS_URL` to override the default endpoint:
//!   - devnet (free, no cost): https://devnet.irys.xyz
//!   - mainnet:                https://node2.irys.xyz
//!
//! Each anchor returns an Irys transaction ID (43-char base58 string).
//! The permanent Arweave URL is: https://arweave.net/<tx_id>
//!
//! Anchors are stored in the `arweave_anchors` table for auditability.

use anyhow::Result;
use serde_json::json;

/// Data describing a ref-update event to be anchored.
#[derive(Debug, Clone)]
pub struct RefAnchor {
    pub repo: String,
    pub owner_did: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    /// IPFS CIDv1 of the commit object, if available
    pub cid: Option<String>,
    pub timestamp: String,
    pub node_did: String,
}

/// Anchor a ref-update to Arweave via Irys.
///
/// Returns the Irys/Arweave transaction ID on success.
/// Returns `Ok("")` if `irys_url` is empty (anchoring disabled).
pub async fn anchor_ref_update(
    client: &reqwest::Client,
    irys_url: &str,
    anchor: &RefAnchor,
) -> Result<String> {
    if irys_url.is_empty() {
        return Ok(String::new());
    }

    let payload = json!({
        "schema": "gitlawb/ref-update/v1",
        "repo": anchor.repo,
        "owner_did": anchor.owner_did,
        "ref_name": anchor.ref_name,
        "old_sha": anchor.old_sha,
        "new_sha": anchor.new_sha,
        "cid": anchor.cid,
        "timestamp": anchor.timestamp,
        "node_did": anchor.node_did,
        "network": "alpha",
    });

    let body = serde_json::to_vec(&payload)?;

    // Irys upload endpoint
    let url = format!("{}/upload", irys_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        // Irys tags allow indexing on Arweave gateway
        .header("x-irys-tags", build_tags_header(anchor))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Irys upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Irys returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Irys response: {e}"))?;

    // Irys response: {"id": "<tx_id>", "timestamp": ..., "version": ...}
    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Irys response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %anchor.repo,
        ref_name = %anchor.ref_name,
        new_sha = %anchor.new_sha,
        tx_id = %tx_id,
        "anchored ref update to Arweave"
    );

    Ok(tx_id)
}

/// The compact release anchor (KTD10). One permanent record per published
/// model release: the pointers an independent consumer needs to rebuild the
/// release (manifest, reconstruction, and the sha256-to-provider-CID block
/// map, all pinned on IPFS) plus the publisher's claim signature.
///
/// Identity fields are RECORD-KEEPING ONLY. `owner_did` and `node_did`
/// inside this payload are attacker-controllable text: an independent
/// consumer binds manifest verification to a DID it already trusts
/// (fetched or pinned out of band), never to a DID read out of the anchor.
#[derive(Debug, Clone)]
pub struct ReleaseAnchor {
    /// `"owner/name"` on the node.
    pub repo: String,
    pub owner_did: String,
    /// The release commit the manifest and signature live in.
    pub release_commit: String,
    /// sha256 of the manifest bytes, the content key the manifest is
    /// resolved by (the CID beside it is provider metadata).
    pub manifest_sha256: String,
    /// Provider CID the manifest bytes were pinned under.
    pub manifest_cid: String,
    /// sha256 and provider CID of the reconstruction object, when the
    /// release has chunked files.
    pub reconstruction_sha256: Option<String>,
    pub reconstruction_cid: Option<String>,
    /// Provider CID of the block map object (sha256 -> provider CID for
    /// every content block the release references).
    pub block_map_cid: String,
    /// The publisher's detached manifest signature (base64), so the anchor
    /// alone reproves the release once the consumer has manifest bytes and
    /// an externally anchored owner DID.
    pub claim_signature: String,
    pub timestamp: String,
    pub node_did: String,
}

/// Anchor a model release root to Arweave via Irys.
///
/// The payload is a few hundred bytes: the file and block sets live behind
/// `block_map_cid` on IPFS rather than inline, so the anchor stays far
/// under the 100 KiB free-upload ceiling even for a 5,000-file,
/// 3,000-block release. Returns the Irys transaction ID, or `Ok("")` when
/// `irys_url` is empty (anchoring disabled).
pub async fn anchor_model_release(
    client: &reqwest::Client,
    irys_url: &str,
    anchor: &ReleaseAnchor,
) -> Result<String> {
    if irys_url.is_empty() {
        return Ok(String::new());
    }

    let body = serde_json::to_vec(&release_anchor_payload(anchor))?;
    let url = format!("{}/upload", irys_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("x-irys-tags", build_release_tags_header(anchor))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Irys upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Irys returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Irys response: {e}"))?;

    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Irys response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %anchor.repo,
        commit = %anchor.release_commit,
        tx_id = %tx_id,
        "anchored model release to Arweave"
    );

    Ok(tx_id)
}

/// The anchored JSON. Kept as its own function so the size and parse-back
/// guarantees are unit-testable without an HTTP mock.
pub fn release_anchor_payload(anchor: &ReleaseAnchor) -> serde_json::Value {
    json!({
        "schema": "gitlawb/model-release-anchor/v1",
        "repo": anchor.repo,
        "owner_did": anchor.owner_did,
        "release_commit": anchor.release_commit,
        "manifest_sha256": anchor.manifest_sha256,
        "manifest_cid": anchor.manifest_cid,
        "reconstruction_sha256": anchor.reconstruction_sha256,
        "reconstruction_cid": anchor.reconstruction_cid,
        "block_map_cid": anchor.block_map_cid,
        "claim_signature": anchor.claim_signature,
        "timestamp": anchor.timestamp,
        "node_did": anchor.node_did,
    })
}

/// Irys tag header for a release anchor. The five tags a discovery query
/// needs; identity tags are indexable metadata, not authorization input.
fn build_release_tags_header(anchor: &ReleaseAnchor) -> String {
    [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/model-release-anchor/v1".to_string(),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Owner-DID:{}", sanitize_tag(&anchor.owner_did)),
        format!("Release-Commit:{}", sanitize_tag(&anchor.release_commit)),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .join(",")
}

/// A per-push manifest of the blobs encrypted this push (Option B3). The
/// `blobs` slice is `(oid, cid)` tuples. Anchored directly to Arweave as its JSON
/// body so the discovery index survives total node loss. Recipient identities are
/// never part of the manifest.
pub struct EncryptedManifest<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub node_did: &'a str,
    pub timestamp: &'a str,
    pub blobs: &'a [(String, String)],
}

/// Anchor a per-push encrypted-blob manifest to Arweave via Irys. The manifest
/// JSON body is the payload (not a CID pointer to IPFS), so the index is
/// permanent and self-contained. Recipient identities are deliberately omitted:
/// the anchor is permanent and public, and the v2 envelopes no longer expose
/// recipients, so the reader set must not be written to Arweave either.
///
/// Returns the Irys/Arweave transaction ID, or `Ok("")` when `irys_url` is empty
/// (anchoring disabled) or there are no blobs to anchor.
pub async fn anchor_encrypted_manifest(
    client: &reqwest::Client,
    irys_url: &str,
    manifest: &EncryptedManifest<'_>,
) -> Result<String> {
    if irys_url.is_empty() || manifest.blobs.is_empty() {
        return Ok(String::new());
    }

    let blobs_json: Vec<serde_json::Value> = manifest
        .blobs
        .iter()
        .map(|(oid, cid)| manifest_blob_json(oid, cid))
        .collect();

    let payload = json!({
        "schema": "gitlawb/encrypted-manifest/v1",
        "repo": manifest.repo,
        "owner_did": manifest.owner_did,
        "node_did": manifest.node_did,
        "timestamp": manifest.timestamp,
        "blobs": blobs_json,
    });

    let body = serde_json::to_vec(&payload)?;
    let url = format!("{}/upload", irys_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("x-irys-tags", build_manifest_tags_header(manifest))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Irys upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Irys returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Irys response: {e}"))?;

    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Irys response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %manifest.repo,
        tx_id = %tx_id,
        blobs = manifest.blobs.len(),
        "anchored encrypted manifest to Arweave"
    );

    Ok(tx_id)
}

/// Serialize one blob for the Arweave manifest. Recipient identities are
/// intentionally absent so the permanent public anchor never records who can
/// read a blob.
fn manifest_blob_json(oid: &str, cid: &str) -> serde_json::Value {
    json!({ "oid": oid, "cid": cid })
}

/// Build the Irys tag header for an encrypted-blob manifest. `Repo` and `Schema`
/// are the tags the `twigpine` recovery query filters on.
fn build_manifest_tags_header(manifest: &EncryptedManifest<'_>) -> String {
    [
        // Written under the old name until writers switch: see docs/LEGACY-NAMES.md.
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/encrypted-manifest/v1".to_string(),
        format!("Repo:{}", sanitize_tag(manifest.repo)),
        format!("Owner-DID:{}", sanitize_tag(manifest.owner_did)),
        format!("Node-DID:{}", sanitize_tag(manifest.node_did)),
    ]
    .join(",")
}

/// Arweave permanent URL for a given Irys transaction ID.
pub fn arweave_url(tx_id: &str) -> String {
    format!("https://arweave.net/{tx_id}")
}

/// Build the Irys tag header value for Arweave indexing.
/// Format: comma-separated "name:value" pairs.
fn build_tags_header(anchor: &RefAnchor) -> String {
    [
        // Written under the old name until writers switch: see docs/LEGACY-NAMES.md.
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/ref-update/v1".to_string(),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Ref:{}", sanitize_tag(&anchor.ref_name)),
        format!("SHA:{}", &anchor.new_sha[..anchor.new_sha.len().min(16)]),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .join(",")
}

/// Strip characters that are invalid in Irys/Arweave tag values.
fn sanitize_tag(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            cid: Some("bafyreib5...".into()),
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6MknndwexV9...".into(),
        };
        let result = anchor_ref_update(&client, "", &anchor).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
        };

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert!(result.is_ok(), "anchor should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_anchor_body_carries_real_old_sha() {
        // The anchored body must serialize the real old→new transition the
        // node was handed, never a zero placeholder. Regression guard for the
        // push handler that used to hardcode `old_sha` to 64 zeros (#26).
        let mut server = mockito::Server::new_async().await;
        let real_old = "1111111111111111111111111111111111111111";
        let real_new = "2222222222222222222222222222222222222222";
        let _mock = server
            .mock("POST", "/upload")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{real_old}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{real_new}"}}"#)),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TX_REAL_OLD_SHA","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: real_old.into(),
            new_sha: real_new.into(),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
        };

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert_eq!(result.unwrap(), "TX_REAL_OLD_SHA");
        // The mock only matches when the posted JSON carries both real SHAs.
        _mock.assert_async().await;
    }

    #[test]
    fn test_arweave_url() {
        let url = arweave_url("7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk");
        assert_eq!(
            url,
            "https://arweave.net/7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        assert_eq!(
            anchor_encrypted_manifest(&client, "", &m).await.unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_noop_when_no_blobs() {
        let client = reqwest::Client::new();
        let blobs: Vec<(String, String)> = vec![];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        // Non-empty URL, but no blobs: still a no-op.
        assert_eq!(
            anchor_encrypted_manifest(&client, "https://example.invalid", &m)
                .await
                .unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"MANIFESTTX123","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        let r = anchor_encrypted_manifest(&client, &server.url(), &m).await;
        assert_eq!(r.unwrap(), "MANIFESTTX123");
        _mock.assert_async().await;
    }

    #[test]
    fn manifest_blob_json_omits_recipients() {
        let v = manifest_blob_json("oid1", "cidA");
        assert_eq!(v["oid"], "oid1");
        assert_eq!(v["cid"], "cidA");
        assert!(
            v.get("recipients").is_none(),
            "Arweave manifest must not anchor recipient identities"
        );
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("alice/myrepo"), "alice/myrepo");
        assert_eq!(sanitize_tag("hello world!"), "helloworld");
    }

    fn release_anchor() -> ReleaseAnchor {
        ReleaseAnchor {
            repo: "did:key:z6Mkowner/m".into(),
            owner_did: "did:key:z6Mkowner".into(),
            release_commit: "a".repeat(40),
            manifest_sha256: "b".repeat(64),
            manifest_cid: "bafkreimanifestcid".into(),
            reconstruction_sha256: Some("c".repeat(64)),
            reconstruction_cid: Some("bafkreireccid".into()),
            block_map_cid: "bafkreimapcid".into(),
            claim_signature: "c2ln".into(),
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknode".into(),
        }
    }

    #[tokio::test]
    async fn test_model_release_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        assert_eq!(
            anchor_model_release(&client, "", &release_anchor())
                .await
                .unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_model_release_anchor_posts_payload_and_tags() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/upload")
            .match_header(
                "x-irys-tags",
                mockito::Matcher::AllOf(vec![
                    mockito::Matcher::Regex("App-Name:gitlawb".to_string()),
                    mockito::Matcher::Regex(
                        "Schema:gitlawb/model-release-anchor/v1".to_string(),
                    ),
                    mockito::Matcher::Regex(format!("Release-Commit:{}", "a".repeat(40))),
                ]),
            )
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(
                    r#"{"schema":"gitlawb/model-release-anchor/v1"}"#.to_string(),
                ),
                mockito::Matcher::PartialJsonString(
                    r#"{"block_map_cid":"bafkreimapcid"}"#.to_string(),
                ),
                mockito::Matcher::PartialJsonString(
                    r#"{"manifest_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#
                        .to_string(),
                ),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"RELTX1","timestamp":1710000000000}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let tx = anchor_model_release(&client, &server.url(), &release_anchor())
            .await
            .expect("anchor posts");
        assert_eq!(tx, "RELTX1");
        _mock.assert_async().await;
    }

    #[test]
    fn release_anchor_payload_stays_compact_and_parseable() {
        let anchor = release_anchor();
        let v = release_anchor_payload(&anchor);
        let bytes = serde_json::to_vec(&v).unwrap();
        // The anchor must stay far under the Irys 100 KiB free-upload
        // ceiling: everything larger lives behind the block-map CID.
        assert!(
            bytes.len() < 4 * 1024,
            "anchor payload grew: {} bytes",
            bytes.len()
        );
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed["schema"].as_str(),
            Some("gitlawb/model-release-anchor/v1")
        );
        assert_eq!(
            parsed["release_commit"].as_str(),
            Some("a".repeat(40).as_str())
        );
        assert_eq!(parsed["claim_signature"].as_str(), Some("c2ln"));
    }
}
