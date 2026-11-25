//! The signed model release manifest (`gitlawb/model-release/v1`).
//!
//! A release is a git commit carrying `.twigpine/model-release.json` (these
//! bytes) and `.twigpine/model-release.sig` (a detached Ed25519 signature).
//! The signature covers the domain tag `gitlawb-model-release-sig/v1\n`
//! followed by the exact manifest bytes: no canonicalization, so a signer and
//! a verifier can never drift over JSON re-serialization, and the version tag
//! lives inside the signed bytes the way the ref cert's does.
//!
//! Verification anchors on a DID the caller supplies, never the manifest's
//! `publisher_did` field: a key read from inside the artifact only proves
//! self-consistency, and anyone can mint a keypair and name its DID. The
//! manifest's field is still checked for equality so a manifest naming one
//! publisher cannot pass for another.

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::did::Did;

pub const MANIFEST_SCHEMA_V1: &str = "gitlawb/model-release/v1";

/// Domain separation tag prepended to the manifest bytes before signing, so
/// a release signature cannot be replayed as a signature over the same bytes
/// in some other protocol.
pub const SIGNING_DOMAIN: &[u8] = b"gitlawb-model-release-sig/v1\n";

/// The exact bytes a publisher signs: the domain tag, then the manifest
/// bytes verbatim.
pub fn signing_input(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIGNING_DOMAIN.len() + manifest_bytes.len());
    v.extend_from_slice(SIGNING_DOMAIN);
    v.extend_from_slice(manifest_bytes);
    v
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("unsupported manifest schema {0:?}")]
    UnknownSchema(String),
    #[error("manifest names publisher {found}, expected {expected}")]
    PublisherMismatch { expected: String, found: String },
    #[error("invalid publisher DID: {0}")]
    Did(String),
    #[error("invalid signature encoding: {0}")]
    SignatureEncoding(String),
    #[error("signature does not verify against the expected publisher")]
    BadSignature,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    Safetensors,
    Gguf,
    Pickle,
    Text,
    Other,
}

/// Where a manifest-listed file's bytes live. Files under the chunking
/// threshold stay ordinary git blobs; larger ones are reconstructed from
/// content blocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    Git,
    Chunked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub format: FileFormat,
    pub storage: StorageKind,
}

/// A publisher's claimed parent release. The node records and displays it;
/// it does not prove the weights derive from the parent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParentRef {
    pub repo: String,
    pub commit: String,
    pub manifest_sha256: String,
}

/// Pointer at the reconstruction object (itself stored as a content block).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconstructionRef {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema: String,
    /// `"owner/name"` on the node.
    pub repo: String,
    pub publisher_did: String,
    pub license: String,
    #[serde(default)]
    pub parent: Option<ParentRef>,
    pub files: Vec<ManifestFile>,
    #[serde(default)]
    pub reconstruction: Option<ReconstructionRef>,
}

impl Manifest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse only the schema tag, for version dispatch. A manifest whose tag
    /// is unknown is refused before any field is trusted.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        #[derive(Deserialize)]
        struct Tag {
            schema: String,
        }
        let tag: Tag = serde_json::from_slice(bytes)?;
        match tag.schema.as_str() {
            MANIFEST_SCHEMA_V1 => Ok(serde_json::from_slice(bytes)?),
            other => Err(ManifestError::UnknownSchema(other.to_string())),
        }
    }
}

/// Sign `manifest_bytes` (already serialized) and return the detached
/// signature as base64 standard, no trailing newline: the exact contents of
/// the `.sig` file.
pub fn sign(key: &SigningKey, manifest_bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let sig = key.sign(&signing_input(manifest_bytes));
    STANDARD.encode(sig.to_bytes())
}

/// Verify `sig_text` (the `.sig` file's contents) over `manifest_bytes`
/// against `expected_did`, a DID the caller resolved from outside the
/// manifest. Fails when the manifest names a different publisher, when the
/// schema version is unknown, and when the signature does not verify.
/// Returns the parsed manifest on success.
pub fn verify(
    manifest_bytes: &[u8],
    sig_text: &str,
    expected_did: &Did,
) -> Result<Manifest, ManifestError> {
    let manifest = Manifest::parse(manifest_bytes)?;
    if manifest.publisher_did != expected_did.to_string() {
        return Err(ManifestError::PublisherMismatch {
            expected: expected_did.to_string(),
            found: manifest.publisher_did,
        });
    }
    // The named publisher was just proven equal to the caller-supplied DID,
    // so the key comes from that DID rather than a second parse of the field.
    let key = expected_did
        .to_verifying_key()
        .map_err(|e| ManifestError::Did(e.to_string()))?;

    use base64::{engine::general_purpose::STANDARD, Engine};
    let sig_bytes = STANDARD
        .decode(sig_text.trim())
        .map_err(|e| ManifestError::SignatureEncoding(e.to_string()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ManifestError::SignatureEncoding("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_array);
    // Strict verification, the same posture the attestation verifier takes.
    key.verify_strict(&signing_input(manifest_bytes), &sig)
        .map_err(|_| ManifestError::BadSignature)?;
    Ok(manifest)
}

/// Classify a file's format from its leading bytes and path. Honest
/// detection, not a security gate: pickle is flagged so consumers can be
/// warned, never refused.
pub fn detect_format(first_bytes: &[u8], path: &str) -> FileFormat {
    if first_bytes.starts_with(b"GGUF") {
        return FileFormat::Gguf;
    }
    // safetensors: an 8-byte little-endian header length followed by '{'.
    // Checked before raw pickle: a header length such as 0x0380 starts with
    // the bytes 0x80 0x03, which the pickle test below would claim.
    // The header length is capped at the 100 MB the safetensors reader
    // itself enforces, so a pickle whose byte 8 is '{' is not claimed.
    const MAX_SAFETENSORS_HEADER: u64 = 100_000_000;
    let header_len = first_bytes
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    if first_bytes.len() >= 9
        && header_len.is_some_and(|n| n > 0 && n <= MAX_SAFETENSORS_HEADER)
        && first_bytes[8] == b'{'
    {
        return FileFormat::Safetensors;
    }
    // Raw pickle: the protocol opcode 0x80 followed by the version byte.
    if first_bytes.len() >= 2 && first_bytes[0] == 0x80 && (2..=5).contains(&first_bytes[1]) {
        return FileFormat::Pickle;
    }
    let lower = path.to_ascii_lowercase();
    // Only a '.' in the final path component makes an extension: an
    // extensionless file named `bin` or `json` must not type itself.
    let ext = lower
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.').map(|(_, e)| e))
        .unwrap_or("");
    // Torch/HF checkpoints are zip archives containing pickled tensors.
    if first_bytes.starts_with(b"PK\x03\x04") && matches!(ext, "bin" | "pt" | "pth" | "ckpt") {
        return FileFormat::Pickle;
    }
    if matches!(ext, "pkl" | "pickle") {
        return FileFormat::Pickle;
    }
    if matches!(
        ext,
        // `tokenizer.model` is deliberately absent: it is a sentencepiece
        // protobuf, so it falls through to `other` like the binaries.
        "json" | "txt" | "md" | "py" | "jinja" | "yaml" | "yml"
    ) {
        return FileFormat::Text;
    }
    FileFormat::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> (SigningKey, Did) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let did = Did::from_verifying_key(&key.verifying_key());
        (key, did)
    }

    fn sample_manifest(did: &Did) -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            repo: "alice/llm".to_string(),
            publisher_did: did.to_string(),
            license: "apache-2.0".to_string(),
            parent: None,
            files: vec![
                ManifestFile {
                    path: "model.safetensors".into(),
                    size: 1024,
                    sha256: "a".repeat(64),
                    format: FileFormat::Safetensors,
                    storage: StorageKind::Chunked,
                },
                ManifestFile {
                    path: "config.json".into(),
                    size: 256,
                    sha256: "b".repeat(64),
                    format: FileFormat::Text,
                    storage: StorageKind::Git,
                },
            ],
            reconstruction: Some(ReconstructionRef {
                sha256: "c".repeat(64),
                size: 512,
            }),
        }
    }

    #[test]
    fn a_manifest_signed_by_the_owner_verifies() {
        let (key, did) = keypair(1);
        let bytes = sample_manifest(&did).to_bytes().unwrap();
        let sig = sign(&key, &bytes);
        let parsed = verify(&bytes, &sig, &did).unwrap();
        assert_eq!(parsed.publisher_did, did.to_string());
        assert_eq!(parsed.files.len(), 2);
    }

    #[test]
    fn a_manifest_naming_another_publisher_fails() {
        // Signed by key Y but naming DID X. Verification takes the
        // expected DID from the caller, so naming X does not help Y's key.
        let (key_y, _did_y) = keypair(2);
        let (_key_x, did_x) = keypair(3);
        let mut manifest = sample_manifest(&did_x);
        manifest.publisher_did = did_x.to_string();
        let bytes = manifest.to_bytes().unwrap();
        let sig = sign(&key_y, &bytes);
        // Verified against X's DID: publisher matches, but Y's signature
        // does not.
        assert!(matches!(
            verify(&bytes, &sig, &did_x),
            Err(ManifestError::BadSignature)
        ));
        // Verified against the signer Y: the named publisher X mismatches.
        let did_y = Did::from_verifying_key(&key_y.verifying_key());
        assert!(matches!(
            verify(&bytes, &sig, &did_y),
            Err(ManifestError::PublisherMismatch { .. })
        ));
    }

    #[test]
    fn a_forged_fully_populated_manifest_fails() {
        // A well-formed manifest naming the real owner but signed by a fresh
        // keypair must fail: the field is data, not the verifying key.
        let (_owner_key, owner_did) = keypair(4);
        let (forger, _forger_did) = keypair(5);
        let bytes = sample_manifest(&owner_did).to_bytes().unwrap();
        let sig = sign(&forger, &bytes);
        assert!(matches!(
            verify(&bytes, &sig, &owner_did),
            Err(ManifestError::BadSignature)
        ));
    }

    #[test]
    fn one_changed_byte_invalidates_the_signature() {
        let (key, did) = keypair(6);
        let bytes = sample_manifest(&did).to_bytes().unwrap();
        let sig = sign(&key, &bytes);
        // Tamper inside the signed bytes without breaking the JSON, so the
        // check proves the signature, not the parser, caught it.
        let mut tampered = bytes.clone();
        let at = tampered
            .windows(b"alice/llm".len())
            .position(|w| w == b"alice/llm")
            .unwrap();
        tampered[at..at + b"alice/llm".len()].copy_from_slice(b"alice/lln");
        Manifest::parse(&tampered).unwrap();
        assert!(matches!(
            verify(&tampered, &sig, &did),
            Err(ManifestError::BadSignature)
        ));
    }

    #[test]
    fn unknown_schema_is_rejected_before_signature_work() {
        let (key, did) = keypair(7);
        let mut manifest = sample_manifest(&did);
        manifest.schema = "gitlawb/model-release/v99".into();
        let bytes = manifest.to_bytes().unwrap();
        let sig = sign(&key, &bytes);
        assert!(matches!(
            verify(&bytes, &sig, &did),
            Err(ManifestError::UnknownSchema(_))
        ));
    }

    #[test]
    fn format_detection() {
        // safetensors: 8-byte LE header length then '{'.
        let mut st = 5u64.to_le_bytes().to_vec();
        st.extend_from_slice(b"{\"a\":0}");
        assert_eq!(detect_format(&st, "m.safetensors"), FileFormat::Safetensors);
        // A header length whose low bytes read as a pickle prefix (0x0480
        // and 0x0380 start 0x80 0x04 / 0x80 0x03) is still safetensors.
        for len in [0x0480u64, 0x0380, 0x0280, 0x0580] {
            let mut overlap = len.to_le_bytes().to_vec();
            overlap.extend_from_slice(b"{\"a\":0}");
            assert_eq!(
                detect_format(&overlap, "m.safetensors"),
                FileFormat::Safetensors,
                "header length {len:#x}"
            );
        }
        // A protocol-2 pickle whose byte 8 happens to be '{' ("a{" string)
        // has an impossible header length, so it stays pickle.
        assert_eq!(
            detect_format(b"\x80\x02X\x02\x00\x00\x00a{q\x00.", "x.bin"),
            FileFormat::Pickle
        );
        // A real pickle whose byte 8 is not '{' stays pickle.
        assert_eq!(
            detect_format(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00", "x.bin"),
            FileFormat::Pickle
        );
        assert_eq!(detect_format(b"GGUF\x01rest", "m.gguf"), FileFormat::Gguf);
        assert_eq!(detect_format(b"\x80\x04x", "torch.bin"), FileFormat::Pickle);
        assert_eq!(
            detect_format(b"PK\x03\x04z", "pytorch_model.bin"),
            FileFormat::Pickle
        );
        // A zip that is NOT a checkpoint extension is not called pickle.
        assert_eq!(
            detect_format(b"PK\x03\x04z", "archive.zip"),
            FileFormat::Other
        );
        // Protocol-0 pickle bytes carry no 0x80 opcode prefix: only the
        // extension names them.
        assert_eq!(detect_format(b"(dp0\n.", "model.pkl"), FileFormat::Pickle);
        assert_eq!(detect_format(b"(dp0\n.", "x.pickle"), FileFormat::Pickle);
        assert_eq!(detect_format(b"(dp0\n.", "model.bin"), FileFormat::Other);
        assert_eq!(detect_format(b"{\"a\":1}", "config.json"), FileFormat::Text);
        // Sentencepiece models are protobufs, not text.
        assert_eq!(detect_format(b"", "tokenizer.model"), FileFormat::Other);
        assert_eq!(
            detect_format(b"\x00\x01\x02", "blob.weird"),
            FileFormat::Other
        );
        // An extensionless final component has no extension, even when the
        // name itself spells one.
        assert_eq!(detect_format(b"PK\x03\x04z", "bin"), FileFormat::Other);
        assert_eq!(detect_format(b"{\"a\":1}", "json"), FileFormat::Other);
        assert_eq!(detect_format(b"PK\x03\x04z", "m.bin"), FileFormat::Pickle);
        assert_eq!(detect_format(b"(dp0\n.", "m.pkl"), FileFormat::Pickle);
        assert_eq!(detect_format(b"{\"a\":1}", "m.json"), FileFormat::Text);
    }

    /// Regenerate the frozen fixture (run once, deliberately):
    /// `cargo test -p twigpine-core manifest_frozen_fixture_write -- --ignored`
    #[test]
    #[ignore = "writes the fixture files; run only when regenerating"]
    fn manifest_frozen_fixture_write() {
        let (key, did) = keypair(42);
        let bytes = sample_manifest(&did).to_bytes().unwrap();
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/model-release-v1"
        );
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/manifest.json"), &bytes).unwrap();
        std::fs::write(format!("{dir}/manifest.sig"), sign(&key, &bytes)).unwrap();
        std::fs::write(format!("{dir}/publisher.did"), did.to_string()).unwrap();
        eprintln!("wrote fixture for {did} to {dir}");
    }

    #[test]
    fn the_frozen_v1_fixture_still_verifies() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/model-release-v1"
        );
        let bytes = std::fs::read(format!("{dir}/manifest.json")).unwrap();
        let sig = std::fs::read_to_string(format!("{dir}/manifest.sig")).unwrap();
        let did: Did = std::fs::read_to_string(format!("{dir}/publisher.did"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let parsed = verify(&bytes, &sig, &did).unwrap();
        assert_eq!(parsed.repo, "alice/llm");
        // And the frozen signature rejects tampering that stays valid
        // JSON, so the signature is what fails, not the parser.
        let mut tampered = bytes.clone();
        let at = tampered
            .windows(b"alice/llm".len())
            .position(|w| w == b"alice/llm")
            .unwrap();
        tampered[at..at + b"alice/llm".len()].copy_from_slice(b"alice/lln");
        Manifest::parse(&tampered).unwrap();
        assert!(matches!(
            verify(&tampered, &sig, &did),
            Err(ManifestError::BadSignature)
        ));
    }
}
