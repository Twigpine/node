//! Content-addressed block storage for model weights.
//!
//! A block is a sequence of content chunks packed into one object, named by
//! the sha256 of its bytes. The store is content-neutral: later content types
//! (datasets, assets) reuse it without a parallel access surface.
//!
//! Writes are verified, not trusted: a caller supplies the expected id and the
//! backend hashes the body as it streams, so a corrupted or malicious payload
//! is rejected and never becomes visible under its claimed name. Reads are
//! ranged, so a downloader resumes without re-serving whole blocks.

use std::fmt;
use std::io;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use thiserror::Error;

pub mod fs;
pub mod s3;

/// A content address: exactly 64 lowercase hex characters, the sha256 of the
/// object's bytes. The shape is validated once at the boundary so every
/// backend can treat `id.as_str()` as a safe storage key fragment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockId(String);

impl BlockId {
    pub fn parse(s: &str) -> Result<Self, BlockIdError> {
        let valid = s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if valid {
            Ok(Self(s.to_string()))
        } else {
            Err(BlockIdError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for BlockId {
    type Err = BlockIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a block id is exactly 64 lowercase hex characters")]
pub struct BlockIdError;

/// What a verified write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The object's bytes were verified and are now stored under its id.
    Stored,
    /// An object already exists under this id. Because the id is the content
    /// hash, the stored bytes are the same bytes, so nothing was written.
    AlreadyPresent,
}

#[derive(Debug, Error)]
pub enum BlockStoreError {
    /// The streamed body did not hash to the id it was written under. Nothing
    /// was stored.
    #[error("body does not hash to the expected block id")]
    DigestMismatch,
    /// The body exceeded the caller-supplied cap while streaming. Nothing was
    /// stored.
    #[error("body exceeds the {0}-byte limit")]
    TooLarge(u64),
    /// The requested byte range is outside the stored object.
    #[error("requested range is outside the object")]
    OutOfRange,
    /// No object exists under this id.
    #[error("no object under this block id")]
    NotFound,
    /// A remote write's outcome cannot be determined: the request may have
    /// committed while its answer was lost. Callers must treat the object as
    /// possibly present and resolve with `size()` before retrying, exactly the
    /// vocabulary `git::publish` uses for an upload whose commit status is
    /// unknown.
    #[error("the write's outcome is unknown; check size() before retrying")]
    Unknown,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Stream `body` into the store under `id`, hashing as it goes. The body
    /// is never fully buffered. Fails with `TooLarge` the moment the body
    /// exceeds `max_len`, with `DigestMismatch` when the bytes do not hash to
    /// `id`, and leaves no object or temporary state behind on any failure.
    async fn put_verified(
        &self,
        id: &BlockId,
        body: BoxStream<'static, io::Result<Bytes>>,
        max_len: u64,
    ) -> Result<PutOutcome, BlockStoreError>;

    /// Stream bytes `[start, end_exclusive)` of the stored object. An empty
    /// range (`start == end_exclusive`) succeeds with an empty stream;
    /// `start > end_exclusive` or an `end_exclusive` past the object size
    /// fails with `OutOfRange`; a missing object fails with `NotFound`.
    /// Backends must honor this contract identically.
    async fn get_range(
        &self,
        id: &BlockId,
        start: u64,
        end_exclusive: u64,
    ) -> Result<BoxStream<'static, io::Result<Bytes>>, BlockStoreError>;

    /// The stored object's length in bytes, or `None` when absent.
    async fn size(&self, id: &BlockId) -> Result<Option<u64>, BlockStoreError>;

    /// Remove the object. Deleting an absent object is not an error.
    async fn delete(&self, id: &BlockId) -> Result<(), BlockStoreError>;

    /// Which backend this is ("fs" or "s3"), for logging and diagnostics.
    fn backend_name(&self) -> &'static str;
}

/// Build the configured backend, or `None` when model hosting is off.
///
/// Fails closed: with the flag on, a backend that cannot be constructed is an
/// error the caller propagates, not a silent fall back to local disk (the
/// same posture purge-spam takes with the object store).
pub async fn build(config: &crate::config::Config) -> anyhow::Result<Option<Arc<dyn BlockStore>>> {
    if !config.model_hosting_enabled {
        return Ok(None);
    }
    if !config.blockstore_s3_bucket.is_empty() {
        let store = s3::S3BlockStore::new(&config.blockstore_s3_bucket).await?;
        return Ok(Some(Arc::new(store)));
    }
    let store = fs::FsBlockStore::new(config.blockstore_dir.clone())?;
    Ok(Some(Arc::new(store)))
}

/// Assertions both backends must satisfy on `get_range` edges, run from each
/// backend's own test module against a live store so the trait contract
/// cannot drift between them.
#[cfg(test)]
pub(crate) mod parity {
    use super::*;
    use futures::StreamExt;
    use sha2::{Digest, Sha256};

    pub(crate) async fn get_range_edge_contract(store: &dyn BlockStore) {
        let body: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let id = BlockId::parse(&hex::encode(Sha256::digest(&body))).unwrap();
        let put_body = futures::stream::iter(vec![Ok(Bytes::from(body.clone()))]).boxed();
        store.put_verified(&id, put_body, u64::MAX).await.unwrap();
        let size = body.len() as u64;

        async fn collect(mut s: BoxStream<'static, io::Result<Bytes>>) -> Vec<u8> {
            let mut out = Vec::new();
            while let Some(c) = s.next().await {
                out.extend_from_slice(&c.unwrap());
            }
            out
        }

        // Empty ranges are in bounds: at offset 0 and at the end.
        assert!(collect(store.get_range(&id, 0, 0).await.unwrap())
            .await
            .is_empty());
        assert!(collect(store.get_range(&id, size, size).await.unwrap())
            .await
            .is_empty());
        // The whole object is the largest legal range.
        assert_eq!(
            collect(store.get_range(&id, 0, size).await.unwrap()).await,
            body
        );
        // One byte past the end is out of bounds, from any start.
        assert!(matches!(
            store
                .get_range(&id, 0, size + 1)
                .await
                .map(|_| ())
                .unwrap_err(),
            BlockStoreError::OutOfRange
        ));
        assert!(matches!(
            store
                .get_range(&id, 10, size + 1)
                .await
                .map(|_| ())
                .unwrap_err(),
            BlockStoreError::OutOfRange
        ));
        // A reversed range is out of bounds.
        assert!(matches!(
            store.get_range(&id, 20, 10).await.map(|_| ()).unwrap_err(),
            BlockStoreError::OutOfRange
        ));
        // A missing object is NotFound, even for an empty range.
        let missing = BlockId::parse(&"0".repeat(64)).unwrap();
        assert!(matches!(
            store
                .get_range(&missing, 0, 1)
                .await
                .map(|_| ())
                .unwrap_err(),
            BlockStoreError::NotFound
        ));
        assert!(matches!(
            store
                .get_range(&missing, 0, 0)
                .await
                .map(|_| ())
                .unwrap_err(),
            BlockStoreError::NotFound
        ));
    }
}
