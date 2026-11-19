//! S3-compatible block backend: objects under `model-blocks/v1/<aa>/<sha>`,
//! written through multipart upload.
//!
//! The verified-write contract maps onto multipart cleanly: parts go up while
//! the body streams (never fully buffered), and the object becomes visible
//! only when `CompleteMultipartUpload` commits, which runs after the hash
//! check. A mismatch aborts the upload instead, so a bad body never leaves an
//! object under a valid-looking id.
//!
//! The one case multipart cannot answer is a lost response: a timeout after
//! the complete request was sent may still have committed the object. That is
//! reported as [`BlockStoreError::Unknown`], the same "maybe sent" vocabulary
//! `git::publish` uses, and the caller resolves it with a HEAD rather than
//! assuming the write failed.

use std::io;

use async_trait::async_trait;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::time::Duration;

use super::{BlockId, BlockStore, BlockStoreError, PutOutcome};

/// Multipart part size. Larger than the 5 MiB floor so a 128 MiB block is a
/// handful of parts, small enough that one part's retry cost stays bounded.
const PART_SIZE: usize = 16 * 1024 * 1024;

const KEY_PREFIX: &str = "model-blocks/v1";

pub struct S3BlockStore {
    s3: S3Client,
    bucket: String,
}

impl S3BlockStore {
    /// Create a client against the configured endpoint: the same
    /// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_ENDPOINT_URL_S3
    /// environment the Tigris repo backend reads.
    pub async fn new(bucket: &str) -> anyhow::Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self {
            s3: S3Client::new(&config),
            bucket: bucket.to_string(),
        })
    }

    /// Build a client pointed at an arbitrary endpoint for tests. The
    /// production constructor reads the endpoint from the environment, which
    /// a test cannot steer; retries are disabled so a dead endpoint fails
    /// fast instead of backing off for seconds.
    #[cfg(test)]
    fn for_testing(bucket: &str, endpoint: &str, timeout: std::time::Duration) -> Self {
        use aws_sdk_s3::config::retry::RetryConfig;
        use aws_sdk_s3::config::timeout::TimeoutConfig;
        use aws_sdk_s3::config::{Credentials, Region};

        let config = aws_sdk_s3::config::Config::builder()
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .region(Region::new("auto"))
            .retry_config(RetryConfig::disabled())
            .timeout_config(TimeoutConfig::builder().operation_timeout(timeout).build())
            .behavior_version_latest()
            .build();
        Self {
            s3: S3Client::from_conf(config),
            bucket: bucket.to_string(),
        }
    }

    fn key(id: &BlockId) -> String {
        let s = id.as_str();
        format!("{KEY_PREFIX}/{}/{s}", &s[..2])
    }

    fn backend<E: std::fmt::Display>(err: E) -> BlockStoreError {
        BlockStoreError::Backend(err.to_string())
    }

    async fn upload_one_part(
        &self,
        key: &str,
        upload_id: &str,
        number: i32,
        bytes: Vec<u8>,
    ) -> Result<CompletedPart, BlockStoreError> {
        let out = self
            .s3
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(number)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(Self::backend)?;
        Ok(CompletedPart::builder()
            .part_number(number)
            .e_tag(out.e_tag().unwrap_or_default())
            .build())
    }

    /// Upload the bytes accumulated in `part_buf` as the next part.
    async fn flush_part(
        &self,
        key: &str,
        upload_id: &str,
        part_buf: &mut Vec<u8>,
        parts: &mut Vec<CompletedPart>,
    ) -> Result<(), BlockStoreError> {
        let staged = std::mem::take(part_buf);
        let number = (parts.len() + 1) as i32;
        parts.push(self.upload_one_part(key, upload_id, number, staged).await?);
        Ok(())
    }

    async fn abort(&self, key: &str, upload_id: &str) {
        if let Err(e) = self
            .s3
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            // An abort that fails leaves orphaned parts, which cost storage
            // but never serve: the object is invisible until a complete
            // commits, and only the upload's owner knows the parts' hashes.
            tracing::warn!(key = %key, "multipart abort failed: {e}");
        }
    }

    /// Classify a failed `CompleteMultipartUpload`: does the failure PROVE
    /// the object was not committed? Only a refusal the server took before
    /// storing (a 4xx) or a request that never left the client proves that;
    /// anything else may have committed while the answer was lost, and the
    /// honest answer is `Unknown`. Same rule as `git::tigris`'s dispatch
    /// classifier, including the cautious fallback for the `#[non_exhaustive]`
    /// error enum.
    fn classify_complete_failure<E>(err: &SdkError<E>) -> BlockStoreError {
        if let Some(status) = err.raw_response().map(|r| r.status().as_u16()) {
            return if (400..500).contains(&status) {
                Self::backend(format!("complete refused with status {status}"))
            } else {
                BlockStoreError::Unknown
            };
        }
        match err {
            SdkError::ConstructionFailure(_) => Self::backend(err.to_string()),
            _ => BlockStoreError::Unknown,
        }
    }
}

#[async_trait]
impl BlockStore for S3BlockStore {
    async fn put_verified(
        &self,
        id: &BlockId,
        mut body: BoxStream<'static, io::Result<Bytes>>,
        max_len: u64,
    ) -> Result<PutOutcome, BlockStoreError> {
        let key = Self::key(id);
        if self.size(id).await?.is_some() {
            return Ok(PutOutcome::AlreadyPresent);
        }

        // A zero-length body cannot be a multipart upload, but it can be a
        // valid (if useless) object under the empty-sha id.
        let upload = self
            .s3
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(Self::backend)?;
        let upload_id = upload.upload_id().unwrap_or_default().to_string();

        let mut hasher = Sha256::new();
        let mut len: u64 = 0;
        let mut part_buf: Vec<u8> = Vec::with_capacity(PART_SIZE);
        let mut parts: Vec<CompletedPart> = Vec::new();

        // `part_buf` is taken and replaced on each flush, so only one part is
        // ever resident, never the whole body.
        let result: Result<(), BlockStoreError> = async {
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(BlockStoreError::Body)?;
                len = len.saturating_add(chunk.len() as u64);
                if len > max_len {
                    return Err(BlockStoreError::TooLarge(max_len));
                }
                hasher.update(&chunk);
                part_buf.extend_from_slice(&chunk);
                if part_buf.len() >= PART_SIZE {
                    self.flush_part(&key, &upload_id, &mut part_buf, &mut parts)
                        .await?;
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            self.abort(&key, &upload_id).await;
            return Err(e);
        }
        if hex::encode(hasher.finalize()) != id.as_str() {
            self.abort(&key, &upload_id).await;
            return Err(BlockStoreError::DigestMismatch);
        }
        if !part_buf.is_empty() {
            if let Err(e) = self
                .flush_part(&key, &upload_id, &mut part_buf, &mut parts)
                .await
            {
                self.abort(&key, &upload_id).await;
                return Err(e);
            }
        }
        if parts.is_empty() {
            // len == 0 and the hash matched, meaning id is the empty-sha.
            self.abort(&key, &upload_id).await;
            self.s3
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .body(ByteStream::from_static(b""))
                .send()
                .await
                .map_err(|e| {
                    if e.raw_response().is_none() {
                        BlockStoreError::Unknown
                    } else {
                        Self::backend(e)
                    }
                })?;
            return Ok(PutOutcome::Stored);
        }

        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        match self
            .s3
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&key)
            .upload_id(&upload_id)
            .multipart_upload(completed)
            .send()
            .await
        {
            Ok(_) => Ok(PutOutcome::Stored),
            Err(e) => {
                let verdict = Self::classify_complete_failure(&e);
                if !matches!(verdict, BlockStoreError::Unknown) {
                    self.abort(&key, &upload_id).await;
                }
                Err(verdict)
            }
        }
    }

    async fn get_range(
        &self,
        id: &BlockId,
        start: u64,
        end_exclusive: u64,
    ) -> Result<BoxStream<'static, io::Result<Bytes>>, BlockStoreError> {
        // Bounds come from a HEAD, not from the GET's range answer: S3
        // clamps an over-long end to the object size instead of failing,
        // which would silently return fewer bytes than fs does.
        let size = match self.size(id).await? {
            Some(size) => size,
            None => return Err(BlockStoreError::NotFound),
        };
        if start > end_exclusive || end_exclusive > size {
            return Err(BlockStoreError::OutOfRange);
        }
        if start == end_exclusive {
            return Ok(futures::stream::empty().boxed());
        }
        let out = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(Self::key(id))
            .range(format!("bytes={start}-{}", end_exclusive - 1))
            .send()
            .await
            .map_err(|e| {
                if e.as_service_error().is_some_and(|s| s.is_no_such_key())
                    || e.raw_response().map(|r| r.status().as_u16()) == Some(404)
                {
                    return BlockStoreError::NotFound;
                }
                // S3 answers an unsatisfiable range with 416 InvalidRange.
                if e.raw_response().map(|r| r.status().as_u16()) == Some(416) {
                    return BlockStoreError::OutOfRange;
                }
                Self::backend(e)
            })?;
        Ok(tokio_util::io::ReaderStream::new(out.body.into_async_read()).boxed())
    }

    async fn size(&self, id: &BlockId) -> Result<Option<u64>, BlockStoreError> {
        match self
            .s3
            .head_object()
            .bucket(&self.bucket)
            .key(Self::key(id))
            .send()
            .await
        {
            Ok(out) => Ok(out.content_length().map(|l| l as u64)),
            Err(e) => {
                let status = e.raw_response().map(|r| r.status().as_u16());
                if e.as_service_error().is_some_and(|s| s.is_not_found()) || status == Some(404) {
                    Ok(None)
                } else {
                    Err(Self::backend(e))
                }
            }
        }
    }

    async fn delete(&self, id: &BlockId) -> Result<(), BlockStoreError> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(Self::key(id))
            .send()
            .await
            .map_err(Self::backend)?;
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes as AxBytes;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::Response;
    use axum::routing::{delete, get, head, post, put};
    use axum::Router;
    use sha2::Digest;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A minimal in-memory S3 mock: just enough of the API surface the
    /// backend calls (multipart create/part/complete/abort, put, get, head,
    /// delete). No signature check; the SDK client is built with test
    /// credentials and the point of the mock is protocol shape, not auth.
    #[derive(Default)]
    struct Objects {
        map: Mutex<HashMap<String, Vec<u8>>>,
        parts: Mutex<HashMap<(String, i32), Vec<u8>>>,
        /// When set, the complete endpoint stores the object and then hangs
        /// past the client's operation timeout, simulating a commit whose
        /// answer was lost.
        hang_on_complete: Mutex<bool>,
    }

    async fn head_handler(
        State(st): State<Arc<Objects>>,
        axum::extract::Path((_bucket, key)): axum::extract::Path<(String, String)>,
    ) -> Response {
        let objects = st.map.lock().unwrap();
        match objects.get(&key) {
            Some(body) => Response::builder()
                .status(StatusCode::OK)
                .header("content-length", body.len().to_string())
                .body(axum::body::Body::empty())
                .unwrap(),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::empty())
                .unwrap(),
        }
    }

    async fn get_handler(
        State(st): State<Arc<Objects>>,
        axum::extract::Path((_bucket, key)): axum::extract::Path<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        let objects = st.map.lock().unwrap();
        let Some(body) = objects.get(&key) else {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from(
                    "<Error><Code>NoSuchKey</Code></Error>",
                ))
                .unwrap();
        };
        if let Some(range) = headers.get("range").and_then(|v| v.to_str().ok()) {
            // bytes=<start>-<end inclusive>
            let spec = range.trim_start_matches("bytes=");
            let (a, b) = spec.split_once('-').unwrap();
            let (start, end): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
            if end >= body.len() {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(axum::body::Body::from(
                        "<Error><Code>InvalidRange</Code></Error>",
                    ))
                    .unwrap();
            }
            return Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .body(axum::body::Body::from(body[start..=end].to_vec()))
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from(body.clone()))
            .unwrap()
    }

    async fn put_handler(
        State(st): State<Arc<Objects>>,
        axum::extract::Path((_bucket, key)): axum::extract::Path<(String, String)>,
        Query(q): Query<HashMap<String, String>>,
        body: AxBytes,
    ) -> Response {
        if let (Some(part), Some(_)) = (
            q.get("partNumber").and_then(|p| p.parse::<i32>().ok()),
            q.get("uploadId"),
        ) {
            st.parts.lock().unwrap().insert((key, part), body.to_vec());
            return Response::builder()
                .status(StatusCode::OK)
                .header("etag", format!("etag-{part}"))
                .body(axum::body::Body::empty())
                .unwrap();
        }
        // Plain put (used by the zero-length object path).
        st.map.lock().unwrap().insert(key, body.to_vec());
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "etag-0")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn post_handler(
        State(st): State<Arc<Objects>>,
        axum::extract::Path((_bucket, key)): axum::extract::Path<(String, String)>,
        Query(q): Query<HashMap<String, String>>,
        body: AxBytes,
    ) -> Response {
        if q.contains_key("uploads") {
            return Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from(
                    "<InitiateMultipartUploadResult><UploadId>u-1</UploadId></InitiateMultipartUploadResult>",
                ))
                .unwrap();
        }
        if q.contains_key("uploadId") {
            // Assemble the object's parts in number order from the complete
            // request's part list.
            let text = String::from_utf8_lossy(&body);
            let mut numbers: Vec<i32> = text
                .match_indices("<PartNumber>")
                .map(|(i, _)| {
                    let rest = &text[i + 12..];
                    rest[..rest.find('<').unwrap()].parse().unwrap()
                })
                .collect();
            numbers.sort_unstable();
            let mut assembled = Vec::new();
            {
                let parts = st.parts.lock().unwrap();
                for n in &numbers {
                    if let Some(p) = parts.get(&(key.clone(), *n)) {
                        assembled.extend_from_slice(p);
                    }
                }
            }
            st.map.lock().unwrap().insert(key.clone(), assembled);
            st.parts.lock().unwrap().retain(|(k, _), _| k != &key);
            if *st.hang_on_complete.lock().unwrap() {
                // The object is stored; the answer never arrives.
                futures::future::pending::<()>().await;
            }
            return Response::builder()
                .status(StatusCode::OK)
                .body(axum::body::Body::from(
                    "<CompleteMultipartUploadResult><ETag>final</ETag></CompleteMultipartUploadResult>",
                ))
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn delete_handler(
        State(st): State<Arc<Objects>>,
        axum::extract::Path((_bucket, key)): axum::extract::Path<(String, String)>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Response {
        if q.contains_key("uploadId") {
            st.parts.lock().unwrap().retain(|(k, _), _| k != &key);
        } else {
            st.map.lock().unwrap().remove(&key);
        }
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// Spawn the mock on an ephemeral port; returns (base_url, state).
    async fn spawn_mock(hang_on_complete: bool) -> (String, Arc<Objects>) {
        let st = Arc::new(Objects {
            hang_on_complete: Mutex::new(hang_on_complete),
            ..Objects::default()
        });
        let app = Router::new()
            .route("/{bucket}/{*key}", get(get_handler))
            .route("/{bucket}/{*key}", put(put_handler))
            .route("/{bucket}/{*key}", post(post_handler))
            .route("/{bucket}/{*key}", head(head_handler))
            .route("/{bucket}/{*key}", delete(delete_handler))
            .with_state(st.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), st)
    }

    fn id_of(bytes: &[u8]) -> BlockId {
        BlockId::parse(&hex::encode(Sha256::digest(bytes))).unwrap()
    }

    fn stream(bytes: Vec<u8>) -> BoxStream<'static, io::Result<Bytes>> {
        futures::stream::iter(vec![Ok(Bytes::from(bytes))]).boxed()
    }

    async fn collect(mut s: BoxStream<'static, io::Result<Bytes>>) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        out
    }

    fn store(url: &str) -> S3BlockStore {
        S3BlockStore::for_testing("blocks", url, Duration::from_secs(10))
    }

    #[tokio::test]
    async fn put_size_get_delete_roundtrip() {
        let (url, _st) = spawn_mock(false).await;
        let s = store(&url);
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let id = id_of(&body);

        assert_eq!(
            s.put_verified(&id, stream(body.clone()), u64::MAX)
                .await
                .unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(s.size(&id).await.unwrap(), Some(body.len() as u64));
        assert_eq!(s.backend_name(), "s3");
        assert_eq!(
            s.put_verified(&id, stream(body.clone()), u64::MAX)
                .await
                .unwrap(),
            PutOutcome::AlreadyPresent
        );

        let got = collect(s.get_range(&id, 1000, 2000).await.unwrap()).await;
        assert_eq!(got, body[1000..2000]);
        assert!(matches!(
            s.get_range(&id, 0, body.len() as u64 + 1)
                .await
                .map(|_| ())
                .unwrap_err(),
            BlockStoreError::OutOfRange | BlockStoreError::Backend(_)
        ));

        s.delete(&id).await.unwrap();
        assert_eq!(s.size(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn range_edge_contract_matches_the_trait() {
        let (url, _st) = spawn_mock(false).await;
        let s = store(&url);
        crate::blockstore::parity::get_range_edge_contract(&s).await;
    }

    #[tokio::test]
    async fn digest_mismatch_aborts_and_stores_nothing() {
        let (url, st) = spawn_mock(false).await;
        let s = store(&url);
        let id = id_of(b"expected");
        let err = s
            .put_verified(&id, stream(b"different".to_vec()), u64::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, BlockStoreError::DigestMismatch));
        assert_eq!(s.size(&id).await.unwrap(), None);
        // The abort removed the staged parts.
        assert!(st.parts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn over_cap_aborts_while_streaming() {
        let (url, _st) = spawn_mock(false).await;
        let s = store(&url);
        let body = vec![7u8; 4096];
        let id = id_of(&body);
        let err = s.put_verified(&id, stream(body), 1024).await.unwrap_err();
        assert!(matches!(err, BlockStoreError::TooLarge(1024)));
        assert_eq!(s.size(&id).await.unwrap(), None);
    }

    /// A complete request that commits server-side but whose answer is lost
    /// must report Unknown, and a later HEAD shows the object is there. The
    /// cautious arm exists so a caller never treats a possibly-stored object
    /// as definitely absent.
    #[tokio::test]
    async fn lost_complete_answer_reports_unknown_then_head_resolves() {
        let (url, _st) = spawn_mock(true).await;
        let s = S3BlockStore::for_testing("blocks", &url, Duration::from_millis(300));
        let body = vec![9u8; 1024];
        let id = id_of(&body);
        let err = s
            .put_verified(&id, stream(body.clone()), u64::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, BlockStoreError::Unknown), "got {err:?}");
        // The write actually committed server-side; a HEAD sees it.
        assert_eq!(
            store(&url).size(&id).await.unwrap(),
            Some(body.len() as u64)
        );
    }
}
