//! Filesystem block backend: objects under `<root>/<aa>/<bb>/<sha>` with
//! staged writes in `<root>/tmp/`.
//!
//! A write lands in a uniquely-named temp file, is fsynced, and becomes
//! visible only through a hard link to its content address, which is atomic
//! and refuses to overwrite: two publishers racing the same object get one
//! `Stored` and one `AlreadyPresent`, never a torn object. The temp file is
//! removed on every failure path, so a rejected body leaves nothing behind.

use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::{BlockId, BlockStore, BlockStoreError, PutOutcome};

pub struct FsBlockStore {
    root: PathBuf,
}

impl FsBlockStore {
    pub fn new(root: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(Self { root })
    }

    fn content_path(&self, id: &BlockId) -> PathBuf {
        let s = id.as_str();
        self.root.join(&s[..2]).join(&s[2..4]).join(s)
    }

    fn temp_path(&self) -> PathBuf {
        self.root
            .join("tmp")
            .join(format!("put-{}", uuid::Uuid::new_v4()))
    }

    async fn cleanup(path: &Path) {
        let _ = tokio::fs::remove_file(path).await;
    }
}

/// Fsync a directory so a name created inside it survives a crash: after
/// `Stored`, a link that only exists in the page cache is a lost write.
#[cfg(unix)]
async fn fsync_dir(dir: &Path) -> io::Result<()> {
    tokio::fs::File::open(dir).await?.sync_all().await
}

/// Directory fsync is a unix durability primitive; elsewhere the link is
/// the best guarantee available.
#[cfg(not(unix))]
async fn fsync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

#[async_trait]
impl BlockStore for FsBlockStore {
    async fn put_verified(
        &self,
        id: &BlockId,
        mut body: BoxStream<'static, io::Result<Bytes>>,
        max_len: u64,
    ) -> Result<PutOutcome, BlockStoreError> {
        let dest = self.content_path(id);
        if dest.exists() {
            return Ok(PutOutcome::AlreadyPresent);
        }

        let tmp = self.temp_path();
        let mut file = match tokio::fs::File::create(&tmp).await {
            Ok(f) => f,
            Err(e) => return Err(e.into()),
        };
        let mut hasher = Sha256::new();
        let mut len: u64 = 0;
        let result: Result<(), BlockStoreError> = async {
            while let Some(chunk) = body.next().await {
                let chunk = chunk.map_err(BlockStoreError::Body)?;
                len = len.saturating_add(chunk.len() as u64);
                if len > max_len {
                    return Err(BlockStoreError::TooLarge(max_len));
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            drop(file);
            Self::cleanup(&tmp).await;
            return Err(e);
        }
        if hex::encode(hasher.finalize()) != id.as_str() {
            drop(file);
            Self::cleanup(&tmp).await;
            return Err(BlockStoreError::DigestMismatch);
        }
        // Flush before the link: a crash between link and write-back would
        // leave a truncated object under a valid id.
        if let Err(e) = file.sync_all().await {
            drop(file);
            Self::cleanup(&tmp).await;
            return Err(e.into());
        }
        drop(file);

        let dir = dest.parent().expect("content path has two levels");
        let fresh_dirs = !dir.exists();
        if let Err(e) = tokio::fs::create_dir_all(dir).await {
            Self::cleanup(&tmp).await;
            return Err(e.into());
        }
        if fresh_dirs {
            // The new <aa>/<bb> levels are themselves names in a parent
            // directory; persist each level's entry.
            for ancestor in [dir.parent().unwrap_or(&self.root), self.root.as_path()] {
                if let Err(e) = fsync_dir(ancestor).await {
                    Self::cleanup(&tmp).await;
                    return Err(e.into());
                }
            }
        }
        // A hard link refuses to replace an existing object, which is what
        // makes a same-content race benign rather than a torn write.
        match tokio::fs::hard_link(&tmp, &dest).await {
            Ok(()) => {
                if let Err(e) = fsync_dir(dir).await {
                    Self::cleanup(&tmp).await;
                    return Err(e.into());
                }
                Self::cleanup(&tmp).await;
                Ok(PutOutcome::Stored)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Self::cleanup(&tmp).await;
                Ok(PutOutcome::AlreadyPresent)
            }
            Err(e) => {
                Self::cleanup(&tmp).await;
                Err(e.into())
            }
        }
    }

    async fn get_range(
        &self,
        id: &BlockId,
        start: u64,
        end_exclusive: u64,
    ) -> Result<BoxStream<'static, io::Result<Bytes>>, BlockStoreError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let path = self.content_path(id);
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(BlockStoreError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata().await?.len();
        if start > end_exclusive || end_exclusive > len {
            return Err(BlockStoreError::OutOfRange);
        }
        file.seek(io::SeekFrom::Start(start)).await?;
        let limited = file.take(end_exclusive - start);
        Ok(tokio_util::io::ReaderStream::new(limited).boxed())
    }

    async fn size(&self, id: &BlockId) -> Result<Option<u64>, BlockStoreError> {
        match tokio::fs::metadata(self.content_path(id)).await {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, id: &BlockId) -> Result<(), BlockStoreError> {
        match tokio::fs::remove_file(self.content_path(id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn backend_name(&self) -> &'static str {
        "fs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn id_of(bytes: &[u8]) -> BlockId {
        BlockId::parse(&hex::encode(Sha256::digest(bytes))).unwrap()
    }

    fn stream(bytes: Vec<u8>) -> BoxStream<'static, io::Result<Bytes>> {
        futures::stream::iter(vec![Ok(Bytes::from(bytes))]).boxed()
    }

    fn chunked_stream(parts: Vec<Vec<u8>>) -> BoxStream<'static, io::Result<Bytes>> {
        futures::stream::iter(parts.into_iter().map(|p| Ok(Bytes::from(p)))).boxed()
    }

    async fn collect(mut s: BoxStream<'static, io::Result<Bytes>>) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        out
    }

    fn store(dir: &tempfile::TempDir) -> FsBlockStore {
        FsBlockStore::new(dir.path().join("blocks")).unwrap()
    }

    #[tokio::test]
    async fn put_get_size_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let body: Vec<u8> = (0..100_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let id = id_of(&body);
        assert_eq!(
            s.put_verified(&id, stream(body.clone()), u64::MAX)
                .await
                .unwrap(),
            PutOutcome::Stored
        );
        assert_eq!(s.size(&id).await.unwrap(), Some(body.len() as u64));
        assert_eq!(s.backend_name(), "fs");
        // A second put of the same content is a no-op.
        assert_eq!(
            s.put_verified(&id, stream(body.clone()), u64::MAX)
                .await
                .unwrap(),
            PutOutcome::AlreadyPresent
        );
    }

    #[tokio::test]
    async fn wrong_id_is_rejected_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let id = id_of(b"different bytes");
        let err = s
            .put_verified(&id, stream(b"actual".to_vec()), u64::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, BlockStoreError::DigestMismatch));
        assert_eq!(s.size(&id).await.unwrap(), None);
        // No temp file survives the failure.
        assert_eq!(
            std::fs::read_dir(dir.path().join("blocks/tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_while_streaming() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let body = vec![0u8; 1024];
        let id = id_of(&body);
        let err = s.put_verified(&id, stream(body), 512).await.unwrap_err();
        assert!(matches!(err, BlockStoreError::TooLarge(512)));
        assert_eq!(s.size(&id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn range_reads_return_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let body: Vec<u8> = (0..255u8).collect();
        let id = id_of(&body);
        s.put_verified(&id, stream(body.clone()), u64::MAX)
            .await
            .unwrap();

        let got = collect(s.get_range(&id, 10, 20).await.unwrap()).await;
        assert_eq!(got, body[10..20]);

        let got = collect(s.get_range(&id, 0, 255).await.unwrap()).await;
        assert_eq!(got, body);

        assert!(matches!(
            s.get_range(&id, 200, 300).await.map(|_| ()).unwrap_err(),
            BlockStoreError::OutOfRange
        ));
        let missing = id_of(b"missing");
        assert!(matches!(
            s.get_range(&missing, 0, 1).await.map(|_| ()).unwrap_err(),
            BlockStoreError::NotFound
        ));
    }

    #[tokio::test]
    async fn range_edge_contract_matches_the_trait() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        crate::blockstore::parity::get_range_edge_contract(&s).await;
    }

    #[tokio::test]
    async fn concurrent_puts_leave_one_object() {
        let dir = tempfile::tempdir().unwrap();
        let s = std::sync::Arc::new(store(&dir));
        let body: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let id = id_of(&body);
        let (a, b) = tokio::join!(
            s.put_verified(&id, stream(body.clone()), u64::MAX),
            s.put_verified(&id, stream(body.clone()), u64::MAX)
        );
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(s.size(&id).await.unwrap(), Some(body.len() as u64));
        let got = collect(s.get_range(&id, 0, body.len() as u64).await.unwrap()).await;
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn delete_removes_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let id = id_of(b"gone");
        s.put_verified(&id, stream(b"gone".to_vec()), u64::MAX)
            .await
            .unwrap();
        s.delete(&id).await.unwrap();
        assert_eq!(s.size(&id).await.unwrap(), None);
        s.delete(&id).await.unwrap();
    }

    #[tokio::test]
    async fn streamed_chunks_hash_the_whole_body() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let body: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let parts: Vec<Vec<u8>> = body.chunks(777).map(|c| c.to_vec()).collect();
        let id = id_of(&body);
        s.put_verified(&id, chunked_stream(parts), u64::MAX)
            .await
            .unwrap();
        let got = collect(s.get_range(&id, 0, body.len() as u64).await.unwrap()).await;
        assert_eq!(got, body);
    }

    #[test]
    fn block_id_shape() {
        assert!(BlockId::parse(&"a".repeat(64)).is_ok());
        for bad in [
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            assert!(BlockId::parse(bad).is_err(), "{bad} must be rejected");
        }
    }
}
