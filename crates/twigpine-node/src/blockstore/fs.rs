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
        let tmp = root.join("tmp");
        // Every directory this call creates, deepest first. Creating them
        // adds an entry to each one's parent, and an entry that is not
        // fsynced is lost on a crash together with every block under it.
        let created: Vec<PathBuf> = tmp
            .ancestors()
            .take_while(|a| !a.as_os_str().is_empty() && !a.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(&tmp)?;
        for dir in &created {
            if let Some(parent) = dir.parent() {
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                fsync_dir_blocking(parent)?;
            }
        }
        Ok(Self { root })
    }

    /// Fsync `dir` and every directory above it up to the store root, so the
    /// whole `<aa>/<bb>/<sha>` name chain is durable. Used wherever success
    /// is reported for a name this call did not itself just publish: a
    /// concurrent writer may have linked it and not yet synced.
    async fn sync_chain(&self, dir: &Path) -> io::Result<()> {
        fsync_dir(dir).await?;
        self.sync_ancestors(dir).await
    }

    /// The directories above a leaf directory, up to and including the root.
    async fn sync_ancestors(&self, dir: &Path) -> io::Result<()> {
        fsync_dir(dir.parent().unwrap_or(&self.root)).await?;
        fsync_dir(&self.root).await
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
    #[cfg(test)]
    SYNCED.lock().unwrap().push(dir.to_path_buf());
    tokio::fs::File::open(dir).await?.sync_all().await
}

#[cfg(unix)]
fn fsync_dir_blocking(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    SYNCED.lock().unwrap().push(dir.to_path_buf());
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir_blocking(_: &Path) -> io::Result<()> {
    Ok(())
}

/// Every directory fsynced in this test process, so a test can assert which
/// names a code path made durable.
#[cfg(test)]
static SYNCED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

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
        let dir = dest.parent().expect("content path has two levels");
        if dest.exists() {
            // The name may belong to a writer that linked it and has not
            // fsynced yet: persist the chain before reporting it present.
            self.sync_chain(dir).await?;
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
                let chunk = chunk?;
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
        if len == 0 {
            drop(file);
            Self::cleanup(&tmp).await;
            return Err(BlockStoreError::EmptyBlock);
        }
        // Flush before the link: a crash between link and write-back would
        // leave a truncated object under a valid id.
        if let Err(e) = file.sync_all().await {
            drop(file);
            Self::cleanup(&tmp).await;
            return Err(e.into());
        }
        drop(file);

        if let Err(e) = tokio::fs::create_dir_all(dir).await {
            Self::cleanup(&tmp).await;
            return Err(e.into());
        }
        // The <aa>/<bb> levels are names in their parents. Persist them on
        // every store, not only when this call created them: a concurrent
        // writer may have created them and not yet synced, and the
        // directory merely existing says nothing about being durable.
        if let Err(e) = self.sync_ancestors(dir).await {
            Self::cleanup(&tmp).await;
            return Err(e.into());
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
                // The winner's link may precede its own directory sync.
                self.sync_chain(dir).await?;
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
    async fn empty_body_is_refused_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        crate::blockstore::parity::empty_body_contract(&s).await;
        assert_eq!(
            std::fs::read_dir(dir.path().join("blocks/tmp"))
                .unwrap()
                .count(),
            0
        );
    }

    /// Directories whose entry was fsynced under `root`, in call order.
    fn synced_under(root: &Path) -> Vec<PathBuf> {
        SYNCED
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.starts_with(root))
            .cloned()
            .collect()
    }

    fn forget_synced(root: &Path) {
        SYNCED.lock().unwrap().retain(|p| !p.starts_with(root));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_new_root_persists_every_created_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().join("a");
        let root = top.join("b").join("blocks");
        FsBlockStore::new(root.clone()).unwrap();
        let synced = synced_under(dir.path());
        // Each directory created on the way down, and the pre-existing
        // directory that now holds the first of them, has been fsynced.
        for expected in [
            dir.path(),
            top.as_path(),
            top.join("b").as_path(),
            root.as_path(),
        ] {
            assert!(
                synced.iter().any(|p| p == expected),
                "{expected:?} not fsynced; got {synced:?}"
            );
        }
    }

    /// A destination that already exists may have been linked by a writer
    /// that has not fsynced yet, so reporting it present must persist the
    /// whole publication chain itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn already_present_persists_the_publication_chain() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let body = b"duplicate".to_vec();
        let id = id_of(&body);
        s.put_verified(&id, stream(body.clone()), u64::MAX)
            .await
            .unwrap();
        let leaf = s.content_path(&id).parent().unwrap().to_path_buf();
        forget_synced(dir.path());
        assert_eq!(
            s.put_verified(&id, stream(body), u64::MAX).await.unwrap(),
            PutOutcome::AlreadyPresent
        );
        let synced = synced_under(dir.path());
        for expected in [leaf.as_path(), leaf.parent().unwrap(), s.root.as_path()] {
            assert!(
                synced.iter().any(|p| p == expected),
                "{expected:?} not fsynced on AlreadyPresent; got {synced:?}"
            );
        }
    }

    /// A second block landing in a directory that already exists still
    /// persists that directory's ancestors: existence is not durability.
    #[cfg(unix)]
    #[tokio::test]
    async fn every_store_persists_the_ancestor_chain() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let first = b"first".to_vec();
        s.put_verified(&id_of(&first), stream(first.clone()), u64::MAX)
            .await
            .unwrap();
        // Same aa/bb directory, different object: find a body whose id
        // shares the first four hex characters.
        let target = id_of(&first);
        let prefix = &target.as_str()[..4];
        let mut n = 0u64;
        let sibling = loop {
            let candidate = n.to_le_bytes().to_vec();
            if id_of(&candidate).as_str().starts_with(prefix) && candidate != first {
                break candidate;
            }
            n += 1;
        };
        forget_synced(dir.path());
        s.put_verified(&id_of(&sibling), stream(sibling.clone()), u64::MAX)
            .await
            .unwrap();
        let leaf = s.content_path(&target).parent().unwrap().to_path_buf();
        let synced = synced_under(dir.path());
        for expected in [leaf.as_path(), leaf.parent().unwrap(), s.root.as_path()] {
            assert!(
                synced.iter().any(|p| p == expected),
                "{expected:?} not fsynced for a store into an existing dir; got {synced:?}"
            );
        }
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
