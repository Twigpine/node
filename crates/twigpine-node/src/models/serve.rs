//! Byte-exact, resumable downloads for the HF resolve route (KTD9).
//!
//! The pure half is `resolve`: turn a `Range`/`If-Range` header pair into a
//! `RangeSpec` over a file of `total` bytes. The streaming half is
//! `slices_stream`, which turns `map_file_range`'s block slices into one
//! ordered byte stream over the block store: a chunked file of any size
//! never buffers past one store chunk, so node memory is bounded by the
//! block size rather than the file size.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use twigpine_core::model::reconstruction::BlockSlice;

use crate::blockstore::{BlockId, BlockStore, BlockStoreError};

/// What a `Range`/`If-Range` pair resolves to over `total` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSpec {
    /// No satisfiable single range: send the whole body with a 200.
    Full,
    /// Send `start..=end_incl` with a 206.
    Single { start: u64, end_incl: u64 },
    /// No range can be satisfied: 416 with `Content-Range: bytes */total`.
    Unsatisfiable,
}

/// Resolve `Range` and `If-Range` header values against a file of `total`
/// bytes whose validator is `etag` (the quoted form is compared
/// quote-insensitively).
///
/// Only a single satisfiable range is honored: a malformed `Range`, a
/// multi-range spec, and an `If-Range` that does not match the current
/// validator all fall back to a full 200 (KTD9: a downloader resumes with
/// one contiguous span, and the RFC lets a server ignore a range it cannot
/// honor rather than answering multipart). A `start` past the end is the
/// one hard answer: 416.
pub fn resolve(range: Option<&str>, if_range: Option<&str>, etag: &str, total: u64) -> RangeSpec {
    let Some(raw) = range else {
        return RangeSpec::Full;
    };
    if let Some(cond) = if_range {
        let cond = cond.trim().trim_matches('"');
        if cond != etag.trim().trim_matches('"') {
            // A stale validator makes the range meaningless: full body.
            return RangeSpec::Full;
        }
    }
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return RangeSpec::Full;
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(',') {
        // Multi-range is deliberately not served: a full 200 is a valid
        // answer and keeps the response shape a downloader can consume.
        return RangeSpec::Full;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeSpec::Full;
    };
    let first = first.trim();
    let last = last.trim();
    if first.is_empty() {
        // Suffix range `bytes=-N`: the last N bytes.
        let Ok(n) = last.parse::<u64>() else {
            return RangeSpec::Full;
        };
        if n == 0 {
            return RangeSpec::Full;
        }
        let len = n.min(total);
        if len == 0 {
            return RangeSpec::Unsatisfiable;
        }
        return RangeSpec::Single {
            start: total - len,
            end_incl: total - 1,
        };
    }
    let Ok(start) = first.parse::<u64>() else {
        return RangeSpec::Full;
    };
    if start >= total {
        return RangeSpec::Unsatisfiable;
    }
    let end_incl = if last.is_empty() {
        total - 1
    } else {
        match last.parse::<u64>() {
            Ok(e) => e.min(total - 1),
            Err(_) => return RangeSpec::Full,
        }
    };
    if start > end_incl {
        // An empty span is an invalid range, not an unsatisfiable one.
        return RangeSpec::Full;
    }
    RangeSpec::Single { start, end_incl }
}

/// Chain the block slices into one ordered byte stream. Each slice is a
/// `get_range` against the block store: the store's own chunked stream is
/// flattened, so a range spanning several blocks still yields contiguous
/// file bytes and peak memory tracks the store's read chunking, never the
/// file's length.
pub fn slices_stream(
    store: Arc<dyn BlockStore>,
    slices: Vec<BlockSlice>,
) -> BoxStream<'static, io::Result<Bytes>> {
    futures::stream::iter(slices)
        .then(move |slice| {
            let store = store.clone();
            async move {
                let id =
                    BlockId::parse(&slice.block).map_err(|e| io::Error::other(e.to_string()))?;
                let end = slice
                    .offset
                    .checked_add(slice.len)
                    .ok_or_else(|| io::Error::other("slice range overflow"))?;
                store
                    .get_range(&id, slice.offset, end)
                    .await
                    .map_err(store_to_io)
            }
        })
        .flat_map(|res| -> BoxStream<'static, io::Result<Bytes>> {
            match res {
                Ok(s) => s,
                Err(e) => futures::stream::once(std::future::ready(Err(e))).boxed(),
            }
        })
        .boxed()
}

fn store_to_io(e: BlockStoreError) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETAG: &str = "\"abc123\"";

    #[test]
    fn no_range_is_full() {
        assert_eq!(resolve(None, None, ETAG, 100), RangeSpec::Full);
    }

    #[test]
    fn open_ended_range() {
        assert_eq!(
            resolve(Some("bytes=1000-"), None, ETAG, 2000),
            RangeSpec::Single {
                start: 1000,
                end_incl: 1999
            }
        );
    }

    #[test]
    fn closed_range_and_clamped_end() {
        assert_eq!(
            resolve(Some("bytes=0-99"), None, ETAG, 2000),
            RangeSpec::Single {
                start: 0,
                end_incl: 99
            }
        );
        // An end past the last byte clamps, not errors.
        assert_eq!(
            resolve(Some("bytes=1990-5000"), None, ETAG, 2000),
            RangeSpec::Single {
                start: 1990,
                end_incl: 1999
            }
        );
    }

    #[test]
    fn suffix_range() {
        assert_eq!(
            resolve(Some("bytes=-50"), None, ETAG, 2000),
            RangeSpec::Single {
                start: 1950,
                end_incl: 1999
            }
        );
        // A suffix longer than the file clamps to the whole file.
        assert_eq!(
            resolve(Some("bytes=-5000"), None, ETAG, 100),
            RangeSpec::Single {
                start: 0,
                end_incl: 99
            }
        );
    }

    #[test]
    fn out_of_bounds_is_unsatisfiable() {
        assert_eq!(
            resolve(Some("bytes=2000-"), None, ETAG, 2000),
            RangeSpec::Unsatisfiable
        );
        assert_eq!(
            resolve(Some("bytes=-1"), None, ETAG, 0),
            RangeSpec::Unsatisfiable
        );
    }

    #[test]
    fn malformed_and_multi_fall_back_to_full() {
        for bad in [
            "items=0-9",
            "bytes=",
            "bytes=a-b",
            "bytes=10-5",
            "bytes=0-10,20-30",
            "bytes=-0",
            "bytes",
        ] {
            assert_eq!(
                resolve(Some(bad), None, ETAG, 100),
                RangeSpec::Full,
                "{bad} must fall back to a full 200"
            );
        }
    }

    #[test]
    fn if_range_gates_the_range() {
        // Matching validator (quoted, like we emit): the range applies.
        assert_eq!(
            resolve(Some("bytes=0-9"), Some("\"abc123\""), ETAG, 100),
            RangeSpec::Single {
                start: 0,
                end_incl: 9
            }
        );
        // Bare (unquoted) comparison still matches.
        assert_eq!(
            resolve(Some("bytes=0-9"), Some("abc123"), ETAG, 100),
            RangeSpec::Single {
                start: 0,
                end_incl: 9
            }
        );
        // A stale etag makes the range meaningless: full body.
        assert_eq!(
            resolve(Some("bytes=0-9"), Some("\"old\""), ETAG, 100),
            RangeSpec::Full
        );
    }

    /// Two slices on two different blocks chain into one contiguous byte
    /// stream; a missing block surfaces as a stream error rather than a
    /// short or fabricated body.
    #[tokio::test]
    async fn slices_stream_chains_blocks_and_fails_on_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn BlockStore> = Arc::new(
            crate::blockstore::fs::FsBlockStore::new(dir.path().to_path_buf()).expect("fs store"),
        );
        let mut ids = Vec::new();
        for bytes in [b"hello-".as_slice(), b"world!".as_slice()] {
            let id = BlockId::parse(&twigpine_core::cid::sha256_hex(bytes)).expect("id");
            let body = futures::stream::iter(vec![Ok(Bytes::from(bytes.to_vec()))]).boxed();
            store.put_verified(&id, body, u64::MAX).await.expect("put");
            ids.push(id.as_str().to_string());
        }

        let slices = vec![
            BlockSlice {
                block: ids[0].clone(),
                offset: 0,
                len: 6,
            },
            BlockSlice {
                block: ids[1].clone(),
                offset: 1,
                len: 5,
            },
        ];
        let mut out = Vec::new();
        let mut s = slices_stream(store.clone(), slices);
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.expect("slice bytes"));
        }
        assert_eq!(out, b"hello-orld!");

        let missing = vec![BlockSlice {
            block: "0".repeat(64),
            offset: 0,
            len: 1,
        }];
        let mut s = slices_stream(store, missing);
        assert!(s.next().await.expect("an item").is_err());
    }
}
