//! `twigpine model`: open-weight model publishing (KTD14) and independent
//! release fetching (KTD15).
//!
//! `twigpine model publish` runs inside a local clone of a fully public
//! Twigpine repo: it classifies files by the chunking threshold, packs the
//! large ones into content blocks with cross-release dedup, uploads the new
//! blocks under an upload session (resuming from a `.git` state file after an
//! interruption), commits the signed manifest, pushes, claims the release,
//! and polls until the node's verification publishes or rejects it. If the
//! release is still verifying when the poll budget expires, the command
//! exits non-zero with the status URL to check later.
//!
//! `twigpine model fetch` rebuilds a published release without the node: it
//! finds release anchors by Irys tag on an Arweave gateway, pulls the
//! manifest, reconstruction object, and sha256-to-CID block map off an IPFS
//! gateway, verifies the manifest signature against a caller-supplied owner
//! DID (never a DID read out of the anchor), and writes byte-verified files
//! in an HF-snapshot-like layout.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest as _;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use twigpine_core::cid::sha256_hex;
use twigpine_core::model::manifest::{
    self, detect_format, Manifest, ManifestFile, ParentRef, ReconstructionRef, StorageKind,
    MANIFEST_SCHEMA_V1,
};
use twigpine_core::model::reconstruction::{
    pack_file_with, BlockEntry, DedupIndex, FileEntry, Reconstruction,
};

use crate::http::{
    json_or_denial, read_body_capped_bytes, read_json, sanitize_node_msg, NodeClient,
};
use crate::identity::load_keypair_from_dir;
use twigpine_core::did::Did;

const DEFAULT_CHUNK_THRESHOLD: u64 = 10 * 1024 * 1024;
const SESSION_HEADER: &str = "x-twigpine-model-session";
const STATE_FILE_NAME: &str = "twigpine-model-publish.json";
const GITIGNORE_BEGIN: &str = "# >>> twigpine-model-publish >>>";
const GITIGNORE_END: &str = "# <<< twigpine-model-publish <<<";
/// huggingface_hub 2.x refuses plain downloads of a single file past this.
const SINGLE_FILE_WARN_BYTES: u64 = 50 << 30;
/// Bound on a fetched prior reconstruction object: big models name thousands
/// of blocks but the object is small JSON; a runaway body is not one.
const RECONSTRUCTION_FETCH_CAP: usize = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(3);
const POLL_BUDGET: Duration = Duration::from_secs(300);

// ── fetch constants ─────────────────────────────────────────────────────────
/// Cap on one anchor transaction body: the anchor is a few hundred bytes of
/// JSON, so a body past this is not one.
const ANCHOR_BODY_CAP: usize = 1024 * 1024;
/// Cap on a fetched manifest: a 5,000-file manifest is a couple of MiB of
/// JSON; larger is not one.
const MANIFEST_FETCH_CAP: usize = 16 * 1024 * 1024;
/// Cap on the sha256 -> provider-CID block map; thousands of entries fit in
/// a few hundred KiB.
const BLOCK_MAP_FETCH_CAP: usize = 64 * 1024 * 1024;
/// One content block fetched whole: bounded by the node's 128 MiB block cap,
/// so the read cap is one byte past it.
const OBJECT_FETCH_CAP: usize = (128 * 1024 * 1024) + 1;
/// Resident budget for the fetched-block LRU. Blocks are ~64 MiB each, so a
/// few shared blocks stay hot across chunked files without holding the model.
const BLOCK_CACHE_BUDGET: usize = 256 * 1024 * 1024;
/// Anchor candidates tried before giving up; anchors iterate newest first so
/// the cap only binds a repo with an absurd anchor history.
const MAX_ANCHOR_CANDIDATES: usize = 64;

const ANCHOR_SCHEMA: &str = "gitlawb/model-release-anchor/v1";
const BLOCK_MAP_SCHEMA: &str = "gitlawb/model-block-map/v1";

/// Paginated discovery query for release anchors, mirroring clone.rs's
/// `ARWEAVE_DISCOVERY_QUERY` with the model-release schema tag. Edges come
/// back newest-first (`sort:HEIGHT_DESC`); the refs are re-sorted locally by
/// block height as well so a gateway that ignores `sort` still tries the
/// newest candidates first.
const ANCHOR_DISCOVERY_QUERY: &str = r#"query($repo:String!,$cursor:String){transactions(tags:[{name:"App-Name",values:["twigpine","gitlawb"]},{name:"Schema",values:["gitlawb/model-release-anchor/v1"]},{name:"Repo",values:[$repo]}],first:100,after:$cursor,sort:HEIGHT_DESC){pageInfo{hasNextPage endCursor}edges{cursor node{id block{height}}}}}"#;

#[derive(Subcommand)]
pub enum ModelCmd {
    /// Publish the working tree as a signed model release; polls until the
    /// release publishes or is rejected, exiting non-zero when it is still
    /// verifying after the poll budget
    Publish(PublishArgs),
    /// Rebuild a published release from Arweave and IPFS, without the node
    Fetch(FetchArgs),
}

#[derive(Args)]
pub struct PublishArgs {
    /// Node base URL (or set TWIGPINE_NODE)
    #[arg(
        long,
        default_value = "https://node.twigpine.com",
        env = "TWIGPINE_NODE"
    )]
    pub node: String,
    /// Skip the permanence confirmation (for scripts)
    #[arg(long)]
    pub yes: bool,
    /// Declare a parent release: <owner>/<repo>@<commit>
    #[arg(long)]
    pub parent: Option<String>,
    /// License identifier recorded in the manifest
    #[arg(long, default_value = "")]
    pub license: String,
    /// Branch to push the release commit to (default: current branch)
    #[arg(long)]
    pub branch: Option<String>,
    /// Chunking threshold in bytes; files at or above it are stored as
    /// content blocks instead of git blobs
    #[arg(long, hide = true, default_value_t = DEFAULT_CHUNK_THRESHOLD)]
    pub chunk_threshold_bytes: u64,
    /// Identity directory override
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct FetchArgs {
    /// Repo to fetch: <owner_did>/<name>
    pub repo: String,
    /// Owner DID the release manifest must verify against. Required: the
    /// anchor's own DID fields are untrusted text and are never used as the
    /// verifying key.
    #[arg(long)]
    pub expect_did: String,
    /// Release commit to fetch (default: the newest anchor that verifies)
    #[arg(long)]
    pub revision: Option<String>,
    /// Output directory (default: <repo>-<commit8>)
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Arweave gateway for release-anchor discovery and bodies
    #[arg(
        long,
        default_value = "https://arweave.net",
        env = "TWIGPINE_ARWEAVE_GATEWAY"
    )]
    pub arweave_gateway: String,
    /// IPFS gateway for the manifest, block map, and content objects
    #[arg(
        long,
        default_value = "https://dweb.link",
        env = "TWIGPINE_IPFS_GATEWAY"
    )]
    pub ipfs_gateway: String,
}

pub async fn run(cmd: ModelCmd) -> Result<()> {
    match cmd {
        ModelCmd::Publish(a) => cmd_publish(a).await,
        ModelCmd::Fetch(a) => cmd_fetch(a).await,
    }
}

// ── git helpers ─────────────────────────────────────────────────────────────

fn git(root: &Path, args: &[&str]) -> Result<Output> {
    // allow-unbounded-git: short-lived CLI process; there is no request
    // permit to hold or client disconnect to outlive.
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let out = git(root, args)?;
    let text = String::from_utf8(out.stdout).context("git output was not utf-8")?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// `git` with `GIT_INDEX_FILE` pointed at a dedicated index, so the release
/// commit is built from an index the user's own staging never touches.
fn git_index(root: &Path, index: &Path, args: &[&str]) -> Result<Output> {
    // allow-unbounded-git: client-side CLI spawn in the user's own checkout;
    // no node admission permit or lease is held.
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_INDEX_FILE", index)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

fn git_nul(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let out = git(root, args)?;
    let text = String::from_utf8(out.stdout).context("git output was not utf-8")?;
    Ok(text
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// `git log` for the release-marker path, newest first; an unborn HEAD just
/// has none. Capped: each commit costs one reconstruction fetch for dedup.
fn release_commits(root: &Path) -> Vec<String> {
    git_lines(
        root,
        &[
            "log",
            "--format=%H",
            "-n",
            "8",
            "--",
            ".twigpine/model-release.json",
        ],
    )
    .unwrap_or_default()
}

fn repo_root() -> Result<PathBuf> {
    // allow-unbounded-git: short-lived CLI process; there is no request
    // permit to hold or client disconnect to outlive.
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!("not inside a git repository");
    }
    let text = String::from_utf8(out.stdout).context("git output was not utf-8")?;
    Ok(PathBuf::from(text.trim()))
}

fn git_dir(root: &Path) -> Result<PathBuf> {
    let lines = git_lines(root, &["rev-parse", "--git-dir"])?;
    let dir = PathBuf::from(lines.first().context("no git dir")?);
    Ok(if dir.is_absolute() {
        dir
    } else {
        root.join(dir)
    })
}

/// Parse a `twigpine://<did>/<repo>` (or `gitlawb://`) remote URL.
fn parse_remote_url(url: &str) -> Option<(String, String)> {
    let rest = twigpine_core::url_scheme::strip_scheme(url.trim())?;
    let slash = rest.rfind('/')?;
    let did = rest[..slash].to_string();
    let repo = twigpine_core::ucan::push::canonical_repo_name(&rest[slash + 1..]).to_string();
    if did.is_empty() || repo.is_empty() {
        return None;
    }
    Some((did, repo))
}

/// The remote name plus (owner did, repo) of the first remote carrying a
/// twigpine URL: origin first, then twigpine/gitlawb, then any other.
fn detect_remote(root: &Path) -> Result<(String, String, String)> {
    let names = git_lines(root, &["remote"])?;
    let preferred = ["origin", "twigpine", "gitlawb"];
    let ordered = preferred
        .iter()
        .filter(|p| names.iter().any(|n| n == *p))
        .map(|p| p.to_string())
        .chain(
            names
                .iter()
                .filter(|n| !preferred.contains(&n.as_str()))
                .cloned(),
        );
    for name in ordered {
        for extra in [&["--all"][..], &["--push", "--all"][..]] {
            let mut args = vec!["remote", "get-url"];
            args.extend_from_slice(extra);
            args.push(&name);
            let Ok(urls) = git_lines(root, &args) else {
                continue;
            };
            if let Some((did, repo)) = urls.iter().find_map(|u| parse_remote_url(u)) {
                // The push must land on the repo the session and claim calls
                // use: a push URL naming a different twigpine repo is an
                // ambiguous destination, not a slow failure after upload.
                let push_urls = git_lines(root, &["remote", "get-url", "--push", "--all", &name])
                    .unwrap_or_default();
                for u in &push_urls {
                    if let Some((pdid, prepo)) = parse_remote_url(u) {
                        if pdid != did || prepo != repo {
                            bail!(
                                "remote {name} pushes to {pdid}/{prepo} but fetches from \
                                 {did}/{repo}; fix the remote's push URL and retry"
                            );
                        }
                    }
                }
                return Ok((name, did, repo));
            }
        }
    }
    bail!("no twigpine:// (or gitlawb://) remote found; run inside a clone of the repo")
}

// ── file classification ─────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// Listed in the manifest with `storage: "git"` and committed.
    Git,
    /// Listed with `storage: "chunked"`, packed into blocks, gitignored.
    Chunked,
    /// At or over the threshold but git-tracked: refused (weights live
    /// outside git).
    LargeTracked,
    /// Untracked and ignored, so not part of the publishable set.
    Ignored,
}

/// The publishable set is git's own view of the tree: tracked files plus
/// untracked files that are not ignored. An ignored file only comes back in
/// at threshold size and only while it sits inside the managed .gitignore
/// block, which is how previously published chunked paths stay findable on
/// re-publish without sweeping ignored junk (a `target/` dir) into a release.
fn classify(size: u64, tracked: bool, ignored: bool, managed: bool, threshold: u64) -> Class {
    if size >= threshold {
        if tracked {
            Class::LargeTracked
        } else if ignored && !managed {
            Class::Ignored
        } else {
            Class::Chunked
        }
    } else if ignored {
        Class::Ignored
    } else {
        Class::Git
    }
}

struct Scan {
    /// Repo-relative paths committed as git blobs.
    git_files: Vec<String>,
    /// Repo-relative paths packed as content blocks.
    chunked_files: Vec<String>,
    /// Tracked files at or over the threshold: the refusal list.
    refused: Vec<String>,
    /// Ignored files at or over the threshold that are not managed: warned
    /// and skipped (see [`classify`]).
    skipped_ignored: Vec<String>,
    /// Tracked paths gone from the worktree but not staged for deletion:
    /// staged into the release commit without entering the manifest.
    deleted: Vec<String>,
}

/// Tracked paths from `git ls-files -s`, minus submodule gitlinks (mode
/// 160000): a gitlink has no blob to hash and is not a manifest file.
fn tracked_paths(root: &Path) -> Result<HashSet<String>> {
    let entries = git_nul(root, &["ls-files", "-s", "-z"])?;
    let mut out = HashSet::new();
    for e in entries {
        let Some((meta, name)) = e.split_once('\t') else {
            continue;
        };
        if meta.starts_with("160000 ") {
            continue;
        }
        out.insert(name.to_string());
    }
    Ok(out)
}

/// Paths listed inside the managed .gitignore block (empty when there is no
/// block): previously published chunked files.
/// One repo-relative path as a gitignore pattern line: anchored at the repo
/// root so it matches only this path, with pattern metacharacters and a
/// trailing space backslash-escaped.
fn escape_gitignore_path(p: &str) -> String {
    let mut out = String::from("/");
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '\\' | '!' | '#' | '[' | ']' | '*' | '?') {
            out.push('\\');
        }
        if c == ' ' && chars.peek().is_none() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn unescape_gitignore_path(line: &str) -> String {
    // Generated patterns are root-anchored; older unanchored blocks decode
    // unchanged either way.
    let line = line.strip_prefix('/').unwrap_or(line);
    let mut out = String::new();
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Paths listed inside the managed .gitignore block (empty when there is no
/// block): previously published chunked files.
fn managed_block_paths(gitignore: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in gitignore.lines() {
        let t = line.trim_end();
        if t == GITIGNORE_BEGIN {
            inside = true;
            continue;
        }
        if t == GITIGNORE_END {
            break;
        }
        if inside && !t.is_empty() {
            out.push(unescape_gitignore_path(t));
        }
    }
    out
}

/// Hold one exclusive lock for the whole publish run: the dedicated index,
/// pathspec file and session state live at fixed names in the git dir.
fn acquire_publish_lock(git_dir: &Path) -> Result<std::fs::File> {
    let path = git_dir.join("twigpine-model-publish.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            bail!("another twigpine model publish is running in this checkout")
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e).context("failed to lock the publish lock"),
    }
}

/// Seed the dedicated release index from HEAD. Chunked paths are dropped from
/// it (index only), so a weight file still in HEAD never rides in the commit.
fn seed_release_index(root: &Path, index_path: &Path, chunked: &[String]) -> Result<()> {
    let _ = std::fs::remove_file(index_path);
    if git(root, &["rev-parse", "--verify", "-q", "HEAD"]).is_ok() {
        git_index(root, index_path, &["read-tree", "HEAD"])?;
    } else {
        git_index(root, index_path, &["read-tree", "--empty"])?;
    }
    for p in chunked {
        git_index(
            root,
            index_path,
            &["update-index", "--force-remove", "--", p],
        )?;
    }
    Ok(())
}

fn scan_files(root: &Path, gitignore: &str, threshold: u64) -> Result<Scan> {
    let tracked = tracked_paths(root)?;
    let others = git_nul(root, &["ls-files", "--others", "-z"])?;
    let unignored: HashSet<String> =
        git_nul(root, &["ls-files", "--others", "--exclude-standard", "-z"])?
            .into_iter()
            .collect();
    let managed: HashSet<String> = managed_block_paths(gitignore).into_iter().collect();

    let mut scan = Scan {
        git_files: Vec::new(),
        chunked_files: Vec::new(),
        refused: Vec::new(),
        skipped_ignored: Vec::new(),
        deleted: Vec::new(),
    };
    let mut consider = |path: &str, is_tracked: bool| -> Result<()> {
        if path.starts_with(".twigpine/") {
            return Ok(()); // release metadata is never a manifest file
        }
        // A path that vanished between listing and stat is not publishable;
        // a tracked one records an unstaged deletion the commit must carry
        // so the released tree drops the file too. Only NotFound is absence:
        // anything else (a permission denial, a dangling loop) fails the scan
        // rather than publishing a silent deletion.
        let meta = match std::fs::symlink_metadata(root.join(path)) {
            Ok(m) => m,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    if is_tracked {
                        scan.deleted.push(path.to_string());
                    }
                    return Ok(());
                }
                bail!("cannot stat {}", root.join(path).display());
            }
        };
        if !meta.is_file() && !meta.file_type().is_symlink() {
            return Ok(());
        }
        let ignored = !is_tracked && !unignored.contains(path);
        match classify(
            meta.len(),
            is_tracked,
            ignored,
            managed.contains(path),
            threshold,
        ) {
            Class::Git => scan.git_files.push(path.to_string()),
            Class::Chunked => scan.chunked_files.push(path.to_string()),
            Class::LargeTracked => scan.refused.push(path.to_string()),
            Class::Ignored => {
                if meta.len() >= threshold {
                    scan.skipped_ignored.push(path.to_string());
                }
            }
        }
        Ok(())
    };

    for p in &tracked {
        consider(p, true)?;
    }
    for p in &others {
        if tracked.contains(p) {
            continue;
        }
        consider(p, false)?;
    }
    // A deletion already staged (`git rm`) is gone from the index, so the
    // loop above never sees it; the seeded release index would restore it.
    if git(root, &["rev-parse", "--verify", "-q", "HEAD"]).is_ok() {
        let staged = git_nul(
            root,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--diff-filter=D",
                "--no-renames",
                "-z",
            ],
        )?;
        for p in staged {
            if !p.starts_with(".twigpine/") && !tracked.contains(&p) {
                scan.deleted.push(p);
            }
        }
    }
    scan.git_files.sort();
    scan.chunked_files.sort();
    scan.refused.sort();
    scan.skipped_ignored.sort();
    scan.deleted.sort();
    Ok(scan)
}

/// NUL pathspec for the release `git add -A`: the git-stored files and the
/// real deletions. A chunked path that is also staged-deleted (`git rm
/// --cached` on a weight) is never named: the managed .gitignore block
/// ignores it, and git refuses an ignored path in an add pathspec. Its
/// deletion is already carried by the seeded release index.
fn release_pathspec(scan: &Scan, stage_gitignore: bool) -> Vec<u8> {
    let chunked: HashSet<&str> = scan.chunked_files.iter().map(String::as_str).collect();
    let mut spec = Vec::new();
    for p in scan.git_files.iter().chain(
        scan.deleted
            .iter()
            .filter(|p| !chunked.contains(p.as_str())),
    ) {
        spec.extend_from_slice(p.as_bytes());
        spec.push(0);
    }
    if stage_gitignore {
        spec.extend_from_slice(b".gitignore");
        spec.push(0);
    }
    spec
}

// ── .gitignore managed block ────────────────────────────────────────────────

/// Insert or replace the managed block so it lists exactly `paths`; an empty
/// list removes the block. Idempotent: rewriting the same list yields the
/// same file content.
fn upsert_managed_block(existing: &str, paths: &[String]) -> String {
    let mut out: Vec<String> = existing.lines().map(str::to_string).collect();
    if let Some(b) = out.iter().position(|l| l.trim_end() == GITIGNORE_BEGIN) {
        let end = out[b + 1..]
            .iter()
            .position(|l| l.trim_end() == GITIGNORE_END)
            .map(|e| b + 1 + e)
            .unwrap_or(out.len() - 1);
        out.drain(b..=end);
        // The blank line we insert before the block goes with it.
        if b > 0 && out.get(b - 1).is_some_and(|l| l.is_empty()) {
            out.remove(b - 1);
        }
    }
    if !paths.is_empty() {
        if !out.is_empty() && !out.last().is_some_and(|l| l.is_empty()) {
            out.push(String::new());
        }
        out.push(GITIGNORE_BEGIN.to_string());
        out.extend(paths.iter().map(|p| escape_gitignore_path(p)));
        out.push(GITIGNORE_END.to_string());
    }
    let mut s = out.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

// ── resume state ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct PublishState {
    session_id: String,
    uploaded: Vec<String>,
    /// Node base URL the session was opened against; empty on state files
    /// written before this field existed.
    #[serde(default)]
    node: String,
    /// `owner/name` the session was opened for.
    #[serde(default)]
    repo: String,
}

/// A saved session is resumable only by the same node and repo: the session
/// id is a bearer credential, so it must never be sent anywhere else.
fn state_resumable(state: &PublishState, node: &str, repo: &str) -> bool {
    state.node == node && state.repo == repo
}

fn load_state(path: &Path) -> PublishState {
    let Ok(text) = std::fs::read_to_string(path) else {
        return PublishState::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Rewrite the state file after each uploaded block: the file carries the
/// resume set, so it is written and fsync'd rather than left in page cache.
fn save_state(path: &Path, state: &PublishState) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    // The file holds the session bearer, so it goes through the owner-only
    // writer, then is fsync'd (the helper does not sync).
    crate::secret_file::write(path, &bytes).with_context(|| format!("write {}", path.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

// ── misc ────────────────────────────────────────────────────────────────────

/// `<owner>/<repo>@<hex commit>` -> ((owner, name), commit).
fn parse_parent(spec: &str) -> Result<((String, String), String)> {
    let (repo, commit) = spec
        .rsplit_once('@')
        .context("parent must be <owner>/<repo>@<commit>")?;
    let (owner, name) = repo
        .split_once('/')
        .context("parent must be <owner>/<repo>@<commit>")?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("parent must be <owner>/<repo>@<commit>");
    }
    if !twigpine_core::cid::is_hex_oid(commit) {
        bail!("parent commit must be a hex sha");
    }
    Ok(((owner.to_string(), name.to_string()), commit.to_string()))
}

fn read_head(path: &Path, n: u64) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(n).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Point the real index's entries for the released paths back at HEAD. The
/// release commit is built under a dedicated index, so without this the
/// user's index still holds the old HEAD tree and every released path shows
/// as a staged reversion the next plain commit would apply. Entries for
/// paths not listed are untouched.
fn sync_index_to_head(root: &Path, git_dir: &Path, paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let spec_path = git_dir.join("twigpine-model-reset-pathspec");
    {
        let mut spec = Vec::new();
        for p in paths {
            spec.extend_from_slice(p.as_bytes());
            spec.push(0);
        }
        std::fs::write(&spec_path, spec)?;
    }
    let res = git(
        root,
        &[
            "--literal-pathspecs",
            "reset",
            "-q",
            "HEAD",
            &format!("--pathspec-from-file={}", spec_path.display()),
            "--pathspec-file-nul",
        ],
    );
    let _ = std::fs::remove_file(&spec_path);
    res.map(|_| ())
}

/// Manifest entry for a .gitignore the release commit stages but the scan
/// did not list as a git file. The managed block is written after the scan,
/// so a publish that creates .gitignore commits it unnamed, and the node
/// rejects the release as "committed but not listed". `None` when there is
/// no .gitignore to stage (a git-only release) or when the scan already
/// lists it, so it never appears twice.
fn staged_gitignore_entry(root: &Path, index: &Path, scan: &Scan) -> Result<Option<ManifestFile>> {
    if !root.join(".gitignore").is_file() || scan.git_files.iter().any(|p| p == ".gitignore") {
        return Ok(None);
    }
    let bytes = staged_blob(root, index, ".gitignore")?;
    Ok(Some(ManifestFile {
        path: ".gitignore".to_string(),
        size: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        format: detect_format(&bytes[..bytes.len().min(64)], ".gitignore"),
        storage: StorageKind::Git,
    }))
}

/// Stage `path` in the release index as the exact bytes on disk: a clean
/// filter on a normal `git add` could rewrite the signed metadata, so the
/// blob is hashed with --no-filters and the index entry pointed at it.
fn stage_unfiltered(root: &Path, index: &Path, path: &str) -> Result<()> {
    let out = git_index(
        root,
        index,
        &["hash-object", "--no-filters", "-w", "--", path],
    )?;
    let sha = String::from_utf8(out.stdout).context("hash-object output was not utf-8")?;
    git_index(
        root,
        index,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("100644,{},{}", sha.trim(), path),
        ],
    )?;
    Ok(())
}

/// Bytes of the blob staged for `path` in the dedicated release index:
/// exactly what the release commit will store, filters and symlink handling
/// included.
fn staged_blob(root: &Path, index: &Path, path: &str) -> Result<Vec<u8>> {
    // Resolve the blob sha through the index rather than `:{path}` revspec
    // syntax: a path that opens with magic characters is parsed as revspec
    // there, not as a filename. Literal pathspecs keep a path that LOOKS
    // like magic from resolving to a different entry.
    let out = git_index(
        root,
        index,
        &["--literal-pathspecs", "ls-files", "-s", "-z", "--", path],
    )?;
    let stdout = String::from_utf8(out.stdout).context("ls-files output was not utf-8")?;
    // `<mode> <sha> <stage>\t<path>`: require the returned entry to name the
    // exact path asked for, so a resolution surprise fails loudly.
    let (meta, name) = stdout
        .trim_end_matches('\0')
        .split_once('\t')
        .with_context(|| format!("{path} is not staged in the index"))?;
    if name != path {
        bail!("{path} resolved to a different index path: {name}");
    }
    let sha = meta
        .split(' ')
        .nth(1)
        .filter(|s| !s.is_empty())
        .with_context(|| format!("{path} is not staged in the index"))?;
    Ok(git(root, &["cat-file", "blob", sha])?.stdout)
}

/// Fetch a prior release's reconstruction object for dedup. A 404 means the
/// commit never became a published release (or its repo stopped serving);
/// any other non-2xx surfaces the node's own body.
async fn fetch_reconstruction(
    client: &NodeClient,
    owner: &str,
    name: &str,
    commit: &str,
) -> Result<Option<Reconstruction>> {
    let path = format!("/api/v1/repos/{owner}/{name}/models/releases/{commit}/reconstruction");
    let resp = client
        .get_signed(&path)
        .await
        .context("reconstruction fetch failed")?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let capped = read_body_capped_bytes(resp, 8 * 1024).await;
        bail!(
            "reconstruction fetch for {commit} failed ({status}): {}",
            crate::http::sanitize_node_msg(&String::from_utf8_lossy(&capped.bytes))
        );
    }
    let capped = read_body_capped_bytes(resp, RECONSTRUCTION_FETCH_CAP).await;
    if capped.truncated || capped.read_failed {
        bail!("reconstruction object for {commit} was oversized or truncated");
    }
    let rec = Reconstruction::parse(&capped.bytes)
        .map_err(|e| anyhow::anyhow!("reconstruction object for {commit} is invalid: {e}"))?;
    Ok(Some(rec))
}

/// Send one content block to the session. Unsigned by protocol: the session
/// id is the bearer credential. A non-2xx body is surfaced through
/// `read_json`'s denial path.
async fn upload_block(
    client: &NodeClient,
    base: &str,
    session_id: &str,
    sha: &str,
    data: Vec<u8>,
) -> Result<()> {
    let resp = client
        .put_unsigned(
            &format!("{base}/models/blocks/{sha}"),
            data,
            &[(SESSION_HEADER, session_id)],
        )
        .await?;
    let _: Value = read_json(resp, "block upload").await?;
    Ok(())
}

/// The failure `cmd_publish` returns when the release is still `verifying`
/// at the poll budget: a non-zero exit that keeps the status URL visible.
fn still_verifying_error(release_id: i64, budget_secs: u64, release_path: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "release {release_id} is still verifying after {budget_secs}s; its status is at\n  \
         GET {release_path}"
    )
}

/// Without `--yes`, publishing requires an explicit "yes" on stdin. Any
/// other answer, including EOF on a pipe, declines.
fn confirm_publish() -> Result<bool> {
    eprint!("type 'yes' to publish: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
}

// ── publish ─────────────────────────────────────────────────────────────────

async fn cmd_publish(args: PublishArgs) -> Result<()> {
    let kp = load_keypair_from_dir(args.dir.as_deref())?;
    let root = repo_root()?;
    let git_dir = git_dir(&root)?;
    let _publish_lock = acquire_publish_lock(&git_dir)?;
    let (remote_name, owner, name) = detect_remote(&root)?;
    let branch = match &args.branch {
        Some(b) => b.clone(),
        None => {
            // allow-unbounded-git: short-lived CLI process; there is no
            // request permit to hold or client disconnect to outlive.
            let out = std::process::Command::new("git")
                .args(["symbolic-ref", "--short", "-q", "HEAD"])
                .current_dir(&root)
                .output()
                .context("failed to run git")?;
            if !out.status.success() {
                bail!("detached HEAD: pass --branch to name the release branch");
            }
            String::from_utf8(out.stdout)
                .context("branch name was not utf-8")?
                .trim()
                .to_string()
        }
    };

    // 1. Scan and refuse tracked large files before anything else happens.
    let gitignore_path = root.join(".gitignore");
    let existing_gitignore = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
    let scan = scan_files(&root, &existing_gitignore, args.chunk_threshold_bytes)?;
    if !scan.refused.is_empty() {
        bail!(
            "these files are {} bytes or larger but tracked in git; weights must live \
             outside git. Remove them from the index first (git rm --cached):\n  {}",
            args.chunk_threshold_bytes,
            scan.refused.join("\n  ")
        );
    }
    for p in &scan.skipped_ignored {
        eprintln!(
            "warning: {p} is at or over the chunk threshold but gitignored; \
             unignore it to publish"
        );
    }

    // 2. Warn + confirm: publishing is permanent.
    println!("Publishing {owner}/{name} as a model release on branch {branch}:");
    println!(
        "  {} git files, {} chunked files",
        scan.git_files.len(),
        scan.chunked_files.len()
    );
    for p in &scan.chunked_files {
        let size = std::fs::symlink_metadata(root.join(p))
            .map(|m| m.len())
            .unwrap_or(0);
        if size > SINGLE_FILE_WARN_BYTES {
            eprintln!(
                "warning: {p} is over 50 GiB; huggingface_hub refuses plain downloads that large"
            );
        }
    }
    eprintln!(
        "publishing is permanent where the node has durability configured: blocks are pinned \
         to IPFS and the release anchor is posted to Arweave, and neither can be taken back. \
         With no IPFS tier and no Irys configured, the bytes stay on this node only and stay \
         available only while it keeps them"
    );
    if !args.yes && !confirm_publish()? {
        println!("aborted");
        return Ok(());
    }

    let client = NodeClient::new(&args.node, Some(kp.clone()));
    let base = format!("/api/v1/repos/{owner}/{name}");

    // 3. Dedup: reconstructions of prior releases in this clone, plus the
    //    declared parent's when given.
    let mut priors: Vec<Reconstruction> = Vec::new();
    let mut parent_ref: Option<ParentRef> = None;
    let prior_commits = release_commits(&root);
    for commit in &prior_commits {
        if let Some(rec) = fetch_reconstruction(&client, &owner, &name, commit).await? {
            priors.push(rec);
        }
    }
    if let Some(spec) = &args.parent {
        let ((powner, pname), pcommit) = parse_parent(spec)?;
        let rec = fetch_reconstruction(&client, &powner, &pname, &pcommit)
            .await?
            .context("declared parent has no published reconstruction on this node")?;
        // There is no manifest-serving route, so the parent manifest sha256
        // is the sha of the manifest bytes in the local clone when the parent
        // commit is here, and the sha of the parent's reconstruction object
        // (the only parent artifact the node serves) otherwise. The node
        // records the field without checking it (R9: a signed claim, not a
        // verified link).
        let manifest_sha = git(
            &root,
            &["show", &format!("{pcommit}:.twigpine/model-release.json")],
        )
        .map(|out| sha256_hex(&out.stdout))
        .unwrap_or_else(|_| sha256_hex(&rec.to_bytes().unwrap_or_default()));
        parent_ref = Some(ParentRef {
            repo: format!("{powner}/{pname}"),
            commit: pcommit,
            manifest_sha256: manifest_sha,
        });
        priors.push(rec);
    }
    let prior_refs: Vec<&Reconstruction> = priors.iter().collect();
    let mut dedup = DedupIndex::from_reconstructions(&prior_refs);
    let mut all_entries: HashMap<String, BlockEntry> = HashMap::new();
    for rec in &priors {
        for b in &rec.blocks {
            all_entries.insert(b.sha256.clone(), b.clone());
        }
    }

    // 4. Open (or resume) the upload session before packing, so each new
    //    block streams out as it seals instead of buffering the whole
    //    model in memory.
    let state_path = git_dir.join(STATE_FILE_NAME);
    let mut state = load_state(&state_path);
    let repo_slug = format!("{owner}/{name}");
    // A state file bound to a different node or repo (or written before the
    // binding existed) is not resumable: drop it before the status call so
    // its session id is never sent to the wrong place.
    if !state_resumable(&state, &args.node, &repo_slug) {
        state = PublishState::default();
    }
    if !state.session_id.is_empty() {
        let resp = client
            .get_signed(&format!("{base}/models/sessions/{}", state.session_id))
            .await
            .context("session status request failed")?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            state = PublishState::default();
        } else {
            let v: Value = read_json(resp, "session status").await?;
            if v["state"].as_str() != Some("open") {
                state = PublishState::default();
            }
        }
    }
    if state.session_id.is_empty() {
        let body = serde_json::to_vec(&json!({}))?;
        let resp = client
            .post(&format!("{base}/models/sessions"), &body)
            .await?;
        let v: Value = json_or_denial("open model session", resp).await?;
        state.session_id = v["session_id"]
            .as_str()
            .context("session response had no session_id")?
            .to_string();
        state.uploaded.clear();
        state.node = args.node.clone();
        state.repo = repo_slug.clone();
        save_state(&state_path, &state)?;
    }
    let mut uploaded: HashSet<String> = state.uploaded.iter().cloned().collect();
    let session_id = state.session_id.clone();

    // 5. Pack every chunked file; shared chunks become terms into prior
    //    blocks, the rest seal into new blocks uploaded as they seal.
    let mut rec = Reconstruction::new();
    let mut files: Vec<ManifestFile> = Vec::new();
    for path in &scan.chunked_files {
        // Pack on a blocking thread and upload each block as it seals: a
        // bounded channel keeps resident memory to a couple of blocks
        // rather than the whole file. The dedup index moves to the thread
        // through an Arc and comes back when it finishes.
        let shared_dedup = std::sync::Arc::new(std::mem::take(&mut dedup));
        let task_dedup = shared_dedup.clone();
        let (block_tx, mut block_rx) =
            tokio::sync::mpsc::channel::<twigpine_core::model::chunking::Block>(2);
        let pack_path = path.clone();
        let pack_root = root.clone();
        let pack_task = tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(pack_root.join(&pack_path))
                .map_err(|e| std::io::Error::new(e.kind(), format!("open {pack_path}: {e}")))?;
            pack_file_with(&pack_path, file, &task_dedup, move |block| {
                block_tx
                    .blocking_send(block)
                    .map_err(|_| std::io::Error::other("block upload channel closed"))
            })
        });
        while let Some(block) = block_rx.recv().await {
            let sha = block.sha256;
            if uploaded.contains(&sha) {
                continue;
            }
            upload_block(&client, &base, &session_id, &sha, block.data).await?;
            state.uploaded.push(sha.clone());
            uploaded.insert(sha.clone());
            save_state(&state_path, &state)?;
            println!("uploaded block {}", &sha[..16]);
        }
        let (file_entry, block_entries) = pack_task
            .await
            .context("pack task failed")?
            .with_context(|| format!("pack {path}"))?;
        dedup = std::sync::Arc::try_unwrap(shared_dedup).unwrap_or_else(|a| (*a).clone());
        // Make this file's fresh chunks visible to the next file's dedup.
        dedup.add_block_entries(&block_entries);
        let head = read_head(&root.join(path), 64)?;
        files.push(ManifestFile {
            path: path.clone(),
            size: file_entry.size,
            sha256: file_entry.sha256.clone(),
            format: detect_format(&head, path),
            storage: StorageKind::Chunked,
        });
        rec.files.push(file_entry);
        for e in block_entries {
            all_entries.insert(e.sha256.clone(), e.clone());
            rec.blocks.push(e);
        }
    }
    // Terms into earlier blocks need those entries in this object: a reader
    // resolves term.block against rec.blocks only.
    // Sorted so the appended block rows (and therefore the serialized
    // reconstruction object and its sha) are identical across processes on
    // a retried publish.
    let mut needed: Vec<String> = rec
        .files
        .iter()
        .flat_map(|f| f.terms.iter().map(|t| t.block.clone()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    needed.sort();
    let mut present: HashSet<String> = rec.blocks.iter().map(|b| b.sha256.clone()).collect();
    for sha in needed {
        if present.contains(&sha) {
            continue;
        }
        let entry = all_entries
            .get(&sha)
            .with_context(|| format!("term references unknown block {sha}"))?;
        present.insert(entry.sha256.clone());
        rec.blocks.push(entry.clone());
    }
    // A release with no chunked files has no chunked bytes to reconstruct:
    // no reconstruction object, no reconstruction block.
    let rec_bytes = if scan.chunked_files.is_empty() {
        Vec::new()
    } else {
        rec.validate()
            .map_err(|e| anyhow::anyhow!("reconstruction object invalid: {e}"))?;
        rec.to_bytes()
            .map_err(|e| anyhow::anyhow!("reconstruction serialize failed: {e}"))?
    };
    let rec_sha = sha256_hex(&rec_bytes);

    // 6. The reconstruction object goes up as one more content block.
    let has_rec = !rec_bytes.is_empty();
    let rec_size = rec_bytes.len() as u64;
    if has_rec && !uploaded.contains(&rec_sha) {
        upload_block(&client, &base, &session_id, &rec_sha, rec_bytes).await?;
        state.uploaded.push(rec_sha.clone());
        save_state(&state_path, &state)?;
        println!("uploaded reconstruction object");
    }

    // 7. Managed .gitignore block. A symlink target outside the checkout is
    //    never written through, and edits made while blocks uploaded are
    //    caught against the scan snapshot rather than silently lost.
    if let Ok(meta) = std::fs::symlink_metadata(&gitignore_path) {
        if meta.file_type().is_symlink() {
            bail!(".gitignore is a symlink; refusing to write through it");
        }
    }
    let new_gitignore = upsert_managed_block(&existing_gitignore, &scan.chunked_files);
    if new_gitignore != existing_gitignore {
        let current = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if current != existing_gitignore {
            bail!(
                ".gitignore changed while blocks uploaded; re-run to publish \
                 from a fresh scan"
            );
        }
        std::fs::write(&gitignore_path, &new_gitignore)?;
    }

    // 8. Stage into a dedicated index seeded from HEAD: the release commit
    //    holds exactly the scanned set, the user's real index and anything
    //    already staged in it are never read or rewritten, and the hashed
    //    blobs below are the same index state the commit records. Only
    //    paths that exist go in the first stage; the release metadata
    //    follows after it is written below.
    let index_path = git_dir.join("twigpine-model-index");
    seed_release_index(&root, &index_path, &scan.chunked_files)?;
    let pathspec_path = git_dir.join("twigpine-model-pathspec");
    {
        let spec = release_pathspec(&scan, gitignore_path.is_file());
        if spec.is_empty() {
            let _ = std::fs::remove_file(&pathspec_path);
        } else {
            std::fs::write(&pathspec_path, spec)?;
        }
    }
    if pathspec_path.exists() {
        let staged = git_index(
            &root,
            &index_path,
            &[
                "--literal-pathspecs",
                "add",
                "-A",
                "--pathspec-file-nul",
                &format!("--pathspec-from-file={}", pathspec_path.display()),
            ],
        );
        let _ = std::fs::remove_file(&pathspec_path);
        staged?;
    }

    // 9. Hash the git-stored files from the release index (the exact bytes
    //    the commit stores), then write and stage the manifest.
    for path in &scan.git_files {
        let bytes = staged_blob(&root, &index_path, path)?;
        files.push(ManifestFile {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            format: detect_format(&bytes[..bytes.len().min(64)], path),
            storage: StorageKind::Git,
        });
    }
    if let Some(entry) = staged_gitignore_entry(&root, &index_path, &scan)? {
        files.push(entry);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = Manifest {
        schema: MANIFEST_SCHEMA_V1.to_string(),
        repo: format!("{owner}/{name}"),
        publisher_did: kp.did().to_string(),
        license: args.license.clone(),
        parent: parent_ref,
        files,
        reconstruction: if !has_rec {
            None
        } else {
            Some(ReconstructionRef {
                sha256: rec_sha,
                size: rec_size,
            })
        },
    };
    let manifest_bytes = manifest
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("manifest serialize failed: {e}"))?;
    let twigpine_dir = root.join(".twigpine");
    std::fs::create_dir_all(&twigpine_dir)?;
    std::fs::write(twigpine_dir.join("model-release.json"), &manifest_bytes)?;
    std::fs::write(
        twigpine_dir.join("model-release.sig"),
        format!(
            "{}\n",
            manifest::sign(
                &ed25519_dalek::SigningKey::from_bytes(&kp.to_seed()),
                &manifest_bytes,
            )
        ),
    )?;
    stage_unfiltered(&root, &index_path, ".twigpine/model-release.json")?;
    stage_unfiltered(&root, &index_path, ".twigpine/model-release.sig")?;
    // What the commit stores must be the signed bytes: re-read the staged
    // blobs and prove both the manifest and its signature before pushing.
    let staged_manifest = staged_blob(&root, &index_path, ".twigpine/model-release.json")?;
    if staged_manifest != manifest_bytes {
        bail!("the staged manifest differs from the signed bytes");
    }
    let staged_sig = staged_blob(&root, &index_path, ".twigpine/model-release.sig")?;
    let staged_sig = String::from_utf8(staged_sig).context("staged signature was not utf-8")?;
    manifest::verify(&staged_manifest, &staged_sig, &kp.did())
        .map_err(|e| anyhow::anyhow!("staged manifest signature does not verify: {e}"))?;

    // 10. Commit when the release index differs, push, and claim HEAD.
    let has_changes = git_index(&root, &index_path, &["diff", "--cached", "--quiet"]).is_err();
    if has_changes {
        let n = prior_commits.len() + 1;
        git_index(
            &root,
            &index_path,
            &["commit", "-m", &format!("model release {n}")],
        )?;
    } else {
        // Nothing staged: a re-publish of identical content lands here, and
        // HEAD must already be a release commit to claim.
        if git(
            &root,
            &["cat-file", "-e", "HEAD:.twigpine/model-release.json"],
        )
        .is_err()
        {
            bail!("nothing to publish and HEAD carries no release manifest");
        }
        println!("no changes to commit; claiming the existing release commit");
    }
    let _ = std::fs::remove_file(&index_path);
    // The dedicated index left the real index holding the old HEAD tree:
    // every released path would look staged for reversion, and the next
    // plain `git commit` would undo the release. Sync exactly the released
    // paths back to HEAD; unrelated staged entries keep their state.
    let mut released: Vec<String> = scan.git_files.clone();
    released.extend(scan.deleted.iter().cloned());
    if gitignore_path.is_file() || git(&root, &["cat-file", "-e", "HEAD:.gitignore"]).is_ok() {
        released.push(".gitignore".to_string());
    }
    released.push(".twigpine/model-release.json".to_string());
    released.push(".twigpine/model-release.sig".to_string());
    sync_index_to_head(&root, &git_dir, &released)?;
    let commit = git_lines(&root, &["rev-parse", "HEAD"])?
        .into_iter()
        .next()
        .context("no HEAD commit")?;

    // allow-unbounded-git: short-lived CLI process; there is no request
    // permit to hold or client disconnect to outlive.
    let push = std::process::Command::new("git")
        .args(["push", &remote_name, &format!("HEAD:{branch}")])
        .current_dir(&root)
        .env("TWIGPINE_NODE", &args.node)
        // The helper on PATH may be a build from before the rename.
        .env("GITLAWB_NODE", &args.node)
        .output()
        .context("failed to run git push")?;
    if !push.status.success() {
        bail!(
            "git push failed:\n{}",
            String::from_utf8_lossy(&push.stderr).trim()
        );
    }
    println!("pushed {commit} to {remote_name}/{branch}");

    let claim_body = serde_json::to_vec(&json!({
        "commit": commit,
        "branch": branch,
    }))?;
    let resp = client
        .post(&format!("{base}/models/claims"), &claim_body)
        .await?;
    let claim: Value = json_or_denial("claim release", resp).await?;
    let release_id = claim["release_id"].as_i64().unwrap_or_default();
    println!("release {release_id} claimed; verifying");

    // 10. Poll until the verification worker settles the release.
    let release_path = format!("{base}/models/releases/{commit}");
    let deadline = Instant::now() + POLL_BUDGET;
    loop {
        // One transport hiccup should not abort the publish; the signed
        // status read is idempotent, so retry it a few times.
        let resp = 'poll: {
            let mut last = None;
            for _ in 0..3 {
                match client.get_signed(&release_path).await {
                    Ok(r) => break 'poll r,
                    Err(e) => {
                        last = Some(e);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
            return Err(last
                .expect("three attempts ran")
                .context("release status request failed"));
        };
        let v: Value = read_json(resp, "release status").await?;
        match v["state"].as_str() {
            Some("published") => {
                println!("published release {release_id}");
                println!("  commit:   {}", v["commit"].as_str().unwrap_or(&commit));
                println!(
                    "  manifest: {}",
                    v["manifest_sha256"].as_str().unwrap_or("?")
                );
                let _ = std::fs::remove_file(&state_path);
                return Ok(());
            }
            Some("rejected") => {
                bail!(
                    "release {release_id} rejected: {}",
                    v["failure_reason"].as_str().unwrap_or("unknown reason")
                );
            }
            _ => {
                if Instant::now() >= deadline {
                    return Err(still_verifying_error(
                        release_id,
                        POLL_BUDGET.as_secs(),
                        &release_path,
                    ));
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }
}

// ── fetch ───────────────────────────────────────────────────────────────────

/// What a verified fetch produced. Returned by [`fetch_model`] so callers
/// (the CLI wrapper, the node e2e test) can report or assert on the run.
#[derive(Debug)]
pub struct FetchReport {
    /// `<owner_did>/<name>` as fetched.
    pub repo: String,
    /// Release commit the verified anchor named.
    pub release_commit: String,
    /// Arweave transaction id of the anchor used.
    pub anchor_tx: String,
    /// Files written under `output_dir`.
    pub files: usize,
    /// Total bytes written.
    pub bytes: u64,
    /// Where the release was rebuilt.
    pub output_dir: PathBuf,
    /// One line per skipped candidate anchor, in the order they were tried.
    pub warnings: Vec<String>,
}

/// The anchor JSON, exactly as `arweave::anchor_model_release` posts it.
/// Identity fields are record-keeping only: `owner_did` is used to SELECT a
/// candidate, never as the verifying key (KTD15).
#[derive(Debug, Deserialize)]
struct ReleaseAnchorBody {
    schema: String,
    repo: String,
    owner_did: String,
    release_commit: String,
    manifest_sha256: String,
    manifest_cid: String,
    #[serde(default)]
    reconstruction_sha256: Option<String>,
    #[serde(default)]
    reconstruction_cid: Option<String>,
    block_map_cid: String,
    claim_signature: String,
}

/// The sha256 -> provider-CID index pinned by the block-map job. `files`
/// indexes git-stored files by manifest sha256 and may be absent on maps
/// produced before the git-file fix; `blocks` indexes content blocks.
#[derive(Debug, Deserialize)]
struct BlockMapBody {
    schema: String,
    #[serde(default)]
    blocks: HashMap<String, String>,
    #[serde(default)]
    files: HashMap<String, String>,
}

/// Record one skip reason: sanitized once, then both the terminal and the
/// report get the same line.
fn note_skip(warnings: &mut Vec<String>, msg: String) {
    let line = sanitize_node_msg(&msg);
    eprintln!("warning: {line}");
    warnings.push(line);
}

/// The shared client plus the two gateway base URLs, bundled so the helper
/// signatures stay small.
struct Net<'a> {
    client: &'a reqwest::Client,
    ag: &'a str,
    ig: &'a str,
}

/// GET `url` and return at most `cap` bytes. `what` names the object for the
/// error. A truncated or dead-mid-read body is an error, not a partial object.
async fn get_capped(
    client: &reqwest::Client,
    url: &str,
    cap: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("{what} request failed"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("{what} fetch returned {status}");
    }
    let capped = read_body_capped_bytes(resp, cap).await;
    if capped.truncated {
        bail!("{what} body exceeded the {cap}-byte cap");
    }
    if capped.read_failed {
        bail!("{what} body failed mid-read");
    }
    Ok(capped.bytes)
}

/// Discover release-anchor transactions for `repo` on the Arweave gateway,
/// newest first. Same paginated, bounded loop shape as clone.rs's manifest
/// discovery, sharing its page parser.
async fn discover_release_anchors(
    net: &Net<'_>,
    repo: &str,
    warnings: &mut Vec<String>,
) -> Vec<crate::clone::TxRef> {
    const MAX_PAGES: usize = 1000;
    const MAX_TX_IDS: usize = 10_000;
    let mut after: Option<String> = None;
    let mut prev_cursor: Option<String> = None;
    let mut seen: HashSet<String> = HashSet::new();
    let mut refs: Vec<crate::clone::TxRef> = Vec::new();
    for page_num in 0..MAX_PAGES {
        let gql_body = json!({
            "query": ANCHOR_DISCOVERY_QUERY,
            "variables": { "repo": repo, "cursor": after },
        });
        let response: Option<Value> = match net
            .client
            .post(format!("{}/graphql", net.ag))
            .json(&gql_body)
            .send()
            .await
        {
            // Status-first, capped, sanitized: the gateway is untrusted text.
            Ok(r) => read_json(r, "anchor discovery").await.ok(),
            Err(_) => None,
        };
        let value = match response {
            Some(v) => v,
            None => {
                // A failure after discovery began leaves a knowingly partial
                // candidate set; a page-1 failure just means no anchors here.
                if page_num > 0 {
                    note_skip(
                        warnings,
                        "Arweave anchor discovery was interrupted by a gateway error".to_string(),
                    );
                }
                break;
            }
        };
        let page = crate::clone::parse_tx_page(&value);
        let full = page.refs.len() >= crate::clone::ARWEAVE_PAGE_SIZE;
        for r in page.refs {
            if seen.insert(r.id.clone()) {
                refs.push(r);
            }
        }
        if refs.len() >= MAX_TX_IDS {
            note_skip(
                warnings,
                format!("Arweave anchor discovery hit the {MAX_TX_IDS}-transaction cap"),
            );
            break;
        }
        match page.has_next {
            Some(true) => match page.end_cursor {
                Some(c) if Some(&c) != prev_cursor.as_ref() => {
                    prev_cursor = Some(c.clone());
                    after = Some(c);
                }
                _ => break,
            },
            Some(false) => break,
            // No pageInfo: terminal. A full page without it may be a silently
            // truncated gateway, so flag that like clone.rs does.
            None => {
                if full {
                    note_skip(
                        warnings,
                        "Arweave gateway returned a full page without pagination \
                         metadata; anchor discovery may be incomplete"
                            .to_string(),
                    );
                }
                break;
            }
        }
    }
    // The query asks for HEIGHT_DESC; rank locally too so an edge order a
    // gateway gets wrong still tries the newest candidate first. Pending
    // anchors (no block) rank newest, matching clone.rs's tie-break.
    refs.sort_by(|a, b| {
        crate::clone::height_rank(b.height).cmp(&crate::clone::height_rank(a.height))
    });
    refs
}

/// Whether an untrusted id (anchor tx, provider CID) is safe to interpolate
/// as one path segment of a gateway URL. Alnum plus the base32/base64url
/// punctuation CIDs and tx ids actually use; `/`, `?`, `#`, and `..` would
/// rewrite the request path on the gateway host.
fn url_path_safe(id: &str) -> bool {
    !id.is_empty()
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
}

/// One anchor candidate through its trust gates: fetch the body, parse the
/// anchor JSON, then fetch the manifest and verify it against the expected
/// DID. Returns `Some(..)` only when the manifest verifies; every failure is
/// a warning plus `None` so the next candidate gets tried.
async fn verify_candidate(
    net: &Net<'_>,
    tx_id: &str,
    repo: &str,
    expect_did: &Did,
    revision: Option<&str>,
    warnings: &mut Vec<String>,
) -> Option<(ReleaseAnchorBody, Manifest)> {
    if !url_path_safe(tx_id) {
        note_skip(warnings, "anchor tx id is not URL-safe".to_string());
        return None;
    }
    let mut skip = |why: String| {
        note_skip(warnings, format!("anchor {tx_id}: {why}"));
        None
    };
    let body = match get_capped(
        net.client,
        &format!("{}/{tx_id}", net.ag),
        ANCHOR_BODY_CAP,
        "anchor",
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return skip(format!("{e}")),
    };
    let anchor: ReleaseAnchorBody = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => return skip(format!("anchor body is not valid JSON: {e}")),
    };
    if anchor.schema != ANCHOR_SCHEMA {
        return skip(format!("unknown anchor schema {:?}", anchor.schema));
    }
    // release_commit is unsigned anchor text that lands in the default
    // output directory name: require a real hex commit shape (40 for sha1
    // repos, 64 for sha256 repos), never a path fragment.
    if !twigpine_core::cid::is_hex_oid(&anchor.release_commit) {
        return skip("release_commit is not a hex commit".to_string());
    }
    if !url_path_safe(&anchor.manifest_cid)
        || !url_path_safe(&anchor.block_map_cid)
        || anchor
            .reconstruction_cid
            .as_deref()
            .is_some_and(|c| !url_path_safe(c))
    {
        return skip("anchor names a CID that is not URL-safe".to_string());
    }
    if anchor.repo != repo {
        return skip(format!(
            "anchor names repo {:?}, expected {repo}",
            anchor.repo
        ));
    }
    // The anchor's DID chooses which anchors to try; it is never the
    // verifying key. A mismatch here is the strongest possible signal the
    // manifest will not verify, so skip without spending the fetch.
    if anchor.owner_did != expect_did.to_string() {
        return skip(format!(
            "anchor names owner {}, expected {}",
            anchor.owner_did, expect_did
        ));
    }
    if let Some(want) = revision {
        if !anchor.release_commit.eq_ignore_ascii_case(want) {
            return skip(format!(
                "anchor names commit {}, expected {want}",
                anchor.release_commit
            ));
        }
    }
    let manifest_bytes = match get_capped(
        net.client,
        &format!("{}/ipfs/{}", net.ig, anchor.manifest_cid),
        MANIFEST_FETCH_CAP,
        "manifest",
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return skip(format!("{e}")),
    };
    let got = sha256_hex(&manifest_bytes);
    if got != anchor.manifest_sha256 {
        return skip(format!(
            "manifest bytes hash to {got}, anchor claims {}",
            anchor.manifest_sha256
        ));
    }
    let manifest = match manifest::verify(&manifest_bytes, &anchor.claim_signature, expect_did) {
        Ok(m) => m,
        Err(e) => return skip(format!("manifest verification failed: {e}")),
    };
    if manifest.repo != repo {
        return skip(format!(
            "verified manifest names repo {:?}, expected {repo}",
            manifest.repo
        ));
    }
    Some((anchor, manifest))
}

/// Byte-budgeted LRU over fetched content blocks. A fine-tuned release
/// shares blocks across files, so a small cache saves re-fetches; the model
/// itself never sits resident.
struct BlockCache {
    map: HashMap<String, Vec<u8>>,
    order: std::collections::VecDeque<String>,
    used: usize,
}

impl BlockCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
            used: 0,
        }
    }

    fn get(&mut self, sha: &str) -> Option<&[u8]> {
        if self.map.contains_key(sha) {
            self.order.retain(|k| k != sha);
            self.order.push_back(sha.to_string());
            return self.map.get(sha).map(|v| v.as_slice());
        }
        None
    }

    fn insert(&mut self, sha: String, bytes: Vec<u8>) {
        if bytes.len() > BLOCK_CACHE_BUDGET {
            return;
        }
        while self.used + bytes.len() > BLOCK_CACHE_BUDGET {
            match self.order.pop_front() {
                Some(old) => {
                    if let Some(v) = self.map.remove(&old) {
                        self.used -= v.len();
                    }
                }
                None => break,
            }
        }
        self.used += bytes.len();
        self.map.insert(sha.clone(), bytes);
        self.order.push_back(sha);
    }
}

/// What chunked rebuild needs to fetch one content block: the network
/// handle, the untrusted block map, and the shared byte-budgeted cache.
struct BlockSource<'a> {
    client: &'a reqwest::Client,
    ig: &'a str,
    map: &'a BlockMapBody,
    cache: &'a mut BlockCache,
}

impl BlockSource<'_> {
    /// Fetch one content block through the block map and hash-check it
    /// against its sha256 key. The map is untrusted (it arrived through the
    /// anchor), so the hash is what binds bytes to the manifest's claim, not
    /// the CID.
    async fn block(&mut self, sha: &str) -> Result<Vec<u8>> {
        if let Some(hit) = self.cache.get(sha) {
            return Ok(hit.to_vec());
        }
        let cid = self
            .map
            .blocks
            .get(sha)
            .with_context(|| format!("block map has no CID for block {sha}"))?;
        if !url_path_safe(cid) {
            bail!("block {sha} maps to a CID that is not URL-safe");
        }
        let bytes = get_capped(
            self.client,
            &format!("{}/ipfs/{cid}", self.ig),
            OBJECT_FETCH_CAP,
            &format!("block {sha}"),
        )
        .await?;
        let got = sha256_hex(&bytes);
        if got != sha {
            bail!("block {sha} content hashes to {got}");
        }
        self.cache.insert(sha.to_string(), bytes.clone());
        Ok(bytes)
    }
}

/// Byte offset of each chunk inside a block, the prefix sum over its chunk
/// table (same layout `reconstruction::chunk_offsets` uses).
fn chunk_offsets(block: &BlockEntry) -> Vec<u64> {
    block
        .chunks
        .iter()
        .scan(0u64, |off, c| {
            let start = *off;
            *off += c.len;
            Some(start)
        })
        .collect()
}

/// Rebuild one chunked file into `out_path` from its terms, streaming to
/// disk. Per-chunk sha256s are verified as slices are consumed and the
/// whole-file digest is checked against the manifest at the end, so at most
/// a handful of blocks are ever resident.
async fn rebuild_chunked(
    source: &mut BlockSource<'_>,
    rec: &Reconstruction,
    file: &FileEntry,
    expect_sha: &str,
    expect_size: u64,
    out_path: &Path,
) -> Result<u64> {
    let blocks: HashMap<&str, &BlockEntry> =
        rec.blocks.iter().map(|b| (b.sha256.as_str(), b)).collect();
    let mut out = std::io::BufWriter::new(
        std::fs::File::create(out_path)
            .with_context(|| format!("create {}", out_path.display()))?,
    );
    let mut hasher = sha2::Sha256::new();
    let mut written = 0u64;
    for term in &file.terms {
        let block = blocks
            .get(term.block.as_str())
            .with_context(|| format!("{}: term names unknown block {}", file.path, term.block))?;
        let data = source.block(&term.block).await?;
        if data.len() as u64 != block.size {
            bail!(
                "block {} serves {} bytes, reconstruction declares {}",
                term.block,
                data.len(),
                block.size
            );
        }
        let offsets = chunk_offsets(block);
        let mut rel = offsets.get(term.chunk_start as usize).copied().unwrap_or(0) as usize;
        for chunk in &block.chunks[term.chunk_start as usize..term.chunk_end as usize] {
            let slice = &data[rel..rel + chunk.len as usize];
            let got = sha256_hex(slice);
            if got != chunk.sha256 {
                bail!(
                    "{}: chunk {} in block {} fails its sha256 check",
                    file.path,
                    chunk.sha256,
                    term.block
                );
            }
            out.write_all(slice)
                .with_context(|| format!("write {}", out_path.display()))?;
            hasher.update(slice);
            written += chunk.len;
            rel += chunk.len as usize;
        }
    }
    out.flush()
        .with_context(|| format!("write {}", out_path.display()))?;
    if written != expect_size {
        bail!(
            "{}: rebuilt {written} bytes, manifest declares {expect_size}",
            file.path
        );
    }
    let digest = hex::encode(hasher.finalize());
    if digest != expect_sha {
        bail!(
            "{}: rebuilt bytes hash to {digest}, manifest declares {expect_sha}",
            file.path
        );
    }
    Ok(written)
}

/// A manifest path must land strictly inside the output dir: relative, all
/// normal components, no traversal. The manifest is signed, but the check is
/// what keeps a signed bad path from writing outside `--output`.
fn safe_output_path(base: &Path, rel: &str) -> Result<PathBuf> {
    use std::path::Component;
    let p = Path::new(rel);
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s),
            _ => bail!("manifest path {rel:?} is not a plain relative path"),
        }
    }
    if parts.is_empty() {
        bail!("manifest path is empty");
    }
    Ok(base.join(p))
}

/// Rebuild a published release from Arweave and IPFS, without the node
/// (KTD15). Anchors are unsigned JSON anyone can post, so each candidate is
/// tried in turn: the anchor body selects candidates (repo, owner DID,
/// optional commit), then the manifest's signature must verify against
/// `expect_did` or the candidate is skipped with a warning. The first
/// candidate whose manifest verifies is THE release; every object after
/// that (reconstruction, block map, blocks, git files) is sha256-checked
/// against the signed manifest's claims, and a hash failure fails the fetch
/// naming the object.
pub async fn fetch_model(args: &FetchArgs) -> Result<FetchReport> {
    let (owner, name) = args
        .repo
        .split_once('/')
        .filter(|(o, n)| !o.is_empty() && !n.is_empty() && !n.contains('/'))
        .context("repo must be <owner>/<name>")?;
    // Anchors tag the full DID; accept the bare DID key (the HF-safe form)
    // by normalizing to did:key, matching the node's repo lookup.
    let owner = if owner.starts_with("did:") {
        owner.to_string()
    } else {
        format!("did:key:{owner}")
    };
    let repo = format!("{owner}/{name}");
    let expect_did: Did = args
        .expect_did
        .parse()
        .context("--expect-did is not a valid DID")?;
    let ag = args.arweave_gateway.trim_end_matches('/');
    let ig = args.ipfs_gateway.trim_end_matches('/');
    // Blocks can run 128 MiB, so the client budget is generous; small
    // objects keep their own shorter reads through the same client.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .context("failed to build HTTP client")?;
    let mut warnings: Vec<String> = Vec::new();
    let net = Net {
        client: &client,
        ag,
        ig,
    };

    let refs = discover_release_anchors(&net, &repo, &mut warnings).await;
    let (anchor_tx, anchor, manifest) = {
        let mut found = None;
        for r in refs.iter().take(MAX_ANCHOR_CANDIDATES) {
            if let Some(v) = verify_candidate(
                &net,
                &r.id,
                &repo,
                &expect_did,
                args.revision.as_deref(),
                &mut warnings,
            )
            .await
            {
                found = Some((r.id.clone(), v.0, v.1));
                break;
            }
        }
        match found {
            Some(v) => v,
            None => bail!(
                "no release anchor for {repo} verified against DID {expect_did} \
                 ({} candidate(s) tried)",
                refs.len().min(MAX_ANCHOR_CANDIDATES)
            ),
        }
    };

    // The manifest verified: from here a broken object is a fetch failure
    // naming the object, not another candidate.
    let rec = match &manifest.reconstruction {
        None => None,
        Some(rec_ref) => {
            let rec_cid = anchor.reconstruction_cid.as_deref().with_context(|| {
                format!(
                    "verified anchor names no reconstruction CID but the manifest \
                     declares one ({})",
                    rec_ref.sha256
                )
            })?;
            if !url_path_safe(rec_cid) {
                bail!("reconstruction CID {rec_cid:?} is not URL-safe");
            }
            let bytes = get_capped(
                &client,
                &format!("{ig}/ipfs/{rec_cid}"),
                RECONSTRUCTION_FETCH_CAP,
                "reconstruction object",
            )
            .await?;
            let got = sha256_hex(&bytes);
            if got != rec_ref.sha256 {
                bail!(
                    "reconstruction object hashes to {got}, manifest declares {}",
                    rec_ref.sha256
                );
            }
            if let Some(claimed) = &anchor.reconstruction_sha256 {
                if *claimed != rec_ref.sha256 {
                    bail!(
                        "anchor claims reconstruction {claimed}, the signed manifest \
                         declares {}",
                        rec_ref.sha256
                    );
                }
            }
            Some(
                Reconstruction::parse(&bytes)
                    .map_err(|e| anyhow::anyhow!("reconstruction object is invalid: {e}"))?,
            )
        }
    };

    let map_bytes = get_capped(
        &client,
        &format!("{ig}/ipfs/{}", anchor.block_map_cid),
        BLOCK_MAP_FETCH_CAP,
        "block map",
    )
    .await?;
    let map: BlockMapBody =
        serde_json::from_slice(&map_bytes).context("block map is not valid JSON")?;
    if map.schema != BLOCK_MAP_SCHEMA {
        bail!("block map has unknown schema {:?}", map.schema);
    }

    let out_dir = args.output.clone().unwrap_or_else(|| {
        // `release_commit` is untrusted anchor text: truncate by chars so a
        // multi-byte boundary cannot panic, like a raw byte slice would.
        let short: String = anchor.release_commit.chars().take(8).collect();
        PathBuf::from(format!("{name}-{short}"))
    });
    if out_dir.exists() {
        let non_empty = out_dir
            .read_dir()
            .with_context(|| format!("output path {} is not a directory", out_dir.display()))?
            .next()
            .is_some();
        if non_empty {
            bail!("output directory {} is not empty", out_dir.display());
        }
    }
    std::fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let rec_by_path: HashMap<&str, &FileEntry> = rec
        .as_ref()
        .map(|r| r.files.iter().map(|f| (f.path.as_str(), f)).collect())
        .unwrap_or_default();
    let mut cache = BlockCache::new();
    let mut total = 0u64;
    for file in &manifest.files {
        let out_path = safe_output_path(&out_dir, &file.path)?;
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match file.storage {
            StorageKind::Git => {
                // Git-stored bytes are pinned by the block-map job under
                // `files` keyed by manifest sha256; `blocks` is the fallback
                // for maps written before that index existed.
                let cid = map
                    .files
                    .get(&file.sha256)
                    .or_else(|| map.blocks.get(&file.sha256))
                    .with_context(|| {
                        format!(
                            "{}: block map has no CID for file {}",
                            file.path, file.sha256
                        )
                    })?;
                if !url_path_safe(cid) {
                    bail!("{}: block map CID is not URL-safe", file.path);
                }
                let bytes = get_capped(
                    &client,
                    &format!("{ig}/ipfs/{cid}"),
                    OBJECT_FETCH_CAP,
                    &format!("file {}", file.path),
                )
                .await?;
                let got = sha256_hex(&bytes);
                if got != file.sha256 {
                    bail!(
                        "{}: fetched bytes hash to {got}, manifest declares {}",
                        file.path,
                        file.sha256
                    );
                }
                std::fs::write(&out_path, &bytes)
                    .with_context(|| format!("write {}", out_path.display()))?;
                total += bytes.len() as u64;
            }
            StorageKind::Chunked => {
                let entry = rec_by_path.get(file.path.as_str()).with_context(|| {
                    format!(
                        "{}: reconstruction object has no entry for a manifest file",
                        file.path
                    )
                })?;
                let rec = rec.as_ref().expect("chunked file implies reconstruction");
                let mut source = BlockSource {
                    client: &client,
                    ig,
                    map: &map,
                    cache: &mut cache,
                };
                total +=
                    rebuild_chunked(&mut source, rec, entry, &file.sha256, file.size, &out_path)
                        .await?;
            }
        }
    }

    Ok(FetchReport {
        repo,
        release_commit: anchor.release_commit,
        anchor_tx,
        files: manifest.files.len(),
        bytes: total,
        output_dir: out_dir,
        warnings,
    })
}

async fn cmd_fetch(args: FetchArgs) -> Result<()> {
    let report = fetch_model(&args).await?;
    println!(
        "fetched {} release {}",
        sanitize_node_msg(&report.repo),
        sanitize_node_msg(&report.release_commit)
    );
    println!("  anchor:   {}", sanitize_node_msg(&report.anchor_tx));
    println!(
        "  verified: {} file(s), {} byte(s)",
        report.files, report.bytes
    );
    println!("  output:   {}", report.output_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const THR: u64 = 1024;

    #[test]
    fn classify_by_threshold_tracking_and_ignore() {
        // Below threshold: tracked or unignored-untracked are git files.
        assert_eq!(classify(THR - 1, true, false, false, THR), Class::Git);
        assert_eq!(classify(THR - 1, false, false, false, THR), Class::Git);
        assert_eq!(classify(THR - 1, false, true, false, THR), Class::Ignored);
        assert_eq!(classify(THR - 1, false, true, true, THR), Class::Ignored);
        // At/above threshold: tracked refuses; untracked chunks unless
        // ignored outside the managed block.
        assert_eq!(classify(THR, true, false, false, THR), Class::LargeTracked);
        assert_eq!(
            classify(THR + 1, true, true, false, THR),
            Class::LargeTracked
        );
        assert_eq!(classify(THR, false, false, false, THR), Class::Chunked);
        assert_eq!(classify(THR, false, true, true, THR), Class::Chunked);
        assert_eq!(classify(THR, false, true, false, THR), Class::Ignored);
    }

    #[test]
    fn managed_block_upsert_insert_replace_idempotent_remove() {
        let base = "*.tmp\n".to_string();
        let paths = vec!["weights/a.bin".to_string(), "b.bin".to_string()];
        let once = upsert_managed_block(&base, &paths);
        assert!(once.contains("*.tmp\n"));
        assert!(once.contains(GITIGNORE_BEGIN));
        assert!(once.contains("/weights/a.bin\n/b.bin\n"));
        assert!(once.contains(GITIGNORE_END));
        assert_eq!(once, upsert_managed_block(&once, &paths), "idempotent");

        let replaced = upsert_managed_block(&once, &["c.bin".to_string()]);
        assert!(replaced.contains("c.bin"));
        assert!(!replaced.contains("a.bin"));

        let removed = upsert_managed_block(&replaced, &[]);
        assert!(!removed.contains(GITIGNORE_BEGIN));
        assert_eq!(removed, "*.tmp\n");

        let empty = upsert_managed_block("", &paths);
        assert_eq!(managed_block_paths(&empty), paths);
    }

    #[test]
    fn a_verifying_release_past_the_budget_is_an_error() {
        // The poll loop needs a live node, so the budget decision is kept
        // in this pure helper: the arm it feeds must exit non-zero with the
        // release id, the budget, and the status path.
        let e = still_verifying_error(7, 300, "/api/v1/repos/o/r/models/releases/cc");
        let msg = e.to_string();
        assert!(msg.contains("7"), "{msg}");
        assert!(msg.contains("300"), "{msg}");
        assert!(
            msg.contains("/api/v1/repos/o/r/models/releases/cc"),
            "{msg}"
        );
    }

    #[test]
    fn managed_block_paths_reads_only_the_block() {
        let text = format!("a\n{GITIGNORE_BEGIN}\nx.bin\ny.bin\n{GITIGNORE_END}\nz\n");
        assert_eq!(managed_block_paths(&text), vec!["x.bin", "y.bin"]);
        assert!(managed_block_paths("nothing here\n").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn save_state_is_owner_only_even_over_a_loose_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let state = PublishState {
            session_id: "bearer".to_string(),
            uploaded: vec![],
            ..PublishState::default()
        };
        save_state(&path, &state).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        // A resume file left loose by an earlier run is tightened on rewrite.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_state(&path, &state).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(load_state(&path), state);
    }

    #[test]
    fn publish_state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let state = PublishState {
            session_id: "abc".to_string(),
            uploaded: vec!["aa".into(), "bb".into()],
            node: "https://node.example".to_string(),
            repo: "owner/name".to_string(),
        };
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path), state);
        assert_eq!(
            load_state(&dir.path().join("missing.json")),
            PublishState::default()
        );
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(load_state(&path), PublishState::default());
    }

    #[test]
    fn a_state_bound_elsewhere_or_unbound_is_not_resumable() {
        let bound = PublishState {
            session_id: "abc".to_string(),
            uploaded: vec![],
            node: "https://node.example".to_string(),
            repo: "owner/name".to_string(),
        };
        assert!(state_resumable(
            &bound,
            "https://node.example",
            "owner/name"
        ));
        assert!(!state_resumable(
            &bound,
            "https://other.example",
            "owner/name"
        ));
        assert!(!state_resumable(
            &bound,
            "https://node.example",
            "owner/other"
        ));
        // A state file from before the binding fields existed deserializes
        // them empty, so it is not resumable either.
        let legacy: PublishState =
            serde_json::from_str(r#"{"session_id":"abc","uploaded":[]}"#).unwrap();
        assert!(!state_resumable(
            &legacy,
            "https://node.example",
            "owner/name"
        ));
    }

    #[test]
    fn parse_parent_shapes() {
        let commit = "a".repeat(40);
        let ((owner, name), c) = parse_parent(&format!("alice/weights@{commit}")).unwrap();
        assert_eq!(
            (owner.as_str(), name.as_str(), c.as_str()),
            ("alice", "weights", commit.as_str())
        );
        // A did:key owner carries colons; the split is on the LAST '@'.
        let did_owner = "did:key:z6MkAbc";
        let ((owner, name), _) = parse_parent(&format!("{did_owner}/weights@{commit}")).unwrap();
        assert_eq!((owner.as_str(), name.as_str()), (did_owner, "weights"));
        for bad in [
            "noslash",
            "a/b@",
            "a/b@cafe",
            &format!("a/b/c@{commit}"),
            &format!("a/b@{commit}x"),
            &format!("a/b@{}", "g".repeat(40)),
        ] {
            assert!(parse_parent(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn manifest_assembly_round_trips_storage_kinds() {
        // The manifest the command writes: schema v1, repo as owner/name,
        // git and chunked entries sorted by path, reconstruction ref present.
        let kp = twigpine_core::identity::Keypair::from_seed(&[3u8; 32]).unwrap();
        let mut files = vec![
            ManifestFile {
                path: "weights.bin".to_string(),
                size: 11,
                sha256: "b".repeat(64),
                format: twigpine_core::model::manifest::FileFormat::Other,
                storage: StorageKind::Chunked,
            },
            ManifestFile {
                path: "README.md".to_string(),
                size: 5,
                sha256: "a".repeat(64),
                format: twigpine_core::model::manifest::FileFormat::Text,
                storage: StorageKind::Git,
            },
        ];
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let m = Manifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            repo: "did:key:z6MkA/w".to_string(),
            publisher_did: kp.did().to_string(),
            license: "apache-2.0".to_string(),
            parent: None,
            files,
            reconstruction: Some(ReconstructionRef {
                sha256: "c".repeat(64),
                size: 42,
            }),
        };
        let bytes = m.to_bytes().unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schema"].as_str(), Some(MANIFEST_SCHEMA_V1));
        assert_eq!(v["repo"].as_str(), Some("did:key:z6MkA/w"));
        assert_eq!(v["license"].as_str(), Some("apache-2.0"));
        let paths: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["path"].as_str())
            .collect();
        assert_eq!(paths, ["README.md", "weights.bin"]);
        let storages: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["storage"].as_str())
            .collect();
        assert_eq!(storages, ["git", "chunked"]);
        let rec_sha = "c".repeat(64);
        assert_eq!(
            v["reconstruction"]["sha256"].as_str(),
            Some(rec_sha.as_str())
        );
    }

    #[test]
    fn remote_url_parses_both_schemes() {
        assert_eq!(
            parse_remote_url("twigpine://did:key:z6MkA/repo.git"),
            Some(("did:key:z6MkA".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_remote_url("gitlawb://did:key:z6MkA/repo"),
            Some(("did:key:z6MkA".to_string(), "repo".to_string()))
        );
        assert_eq!(parse_remote_url("https://x/y"), None);
    }

    fn tgit(dir: &Path, args: &[&str]) -> String {
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

    fn trepo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tgit(dir.path(), &["init", "-q", "-b", "main"]);
        dir
    }

    #[test]
    fn a_push_url_naming_a_different_repo_is_rejected() {
        let dir = trepo();
        tgit(
            dir.path(),
            &["remote", "add", "origin", "twigpine://did:key:z6MkA/aaa"],
        );
        tgit(
            dir.path(),
            &[
                "remote",
                "set-url",
                "--push",
                "origin",
                "twigpine://did:key:z6MkB/bbb",
            ],
        );
        let e = detect_remote(dir.path()).unwrap_err();
        assert!(e.to_string().contains("pushes to"), "{e}");
    }

    #[test]
    fn a_matching_push_url_is_accepted() {
        let dir = trepo();
        tgit(
            dir.path(),
            &["remote", "add", "origin", "twigpine://did:key:z6MkA/aaa"],
        );
        tgit(
            dir.path(),
            &[
                "remote",
                "set-url",
                "--push",
                "origin",
                "twigpine://did:key:z6MkA/aaa",
            ],
        );
        assert_eq!(
            detect_remote(dir.path()).unwrap(),
            (
                "origin".to_string(),
                "did:key:z6MkA".to_string(),
                "aaa".to_string()
            )
        );
    }

    #[test]
    fn managed_patterns_anchor_at_root_and_escape_wildcards() {
        assert_eq!(escape_gitignore_path("a*b?.bin"), "/a\\*b\\?.bin");
        assert_eq!(escape_gitignore_path("weights.bin"), "/weights.bin");
        let text =
            format!("{GITIGNORE_BEGIN}\n/weights.bin\n/experiments/weights.bin\n{GITIGNORE_END}\n");
        assert_eq!(
            managed_block_paths(&text),
            vec!["weights.bin", "experiments/weights.bin"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_literal_pathspec_filename_resolves_its_own_blob() {
        let dir = trepo();
        std::fs::write(dir.path().join(":(glob)weights*.txt"), b"magic").unwrap();
        std::fs::write(dir.path().join("weights-a.txt"), b"plain").unwrap();
        tgit(
            dir.path(),
            &[
                "--literal-pathspecs",
                "add",
                "--",
                ":(glob)weights*.txt",
                "weights-a.txt",
            ],
        );
        let index = dir.path().join(".git/index");
        assert_eq!(
            staged_blob(dir.path(), &index, ":(glob)weights*.txt").unwrap(),
            b"magic"
        );
        assert_eq!(
            staged_blob(dir.path(), &index, "weights-a.txt").unwrap(),
            b"plain"
        );
    }

    fn tcommit(dir: &Path, index: &Path, msg: &str) {
        git_index(
            dir,
            index,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                msg,
            ],
        )
        .unwrap();
    }

    /// After the release commit and the index sync, status must show only
    /// what the user staged: no released path may linger as a staged
    /// reversion the next plain commit would apply.
    fn assert_only_unrelated_staged(dir: &Path) {
        let status = tgit(dir, &["status", "--porcelain"]);
        assert_eq!(status, "A  unrelated.bin", "status");
        let staged = tgit(dir, &["diff", "--cached", "--name-status"]);
        assert_eq!(staged, "A\tunrelated.bin", "diff --cached");
    }

    #[test]
    fn the_release_index_leaves_user_staging_alone() {
        let dir = trepo();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        tgit(dir.path(), &["add", "a.txt"]);
        tgit(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        );
        // An unrelated file staged in the real index must not ride into the
        // release commit, and must still be staged afterwards.
        std::fs::write(dir.path().join("unrelated.bin"), b"u").unwrap();
        tgit(dir.path(), &["add", "unrelated.bin"]);
        let index = dir.path().join(".git").join("tmp-index");
        git_index(dir.path(), &index, &["read-tree", "HEAD"]).unwrap();
        std::fs::write(dir.path().join("b.txt"), b"b").unwrap();
        git_index(dir.path(), &index, &["add", "b.txt"]).unwrap();
        tcommit(dir.path(), &index, "rel");
        let tree = tgit(dir.path(), &["ls-tree", "--name-only", "HEAD"]);
        assert!(!tree.contains("unrelated.bin"), "{tree}");
        assert!(tree.contains("b.txt"), "{tree}");
        sync_index_to_head(dir.path(), &dir.path().join(".git"), &["b.txt".to_string()]).unwrap();
        assert_only_unrelated_staged(dir.path());
    }

    #[test]
    fn the_index_sync_handles_a_deleted_tracked_path() {
        let dir = trepo();
        std::fs::write(dir.path().join("gone.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("kept.txt"), b"y").unwrap();
        tgit(dir.path(), &["add", "gone.txt", "kept.txt"]);
        tgit(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        );
        std::fs::write(dir.path().join("unrelated.bin"), b"u").unwrap();
        tgit(dir.path(), &["add", "unrelated.bin"]);
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();
        let index = dir.path().join(".git").join("tmp-index");
        git_index(dir.path(), &index, &["read-tree", "HEAD"]).unwrap();
        git_index(dir.path(), &index, &["add", "-A", "gone.txt"]).unwrap();
        tcommit(dir.path(), &index, "rel");
        let tree = tgit(dir.path(), &["ls-tree", "--name-only", "HEAD"]);
        assert!(!tree.contains("gone.txt"), "{tree}");
        sync_index_to_head(
            dir.path(),
            &dir.path().join(".git"),
            &["gone.txt".to_string()],
        )
        .unwrap();
        assert_only_unrelated_staged(dir.path());
    }

    #[test]
    fn the_index_sync_works_on_a_repos_first_commit() {
        let dir = trepo();
        std::fs::write(dir.path().join("unrelated.bin"), b"u").unwrap();
        tgit(dir.path(), &["add", "unrelated.bin"]);
        let index = dir.path().join(".git").join("tmp-index");
        git_index(dir.path(), &index, &["read-tree", "--empty"]).unwrap();
        std::fs::write(dir.path().join("rel.txt"), b"r").unwrap();
        git_index(dir.path(), &index, &["add", "rel.txt"]).unwrap();
        tcommit(dir.path(), &index, "first release");
        sync_index_to_head(
            dir.path(),
            &dir.path().join(".git"),
            &["rel.txt".to_string()],
        )
        .unwrap();
        assert_only_unrelated_staged(dir.path());
    }

    #[test]
    fn an_unstaged_tracked_deletion_is_recorded_for_staging() {
        let dir = trepo();
        std::fs::write(dir.path().join("gone.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("kept.txt"), b"y").unwrap();
        tgit(dir.path(), &["add", "gone.txt", "kept.txt"]);
        tgit(
            dir.path(),
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        );
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();
        let scan = scan_files(dir.path(), "", 1024).unwrap();
        assert_eq!(scan.deleted, vec!["gone.txt"]);
        assert!(scan.git_files.contains(&"kept.txt".to_string()));
        assert!(!scan.git_files.contains(&"gone.txt".to_string()));
    }

    fn tcommit_all(root: &Path) {
        tgit(
            root,
            &[
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        );
    }

    fn index_listing(root: &Path, index: &Path) -> Vec<String> {
        let out = git_index(root, index, &["ls-files"]).unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn the_publish_lock_is_exclusive_while_held() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_publish_lock(dir.path()).unwrap();
        assert!(acquire_publish_lock(dir.path()).is_err());
        drop(first);
        assert!(acquire_publish_lock(dir.path()).is_ok());
    }

    #[test]
    fn a_head_weight_file_made_chunked_leaves_the_release_index() {
        let dir = trepo();
        std::fs::write(dir.path().join("weights.bin"), vec![7u8; 4096]).unwrap();
        std::fs::write(dir.path().join("kept.txt"), b"y").unwrap();
        tgit(dir.path(), &["add", "weights.bin", "kept.txt"]);
        tcommit_all(dir.path());
        tgit(dir.path(), &["rm", "--cached", "-q", "weights.bin"]);
        let scan = scan_files(dir.path(), "", 1024).unwrap();
        assert_eq!(scan.chunked_files, vec!["weights.bin"]);
        assert_eq!(scan.deleted, vec!["weights.bin"]);
        // The managed .gitignore block ignores weights.bin; it is both
        // chunked and staged-deleted here.
        std::fs::write(
            dir.path().join(".gitignore"),
            upsert_managed_block("", &scan.chunked_files),
        )
        .unwrap();
        let index = dir.path().join(".git").join("twigpine-model-index");
        seed_release_index(dir.path(), &index, &scan.chunked_files).unwrap();
        let spec = dir.path().join(".git").join("tmp-pathspec");
        std::fs::write(&spec, release_pathspec(&scan, true)).unwrap();
        git_index(
            dir.path(),
            &index,
            &[
                "--literal-pathspecs",
                "add",
                "-A",
                "--pathspec-file-nul",
                &format!("--pathspec-from-file={}", spec.display()),
            ],
        )
        .unwrap();
        assert!(dir.path().join("weights.bin").is_file());
        let listed = index_listing(dir.path(), &index);
        assert!(!listed.contains(&"weights.bin".to_string()));
        assert!(listed.contains(&"kept.txt".to_string()));
        assert!(listed.contains(&".gitignore".to_string()));
    }

    #[test]
    fn metadata_stages_around_a_clean_filter() {
        let dir = trepo();
        // A clean filter rewriting JSON bytes: a plain `git add` stores the
        // filtered text, stage_unfiltered must store the disk bytes.
        tgit(
            dir.path(),
            &["config", "filter.rewrite.clean", "sed s/signed/rewritten/"],
        );
        std::fs::write(dir.path().join(".gitattributes"), "*.json filter=rewrite\n").unwrap();
        tgit(dir.path(), &["add", ".gitattributes"]);
        tcommit_all(dir.path());
        std::fs::create_dir_all(dir.path().join(".twigpine")).unwrap();
        std::fs::write(dir.path().join(".twigpine/model-release.json"), b"signed").unwrap();
        std::fs::write(dir.path().join(".twigpine/control.json"), b"signed").unwrap();
        let index = dir.path().join(".git").join("tmp-index");
        git_index(dir.path(), &index, &["read-tree", "--empty"]).unwrap();
        stage_unfiltered(dir.path(), &index, ".twigpine/model-release.json").unwrap();
        assert_eq!(
            staged_blob(dir.path(), &index, ".twigpine/model-release.json").unwrap(),
            b"signed"
        );
        // Control: the same bytes through a filtered add are rewritten.
        git_index(dir.path(), &index, &["add", ".twigpine/control.json"]).unwrap();
        assert_eq!(
            staged_blob(dir.path(), &index, ".twigpine/control.json").unwrap(),
            b"rewritten"
        );
    }

    #[test]
    fn a_gitignore_created_mid_publish_enters_the_manifest_inventory() {
        let dir = trepo();
        std::fs::write(dir.path().join("kept.txt"), b"y").unwrap();
        std::fs::write(dir.path().join("weights.bin"), vec![7u8; 4096]).unwrap();
        tgit(dir.path(), &["add", "kept.txt"]);
        tcommit_all(dir.path());
        // The scan runs before the managed block is written, so a publish
        // that creates .gitignore cannot have it in scan.git_files.
        let scan = scan_files(dir.path(), "", 1024).unwrap();
        assert_eq!(scan.chunked_files, vec!["weights.bin"]);
        assert!(!scan.git_files.contains(&".gitignore".to_string()));
        std::fs::write(
            dir.path().join(".gitignore"),
            upsert_managed_block("", &scan.chunked_files),
        )
        .unwrap();
        let index = dir.path().join(".git").join("tmp-index");
        seed_release_index(dir.path(), &index, &scan.chunked_files).unwrap();
        let spec = dir.path().join(".git").join("tmp-pathspec");
        std::fs::write(&spec, release_pathspec(&scan, true)).unwrap();
        git_index(
            dir.path(),
            &index,
            &[
                "--literal-pathspecs",
                "add",
                "-A",
                "--pathspec-file-nul",
                &format!("--pathspec-from-file={}", spec.display()),
            ],
        )
        .unwrap();
        let entry = staged_gitignore_entry(dir.path(), &index, &scan)
            .unwrap()
            .expect("a staged .gitignore yields an entry");
        assert_eq!(entry.path, ".gitignore");
        assert!(matches!(entry.storage, StorageKind::Git));

        // A .gitignore the scan already lists is not named twice, and a
        // git-only release with no .gitignore gets no entry.
        let scan2 = scan_files(dir.path(), "", 1024).unwrap();
        assert!(scan2.git_files.contains(&".gitignore".to_string()));
        assert!(staged_gitignore_entry(dir.path(), &index, &scan2)
            .unwrap()
            .is_none());
        std::fs::remove_file(dir.path().join(".gitignore")).unwrap();
        assert!(staged_gitignore_entry(dir.path(), &index, &scan)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_staged_rename_records_the_old_path_as_deleted() {
        let dir = trepo();
        std::fs::write(dir.path().join("old.txt"), b"x").unwrap();
        tgit(dir.path(), &["add", "."]);
        tcommit_all(dir.path());
        tgit(dir.path(), &["mv", "old.txt", "new.txt"]);
        let scan = scan_files(dir.path(), "", 1024).unwrap();
        assert_eq!(scan.deleted, vec!["old.txt"]);
    }

    #[test]
    #[cfg(unix)]
    fn a_stat_error_other_than_absence_fails_the_scan() {
        use std::os::unix::fs::PermissionsExt;
        let dir = trepo();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/kept.txt"), b"y").unwrap();
        tgit(dir.path(), &["add", "."]);
        tcommit_all(dir.path());
        // An unreadable directory makes symlink_metadata fail with
        // PermissionDenied: that is not "file deleted".
        std::fs::set_permissions(dir.path().join("sub"), std::fs::Permissions::from_mode(0o0))
            .unwrap();
        let err = scan_files(dir.path(), "", 1024).err().expect("scan fails");
        std::fs::set_permissions(
            dir.path().join("sub"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(err.to_string().contains("sub/kept.txt"), "{err}");
    }

    #[test]
    fn a_staged_deletion_is_recorded_and_dropped_from_the_release_index() {
        let dir = trepo();
        std::fs::write(dir.path().join("gone.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("kept.txt"), b"y").unwrap();
        tgit(dir.path(), &["add", "gone.txt", "kept.txt"]);
        tcommit_all(dir.path());
        tgit(dir.path(), &["rm", "-q", "gone.txt"]);
        let scan = scan_files(dir.path(), "", 1024).unwrap();
        assert_eq!(scan.deleted, vec!["gone.txt"]);
        let index = dir.path().join(".git").join("twigpine-model-index");
        seed_release_index(dir.path(), &index, &scan.chunked_files).unwrap();
        let spec = dir.path().join(".git").join("tmp-pathspec");
        let mut bytes = Vec::new();
        for p in scan.git_files.iter().chain(&scan.deleted) {
            bytes.extend_from_slice(p.as_bytes());
            bytes.push(0);
        }
        std::fs::write(&spec, bytes).unwrap();
        git_index(
            dir.path(),
            &index,
            &[
                "--literal-pathspecs",
                "add",
                "-A",
                "--pathspec-file-nul",
                &format!("--pathspec-from-file={}", spec.display()),
            ],
        )
        .unwrap();
        let listed = index_listing(dir.path(), &index);
        assert!(!listed.contains(&"gone.txt".to_string()));
        assert!(listed.contains(&"kept.txt".to_string()));
    }
}
