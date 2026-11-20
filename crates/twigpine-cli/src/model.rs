//! `twigpine model`: open-weight model publishing (KTD14) and independent
//! release fetching (KTD15).
//!
//! `twigpine model publish` runs inside a local clone of a fully public
//! Twigpine repo: it classifies files by the chunking threshold, packs the
//! large ones into content blocks with cross-release dedup, uploads the new
//! blocks under an upload session (resuming from a `.git` state file after an
//! interruption), commits the signed manifest, pushes, claims the release,
//! and polls until the node's verification publishes it.
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
    /// Publish the working tree as a signed model release
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

/// One repo-relative path as a gitignore pattern line: pattern
/// metacharacters and a trailing space are backslash-escaped.
fn escape_gitignore_path(p: &str) -> String {
    let mut out = String::new();
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '\\' | '!' | '#' | '[' | ']') {
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
    };
    let mut consider = |path: &str, is_tracked: bool| {
        if path.starts_with(".twigpine/") {
            return; // release metadata is never a manifest file
        }
        // A path that vanished between listing and stat (or a tracked file
        // deleted in the worktree, whose staged deletion `git add -A` picks
        // up) is simply not in the publishable set.
        let Ok(meta) = std::fs::symlink_metadata(root.join(path)) else {
            return;
        };
        if !meta.is_file() && !meta.file_type().is_symlink() {
            return;
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
    };

    for p in &tracked {
        consider(p, true);
    }
    for p in &others {
        if tracked.contains(p) {
            continue;
        }
        consider(p, false);
    }
    scan.git_files.sort();
    scan.chunked_files.sort();
    scan.refused.sort();
    scan.skipped_ignored.sort();
    Ok(scan)
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
    let mut f = std::fs::File::create(path).with_context(|| format!("write {}", path.display()))?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(())
}

// ── misc ────────────────────────────────────────────────────────────────────

/// `<owner>/<repo>@<40-hex commit>` -> ((owner, name), commit).
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
    if commit.len() != 40 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("parent commit must be a 40-hex sha");
    }
    Ok(((owner.to_string(), name.to_string()), commit.to_string()))
}

fn read_head(path: &Path, n: u64) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = Vec::new();
    f.take(n).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Bytes of the staged index blob for `path`: exactly what the release
/// commit will store, filters and symlink handling included.
fn staged_blob(root: &Path, path: &str) -> Result<Vec<u8>> {
    // Resolve the blob sha through the index rather than `:{path}` revspec
    // syntax: a path that opens with magic characters is parsed as revspec
    // there, not as a filename.
    let out = git(root, &["ls-files", "-s", "-z", "--", path])?;
    let stdout = String::from_utf8(out.stdout).context("ls-files output was not utf-8")?;
    // `<mode> <sha> <stage>\t<path>`: the sha is the second blank field.
    let sha = stdout
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
        "publishing is permanent: blocks are pinned to IPFS and the manifest anchors \
         to Arweave, so the bytes stay fetchable even if this repo is later removed"
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
    let needed: HashSet<String> = rec
        .files
        .iter()
        .flat_map(|f| f.terms.iter().map(|t| t.block.clone()))
        .collect();
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

    // 7. Managed .gitignore block, then stage exactly the publishable set
    //    through a NUL pathspec: a bare `git add -A` would sweep in work the
    //    scan never saw (files created or un-ignored during the upload, or
    //    index changes staged for something else).
    let new_gitignore = upsert_managed_block(&existing_gitignore, &scan.chunked_files);
    if new_gitignore != existing_gitignore {
        std::fs::write(&gitignore_path, &new_gitignore)?;
    }
    let pathspec_path = git_dir.join("twigpine-model-pathspec");
    {
        let mut spec = Vec::new();
        for p in &scan.git_files {
            spec.extend_from_slice(p.as_bytes());
            spec.push(0);
        }
        for p in [
            ".gitignore",
            ".twigpine/model-release.json",
            ".twigpine/model-release.sig",
        ] {
            spec.extend_from_slice(p.as_bytes());
            spec.push(0);
        }
        std::fs::write(&pathspec_path, spec)?;
    }
    let staged = git(
        &root,
        &[
            "add",
            "-A",
            "--pathspec-file-nul",
            &format!("--pathspec-from-file={}", pathspec_path.display()),
        ],
    );
    let _ = std::fs::remove_file(&pathspec_path);
    staged?;

    // 8. Hash the git-stored files from the index (the exact bytes the
    //    commit stores), then write and stage the manifest.
    for path in &scan.git_files {
        let bytes = staged_blob(&root, path)?;
        files.push(ManifestFile {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            format: detect_format(&bytes[..bytes.len().min(64)], path),
            storage: StorageKind::Git,
        });
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
    git(
        &root,
        &[
            "add",
            ".twigpine/model-release.json",
            ".twigpine/model-release.sig",
        ],
    )?;

    // 9. Commit when the index differs, push, and claim HEAD.
    let has_changes = git(&root, &["diff", "--cached", "--quiet"]).is_err();
    if has_changes {
        let n = prior_commits.len() + 1;
        git(&root, &["commit", "-m", &format!("model release {n}")])?;
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
                    println!(
                        "release {release_id} is still verifying after {}s; its status is at\n  \
                         GET {release_path}",
                        POLL_BUDGET.as_secs()
                    );
                    return Ok(());
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
        let response = match net
            .client
            .post(format!("{}/graphql", net.ag))
            .json(&gql_body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.json::<Value>().await.ok(),
            _ => None,
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
    let commit = &anchor.release_commit;
    if !(commit.len() == 40 || commit.len() == 64)
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
        if anchor.release_commit != want {
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
        assert!(once.contains("weights/a.bin\nb.bin\n"));
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
    fn managed_block_paths_reads_only_the_block() {
        let text = format!("a\n{GITIGNORE_BEGIN}\nx.bin\ny.bin\n{GITIGNORE_END}\nz\n");
        assert_eq!(managed_block_paths(&text), vec!["x.bin", "y.bin"]);
        assert!(managed_block_paths("nothing here\n").is_empty());
    }

    #[test]
    fn publish_state_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE_NAME);
        let state = PublishState {
            session_id: "abc".to_string(),
            uploaded: vec!["aa".into(), "bb".into()],
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
}
