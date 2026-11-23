//! Issue storage as git refs.
//!
//! Issues are stored as signed JSON blobs in git refs:
//!   refs/gitlawb/issues/<uuid>
//!
//! This makes them content-addressed and travel with the repo.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Write a JSON blob for an issue and set the ref.
pub fn create_issue(repo_path: &Path, issue_id: &str, json: &str) -> Result<()> {
    // Write the JSON blob as a git object
    let hash_output = Command::new("git")
        .args(["hash-object", "--stdin", "-w"])
        .current_dir(repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git hash-object")?;

    use std::io::Write;
    let mut child = hash_output;
    // Write the blob to stdin, but always reap the child afterward even if the
    // write fails, so a stdin-write error can't drop the Child unwaited and leak
    // a zombie (#53).
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(json.as_bytes()),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "git hash-object stdin unavailable",
        )),
    };
    let output = child.wait_with_output().context("git hash-object failed")?;
    write_result.context("failed to write to git hash-object stdin")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git hash-object failed: {stderr}");
    }

    let hash =
        String::from_utf8(output.stdout).context("git hash-object output is not valid UTF-8")?;
    let hash = hash.trim();

    // Update the ref
    let ref_name = format!("refs/gitlawb/issues/{issue_id}");
    let update_output = Command::new("git")
        .args(["update-ref", &ref_name, hash])
        .current_dir(repo_path)
        .output()
        .context("failed to run git update-ref")?;

    if !update_output.status.success() {
        let stderr = String::from_utf8_lossy(&update_output.stderr);
        anyhow::bail!("git update-ref failed: {stderr}");
    }

    Ok(())
}

/// Issue ids are UUIDs; refs under `refs/gitlawb/issues/` only ever carry
/// `[0-9a-zA-Z_-]` names. Anything else is not a value we pass to git.
fn issue_ref_name_is_safe(ref_name: &str) -> bool {
    let Some(id) = ref_name.strip_prefix("refs/gitlawb/issues/") else {
        return false;
    };
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// True iff `ref_name` appears verbatim in a `for-each-ref` listing.
fn ref_listed(for_each_ref_stdout: &[u8], ref_name: &str) -> bool {
    String::from_utf8_lossy(for_each_ref_stdout)
        .lines()
        .any(|line| line.trim() == ref_name)
}

/// Resolve a ref name without putting it on a command line: enumerate refs
/// (constant argv) and match in memory. A nonzero exit propagates, so "cannot
/// determine" is an error rather than a quiet `false`.
fn ref_name_resolves(repo_path: &Path, ref_name: &str) -> Result<bool> {
    // allow-unbounded-git: failure-path existence recheck, module convention.
    let out = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)"])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("git for-each-ref failed: {}", stderr.trim());
    }
    Ok(ref_listed(&out.stdout, ref_name))
}

/// Deadline-bounded variant of [`ref_name_resolves`], same semantics on the
/// shared runner: a nonzero enumeration is an error, never a quiet `false`.
fn ref_name_resolves_bounded(
    git_bin: &str,
    repo_path: &Path,
    ref_name: &str,
    deadline: std::time::Instant,
) -> Result<bool> {
    let out = crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["for-each-ref", "--format=%(refname)"],
        repo_path,
        b"",
        deadline,
    )?;
    Ok(ref_listed(&out, ref_name))
}

/// The "<oid> blob <size>" header parse and body slice of `cat-file --batch`
/// output, shared by the unbounded and bounded readers. The caller handles the
/// "<spec> missing" line first; anything else here is one object's answer.
fn catfile_batch_body(ref_name: &str, stdout: &[u8]) -> Result<Option<String>> {
    // Header: "<oid> <type> <size>\n" then exactly <size> bytes plus a newline.
    let header_end = stdout
        .iter()
        .position(|b| *b == b'\n')
        .context("unexpected git cat-file --batch output")?;
    let header = String::from_utf8_lossy(&stdout[..header_end]);
    let mut parts = header.split(' ');
    parts.next();
    let obj_type = parts.next().unwrap_or("");
    if obj_type != "blob" {
        anyhow::bail!("issue ref {ref_name} resolves to a non-blob object");
    }
    let size: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .context("unexpected git cat-file --batch header")?;
    let body = &stdout[header_end + 1..];
    anyhow::ensure!(
        body.len() >= size,
        "truncated git cat-file --batch body for {ref_name}"
    );
    Ok(Some(String::from_utf8_lossy(&body[..size]).to_string()))
}

/// Read the blob behind an issue ref.
///
/// `Ok(None)` means the ref itself is absent. A ref that resolves but whose
/// object cannot be read (corrupt object, unreadable store, a mid-read gc) is
/// an error, not an absence (#426).
///
/// The ref name reaches git on stdin, never argv: `cat-file --batch` answers
/// `<oid> <type> <size>\n<body>\n` for a readable object and
/// `<spec> missing\n` for an absent ref or an unreadable object alike, so the
/// `missing` case is re-resolved by name enumeration to tell them apart.
fn read_issue_blob(repo_path: &Path, ref_name: &str) -> Result<Option<String>> {
    if !issue_ref_name_is_safe(ref_name) {
        anyhow::bail!("refusing issue ref outside the issues namespace: {ref_name}");
    }

    // allow-unbounded-git: this module's spawns predate the bounded runner and
    // its callers run inside issue handlers that already hold the repo guard.
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git cat-file --batch")?;

    use std::io::Write;
    // Reap the child even when the write fails so a stdin error cannot drop an
    // unwaited Child and leak a zombie (#53).
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(ref_name.as_bytes())
            .and_then(|()| stdin.write_all(b"\n")),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "git cat-file --batch stdin unavailable",
        )),
    };
    let output = child
        .wait_with_output()
        .context("git cat-file --batch failed")?;
    write_result.context("failed to write ref name to git cat-file stdin")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git cat-file --batch failed: {}", stderr.trim());
    }

    // "<spec> missing\n" covers an absent ref and an unreadable object; only a
    // ref that still resolves is the error case.
    let missing = format!("{ref_name} missing\n");
    if output.stdout.as_slice() == missing.as_bytes() {
        return match ref_name_resolves(repo_path, ref_name)? {
            true => anyhow::bail!("issue ref resolves but its object is unreadable: {ref_name}"),
            false => Ok(None),
        };
    }

    catfile_batch_body(ref_name, &output.stdout)
}

/// Deadline-bounded variant of [`read_issue_blob`]: the same missing-vs-error
/// split and the same body parse, with the `cat-file` child and the
/// failure-path recheck on the shared bounded runner.
fn read_issue_blob_bounded(
    git_bin: &str,
    repo_path: &Path,
    ref_name: &str,
    deadline: std::time::Instant,
) -> Result<Option<String>> {
    if !issue_ref_name_is_safe(ref_name) {
        anyhow::bail!("refusing issue ref outside the issues namespace: {ref_name}");
    }

    let mut spec = ref_name.as_bytes().to_vec();
    spec.push(b'\n');
    let stdout = crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["cat-file", "--batch"],
        repo_path,
        &spec,
        deadline,
    )?;

    // Same disambiguation as the unbounded reader: "missing" covers an absent
    // ref and an unreadable object; only a ref that still resolves is an error.
    let missing = format!("{ref_name} missing\n");
    if stdout.as_slice() == missing.as_bytes() {
        return match ref_name_resolves_bounded(git_bin, repo_path, ref_name, deadline)? {
            true => anyhow::bail!("issue ref resolves but its object is unreadable: {ref_name}"),
            false => Ok(None),
        };
    }

    catfile_batch_body(ref_name, &stdout)
}

/// Deadline-bounded variant of [`create_issue`] for compensation paths: the
/// same hash-object + update-ref write, but every git child runs through the
/// shared bounded runner so a hung git cannot stall the write guard past
/// `git_service_timeout`.
pub fn create_issue_bounded(
    git_bin: &str,
    repo_path: &Path,
    issue_id: &str,
    json: &str,
    deadline: std::time::Instant,
) -> Result<()> {
    let out = crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["hash-object", "--stdin", "-w"],
        repo_path,
        json.as_bytes(),
        deadline,
    )?;
    let hash = String::from_utf8(out).context("git hash-object output is not valid UTF-8")?;
    let hash = hash.trim();
    let ref_name = format!("refs/gitlawb/issues/{issue_id}");
    crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["update-ref", &ref_name, hash],
        repo_path,
        b"",
        deadline,
    )?;
    Ok(())
}

/// Remove a single issue ref while the write guard still holds the advisory lock,
/// after a definite publish refusal. Best-effort: a failed delete leaves a
/// local-only orphan, which is still better than telling the client to retry into a
/// duplicate id. Not used on `UploadUnknowable`, where the PUT may still land.
pub fn delete_issue_ref(
    git_bin: &str,
    repo_path: &Path,
    issue_id: &str,
    deadline: std::time::Instant,
) -> Result<()> {
    let ref_name = format!("refs/gitlawb/issues/{issue_id}");
    crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["update-ref", "-d", &ref_name],
        repo_path,
        b"",
        deadline,
    )?;
    Ok(())
}

/// List all issue refs and return their JSON content.
pub fn list_issues(repo_path: &Path) -> Result<Vec<String>> {
    // List all refs under refs/gitlawb/issues/
    let list_output = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname)",
            "refs/gitlawb/issues/",
        ])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;

    // for-each-ref exits 0 with empty output when no refs match, so a nonzero
    // exit is a real enumeration failure, not "no issues yet".
    if !list_output.status.success() {
        let stderr = String::from_utf8_lossy(&list_output.stderr);
        anyhow::bail!("git for-each-ref failed: {}", stderr.trim());
    }

    let refs_str = String::from_utf8_lossy(&list_output.stdout);
    let mut issues = Vec::new();

    for ref_name in refs_str.lines() {
        let ref_name = ref_name.trim();
        if ref_name.is_empty() {
            continue;
        }

        // Read the blob content. A ref that vanished between for-each-ref and
        // here is skipped; a ref that resolves but fails to read propagates so
        // a degraded object store errors the listing instead of under-reporting.
        match read_issue_blob(repo_path, ref_name)? {
            Some(content) => issues.push(content),
            None => continue,
        }
    }

    Ok(issues)
}

/// The (exact ref, enumeration glob) an issue id or prefix resolves through, or
/// `None` when the input is not a possible issue id at all. Shared by the
/// unbounded and bounded resolvers so both apply the same id validation.
fn issue_lookup_refs(id_or_prefix: &str) -> Option<(String, String)> {
    // The id comes from the request path and is spliced into a git revision and a
    // for-each-ref pattern. Issue ids are UUIDs, so accept only ASCII
    // alphanumerics and '-': anything else (`^{blob}`, `@{0}`, `*`, `/`, `..`) is
    // revision or glob syntax, never an issue id, and is reported as not found.
    if id_or_prefix.is_empty()
        || !id_or_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }

    // List all refs that start with the given string; the glob also matches the exact
    // ref. The id handed back is always git's own refname, never the request input.
    let exact_ref = format!("refs/gitlawb/issues/{id_or_prefix}");
    Some((exact_ref.clone(), format!("{exact_ref}*")))
}

/// Pick the winning ref out of a `for-each-ref` listing for `prefix_glob`.
/// `exact_object_exists` re-checks the exact ref's object through whichever
/// runner the caller uses. Shared by the unbounded and bounded resolvers.
fn resolve_issue_match(
    id_or_prefix: &str,
    exact_ref: &str,
    for_each_ref_stdout: &[u8],
    exact_object_exists: impl FnOnce(&str) -> Result<bool>,
) -> Result<Option<String>> {
    let output = String::from_utf8_lossy(for_each_ref_stdout);
    let matches: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    // An exact id wins over longer ids that share it as a prefix, but only if its
    // object exists: for-each-ref also lists a ref whose blob is missing, so a
    // dangling exact ref falls through to the prefix rules below.
    let exact = match matches.iter().find(|m| **m == exact_ref) {
        Some(m) => exact_object_exists(m)?.then_some(*m),
        None => None,
    };
    let found = match exact {
        Some(m) => m,
        None => match matches.as_slice() {
            [] => return Ok(None),
            [m] => *m,
            _ => anyhow::bail!(
                "ambiguous issue prefix '{}': matches {} issues",
                id_or_prefix,
                matches.len()
            ),
        },
    };
    // Strip the "refs/gitlawb/issues/" prefix to get the bare ID.
    let full_id = found
        .strip_prefix("refs/gitlawb/issues/")
        .unwrap_or(found)
        .to_string();
    Ok(Some(full_id))
}

/// Resolve an issue ID or 8-char prefix to the full UUID stored in git refs.
/// Returns Ok(Some(full_id)) on unique match, Ok(None) if not found,
/// Err if the prefix is ambiguous (matches more than one issue).
pub fn resolve_issue_id(repo_path: &Path, id_or_prefix: &str) -> Result<Option<String>> {
    let Some((exact_ref, prefix_glob)) = issue_lookup_refs(id_or_prefix) else {
        return Ok(None);
    };

    // allow-unbounded-git: this module's spawns predate the bounded runner;
    // under-lock callers use resolve_issue_id_bounded.
    let list = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)", &prefix_glob])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;

    // for-each-ref exits 0 with empty output when nothing matches, so a
    // nonzero exit is a real enumeration failure (e.g. not a repo), not
    // "issue not found".
    if !list.status.success() {
        let stderr = String::from_utf8_lossy(&list.stderr);
        anyhow::bail!("git for-each-ref failed: {}", stderr.trim());
    }

    resolve_issue_match(id_or_prefix, &exact_ref, &list.stdout, |m| {
        // allow-unbounded-git: same pre-lock path as above; under-lock callers
        // use resolve_issue_id_bounded.
        let check = Command::new("git")
            .args(["cat-file", "-e", m])
            .current_dir(repo_path)
            .output()
            .context("failed to run git cat-file -e")?;
        Ok(check.status.success())
    })
}

/// Deadline-bounded variant of [`resolve_issue_id`]: the same lookup and the
/// same exact-id-wins, dangling-exact-fallthrough and ambiguous-prefix rules,
/// but every git child runs through the shared bounded runner so a hung git
/// cannot outlive the lock-hold deadline it is called under.
pub fn resolve_issue_id_bounded(
    git_bin: &str,
    repo_path: &Path,
    id_or_prefix: &str,
    deadline: std::time::Instant,
) -> Result<Option<String>> {
    let Some((exact_ref, prefix_glob)) = issue_lookup_refs(id_or_prefix) else {
        return Ok(None);
    };

    let stdout = crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["for-each-ref", "--format=%(refname)", &prefix_glob],
        repo_path,
        b"",
        deadline,
    )?;

    resolve_issue_match(id_or_prefix, &exact_ref, &stdout, |m| {
        // The raw runner, not the bailing wrapper: the exact-existence check
        // classifies a nonzero exit as "dangling", not as a failure.
        let (status, _, _) = crate::git::visibility_pack::run_bounded_git_raw(
            git_bin,
            &["cat-file", "-e", m],
            repo_path,
            b"",
            deadline,
        )?;
        Ok(status.success())
    })
}

/// The status flip a close applies to an issue's stored JSON.
fn closed_issue_json(raw: &str) -> Result<String> {
    let mut issue: serde_json::Value =
        serde_json::from_str(raw).context("invalid issue JSON in git ref")?;
    issue["status"] = serde_json::Value::String("closed".to_string());
    serde_json::to_string(&issue).context("failed to serialize updated issue")
}

/// Close an issue by updating its status to "closed" in the git ref.
/// Returns the updated JSON, or None if the issue doesn't exist.
pub fn close_issue(repo_path: &Path, issue_id: &str) -> Result<Option<String>> {
    let full_id = match resolve_issue_id(repo_path, issue_id)? {
        Some(id) => id,
        None => return Ok(None),
    };

    // A ref that resolved and is now absent was deleted between the two calls;
    // any other read failure propagates as an error rather than panic (#426).
    let raw = match get_issue(repo_path, &full_id)? {
        Some(raw) => raw,
        None => return Ok(None),
    };

    let updated = closed_issue_json(&raw)?;
    create_issue(repo_path, &full_id, &updated)?;
    Ok(Some(updated))
}

/// Deadline-bounded variant of [`close_issue`], for the under-lock close path:
/// the same resolve, read and status flip, with every git child on the bounded
/// runner so a hung git cannot pin the lock-pool slot past the hold deadline.
pub fn close_issue_bounded(
    git_bin: &str,
    repo_path: &Path,
    issue_id: &str,
    deadline: std::time::Instant,
) -> Result<Option<String>> {
    let full_id = match resolve_issue_id_bounded(git_bin, repo_path, issue_id, deadline)? {
        Some(id) => id,
        None => return Ok(None),
    };

    let raw = match get_issue_bounded(git_bin, repo_path, &full_id, deadline)? {
        Some(raw) => raw,
        None => return Ok(None),
    };

    let updated = closed_issue_json(&raw)?;
    create_issue_bounded(git_bin, repo_path, &full_id, &updated, deadline)?;
    Ok(Some(updated))
}

/// Get a single issue by ID or 8-char prefix.
pub fn get_issue(repo_path: &Path, issue_id: &str) -> Result<Option<String>> {
    let full_id = match resolve_issue_id(repo_path, issue_id)? {
        Some(id) => id,
        None => return Ok(None),
    };

    let ref_name = format!("refs/gitlawb/issues/{full_id}");
    read_issue_blob(repo_path, &ref_name)
}

/// Deadline-bounded variant of [`get_issue`], for reads that run under the
/// write guard and must not outlive its lock-hold deadline.
pub fn get_issue_bounded(
    git_bin: &str,
    repo_path: &Path,
    issue_id: &str,
    deadline: std::time::Instant,
) -> Result<Option<String>> {
    let full_id = match resolve_issue_id_bounded(git_bin, repo_path, issue_id, deadline)? {
        Some(id) => id,
        None => return Ok(None),
    };

    let ref_name = format!("refs/gitlawb/issues/{full_id}");
    read_issue_blob_bounded(git_bin, repo_path, &ref_name, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn init_repo(dir: &TempDir) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .output()
            .unwrap();
    }

    #[test]
    fn test_resolve_exact_id_found() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"abc12345-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        let resolved = resolve_issue_id(dir.path(), full_id).unwrap();
        assert_eq!(resolved, Some(full_id.to_string()));
    }

    #[test]
    fn test_resolve_exact_id_wins_over_longer_id() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(dir.path(), "abc12345", r#"{"status":"open"}"#).unwrap();
        create_issue(dir.path(), "abc12345-0000", r#"{"status":"open"}"#).unwrap();
        let resolved = resolve_issue_id(dir.path(), "abc12345").unwrap();
        assert_eq!(resolved, Some("abc12345".to_string()));
    }

    #[test]
    fn test_resolve_dangling_exact_id_does_not_win_over_longer_id() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(dir.path(), "abc12345", r#"{"status":"open","n":1}"#).unwrap();
        create_issue(dir.path(), "abc12345-0000", r#"{"status":"open","n":2}"#).unwrap();
        // Dangle the exact ref: the ref stays listed by for-each-ref, but its blob is gone.
        let out = Command::new("git")
            .args(["rev-parse", "refs/gitlawb/issues/abc12345"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let hash = String::from_utf8(out.stdout).unwrap();
        let hash = hash.trim();
        std::fs::remove_file(
            dir.path()
                .join(".git/objects")
                .join(&hash[..2])
                .join(&hash[2..]),
        )
        .unwrap();

        let result = resolve_issue_id(dir.path(), "abc12345");
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
        assert!(close_issue(dir.path(), "abc12345").is_err());
    }

    #[test]
    fn test_resolve_prefix_matches_unique() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"abc12345-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        let resolved = resolve_issue_id(dir.path(), "abc12345").unwrap();
        assert_eq!(resolved, Some(full_id.to_string()));
    }

    #[test]
    fn test_resolve_rejects_revision_syntax() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"abc12345-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        // Each of these resolves to (or globs over) the issue blob in git, but none
        // is an issue id, so the lookup must not accept it.
        for crafted in [
            "abc12345-0000-0000-0000-000000000000^{blob}",
            "abc12345-0000-0000-0000-000000000000^{}",
            "abc12345-0000-0000-0000-000000000000~0",
            "*",
            "",
        ] {
            assert_eq!(
                resolve_issue_id(dir.path(), crafted).unwrap(),
                None,
                "{crafted:?}"
            );
            assert_eq!(get_issue(dir.path(), crafted).unwrap(), None, "{crafted:?}");
        }
    }

    #[test]
    fn test_resolve_prefix_not_found() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let resolved = resolve_issue_id(dir.path(), "deadbeef").unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolve_ambiguous_prefix_errors() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(
            dir.path(),
            "abc12345-aaaa-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        create_issue(
            dir.path(),
            "abc12345-bbbb-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        let result = resolve_issue_id(dir.path(), "abc12345");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }

    #[test]
    fn delete_issue_ref_removes_a_created_ref() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "eee88888-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"eee88888-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();
        delete_issue_ref(
            "git",
            dir.path(),
            full_id,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(resolve_issue_id(dir.path(), full_id).unwrap(), None);
    }

    #[test]
    fn test_close_issue_via_prefix() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "def99999-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"def99999-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();

        let updated = close_issue(dir.path(), "def99999").unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["status"], "closed");
    }

    /// Overwrite the loose object behind an issue ref with garbage, so
    /// `cat-file` fails while `rev-parse` still resolves the ref (#426).
    fn corrupt_issue_object(dir: &TempDir, full_id: &str) {
        let oid_out = Command::new("git")
            .args(["rev-parse", &format!("refs/gitlawb/issues/{full_id}")])
            .current_dir(dir.path())
            .output()
            .unwrap();
        let oid = String::from_utf8(oid_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        let obj = dir
            .path()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..]);
        std::fs::remove_file(&obj).unwrap();
        std::fs::write(&obj, b"garbage").unwrap();
    }

    #[test]
    fn test_get_and_close_missing_issue_return_none() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        assert_eq!(get_issue(dir.path(), "nosuch00").unwrap(), None);
        assert_eq!(close_issue(dir.path(), "nosuch00").unwrap(), None);
    }

    // #426: a directory that is not a repo makes `cat-file --batch` exit
    // nonzero; that failure is an error, not a quiet None.
    #[test]
    fn test_issue_read_on_non_repo_errors_instead_of_none() {
        let dir = TempDir::new().unwrap();
        let not_a_repo = dir.path().join("not-a-repo");
        std::fs::create_dir_all(&not_a_repo).unwrap();
        assert!(read_issue_blob(&not_a_repo, "refs/gitlawb/issues/deadbeef").is_err());
    }

    // #426: the ref name is constrained to the issues namespace and a safe
    // charset before it is fed to git, even on stdin (a newline would smuggle
    // a second `--batch` spec).
    #[test]
    fn test_issue_read_rejects_ref_outside_issues_namespace() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        assert!(read_issue_blob(dir.path(), "refs/heads/main").is_err());
        assert!(read_issue_blob(dir.path(), "refs/gitlawb/issues/../x").is_err());
    }

    // #426: a failed for-each-ref enumeration is an error, not an empty list.
    #[test]
    fn test_list_issues_on_non_repo_errors_instead_of_empty() {
        let dir = TempDir::new().unwrap();
        let not_a_repo = dir.path().join("not-a-repo");
        std::fs::create_dir_all(&not_a_repo).unwrap();
        assert!(list_issues(&not_a_repo).is_err());
    }

    // #426: the same enumeration failure inside resolve_issue_id must reach
    // get_issue/close_issue as an error, not a "not found" None.
    #[test]
    fn test_get_and_close_on_non_repo_error_instead_of_none() {
        let dir = TempDir::new().unwrap();
        let not_a_repo = dir.path().join("not-a-repo");
        std::fs::create_dir_all(&not_a_repo).unwrap();
        assert!(get_issue(&not_a_repo, "nosuch00").is_err());
        assert!(close_issue(&not_a_repo, "nosuch00").is_err());
    }

    // #426: a ref that resolves but whose object is corrupt is a read error,
    // not an absent issue. `close_issue` used to `expect()` on that None and
    // panic inside a request handler holding the write guard.
    #[test]
    fn test_corrupt_issue_object_errors_instead_of_panicking() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "bad00000-0000-0000-0000-000000000000";
        create_issue(dir.path(), full_id, r#"{"status":"open"}"#).unwrap();
        corrupt_issue_object(&dir, full_id);

        assert!(get_issue(dir.path(), full_id).is_err());
        assert!(close_issue(dir.path(), full_id).is_err());
        assert!(list_issues(dir.path()).is_err());
    }

    fn bounded_deadline() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(30)
    }

    #[test]
    fn test_bounded_resolve_exact_id_wins_over_longer_id() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(dir.path(), "abc12345", r#"{"status":"open"}"#).unwrap();
        create_issue(dir.path(), "abc12345-0000", r#"{"status":"open"}"#).unwrap();
        let resolved =
            resolve_issue_id_bounded("git", dir.path(), "abc12345", bounded_deadline()).unwrap();
        assert_eq!(resolved, Some("abc12345".to_string()));
    }

    #[test]
    fn test_bounded_resolve_prefix_matches_unique() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(dir.path(), full_id, r#"{"status":"open"}"#).unwrap();
        let resolved =
            resolve_issue_id_bounded("git", dir.path(), "abc12345", bounded_deadline()).unwrap();
        assert_eq!(resolved, Some(full_id.to_string()));
    }

    #[test]
    fn test_bounded_resolve_ambiguous_prefix_errors() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(
            dir.path(),
            "abc12345-aaaa-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        create_issue(
            dir.path(),
            "abc12345-bbbb-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        let err = resolve_issue_id_bounded("git", dir.path(), "abc12345", bounded_deadline())
            .unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn test_bounded_resolve_rejects_revision_syntax() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "abc12345-0000-0000-0000-000000000000";
        create_issue(dir.path(), full_id, r#"{"status":"open"}"#).unwrap();
        // The bounded lookup applies the same id validation: none of these may
        // reach git as a revision or a glob.
        for crafted in [
            "abc12345-0000-0000-0000-000000000000^{blob}",
            "abc12345-0000-0000-0000-000000000000~0",
            "*",
            "",
            "..",
        ] {
            assert_eq!(
                resolve_issue_id_bounded("git", dir.path(), crafted, bounded_deadline()).unwrap(),
                None,
                "{crafted:?}"
            );
            assert_eq!(
                get_issue_bounded("git", dir.path(), crafted, bounded_deadline()).unwrap(),
                None,
                "{crafted:?}"
            );
        }
    }

    #[test]
    fn test_bounded_get_and_close_missing_issue_return_none() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        assert_eq!(
            get_issue_bounded("git", dir.path(), "nosuch00", bounded_deadline()).unwrap(),
            None
        );
        assert_eq!(
            close_issue_bounded("git", dir.path(), "nosuch00", bounded_deadline()).unwrap(),
            None
        );
    }

    #[test]
    fn test_bounded_close_issue_via_prefix() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        let full_id = "def99999-0000-0000-0000-000000000000";
        create_issue(
            dir.path(),
            full_id,
            r#"{"id":"def99999-0000-0000-0000-000000000000","status":"open"}"#,
        )
        .unwrap();

        let updated = close_issue_bounded("git", dir.path(), "def99999", bounded_deadline())
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&updated).unwrap();
        assert_eq!(v["status"], "closed");
    }

    // A deadline already spent must not let a git child run out its own clock:
    // the watchdog kills it immediately and the call surfaces GitServiceTimeout
    // rather than hanging for the shim's full sleep.
    #[test]
    fn test_bounded_calls_abort_an_expired_deadline() {
        use crate::test_support::git_shim;

        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(dir.path(), "abc12345", r#"{"status":"open"}"#).unwrap();
        let shim = git_shim::create("gl-issues-expired-git", git_shim::Behavior::Hang);
        let spent = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap_or_else(std::time::Instant::now);
        let git_bin = shim.to_str().unwrap().to_string();

        let started = std::time::Instant::now();
        let err = resolve_issue_id_bounded(&git_bin, dir.path(), "abc12345", spent)
            .expect_err("a spent deadline must fail the lookup");
        assert!(
            err.downcast_ref::<crate::git::smart_http::GitServiceTimeout>()
                .is_some(),
            "the killed child must surface as GitServiceTimeout, got: {err:#}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "an expired deadline must abort at once, not after the shim's 30s hang"
        );
    }

    #[test]
    fn test_list_issues_returns_all() {
        let dir = TempDir::new().unwrap();
        init_repo(&dir);
        create_issue(
            dir.path(),
            "aaa00000-0000-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        create_issue(
            dir.path(),
            "bbb00000-0000-0000-0000-000000000000",
            r#"{"status":"open"}"#,
        )
        .unwrap();
        assert_eq!(list_issues(dir.path()).unwrap().len(), 2);
    }
}
