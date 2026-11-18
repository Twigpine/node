//! `twigpine doctor` — check your Twigpine installation and connectivity.
//!
//! Checks:
//!   1. Identity        — ~/.twigpine/identity.pem exists, DID parseable
//!   2. Registration    — ~/.twigpine/ucan.json exists (registered with a node)
//!   3. TWIGPINE_NODE    — env var points at a public node (unset is advisory)
//!   4. Node            — TWIGPINE_NODE is reachable (default: https://node.twigpine.com)
//!   5. git helper      — git-remote-gitlawb (the name git runs) is in PATH
//!   6. git             — git is installed
//!   7. version         — twigpine is up to date with latest GitHub release

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use twigpine_core::resolve_transport_node;
use twigpine_core::transport_policy;

use crate::http::{sanitize_node_msg, NodeClient};

const PUBLIC_NODE: &str = "https://node.twigpine.com";
const GITHUB_API_BASE: &str = "https://api.github.com";

#[derive(Args)]
pub struct DoctorArgs {
    /// Node URL to check connectivity against
    #[arg(long, default_value = PUBLIC_NODE, env = "TWIGPINE_NODE")]
    pub node: String,

    /// Identity directory (default: the parent of $TWIGPINE_KEY, else ~/.twigpine)
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

struct Check {
    label: &'static str,
    state: CheckState,
    detail: String,
    fix: Option<String>,
}

enum CheckState {
    Ok,
    Warn,
    Fail,
}

impl Check {
    fn pass(label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Ok,
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn fail(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// Resolve the config dir and key path without aborting on a refused resolver.
/// The whole point of doctor is to explain a broken setup, so a `TWIGPINE_KEY`
/// or `--dir` the resolvers reject becomes `Check::fail` rows for the checks
/// that depend on them, while node/git checks still run.
fn resolve_config_paths(
    args_dir: Option<PathBuf>,
) -> (Option<PathBuf>, Option<PathBuf>, Vec<Check>) {
    let dir = crate::identity::identity_dir(args_dir.clone());
    let mut checks = Vec::new();
    let dir = match dir {
        Ok(d) => Some(d),
        Err(e) => {
            checks.push(Check::fail(
                "identity",
                format!("could not resolve config dir: {e}"),
                "fix TWIGPINE_KEY or --dir",
            ));
            checks.push(Check::fail(
                "registration",
                "skipped: config dir unresolved",
                "fix TWIGPINE_KEY or --dir",
            ));
            None
        }
    };
    let pem_path = match crate::identity::key_path_for(args_dir.as_deref()) {
        Ok(p) => Some(p),
        Err(e) => {
            if dir.is_some() {
                checks.push(Check::fail(
                    "identity",
                    format!("could not resolve key path: {e}"),
                    "fix TWIGPINE_KEY or --dir",
                ));
            }
            None
        }
    };
    (dir, pem_path, checks)
}

pub async fn run(args: DoctorArgs) -> Result<()> {
    println!("twigpine doctor — checking your Twigpine setup");
    println!();

    // The same resolver every other command uses. `doctor` reporting on
    // `~/.twigpine` while `twigpine register` writes to the parent of `TWIGPINE_KEY` would
    // make the one command whose job is to explain a broken setup the one that
    // misreports it.
    let args_dir = args.dir.clone();
    let (dir, pem_path, resolver_rows) = resolve_config_paths(args_dir.clone());
    let mut checks = resolver_rows;

    // ── 1. Identity ───────────────────────────────────────────────────────
    if pem_path.as_ref().is_some_and(|p| p.exists()) {
        let pem_path = pem_path.as_ref().unwrap();
        match std::fs::read_to_string(pem_path)
            .ok()
            .and_then(|pem| twigpine_core::identity::Keypair::from_pem(&pem).ok())
        {
            Some(kp) => {
                let did = kp.did().to_string();
                let short = did.chars().take(40).collect::<String>();
                checks.push(Check::pass("identity", format!("{short}…")));
            }
            None => {
                checks.push(Check::fail(
                    "identity",
                    format!("exists at {} but could not be parsed", pem_path.display()),
                    "twigpine identity new --force",
                ));
            }
        }
    } else if let Some(pem_path) = &pem_path {
        let home = dirs::home_dir();
        match twigpine_core::identity_path::stranded_legacy_key(pem_path, home.as_deref()) {
            // The key is in the folder from before the rename. "identity new"
            // would be the wrong advice: it means a second identity.
            Some(legacy) => checks.push(Check::fail(
                "identity",
                format!(
                    "not found at {}, but there is one at {}",
                    pem_path.display(),
                    legacy.display()
                ),
                twigpine_core::identity_path::stranded_legacy_key_message(pem_path, &legacy),
            )),
            None => checks.push(Check::fail(
                "identity",
                format!("not found at {}", pem_path.display()),
                "twigpine identity new",
            )),
        }
    }

    // ── 2. Registration ───────────────────────────────────────────────────
    if let Some(dir) = &dir {
        let ucan_path = dir.join("ucan.json");
        if ucan_path.exists() {
            match std::fs::read_to_string(&ucan_path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            {
                Some(v) => {
                    let node = v["node"].as_str().unwrap_or("unknown");
                    checks.push(Check::pass(
                        "registration",
                        format!("registered with {node}"),
                    ));
                }
                None => {
                    checks.push(Check::fail(
                        "registration",
                        "ucan.json exists but is malformed",
                        "twigpine register",
                    ));
                }
            }
        } else {
            checks.push(Check::fail(
                "registration",
                "not registered with any node",
                "twigpine register",
            ));
        }
    }

    // ── 3. TWIGPINE_NODE env var ───────────────────────────────────────────
    // The node `git clone` / `git push` will contact is not always the node `twigpine`
    // contacts: `--node` defaults to the public node and an explicit flag outranks
    // the environment, so the two diverge whenever the variable is unset, blank, or
    // overridden. Probing only `twigpine`'s node is what let doctor greenlight an install
    // whose transport was dead, so resolve the transport's node through the same
    // function the helper uses and report on that one.
    let env_node = std::env::var("TWIGPINE_NODE").ok();
    let transport_node = resolve_transport_node(env_node.as_deref());
    let gl_node = sanitize_node_msg(&args.node);

    // clap binds `args.node` from the environment verbatim, while the resolver
    // trims, so compare against the trimmed value or padding alone reads as a split.
    if transport_node == args.node.trim() {
        // twigpine and the transport agree, so one row covers both. Classify the row from
        // the variable itself: `--node` matching the transport default does not mean
        // the user set `TWIGPINE_NODE`.
        let env_val = env_node
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(sanitize_node_msg);
        checks.push(gitlawb_node_env_check(env_val.as_deref()));
    } else {
        let verdict = probe_transport(&transport_node).await;
        let detail = format!(
            "git push/clone will use {} ({}); twigpine targets {gl_node}",
            sanitize_node_msg(&transport_node),
            verdict.detail
        );
        // The remedy is shell input, so it is built from the canonical value and
        // quoted for the shell. The display string above is capped and stripped for
        // the terminal, which is a different encoding and must not be reused here.
        let fix = format!(
            "export TWIGPINE_NODE={}",
            shell_single_quote(&recovery_target(&args.node))
        );
        // Tiering follows who chose the broken value. An unset variable on a stock
        // install is advisory: `twigpine` works, only `git push`/`git clone` do not, and
        // #357 requires that install to keep exiting 0. A variable the user set to
        // something unusable is a real misconfiguration.
        let env_was_set = env_node
            .as_deref()
            .map(str::trim)
            .is_some_and(|v| !v.is_empty());
        if verdict.usable || !env_was_set {
            checks.push(Check::warn("TWIGPINE_NODE", detail, fix));
        } else {
            checks.push(Check::fail("TWIGPINE_NODE", detail, fix));
        }
    }

    // ── 4. Node connectivity ──────────────────────────────────────────────
    // TWIGPINE_NODE="" binds args.node to "" through clap, and check 3 groups
    // empty with unset. The probe must apply the same normalization or it
    // would dial "" and Fail while the env row only Warns.
    let node_url = effective_node_url(&args.node);
    let client = NodeClient::new(node_url, None);
    match client.get("/").await {
        Ok(resp) if resp.status().is_success() => {
            let info = resp.json::<serde_json::Value>().await.unwrap_or_default();
            let version = info["version"].as_str().unwrap_or("?");
            let did = info["did"].as_str().unwrap_or("?");
            let short_did = did.chars().take(30).collect::<String>();
            checks.push(Check::pass(
                "node",
                format!("{} — v{version} ({short_did}…)", node_url),
            ));
            // Capability drift: a node newer than this CLI may require features
            // (RFC 9421 signing, iCaptcha) the CLI doesn't speak.
            let gl_ver = env!("CARGO_PKG_VERSION");
            if version != "?" && is_newer(version, gl_ver) {
                checks.push(Check::warn(
                    "twigpine version",
                    format!(
                        "node is v{version} but twigpine is v{gl_ver} — your CLI may be missing \
                         features (signing / iCaptcha) this node requires"
                    ),
                    "upgrade twigpine: curl -fsSL https://twigpine.com/install.sh | sh",
                ));
            }
        }
        Ok(resp) => {
            checks.push(Check::fail(
                "node",
                format!("{} returned HTTP {}", node_url, resp.status()),
                "check TWIGPINE_NODE env var or try twigpine register --node <url>",
            ));
        }
        Err(e) => {
            checks.push(Check::fail(
                "node",
                format!("{} unreachable: {e}", node_url),
                "check your internet connection or set TWIGPINE_NODE",
            ));
        }
    }

    // ── 4b. iCaptcha capability ───────────────────────────────────────────
    // Gated writes (repo create / register / fork) auto-solve a challenge at the
    // iCaptcha service; check it's reachable so the failure mode is obvious.
    let icaptcha_url = std::env::var("TWIGPINE_ICAPTCHA_URL")
        .unwrap_or_else(|_| icaptcha_client::DEFAULT_URL.to_string());
    match NodeClient::new(&icaptcha_url, None).get("/v1/pubkey").await {
        Ok(resp) if resp.status().is_success() => {
            checks.push(Check::pass("iCaptcha", format!("{icaptcha_url} reachable")));
        }
        Ok(resp) => {
            checks.push(Check::warn(
                "iCaptcha",
                format!("{icaptcha_url} returned HTTP {}", resp.status()),
                "gated writes (repo create / register) may fail until iCaptcha is reachable",
            ));
        }
        Err(e) => {
            checks.push(Check::warn(
                "iCaptcha",
                format!("{icaptcha_url} unreachable: {e}"),
                "set TWIGPINE_ICAPTCHA_URL or check connectivity — repo create / register solve a challenge there",
            ));
        }
    }

    // ── 5. git-remote-twigpine helper ──────────────────────────────────────
    // Use PATH lookup only — invoking the binary directly triggers git internals
    // that error with "fatal: not a git repository" outside of a git repo.
    // Git picks its helper by URL scheme, so a `gitlawb://` remote runs the helper
    // under the scheme's name. It is the same program as git-remote-twigpine;
    // probing this name is what tells us clone and push will work.
    if which_in_path("git-remote-gitlawb") {
        checks.push(Check::pass("git-remote-gitlawb", "found in PATH"));
    } else {
        checks.push(Check::fail(
            "git-remote-gitlawb",
            "not found in PATH — gitlawb:// clone/push will not work",
            "curl -fsSL https://twigpine.com/install.sh | sh",
        ));
    }

    // ── 6. git ────────────────────────────────────────────────────────────
    match std::process::Command::new("git")
        .arg("--version")
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => {
            let ver = String::from_utf8_lossy(&o.stdout);
            checks.push(Check::pass("git", ver.trim().to_string()));
        }
        _ => {
            checks.push(Check::fail(
                "git",
                "git not found in PATH",
                "install git: https://git-scm.com",
            ));
        }
    }

    // ── 7. Version up to date ─────────────────────────────────────────────
    let current = env!("CARGO_PKG_VERSION");
    // Production uses the real endpoint; the override exists so the subprocess tests
    // can route the release lookup to a local fixture instead of the public API.
    let github_api = std::env::var("TWIGPINE_GITHUB_API_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| GITHUB_API_BASE.to_string());
    checks.push(check_version(current, &github_api).await);

    // Settings still given under their names from before the rename. They
    // work; this row only appears when there is something to update.
    if let Some(check) = legacy_settings_check(&twigpine_core::legacy_env::report()) {
        checks.push(check);
    }

    // ── Render ────────────────────────────────────────────────────────────
    for check in &checks {
        let icon = match check.state {
            CheckState::Ok => "✓",
            CheckState::Warn => "⚠",
            CheckState::Fail => "✗",
        };
        println!("  {icon}  {:<24}  {}", check.label, check.detail);
    }

    println!();

    let has_failures_now = has_failures(&checks);
    let has_issues = checks
        .iter()
        .any(|c| matches!(c.state, CheckState::Fail | CheckState::Warn));
    if !has_issues {
        println!("Everything looks good. Run `twigpine quickstart` to create your first repo.");
    } else {
        if has_failures_now {
            println!("Some checks failed. Suggested fixes:");
        } else {
            println!("Setup looks good with some warnings:");
        }
        for check in &checks {
            if matches!(check.state, CheckState::Fail | CheckState::Warn) {
                if let Some(fix) = &check.fix {
                    println!("  {}:  {fix}", check.label);
                }
            }
        }
        println!();
        if has_failures_now {
            println!("Run `twigpine quickstart` for a guided setup.");
        }
    }

    // #357: a non-zero exit is the only signal scripting and CI have. Warn-only
    // rows stay exit 0 (iCaptcha offline, version drift are both
    // non-fatal); Fail-class rows (identity, registration, node
    // reachable, git-remote-twigpine present, git present) flip to exit 1.
    // Direct `process::exit` rather than returning Err: the prose above is the
    // user-facing summary, and an anyhow Error frame would just duplicate it.
    if has_failures(&checks) {
        std::process::exit(1);
    }

    Ok(())
}

/// Outcome of probing the node the git transport will use.
struct TransportVerdict {
    /// True only when the endpoint identified itself as a gitlawb node. A bare 200
    /// is not enough: any local service answering on that port would otherwise be
    /// reported as a working transport, which is the false green this check exists
    /// to catch.
    usable: bool,
    detail: String,
}

/// Cap on the root document the probe reads. A gitlawb node's `/` is a few hundred
/// bytes of identity; anything near this size is not one.
const PROBE_BODY_CAP: usize = 16 * 1024;

/// Quote `s` as one POSIX shell word. Single quotes are the only construct that
/// needs care inside single quotes: close, emit an escaped quote, reopen.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The value the remedy tells the user to export, taken from the normalized node
/// (blank means the public node, as for the connectivity probe) and not truncated.
/// A value carrying terminal control characters is not something to hand back for
/// pasting, so the public node stands in for it.
fn recovery_target(node: &str) -> String {
    let target = effective_node_url(node).trim();
    if twigpine_core::sanitize::strip_terminal_controls(target) == target {
        target.to_string()
    } else {
        PUBLIC_NODE.to_string()
    }
}

/// Probe `url` and describe what is actually there.
///
/// This models the git helper, so it takes the helper's transport policy: a
/// plaintext http node off this machine is refused without a request unless
/// `TWIGPINE_ALLOW_INSECURE_HTTP` opts in; a loopback http node is dialed directly,
/// never through a proxy; every other node uses reqwest's default environment proxy
/// discovery, as the helper does; redirects follow the shared same-origin decision
/// and chain bound; and the identity must parse as a DID, which the helper requires
/// before it builds a delegation. It is deliberately not `NodeClient`, because it
/// must not inherit the 30s request timeout, which stalls every stock `twigpine doctor`
/// run behind a hung listener, and it sends no credentials.
async fn probe_transport(url: &str) -> TransportVerdict {
    let allow_insecure = std::env::var("TWIGPINE_ALLOW_INSECURE_HTTP")
        .is_ok_and(|v| transport_policy::allow_insecure_http_value(&v));
    if !allow_insecure && transport_policy::is_insecure_remote(url) {
        return TransportVerdict {
            usable: false,
            detail: "refused: plaintext http to a remote node (use https://, or set \
                     TWIGPINE_ALLOW_INSECURE_HTTP=1 for a trusted private network)"
                .to_string(),
        };
    }
    let builder = reqwest::Client::builder();
    // The helper's own condition: a loopback http node is never proxied.
    let builder = if transport_policy::is_http(url) && !transport_policy::is_insecure_remote(url) {
        builder.no_proxy()
    } else {
        builder
    };
    let client = match builder
        .redirect(reqwest::redirect::Policy::custom(
            crate::http::same_origin_redirect,
        ))
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return TransportVerdict {
                usable: false,
                detail: format!("probe failed: {}", sanitize_node_msg(&e.to_string())),
            }
        }
    };
    // Request the configured base verbatim, as the helper's identity lookup does:
    // a reverse-proxied `https://host/mount` serves identity at exactly `/mount`,
    // and reqwest supplies the `/` for an origin-only URL.
    match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = crate::http::read_body_capped_bytes(resp, PROBE_BODY_CAP).await;
            if body.truncated || body.read_failed {
                return TransportVerdict {
                    usable: false,
                    detail: "response too large or incomplete for a gitlawb node".to_string(),
                };
            }
            let info = serde_json::from_slice::<serde_json::Value>(&body.bytes).unwrap_or_default();
            if info["did"]
                .as_str()
                .is_some_and(|d| d.parse::<twigpine_core::did::Did>().is_ok())
            {
                TransportVerdict {
                    usable: true,
                    detail: "reachable".to_string(),
                }
            } else {
                TransportVerdict {
                    usable: false,
                    detail: "something is listening but it is not a gitlawb node".to_string(),
                }
            }
        }
        Ok(resp) => TransportVerdict {
            usable: false,
            detail: format!("returned HTTP {}", resp.status()),
        },
        Err(e) => TransportVerdict {
            usable: false,
            detail: format!("unreachable: {}", sanitize_node_msg(&e.to_string())),
        },
    }
}

/// Classify the `TWIGPINE_NODE` env var for `twigpine doctor`. Extracted so unit
/// tests can pin the Warn tier directly (#357): an unset env is advisory, not
/// a failure, because `--node` defaults to `https://node.twigpine.com` and the
/// CLI works without it. Flipping this back to `Check::fail` must break a
/// test, not just change prose.
fn gitlawb_node_env_check(env_val: Option<&str>) -> Check {
    match env_val {
        // A loopback host is a legitimate setup (self-hosted node, dev
        // harness) — the connectivity check below fails loudly if it is not
        // actually reachable, so don't red-flag the configuration itself.
        Some(v) if is_loopback_url(v) => Check::pass(
            "TWIGPINE_NODE",
            format!(
                "{v} (local node — intentional for self-hosting/dev; unset to target the public network)"
            ),
        ),
        Some(v) if !v.is_empty() => Check::pass("TWIGPINE_NODE", v.to_string()),
        // `--node` defaults to `https://node.twigpine.com` and the CLI works
        // fine without the variable, so an unset env is advisory, not a
        // failure. Warn-class keeps the exit code 0 for a stock working
        // install; this used to be Fail, which the obvious "return non-zero
        // on any failure" change would have flipped to exit 1 on every
        // default-config install (#357).
        _ => Check::warn(
            "TWIGPINE_NODE",
            "not set — git-remote-twigpine will fall back to http://127.0.0.1:7545",
            format!("export TWIGPINE_NODE={PUBLIC_NODE}"),
        ),
    }
}

/// The URL the connectivity probe should dial. `TWIGPINE_NODE` set but empty
/// (or whitespace-only) binds `args.node` to `""` through clap rather than
/// to the `default_value`, and check 3 already groups empty with unset, so
/// the probe applies the same normalization: an empty effective URL means
/// the public node, same as unset.
fn effective_node_url(node: &str) -> &str {
    if node.trim().is_empty() {
        PUBLIC_NODE
    } else {
        node.trim()
    }
}

/// True when at least one check is Fail-class. Warn-only runs (iCaptcha offline,
/// version drift, TWIGPINE_NODE unset) keep exit 0;
/// this is the gating predicate for #357's exit-status fix.
fn has_failures(checks: &[Check]) -> bool {
    checks.iter().any(|c| matches!(c.state, CheckState::Fail))
}

/// True when the URL's host is exactly a loopback address. Substring checks
/// misclassify hosts like `localhost.example` or URLs with "localhost" in the
/// path, so parse and compare the actual host.
fn is_loopback_url(value: &str) -> bool {
    reqwest::Url::parse(value)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1")
        })
        .unwrap_or(false)
}

/// Check if a binary name exists anywhere on PATH.
fn which_in_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                dir.join(name).exists()
                    || (cfg!(target_os = "windows") && dir.join(format!("{name}.exe")).exists())
            })
        })
        .unwrap_or(false)
}

/// Fetch the latest release tag from Twigpine/node (the actual release repo — see install.sh's
/// `TWIGPINE_RELEASE_REPO` default) and compare to current version.
/// A warn row naming settings given under their old `GITLAWB_` names, or
/// under both names with different values. `None` when there are none.
fn legacy_settings_check(report: &twigpine_core::legacy_env::Report) -> Option<Check> {
    if report.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    if !report.legacy_only.is_empty() {
        parts.push(format!(
            "set under the old GITLAWB_ name (still works): {}",
            report.legacy_only.join(", ")
        ));
    }
    if !report.conflicts.is_empty() {
        parts.push(format!(
            "set under both names with different values (TWIGPINE_ wins): {}",
            report.conflicts.join(", ")
        ));
    }
    Some(Check::warn(
        "settings",
        parts.join("; "),
        "rename GITLAWB_* to TWIGPINE_* in your shell profile or service unit",
    ))
}

async fn check_version(current: &'static str, github_api_base: &str) -> Check {
    let client = match reqwest::Client::builder()
        .user_agent(format!("gl/{current}"))
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Check::pass("version", format!("v{current} (could not check)")),
    };

    let resp = match client
        .get(format!(
            "{github_api_base}/repos/Twigpine/node/releases/latest"
        ))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Check::pass("version", format!("v{current} (offline — could not check)")),
    };

    if !resp.status().is_success() {
        return Check::pass(
            "version",
            format!("v{current} (GitHub API returned HTTP {})", resp.status()),
        );
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Check::pass("version", format!("v{current} (invalid response)")),
    };

    let tag = match body["tag_name"].as_str() {
        Some(t) => t.trim_start_matches('v'),
        None => {
            return Check::pass(
                "version",
                format!("v{current} (could not parse latest tag)"),
            )
        }
    };

    if is_newer(tag, current) {
        Check::warn(
            "version",
            format!("v{current} → v{} available", sanitize_node_msg(tag)),
            "curl -fsSL https://twigpine.com/install.sh | sh",
        )
    } else {
        Check::pass("version", format!("v{current} (up to date)"))
    }
}

/// Returns true if `latest` is strictly newer than `current` (simple semver comparison).
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> (u32, u32, u32) {
        let mut parts = v.splitn(3, '.').map(|p| p.parse::<u32>().unwrap_or(0));
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    }
    parse(latest) > parse(current)
}

#[cfg(test)]
mod tests {
    /// The quoted word must reach a real shell as exactly one value and run nothing
    /// else, for the inputs that break naive single-quoting.
    #[cfg(unix)]
    #[test]
    fn shell_single_quote_round_trips_through_sh() {
        let marker = std::env::temp_dir().join(format!("gl-doctor-quote-{}", std::process::id()));
        let cases = [
            "plain".to_string(),
            "it's".to_string(),
            "x'; touch MARK; #'".to_string(),
            "has space and $HOME `id` $(id) ;|&".to_string(),
            "'".to_string(),
            "https://example.com/".to_string() + &"a".repeat(500),
        ];
        for value in cases {
            let value = value.replace("MARK", marker.to_str().unwrap());
            let script = format!("X={}; printf %s \"$X\"", shell_single_quote(&value));
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                value,
                "round trip failed for {value:?}"
            );
            assert!(!marker.exists(), "quoting let a command run for {value:?}");
        }
    }

    #[test]
    fn recovery_target_uses_normalized_state_and_keeps_the_full_value() {
        assert_eq!(recovery_target(""), PUBLIC_NODE);
        assert_eq!(recovery_target("   "), PUBLIC_NODE);
        assert_eq!(recovery_target("  http://h:1  "), "http://h:1");
        // Control characters are rejected, not stripped into a different value.
        assert_eq!(recovery_target("http://h:1/\u{1b}[31m"), PUBLIC_NODE);
        assert_eq!(recovery_target("http://h:1/\u{202e}"), PUBLIC_NODE);
        // Longer than the 200 character display cap, still whole.
        let long = format!("http://h:1/{}", "a".repeat(300));
        assert_eq!(recovery_target(&long), long);
    }

    use super::*;

    #[test]
    fn loopback_url_detection_is_host_exact() {
        assert!(is_loopback_url("http://127.0.0.1:7545"));
        assert!(is_loopback_url("http://localhost:7545"));
        assert!(is_loopback_url("http://[::1]:7545"));
        assert!(!is_loopback_url("https://localhost.example"));
        assert!(!is_loopback_url("https://node.twigpine.com/localhost"));
        assert!(!is_loopback_url("not a url"));
    }

    #[test]
    fn refused_resolver_becomes_check_rows_not_abort() {
        // A relative TWIGPINE_KEY makes both resolvers Err; doctor must turn
        // that into fail rows for the dependent checks and keep going, not
        // exit before the node/git checks ever run.
        crate::identity::test_env::with_key(Some("relative/path"), || {
            let (dir, pem_path, rows) = resolve_config_paths(None);
            assert!(dir.is_none() && pem_path.is_none());
            let fails: Vec<_> = rows
                .iter()
                .filter(|c| matches!(c.state, CheckState::Fail))
                .map(|c| c.label)
                .collect();
            assert!(fails.contains(&"identity"), "rows: {fails:?}");
            assert!(fails.contains(&"registration"), "rows: {fails:?}");
        });
    }

    #[test]
    fn test_is_newer_minor_bump() {
        assert!(is_newer("0.2.0", "0.1.0"));
    }

    #[test]
    fn test_is_newer_patch_bump() {
        assert!(is_newer("0.1.1", "0.1.0"));
    }

    #[test]
    fn test_is_newer_major_bump() {
        assert!(is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_is_newer_same_version() {
        assert!(!is_newer("0.1.0", "0.1.0"));
    }

    #[test]
    fn test_is_newer_older_version() {
        assert!(!is_newer("0.1.0", "0.2.0"));
    }

    #[test]
    fn test_which_in_path_git_present() {
        // git should be installed on any dev machine
        assert!(which_in_path("git"));
    }

    #[test]
    fn test_which_in_path_missing_binary() {
        assert!(!which_in_path("this-binary-does-not-exist-gl-test-12345"));
    }

    #[tokio::test]
    async fn test_check_version_queries_node_releases() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Twigpine/node/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tag_name":"v9.9.9"}"#)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Warn));
        assert!(check.detail.contains("v9.9.9"));
    }

    #[tokio::test]
    async fn test_check_version_up_to_date() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Twigpine/node/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tag_name":"v0.1.0"}"#)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Ok));
        assert!(check.detail.contains("up to date"));
    }

    #[tokio::test]
    async fn test_check_version_http_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Twigpine/node/releases/latest")
            .with_status(403)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Ok));
        assert!(check.detail.contains("GitHub API returned HTTP 403"));
    }

    /// #357: an all-Ok run does not flip the exit code to non-zero — a healthy
    /// install must keep returning 0 so scripts like `twigpine doctor && twigpine push`
    /// keep working.
    #[test]
    fn exit_predicate_is_false_for_all_ok() {
        let checks = vec![
            Check::pass("identity", "ok"),
            Check::pass("registration", "ok"),
            Check::pass("git", "ok"),
        ];
        assert!(!has_failures(&checks));
    }

    /// #357: Warn-class rows (iCaptcha offline, version drift,
    /// TWIGPINE_NODE unset on a default-config install) are NOT
    /// exit-status failures — they are still printed to the user but the
    /// process exits 0. This is the rule that the previous "any
    /// Fail-or-Warn row → exit 1" change would have broken for stock
    /// installs that simply have not set the env var.
    #[test]
    fn exit_predicate_is_false_for_warn_only() {
        let checks = vec![
            Check::pass("identity", "ok"),
            Check::warn("TWIGPINE_NODE", "unset", "export TWIGPINE_NODE=..."),
            Check::warn("iCaptcha", "offline", "check connectivity"),
            Check::warn("version", "drift", "upgrade"),
        ];
        assert!(!has_failures(&checks));
    }

    /// #357: a single Fail-class row trips the exit code. The set of Fail
    /// rows is whatever `run` writes through `Check::fail`: identity missing
    /// or unparseable, registration missing/malformed, node unreachable,
    /// git-remote-twigpine absent, git absent.
    #[test]
    fn exit_predicate_is_true_when_a_fail_row_is_present() {
        let checks = vec![
            Check::pass("registration", "ok"),
            Check::fail("identity", "missing", "twigpine identity new"),
            Check::pass("git", "ok"),
        ];
        assert!(has_failures(&checks));

        let mixed_warns = vec![
            Check::pass("identity", "ok"),
            Check::warn("TWIGPINE_NODE", "unset", "export"),
            Check::fail("node", "unreachable", "check network"),
            Check::warn("iCaptcha", "offline", "check"),
        ];
        assert!(has_failures(&mixed_warns));
    }

    /// #357: `TWIGPINE_NODE` unset must be Warn, not Fail. This pins the
    /// re-tier so flipping it back to `Check::fail` breaks the suite — the
    /// previous `has_failures`-only tests built their own `Check::warn` rows
    /// and could not see the re-tier at all.
    #[test]
    fn legacy_settings_row_appears_only_when_an_old_name_is_in_use() {
        use twigpine_core::legacy_env::Report;
        assert!(legacy_settings_check(&Report::default()).is_none());

        let check = legacy_settings_check(&Report {
            legacy_only: vec!["TWIGPINE_NODE".into()],
            conflicts: vec!["TWIGPINE_KEY".into()],
        })
        .expect("a row");
        assert!(matches!(check.state, CheckState::Warn));
        assert!(check.detail.contains("TWIGPINE_NODE"), "{}", check.detail);
        assert!(check.detail.contains("TWIGPINE_KEY"), "{}", check.detail);
    }

    #[test]
    fn gitlawb_node_env_unset_is_warn() {
        let check = gitlawb_node_env_check(None);
        assert!(matches!(check.state, CheckState::Warn));
        assert!(check.detail.contains("not set"));
        let empty = gitlawb_node_env_check(Some(""));
        assert!(matches!(empty.state, CheckState::Warn));
    }

    /// `TWIGPINE_NODE=""` binds `args.node` to `""` through clap, and check 3
    /// groups empty with unset. The probe must dial the same URL unset
    /// would — removing the normalization makes check 4 probe `""` and Fail
    /// while the env row only Warns, so an empty env install exits 1.
    #[test]
    fn effective_node_url_treats_empty_and_blank_as_unset() {
        assert_eq!(effective_node_url(""), PUBLIC_NODE);
        assert_eq!(effective_node_url("   "), PUBLIC_NODE);
        assert_eq!(effective_node_url("\t\n"), PUBLIC_NODE);
        assert_eq!(
            effective_node_url("http://127.0.0.1:7545"),
            "http://127.0.0.1:7545"
        );
    }

    #[test]
    fn gitlawb_node_env_set_is_pass() {
        let check = gitlawb_node_env_check(Some("https://node.twigpine.com"));
        assert!(matches!(check.state, CheckState::Ok));
        assert!(check.detail.contains("https://node.twigpine.com"));
    }

    #[test]
    fn gitlawb_node_env_loopback_is_pass() {
        for url in ["http://127.0.0.1:7545", "http://localhost:7545"] {
            let check = gitlawb_node_env_check(Some(url));
            assert!(
                matches!(check.state, CheckState::Ok),
                "loopback {url} must be Ok, not Warn/Fail"
            );
        }
    }
}
