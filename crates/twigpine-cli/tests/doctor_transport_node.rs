//! `twigpine doctor` must diagnose the node the git transport will actually use.
//!
//! `twigpine`'s `--node` defaults to the public node while `git-remote-twigpine` falls
//! back to a local one, and an explicit `--node` outranks the environment. So the
//! two disagree whenever TWIGPINE_NODE is unset, blank, or overridden, and doctor's
//! own `node` row describes a URL `git clone` and `git push` never contact.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const DID_BODY: &str = r#"{"did":"did:key:z6MkTestNode","version":"0.0.0"}"#;

/// A request-counting HTTP fixture. `handler(hit_index, request_head)` returns the
/// raw bytes to write back. Runs for the life of the test process, one connection
/// at a time, which is all these probes need.
fn serve(handler: impl Fn(usize, &str) -> Vec<u8> + Send + 'static) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            let i = seen.fetch_add(1, Ordering::SeqCst);
            let _ = s.write_all(&handler(i, &head));
            let _ = s.flush();
        }
    });
    (port, hits)
}

fn http(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn did_ok() -> Vec<u8> {
    http(
        "200 OK",
        "Content-Type: application/json\r\n",
        DID_BODY.as_bytes(),
    )
}

/// A proxy fixture that answers every request with a DID and counts only the
/// requests naming `target`. Doctor's other rows go through the same proxy
/// variable, so a raw hit count cannot tell the transport probe apart.
fn counting_proxy(target: String) -> (u16, Arc<AtomicUsize>) {
    let to_target = Arc::new(AtomicUsize::new(0));
    let counter = to_target.clone();
    let (port, _) = serve(move |_, head| {
        if head.lines().next().is_some_and(|l| l.contains(&target)) {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        did_ok()
    });
    (port, to_target)
}

/// Substring that marks the divergence clause. Present only when twigpine and the git
/// transport resolve different nodes.
const DIVERGENCE: &str = "git push/clone will use";

struct Run {
    stdout: String,
}

const PROXY_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

impl Run {
    /// The single output line carrying the divergence clause, so an assertion
    /// cannot be satisfied by an unrelated row that happens to print the same URL.
    fn divergence_line(&self) -> Option<&str> {
        self.stdout.lines().find(|l| l.contains(DIVERGENCE))
    }
}

fn doctor(env_node: Option<&str>, gl_node: &str) -> Run {
    doctor_with(env_node, Some(gl_node), &[])
}

/// `node_flag: None` runs without `--node`, so clap binds `args.node` from the
/// environment exactly as a user's shell would.
fn doctor_with(env_node: Option<&str>, node_flag: Option<&str>, extra_env: &[(&str, &str)]) -> Run {
    // The release lookup goes to a local fixture, so no run reaches api.github.com.
    // The hit count is asserted below: if the override stops being honored the
    // request escapes, the fixture sees nothing, and every test here fails.
    let (release_port, release_hits) = serve(|_, _| http("404 Not Found", "", b"{}"));
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_twigpine"));
    cmd.arg("doctor");
    if let Some(n) = node_flag {
        cmd.args(["--node", n]);
    }
    // No setting from the developer's shell reaches the run, under either
    // name: an exported TWIGPINE_ALLOW_INSECURE_HTTP or GITLAWB_NODE would
    // change what these tests observe. Cleared first, so the settings the
    // test sets below survive. Upper-cased because Windows treats names as
    // case-insensitive.
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("GITLAWB_") || upper.starts_with("TWIGPINE_") {
            cmd.env_remove(name);
        }
    }
    cmd.arg("--dir")
        .arg(dir.path().join("gitlawb"))
        .env("TWIGPINE_ICAPTCHA_URL", "http://127.0.0.1:1")
        .env(
            "TWIGPINE_GITHUB_API_URL",
            format!("http://127.0.0.1:{release_port}"),
        );
    for v in PROXY_VARS {
        cmd.env_remove(v);
    }
    match env_node {
        Some(v) => cmd.env("TWIGPINE_NODE", v),
        None => cmd.env_remove("TWIGPINE_NODE"),
    };
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    // Under a configured proxy the lookup goes to the proxy fixture, not this one,
    // so the fixture-boundary check only applies to the unproxied runs.
    let proxied = extra_env
        .iter()
        .any(|(k, _)| *k == "HTTP_PROXY" || *k == "TWIGPINE_GITHUB_API_URL");
    assert!(
        proxied || release_hits.load(Ordering::SeqCst) >= 1,
        "the release lookup never reached the fixture, so it went to the public API"
    );
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// TWIGPINE_NODE unset: the helper falls back to the local node, twigpine targets the
/// public one, so the row must name the local node as the transport target.
#[test]
fn unset_env_reports_the_transport_node() {
    let r = doctor(None, "http://127.0.0.1:1");
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    assert!(
        line.contains(twigpine_core::DEFAULT_LOCAL_NODE),
        "divergence row must name the helper's node, got: {line}"
    );
}

/// A blank value is not a configured node. The helper must fall back exactly as
/// it does when the variable is absent, and doctor must say so.
#[test]
fn blank_env_is_treated_as_unset() {
    for blank in ["", "   ", "\t"] {
        let r = doctor(Some(blank), "http://127.0.0.1:1");
        let line = r
            .divergence_line()
            .unwrap_or_else(|| panic!("no divergence row for {blank:?}, got:\n{}", r.stdout));
        assert!(
            line.contains(twigpine_core::DEFAULT_LOCAL_NODE),
            "blank env must resolve to the local default, got: {line}"
        );
    }
}

/// An explicit `--node` outranks the environment, so the transport still goes
/// somewhere twigpine never probes. This state produced no row at all before.
#[test]
fn explicit_node_flag_overriding_env_is_still_reported() {
    let r = doctor(Some("http://127.0.0.1:2"), "http://127.0.0.1:1");
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    assert!(
        line.contains("127.0.0.1:2"),
        "row must name the env-configured transport node, got: {line}"
    );
}

/// No divergence when both resolve the same node: one row, no clause.
#[test]
fn agreeing_env_and_flag_produce_no_divergence_row() {
    let r = doctor(Some("http://127.0.0.1:1"), "http://127.0.0.1:1");
    assert!(
        r.divergence_line().is_none(),
        "twigpine and the transport agree; expected no divergence row, got:\n{}",
        r.stdout
    );
}

/// `--node` equal to the transport default says nothing about whether the user
/// set `TWIGPINE_NODE`. With the variable unset the row must stay the advisory
/// "not set" Warn, not a Pass describing a configured loopback node.
#[test]
fn unset_env_with_flag_equal_to_transport_default_still_warns_not_set() {
    let r = doctor(None, "http://127.0.0.1:7545");
    let row = r
        .stdout
        .lines()
        .find(|l| l.contains("TWIGPINE_NODE"))
        .unwrap_or_else(|| panic!("no TWIGPINE_NODE row in:\n{}", r.stdout));
    assert!(
        row.contains("not set"),
        "unset env must report 'not set', got row {row:?} in:\n{}",
        r.stdout
    );
    assert!(
        !row.contains("intentional for self-hosting/dev"),
        "unset env must not read as a configured loopback node: {row:?}"
    );
}

/// The bug this check exists to prevent, one level down: something answering 200
/// on the transport port is not proof a Twigpine node is there. Reporting it as a
/// healthy transport is the same false green doctor already shipped once.
#[test]
fn a_non_gitlawb_200_is_not_a_healthy_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let Ok(mut s) = stream else { continue };
            // Read the request first. Writing the response without draining the
            // request leaves the client seeing a reset rather than a 200, which
            // silently turns this test into a probe of the unreachable path.
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let body = b"<html>not a node</html>";
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(body);
            let _ = s.flush();
        }
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    // Positive assertion: only the identity check can produce this text, so the
    // test cannot pass by the probe quietly failing instead.
    assert!(
        line.contains("not a Twigpine node"),
        "a non-gitlawb 200 must be called out, not reported reachable, got: {line}"
    );
}

/// Control characters from an attacker-influenceable node URL must not reach the
/// terminal raw, including inside the paste-ready remedy line.
///
/// Scoped to the rows this check owns. The unchanged `node` row at doctor.rs:180,
/// :199 and :206 still interpolates the raw URL and is a separate pre-existing
/// leak, so asserting over the whole of stdout would fail for a reason this
/// change did not introduce and cannot fix without touching adjacent code.
#[test]
fn control_characters_in_the_node_url_are_stripped() {
    let r = doctor(None, "http://127.0.0.1:1/\u{1b}[31m\u{7}\u{202e}");
    let owned: String = r
        .stdout
        .lines()
        .filter(|l| l.contains(DIVERGENCE) || l.trim_start().starts_with("TWIGPINE_NODE:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        owned.contains(DIVERGENCE),
        "expected the divergence row and its remedy, got:\n{}",
        r.stdout
    );
    assert!(
        !owned.contains('\u{1b}') && !owned.contains('\u{7}') && !owned.contains('\u{202e}'),
        "raw control characters reached stdout:\n{owned:?}"
    );
}

/// #357's tiering: an unset variable is advisory (twigpine still works), a variable the
/// user set to something unusable is a real failure. Nothing pinned this, and the
/// difference decides whether a stock install exits non-zero once #391 lands.
#[test]
fn unset_env_warns_while_a_broken_configured_node_fails() {
    let stock = doctor(None, "http://127.0.0.1:1");
    let line = stock.divergence_line().unwrap();
    assert!(
        line.trim_start().starts_with('\u{26a0}'),
        "an unset variable must stay advisory on a stock install, got: {line}"
    );

    let misconfigured = doctor(Some("http://127.0.0.1:2"), "http://127.0.0.1:1");
    let line = misconfigured.divergence_line().unwrap();
    assert!(
        line.trim_start().starts_with('\u{2717}'),
        "a configured but unusable node must fail, got: {line}"
    );
}

/// #357's constraint, as it reads once doctor exits non-zero on any Fail-class row:
/// an unset variable must not contribute one. The run still exits 1 here because
/// the empty tempdir has no identity, so assert on the rows, not the exit code.
#[test]
fn an_unset_env_adds_no_failing_row() {
    let r = doctor(None, "http://127.0.0.1:1");
    let failing: Vec<&str> = r
        .stdout
        .lines()
        .filter(|l| l.trim_start().starts_with('\u{2717}'))
        .collect();
    assert!(
        failing.iter().all(|l| !l.contains("TWIGPINE_NODE")),
        "an unset variable must stay advisory, got failing rows: {failing:?}"
    );
    assert!(r.divergence_line().is_some(), "got:\n{}", r.stdout);
}

/// The suggested fix line printed under "Suggested fixes", or the empty string.
fn fix_line(r: &Run) -> &str {
    r.stdout
        .lines()
        .find(|l| l.trim_start().starts_with("TWIGPINE_NODE:"))
        .unwrap_or("")
}

/// A same-origin redirect that re-issues the identical request-target is the one
/// shape the transport follows, so doctor must follow it too and report the node.
#[test]
fn an_identical_target_redirect_is_followed_like_the_transport() {
    let (port, _) = serve(|i, _| {
        if i < 2 {
            http("302 Found", "Location: /\r\n", b"")
        } else {
            did_ok()
        }
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(line.contains("(reachable)"), "got: {line}");
}

/// The transport stops at a redirect to another origin, so a node that redirects
/// `/` elsewhere is not a working transport and the other origin is never contacted.
#[test]
fn a_cross_origin_redirect_is_refused_and_never_contacted() {
    let (other, other_hits) = serve(|_, _| did_ok());
    let (port, _) = serve(move |_, _| {
        http(
            "302 Found",
            &format!("Location: http://127.0.0.1:{other}/\r\n"),
            b"",
        )
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(
        line.contains("HTTP 302"),
        "a refused redirect surfaces the 3xx, got: {line}"
    );
    assert!(!line.contains("(reachable)"), "got: {line}");
    assert_eq!(
        other_hits.load(Ordering::SeqCst),
        0,
        "the redirect target was contacted"
    );
}

/// Same origin but a different request-target is also refused by the transport.
#[test]
fn a_request_target_changing_redirect_is_refused() {
    let (port, _) = serve(|i, _| {
        if i == 0 {
            http("302 Found", "Location: /elsewhere\r\n", b"")
        } else {
            did_ok()
        }
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(line.contains("HTTP 302"), "got: {line}");
}

/// The helper keeps reqwest's environment proxy discovery, so a node that is only
/// reachable through the configured proxy works for clone/push and must read as
/// reachable here.
#[test]
fn a_node_reachable_only_through_the_configured_proxy_is_reachable() {
    let (proxy, proxy_hits) = counting_proxy("node.invalid".to_string());
    let r = doctor_with(
        Some("http://node.invalid:7545"),
        Some("http://127.0.0.1:1"),
        &[
            ("HTTP_PROXY", &format!("http://127.0.0.1:{proxy}")),
            ("TWIGPINE_ALLOW_INSECURE_HTTP", "1"),
        ],
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(line.contains("(reachable)"), "got: {line}");
    assert!(
        proxy_hits.load(Ordering::SeqCst) >= 1,
        "the probe bypassed the proxy"
    );
}

/// The helper builds its client with `no_proxy()` for a loopback http node, so
/// clone/push dial it directly whatever proxy is configured. Doctor must take the
/// same path: a dead proxy cannot make a reachable loopback node read as down, and
/// a live proxy that answers with a DID cannot make an unreachable one read as up.
#[test]
fn a_loopback_node_is_probed_directly_behind_a_dead_proxy() {
    let (node, node_hits) = serve(|_, _| did_ok());
    let r = doctor_with(
        Some(&format!("http://127.0.0.1:{node}")),
        Some("http://127.0.0.1:1"),
        &[("HTTP_PROXY", "http://127.0.0.1:1")],
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(line.contains("(reachable)"), "got: {line}");
    assert!(
        node_hits.load(Ordering::SeqCst) >= 1,
        "the probe never reached the loopback node directly"
    );
}

#[test]
fn a_loopback_node_is_never_sent_through_a_live_proxy() {
    let (node, node_hits) = serve(|_, _| did_ok());
    let (proxy, proxy_hits) = counting_proxy(format!("127.0.0.1:{node}"));
    let r = doctor_with(
        Some(&format!("http://127.0.0.1:{node}")),
        Some("http://127.0.0.1:1"),
        &[("HTTP_PROXY", &format!("http://127.0.0.1:{proxy}"))],
    );
    assert!(
        r.divergence_line()
            .is_some_and(|l| l.contains("(reachable)")),
        "got:\n{}",
        r.stdout
    );
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        0,
        "a loopback probe went through the proxy"
    );
    assert!(node_hits.load(Ordering::SeqCst) >= 1);
}

/// The helper refuses a non-loopback `http://` node before sending anything unless
/// `TWIGPINE_ALLOW_INSECURE_HTTP` is truthy. Doctor must report that refusal, as a
/// failure because the user set the variable, and must not contact the node.
#[test]
fn a_plaintext_remote_node_is_refused_like_the_helper_and_never_probed() {
    let (proxy, proxy_hits) = counting_proxy("node.invalid".to_string());
    let proxy_env = format!("http://127.0.0.1:{proxy}");
    let r = doctor_with(
        Some("http://node.invalid:7545"),
        Some("http://127.0.0.1:1"),
        &[("HTTP_PROXY", &proxy_env)],
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(
        line.trim_start().starts_with('\u{2717}'),
        "a refused configured node must fail, got: {line}"
    );
    assert!(line.contains("plaintext"), "got: {line}");
    assert!(!line.contains("(reachable)"), "got: {line}");
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        0,
        "a refused node must not be contacted"
    );
}

/// Must-not case for the refusal: an explicit opt-in (and only a truthy one) lifts it.
#[test]
fn the_plaintext_refusal_follows_the_helpers_opt_in_parsing() {
    let (proxy, _) = serve(|_, _| did_ok());
    let proxy_env = format!("http://127.0.0.1:{proxy}");
    for (val, allowed) in [
        ("1", true),
        (" TRUE ", true),
        ("0", false),
        ("false", false),
        ("", false),
        ("yes", false),
    ] {
        let r = doctor_with(
            Some("http://node.invalid:7545"),
            Some("http://127.0.0.1:1"),
            &[
                ("HTTP_PROXY", &proxy_env),
                ("TWIGPINE_ALLOW_INSECURE_HTTP", val),
            ],
        );
        let line = r
            .divergence_line()
            .unwrap_or_else(|| panic!("no row for {val:?}:\n{}", r.stdout));
        assert_eq!(
            line.contains("(reachable)"),
            allowed,
            "opt-in {val:?} gave: {line}"
        );
        assert_eq!(
            line.contains("plaintext"),
            !allowed,
            "opt-in {val:?}: {line}"
        );
    }
}

/// An unset variable stays advisory even when the default would be refused, which
/// cannot happen today (the default is loopback), so the tier is pinned on the
/// configured case only; a TLS remote must never trip the refusal.
#[test]
fn an_https_remote_node_is_not_refused() {
    let r = doctor_with(
        Some("https://node.invalid:7545"),
        Some("http://127.0.0.1:1"),
        &[],
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(!line.contains("plaintext"), "got: {line}");
}

/// The helper parses the node DID before it will build a UCAN invocation, so an
/// empty or malformed `did` is not a usable identity.
#[test]
fn an_empty_or_malformed_did_is_not_a_healthy_transport() {
    for body in [
        r#"{"did":""}"#,
        r#"{"did":"not-a-did"}"#,
        r#"{"did":"did:unknown:abc"}"#,
    ] {
        let (port, _) = serve(move |_, _| http("200 OK", "", body.as_bytes()));
        let r = doctor(
            Some(&format!("http://127.0.0.1:{port}")),
            "http://127.0.0.1:1",
        );
        let line = r
            .divergence_line()
            .unwrap_or_else(|| panic!("no row for {body}:\n{}", r.stdout));
        assert!(
            line.contains("not a Twigpine node"),
            "{body} must not read as healthy, got: {line}"
        );
    }
}

/// A valid-looking identity at the head of an oversized body is still an
/// unbounded read, so it is rejected rather than parsed.
#[test]
fn an_oversized_probe_body_is_rejected_not_parsed() {
    let mut body = String::from(r#"{"did":"did:key:z6MkTestNode","pad":""#);
    body.push_str(&"A".repeat(2 * 1024 * 1024));
    body.push_str("\"}");
    let (port, _) = serve(move |_, _| {
        http(
            "200 OK",
            "Content-Type: application/json\r\n",
            body.as_bytes(),
        )
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no row:\n{}", r.stdout));
    assert!(line.contains("too large"), "got: {line}");
    assert!(!line.contains("(reachable)"), "got: {line}");
}

/// Blank TWIGPINE_NODE with no `--node`: clap hands doctor the raw blank value, and
/// the remedy must not reproduce it. It names the public node instead.
#[test]
fn a_blank_env_remedy_does_not_reproduce_the_blank_value() {
    for blank in ["   ", "\t"] {
        let r = doctor_with(Some(blank), None, &[]);
        let fix = fix_line(&r);
        assert!(
            fix.contains("export TWIGPINE_NODE='https://node.twigpine.com'"),
            "blank {blank:?} must be replaced by a valid target, got: {fix:?}\n{}",
            r.stdout
        );
    }
}

/// A node value with an apostrophe must not close the quoting and run what follows.
#[test]
fn an_apostrophe_in_the_node_value_cannot_break_out_of_the_remedy() {
    let r = doctor(None, "http://127.0.0.1:1/x'; touch /tmp/pwned; #'");
    let fix = fix_line(&r);
    assert!(
        fix.contains(r#"'http://127.0.0.1:1/x'\''; touch /tmp/pwned; #'\'''"#),
        "apostrophes must be escaped, got: {fix:?}"
    );
}

/// `TWIGPINE_NODE` may carry a path prefix (a reverse-proxied `https://host/mount`),
/// with identity served at exactly that prefix and nothing at `/mount/`. The probe
/// must request the configured base verbatim, as the helper does.
#[test]
fn a_path_prefixed_transport_node_is_probed_at_its_exact_base() {
    let (port, _) = serve(|_, head| {
        if head.starts_with("GET /mount HTTP/1.1") {
            did_ok()
        } else {
            http("404 Not Found", "", b"{}")
        }
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}/mount")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    assert!(line.contains("(reachable)"), "got: {line}");
}

/// A release tag from the configurable API source is untrusted text bound for the
/// terminal. Controls and line breaks in it must not reach stdout.
#[test]
fn a_hostile_release_tag_cannot_reach_the_terminal_raw() {
    let body = r#"{"tag_name":"v999.0.0\u001b]0;RELEASE-CONTROL\u0007\nspoofed-row\u202e"}"#;
    let (api, hits) = serve(move |_, _| {
        http(
            "200 OK",
            "Content-Type: application/json\r\n",
            body.as_bytes(),
        )
    });
    let r = doctor_with(
        None,
        Some("http://127.0.0.1:1"),
        &[(
            "TWIGPINE_GITHUB_API_URL",
            &format!("http://127.0.0.1:{api}"),
        )],
    );
    assert!(hits.load(Ordering::SeqCst) >= 1, "fixture never hit");
    assert!(
        r.stdout.contains("v999.0.0"),
        "the version row must still show the tag:\n{}",
        r.stdout
    );
    for bad in ['\u{1b}', '\u{7}', '\u{202e}'] {
        assert!(
            !r.stdout.contains(bad),
            "control {bad:?} reached stdout:\n{:?}",
            r.stdout
        );
    }
    assert!(
        !r.stdout
            .lines()
            .any(|l| l.trim_start().starts_with("spoofed-row")),
        "tag forged an output line:\n{}",
        r.stdout
    );
}

/// The probe validates the bytes the endpoint sent, not a lossy rendering of them.
/// A 200 whose JSON string carries invalid UTF-8 is not a document the helper's
/// strict identity lookup can read, so it must not be called reachable. A valid
/// control confirms the fixture reaches the identity check at all.
#[test]
fn invalid_utf8_in_the_identity_body_is_not_a_reachable_node() {
    let cases: [(&[u8], bool); 3] = [
        (br#"{"did":"did:key:z6MkTestNode","pad":"ok"}"#, true),
        (
            b"{\"did\":\"did:key:z6MkTestNode\",\"pad\":\"\xff\"}",
            false,
        ),
        (b"{\"did\":\"did:key:z6Mk\xfeTestNode\"}", false),
    ];
    for (body, reachable) in cases {
        let served = body.to_vec();
        let (port, _) =
            serve(move |_, _| http("200 OK", "Content-Type: application/json\r\n", &served));
        let r = doctor(
            Some(&format!("http://127.0.0.1:{port}")),
            "http://127.0.0.1:1",
        );
        let line = r
            .divergence_line()
            .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
        assert_eq!(
            line.contains("(reachable)"),
            reachable,
            "body {:?}: got: {line}",
            String::from_utf8_lossy(body)
        );
    }
}

/// A padded `TWIGPINE_NODE` with no `--node` resolves to the trimmed URL for the
/// transport, so the connectivity row must dial the trimmed URL too instead of
/// failing to parse ` http://host:port /`.
#[test]
fn a_padded_env_node_is_dialed_trimmed_by_the_connectivity_row() {
    let (port, _) = serve(|_, _| did_ok());
    let r = doctor_with(Some(&format!(" http://127.0.0.1:{port} ")), None, &[]);
    let node_row = r
        .stdout
        .lines()
        .find(|l| l.contains("v0.0.0"))
        .unwrap_or_else(|| panic!("no passing node row, got:\n{}", r.stdout));
    assert!(
        node_row.contains(&format!("http://127.0.0.1:{port}")),
        "got: {node_row}"
    );
}

/// clap binds `--node` from `TWIGPINE_NODE` verbatim, while the transport resolver
/// trims it. A padded value therefore resolves to the same node on both sides, and
/// doctor must not read the whitespace difference as a divergence: no divergence
/// clause, and the env row classified as the configured loopback node (Pass),
/// whether or not that node is up.
#[test]
fn a_padded_env_node_is_not_a_divergence() {
    for up in [true, false] {
        let port = if up { serve(|_, _| did_ok()).0 } else { 1 };
        let r = doctor_with(Some(&format!(" http://127.0.0.1:{port} ")), None, &[]);
        assert!(
            r.divergence_line().is_none(),
            "padding alone is not a divergence (node up: {up}), got:\n{}",
            r.stdout
        );
        let row = r
            .stdout
            .lines()
            .find(|l| l.contains("TWIGPINE_NODE") && !l.trim_start().starts_with("TWIGPINE_NODE:"))
            .unwrap_or_else(|| panic!("no TWIGPINE_NODE row, got:\n{}", r.stdout));
        assert!(
            !row.trim_start().starts_with('\u{2717}'),
            "padding alone must not fail the env row (node up: {up}): {row}"
        );
        assert!(
            row.contains("intentional for self-hosting/dev"),
            "a padded loopback env must classify as the configured loopback node (node up: {up}): {row}"
        );
    }
}

/// The `settings` row doctor prints when a setting was given under its name
/// from before the rename.
fn settings_row(r: &Run) -> Option<&str> {
    // The row itself, not the fix hint printed under it.
    r.stdout
        .lines()
        .find(|l| l.contains("under the old GITLAWB_ name") || l.contains("TWIGPINE_ wins"))
}

#[test]
fn a_setting_under_its_old_name_still_selects_the_node() {
    let (port, hits) = serve(|_, _| did_ok());
    let url = format!("http://127.0.0.1:{port}");
    // No --node and no TWIGPINE_NODE: the old name is the only source.
    let r = doctor_with(None, None, &[("GITLAWB_NODE", &url)]);
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the node named by GITLAWB_NODE was never contacted:\n{}",
        r.stdout
    );
    let row = settings_row(&r).unwrap_or_else(|| panic!("no settings row:\n{}", r.stdout));
    assert!(row.contains("TWIGPINE_NODE"), "{row}");
}

#[test]
fn the_new_name_wins_over_the_old_one_and_doctor_says_so() {
    let (new_port, new_hits) = serve(|_, _| did_ok());
    let (old_port, old_hits) = serve(|_, _| did_ok());
    let new_url = format!("http://127.0.0.1:{new_port}");
    let old_url = format!("http://127.0.0.1:{old_port}");
    let r = doctor_with(Some(&new_url), None, &[("GITLAWB_NODE", &old_url)]);
    assert!(new_hits.load(Ordering::SeqCst) > 0, "{}", r.stdout);
    assert_eq!(old_hits.load(Ordering::SeqCst), 0, "{}", r.stdout);
    let row = settings_row(&r).unwrap_or_else(|| panic!("no settings row:\n{}", r.stdout));
    assert!(row.contains("TWIGPINE_ wins"), "{row}");
}

#[test]
fn no_settings_row_without_an_old_name() {
    let (port, _) = serve(|_, _| did_ok());
    let url = format!("http://127.0.0.1:{port}");
    let r = doctor_with(Some(&url), None, &[]);
    assert!(settings_row(&r).is_none(), "{}", r.stdout);
}
