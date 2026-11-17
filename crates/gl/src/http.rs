//! Signed HTTP client for Twigpine API calls (async).
//!
//! Writes are signed with RFC 9421 HTTP Signatures. When the node gates a write
//! behind iCaptcha (HTTP 403 `icaptcha_proof_required`, advertised via the
//! `x-icaptcha-url` / `x-icaptcha-level` headers), the client transparently
//! solves the challenge and re-signs the write with the `x-icaptcha-proof`
//! header attached (see `crates/icaptcha-client`).

use anyhow::{Context, Result};
use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;
use gitlawb_core::node_denial::NodeDenial;
use icaptcha_client::IcaptchaCfg;
use serde_json::Value;

/// Max times we'll fetch a fresh proof and retry a 403-iCaptcha response
/// (absorbs proof expiry / first-seen replay).
const MAX_ICAPTCHA_RETRIES: usize = 2;

/// Max bytes buffered from a denial body before we give up on parsing it. Node
/// error bodies are a few hundred bytes of JSON; anything past this is not one,
/// and reading it unbounded is exactly the allocation a hostile node would aim
/// for.
pub(crate) const DENIAL_BODY_CAP: usize = 64 * 1024;

/// Max bytes read from a git smart-HTTP ref advertisement. Real ads are small;
/// this bounds hostile 200 responses on the MCP `git_refs` path.
pub(crate) const GIT_REFS_BODY_CAP: usize = 256 * 1024;

/// Max characters of a node-supplied message we will echo to the terminal.
const NODE_MSG_CHARS: usize = 200;

/// Total request timeout: from the start of connecting through the end of the
/// response body, so it bounds a slow download and not just a slow handshake.
const TOTAL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `url` would send a signed request off this machine in cleartext.
///
/// True only for `http://` to a non-loopback host. RFC 9421 signs the request
/// but does not encrypt it, so on a plaintext hop the `Signature` header and
/// the body are both readable, and a captured signature is replayable for its
/// freshness window against any host.
///
/// Loopback is decided from the parsed address rather than a string match, so
/// `127.0.0.2`, `[::1]` and an IPv4-mapped `[::ffff:127.0.0.1]` are all
/// recognised as this machine. A value that does not parse, or that is not
/// http(s), is not this guard's business and returns false: it fails later with
/// its own error, and naming it a TLS problem would misdirect the reader.
fn is_insecure_remote(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" {
        return false;
    }
    // host_str() keeps the brackets on an IPv6 literal.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return false;
        }
        // An IPv4-mapped IPv6 literal hides a v4 loopback from is_loopback().
        if let std::net::IpAddr::V6(v6) = ip {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if v4.is_loopback() {
                    return false;
                }
            }
        }
    }
    true
}

/// True when `url` is an `http://` address on this machine. Same loopback
/// rules as [`is_insecure_remote`].
///
/// The client does not use the proxy environment for such a node: reqwest's
/// own `NO_PROXY` matching differs from any string matcher written here (it
/// parses addresses and CIDR blocks apart from domains, and a wildcard is only
/// a domain entry), so deciding "would this go through the proxy" ourselves
/// can disagree with where the request actually goes. Routing a loopback node
/// directly makes the answer true by construction. See `NodeClient::with_timeout`.
fn is_loopback_http(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return false;
    };
    parsed.scheme() == "http" && parsed.host_str().is_some() && !is_insecure_remote(url)
}

/// Refuse to sign a request destined for a cleartext hop off this machine
/// unless the operator has opted in. `GITLAWB_ALLOW_INSECURE_HTTP` exists for a
/// private LAN where the operator has decided that is acceptable; only `1` or
/// `true` opts in. A loopback node is never proxied (see
/// [`is_loopback_http`]), so a proxy cannot carry its signed requests
/// off-machine and the loopback exemption holds under any proxy environment.
fn ensure_signing_transport(node_base: &str, allow_insecure: bool) -> Result<()> {
    if allow_insecure || !is_insecure_remote(node_base) {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to send a signed request to {node_base} over plaintext http.\n\
         The request is signed but not encrypted, so the Signature header and \
         the body are readable by anyone on the path, and a captured signature \
         can be replayed.\n\
         Use https://, or set GITLAWB_ALLOW_INSECURE_HTTP=1 to accept the risk \
         (for a trusted private network only)."
    )
}

/// Parse a `GITLAWB_ALLOW_INSECURE_HTTP` value. Only `1` or `true`
/// (case-insensitive, after trim) opens the gate. Presence alone is not
/// consent: `=0`, `=false` and an empty value read as "not opting in" to the
/// operator, and the README and the refusal message document `=1`. A non-empty
/// value that is not truthy warns, so a misspelling is neither a silent yes nor
/// a silent no. Same contract as `git-remote-gitlawb` and `icaptcha-client`.
fn allow_insecure_http_from_str(raw: Option<&str>) -> bool {
    let Some(v) = raw else {
        return false;
    };
    let t = v.trim();
    if t.eq_ignore_ascii_case("1") || t.eq_ignore_ascii_case("true") {
        return true;
    }
    if !t.is_empty() {
        warn_allow_insecure_http_non_truthy();
    }
    false
}

/// Fixed warning for a set but non-truthy value. The raw value is never printed.
fn warn_allow_insecure_http_non_truthy() {
    eprintln!(
        "warning: GITLAWB_ALLOW_INSECURE_HTTP is set but not truthy (expected 1 or true); \
         plaintext http to a remote node remains refused"
    );
}

/// The operator opt-in for a plaintext remote, read at request time so a test
/// or shell can set it without rebuilding the client. A non-UTF-8 value fails
/// closed and warns like any other non-truthy one.
fn insecure_http_allowed() -> bool {
    match std::env::var("GITLAWB_ALLOW_INSECURE_HTTP") {
        Ok(v) => allow_insecure_http_from_str(Some(&v)),
        Err(std::env::VarError::NotUnicode(_)) => {
            warn_allow_insecure_http_non_truthy();
            false
        }
        Err(std::env::VarError::NotPresent) => false,
    }
}

/// Follow a redirect only when it stays on the origin that issued it AND re-issues the
/// identical request-target, and only for as long as the chain bound allows.
///
/// The decision itself is [`gitlawb_core::redirect::may_follow`], shared with
/// `git-remote-gitlawb` so the two signing clients cannot drift apart on it. Refusal
/// is `stop`, not `error`: the 3xx comes back as an ordinary response and each caller
/// reports it through the status path it already has.
///
/// `Policy::custom` replaces reqwest's built-in limit, so the chain bound is restated
/// here. Same-origin redirects can cycle, and this is what stops a node answering 302
/// to itself from being followed indefinitely. It is not what makes the request
/// finite: `.timeout(...)` on the same builder is a TOTAL request timeout covering the
/// whole chain, so without this bound the worst case is a 30 second spin, not an
/// endless one. The bound is what keeps that spin from costing the node a request per
/// round trip for the full 30 seconds.
///
/// `>` and not `>=`: reqwest pushes the redirecting URL onto `previous` before
/// consulting the policy, so on the first redirect `previous.len()` is already 1, and
/// `>=` would permit `MAX_REDIRECTS - 1` follows. `Policy::limited(max)` refuses at
/// `previous.len() > max`, and matching it is the point of reusing its value.
fn same_origin_redirect(attempt: reqwest::redirect::Attempt<'_>) -> reqwest::redirect::Action {
    let Some(previous) = attempt.previous().last() else {
        // No previous URL to compare against. Unreachable through reqwest, which
        // pushes the redirecting URL before consulting the policy, but the safe
        // reading of "cannot prove same-origin" is to refuse.
        return attempt.stop();
    };
    if attempt.previous().len() > gitlawb_core::redirect::MAX_REDIRECTS {
        return attempt.stop();
    }
    if gitlawb_core::redirect::may_follow(previous, attempt.url()) {
        attempt.follow()
    } else {
        attempt.stop()
    }
}

pub struct NodeClient {
    inner: reqwest::Client,
    pub node_url: String,
    keypair: Option<Keypair>,
}

impl NodeClient {
    pub fn new(node_url: impl Into<String>, keypair: Option<Keypair>) -> Self {
        Self::with_timeout(node_url, keypair, TOTAL_REQUEST_TIMEOUT)
    }

    /// `new` with the total request timeout as a parameter, so a test can drive the
    /// timeout's behaviour without waiting out the shipped value. `new` supplies the
    /// shipped one, which is what makes the scaled-down test cover the real client.
    fn with_timeout(
        node_url: impl Into<String>,
        keypair: Option<Keypair>,
        timeout: std::time::Duration,
    ) -> Self {
        let node_url = node_url.into();
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::custom(same_origin_redirect))
            .user_agent(format!("gl/{} gitlawb-cli", env!("CARGO_PKG_VERSION")));
        // A loopback node is reached directly, ignoring HTTP_PROXY/ALL_PROXY, so
        // a proxy can never carry its signed requests off this machine and the
        // guard needs no model of the proxy environment. Redirects cannot leave
        // the origin (`same_origin_redirect`), so the direct route covers them.
        if is_loopback_http(&node_url) {
            builder = builder.no_proxy();
        }
        let inner = builder.build().expect("failed to build HTTP client");
        Self {
            inner,
            node_url,
            keypair,
        }
    }

    /// GET request — no auth (public read endpoints).
    pub async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        self.inner
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
    }

    /// GET that signs when a keypair is available; falls back to unsigned for public repos.
    pub async fn get_authed(&self, path: &str) -> Result<reqwest::Response> {
        if self.keypair.is_some() {
            self.get_signed(path).await
        } else {
            self.get(path).await
        }
    }

    /// GET with RFC 9421 HTTP Signature auth, for owner-only read endpoints.
    /// Signs over the empty body (same shape the node verifies for signed reads).
    pub async fn get_signed(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        let kp = self
            .keypair
            .as_ref()
            .context("get_signed requires an identity keypair")?;
        ensure_signing_transport(&self.node_url, insecure_http_allowed())?;
        let signed = sign_request(kp, "GET", path, b"");
        let req = self
            .inner
            .get(&url)
            .header("Content-Digest", signed.content_digest)
            .header("Signature-Input", signed.signature_input)
            .header("Signature", signed.signature);
        req.send().await.with_context(|| format!("GET {url}"))
    }

    /// GET that signs when an identity keypair is present and falls back to an
    /// anonymous GET otherwise — for read-visibility endpoints, where a public
    /// repo is readable anonymously but a private repo requires the owner/reader
    /// to be authenticated. Mirrors the conditional signing of post/put/delete.
    pub async fn get_maybe_signed(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        if self.keypair.is_some() {
            ensure_signing_transport(&self.node_url, insecure_http_allowed())?;
        }
        let mut req = self.inner.get(&url);
        if let Some(kp) = &self.keypair {
            let signed = sign_request(kp, "GET", path, b"");
            req = req
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature);
        }
        req.send().await.with_context(|| format!("GET {url}"))
    }

    /// POST with JSON body + RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn post(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("POST", path, body).await
    }

    /// POST with JSON body + RFC 9421 signing and an optional user-provided
    /// iCaptcha proof, sent on the initial request.
    pub async fn post_with_proof(
        &self,
        path: &str,
        body: &[u8],
        initial_proof: Option<&str>,
    ) -> Result<reqwest::Response> {
        self.send_signed_with_proof("POST", path, body, initial_proof)
            .await
    }

    /// PUT with RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn put(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("PUT", path, body).await
    }

    /// DELETE with RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn delete(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("DELETE", path, body).await
    }

    /// Sign + send a write. On a 403 iCaptcha challenge (detected via the
    /// `x-icaptcha-*` headers) attach the proof and send the write again, up to
    /// [`MAX_ICAPTCHA_RETRIES`]. Each attempt goes through `send_once`, which
    /// signs afresh, so the retry is a new signature over the same bytes, not a
    /// resend of the original one. Emits an actionable hint on a 401 "not an
    /// agent" (the old-CLI / unregistered failure mode), and converts every
    /// denial the node names in `x-gitlawb-error` into an error.
    async fn send_signed(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<reqwest::Response> {
        self.send_signed_with_proof(method, path, body, None).await
    }

    /// Sign + send a write. `initial_proof`, if provided, is attached to the
    /// first request. On a 403 iCaptcha challenge advertised via
    /// `x-icaptcha-*` headers, solve and retry up to MAX_ICAPTCHA_RETRIES.
    async fn send_signed_with_proof(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        initial_proof: Option<&str>,
    ) -> Result<reqwest::Response> {
        let mut proof = initial_proof.map(str::to_owned);
        let mut attempts = 0;

        loop {
            let resp = self.send_once(method, path, body, proof.as_deref()).await?;

            let status = resp.status();

            if status == reqwest::StatusCode::UNAUTHORIZED
                && resp
                    .headers()
                    .get("x-gitlawb-error")
                    .and_then(|v| v.to_str().ok())
                    == Some("human_detected")
            {
                eprintln!(
                    "note: this node requires signed requests (RFC 9421). If writes keep \
                     failing, your `gl` may be too old — upgrade it — or you're not registered: \
                     run `gl register`."
                );
            }

            if status == reqwest::StatusCode::FORBIDDEN && attempts < MAX_ICAPTCHA_RETRIES {
                if let Some(cfg) = self.icaptcha_cfg(resp.headers())? {
                    attempts += 1;
                    proof = Some(obtain_proof(cfg).await?);
                    continue;
                }
            }

            if let Some(rejection) = signature_rejection(&resp) {
                return Err(rejection.into_error(method, path, resp).await);
            }
            return Ok(resp);
        }
    }

    /// Build, sign, and send one request, optionally attaching a proof header.
    async fn send_once(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<&str>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        if self.keypair.is_some() {
            ensure_signing_transport(&self.node_url, insecure_http_allowed())?;
        }
        let mut req = self
            .inner
            .request(method.parse().expect("valid HTTP method"), &url)
            .header("Content-Type", "application/json")
            .body(body.to_vec());

        if let Some(kp) = &self.keypair {
            let signed = sign_request(kp, method, path, body);
            req = req
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature);
        }
        if let Some(p) = proof {
            req = req.header(icaptcha_client::PROOF_HEADER, p);
        }

        req.send().await.with_context(|| format!("{method} {url}"))
    }

    /// If `headers` describe an iCaptcha 403, build the solve config (binding the
    /// proof's `sub` to our DID). Returns `None` for a non-iCaptcha 403.
    fn icaptcha_cfg(&self, headers: &reqwest::header::HeaderMap) -> Result<Option<IcaptchaCfg>> {
        let url = headers.get("x-icaptcha-url").and_then(|v| v.to_str().ok());
        let level = headers
            .get("x-icaptcha-level")
            .and_then(|v| v.to_str().ok());
        if url.is_none() && level.is_none() {
            return Ok(None); // not an iCaptcha challenge
        }
        let kp = self
            .keypair
            .as_ref()
            .context("iCaptcha challenge requires an identity keypair (run `gl identity new`)")?;
        Ok(Some(IcaptchaCfg::new(
            kp.did().to_string(),
            url.map(str::to_string),
            level.and_then(|l| l.parse().ok()),
        )))
    }
}

/// A write the node refused with a code this build recognises.
struct SignatureRejection {
    /// Which denial it was. Its `as_str` is the `x-gitlawb-error` code, printed
    /// verbatim so scripts can match on it.
    denial: NodeDenial,
    /// What the user should actually do next.
    hint: &'static str,
}

impl SignatureRejection {
    /// Consume the response to fold the node's own message into the error.
    /// Called only after [`signature_rejection`] has decided from the status and
    /// header, since reading the body takes the response by value.
    ///
    /// The message is attacker controlled (any node the user points `gl` at
    /// wrote it), so the read is capped and the string is stripped of control
    /// characters and bidi overrides before it can reach a terminal: without
    /// that, the text whose whole job is to say "your write was REFUSED" can
    /// clear the screen and print a fake success line.
    async fn into_error(self, method: &str, path: &str, resp: reqwest::Response) -> anyhow::Error {
        let status = resp.status();
        let capped = read_body_capped(resp, DENIAL_BODY_CAP).await;
        let node_msg = serde_json::from_str::<serde_json::Value>(&capped.text)
            .ok()
            .and_then(|b| b["message"].as_str().map(sanitize_node_msg))
            .filter(|m| !m.is_empty());
        let Self { denial, hint } = self;
        let code = denial.as_str();
        match node_msg {
            Some(m) => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint} ({m})"),
            None => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint}"),
        }
    }
}

/// Recognise a node rejection from the status and the
/// `x-gitlawb-error` header, before anything reads the body.
///
/// Known limit: the node also puts the same code in the body's `error` field,
/// and this does not look at it, so a proxy or CDN that strips unknown `X-`
/// headers switches the detection off. Reading the body to recover the second
/// signal is destructive, and handing the caller back a response it can still
/// parse needs `http::Response::builder` (the only constructor
/// `reqwest::Response::from` takes), which is a dependency this crate does not
/// carry. The commands that must not mistake a denial for a success do not rely
/// on this alone: `gl init` compares the structured error code from the body,
/// and the `gl task` writes check the status before parsing.
///
/// None of these is ever retried. A `signature_replayed` 409 means the node
/// already admitted a request carrying this signature, so re-sending the same
/// bytes risks applying the mutation twice, which is the duplicate write the
/// ledger exists to prevent. (The iCaptcha 403 retry above does not have that
/// problem: `verify_request` runs inside the handler, so the ledger has already
/// been charged by the time the challenge is returned, but `send_once` signs
/// every attempt afresh and each signature carries its own nonce, so the retry
/// arrives under a ledger key the node has never seen.) The 400, 429, 500 and
/// 503 cases did not apply the write; 429 and 503 are retryable, but doing it
/// automatically would only hammer a node that is already saying "not now", so
/// they surface to the user instead.
///
/// The set of codes is [`NodeDenial`], shared with the node so both halves
/// spell them the same way. The `match` below has no wildcard arm on purpose:
/// adding a denial to the node stops this crate compiling until someone writes
/// the caller's instructions for it. That is the whole point of the type, since
/// the previous arrangement (a list of literals in each crate) silently missed
/// `signature_nonce_too_short` for several commits and returned `Ok(400)` for it.
fn signature_rejection(resp: &reqwest::Response) -> Option<SignatureRejection> {
    let code = resp.headers().get("x-gitlawb-error")?.to_str().ok()?;
    // A code this build does not know: not our denial to describe. The header
    // came from a node the user chose, which may be newer, older, or hostile,
    // so the response goes back to the caller untouched.
    let denial = NodeDenial::from_code(code)?;
    // The status has to agree with the code, so a stray header on a 200 cannot
    // turn a success into a refusal.
    if resp.status().as_u16() != denial.status() {
        return None;
    }
    let hint = match denial {
        NodeDenial::NonceRequired => {
            "this node requires a nonce in the request signature and the request did not carry \
             one. The write did not happen; upgrade `gl` and run the command again"
        }
        NodeDenial::NonceTooShort => {
            "this node rejected the nonce in the request signature as too short to be unique. \
             The write did not happen; upgrade `gl` and run the command again"
        }
        NodeDenial::Replayed => {
            "the node already admitted a request with this signature and will not take it twice. \
             Do not resend: check whether the change took effect before running the command again"
        }
        NodeDenial::LedgerFull => {
            "this identity has too many unexpired signatures on the node, so it is refusing more \
             signed writes for now. The write did not happen; wait a moment and run the command \
             again"
        }
        NodeDenial::IdentityMissing => {
            "the node reached its signature ledger without a verified identity and refused the \
             write. The write did not happen; this is a fault on the node, so report it to the \
             operator"
        }
        NodeDenial::LedgerUnavailable => {
            "the node's signature ledger is unavailable, so it is refusing signed writes. \
             The write did not happen; retry later or ask the node operator to check the node"
        }
        NodeDenial::RateLimited => {
            "a rate limit on the node refused this request. The write did not happen; \
             re-signing will not help, so wait and try again"
        }
    };
    Some(SignatureRejection { denial, hint })
}

/// Read a node reply, turning a non-2xx into an error instead of handing the
/// caller an error body that pretty-prints like a success. The message is read
/// under a cap and sanitized, same as a signature denial.
pub(crate) async fn json_or_denial<T: serde::de::DeserializeOwned>(
    what: &str,
    resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let capped = read_body_capped(resp, DENIAL_BODY_CAP).await;
        let msg = serde_json::from_str::<serde_json::Value>(&capped.text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| match (capped.read_failed, capped.truncated) {
                (true, _) if capped.text.is_empty() => {
                    "(response body could not be read)".to_string()
                }
                (true, _) => {
                    format!(
                        "(response body cut short by a read failure) {}",
                        capped.text
                    )
                }
                (false, true) => format!("{} (truncated)", capped.text),
                (false, false) => capped.text,
            });
        anyhow::bail!("{what} failed ({status}): {}", sanitize_node_msg(&msg));
    }
    resp.json::<T>()
        .await
        .with_context(|| format!("invalid JSON response from {what}"))
}

/// Run the (blocking) iCaptcha solve loop off the async runtime.
async fn obtain_proof(cfg: IcaptchaCfg) -> Result<String> {
    tokio::task::spawn_blocking(move || icaptcha_client::obtain_proof(&cfg, None))
        .await
        .context("iCaptcha solver task panicked")?
}

/// What a capped body read produced. `text` is the bytes that arrived; the two flags
/// say why the read stopped where it did, which a caller that CLASSIFIES on the body
/// cannot work out from the text alone.
pub(crate) struct CappedBody {
    /// The bytes read, lossily decoded.
    pub(crate) text: String,
    /// The cap cut the body short.
    pub(crate) truncated: bool,
    /// A chunk read FAILED part-way through, so the body is not merely short, it is
    /// unfinished and the node may have had more to say.
    pub(crate) read_failed: bool,
}

/// The byte twin of [`CappedBody`]: the same completion flags, but the payload is
/// left as the exact bytes that arrived. Byte-oriented protocol consumers (the git
/// smart-HTTP ref advertisement on the MCP `git_refs` path) must read through this
/// one: git ref names are byte strings that need not be UTF-8, so a lossy decode
/// followed by `as_bytes()` is not a display nicety but corruption — each invalid
/// byte becomes the 3-byte U+FFFD, changing both the ref name and the pkt-line
/// length accounting, and a valid repository stops validating.
pub(crate) struct CappedBytes {
    /// The bytes read, exactly as they arrived.
    pub(crate) bytes: Vec<u8>,
    /// The cap cut the body short.
    pub(crate) truncated: bool,
    /// A chunk read FAILED part-way through, so the body is not merely short, it is
    /// unfinished and the node may have had more to say.
    pub(crate) read_failed: bool,
}

/// Read at most `cap` bytes of a response body, raw. Bounds the allocation from a
/// hostile or broken node returning a huge body — the display is capped
/// separately, but the read itself must not be unbounded (INV-6, read half).
///
/// `truncated` reports whether the cap cut the body short. A caller that CLASSIFIES
/// on the body needs it: a cut body fails JSON parse, and a parse failure is
/// indistinguishable from a node that sent no code at all, so without this flag an
/// oversized body silently picks a different arm. A protocol consumer needs it even
/// more: a cut pkt-line stream can still be a syntactically valid *prefix*, so
/// without the flag a bounded read is indistinguishable from a clean EOF and the
/// prefix parses as the complete answer.
///
/// `read_failed` reports the other way a body can end early. A mid-body read error
/// used to leave through the same exit as a clean end of stream, so a 500 whose body
/// died in transit surfaced as an empty message and the caller was told
/// `node returned 500: ` with nothing after the colon. That is a report of what the
/// node said, and the node never got to say it.
pub(crate) async fn read_body_capped_bytes(mut resp: reqwest::Response, cap: usize) -> CappedBytes {
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut read_failed = false;
    while buf.len() < cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    truncated = true;
                    break; // hit the cap mid-chunk
                }
            }
            Ok(None) => break, // clean end of body
            Err(_) => {
                read_failed = true;
                break;
            }
        }
    }
    // A body that lands exactly on the cap may or may not have more behind it;
    // report it as cut, since the classification that follows cannot tell either.
    if buf.len() >= cap {
        truncated = true;
    }
    CappedBytes {
        bytes: buf,
        truncated,
        read_failed,
    }
}

/// Text view of [`read_body_capped_bytes`], for callers that go on to display or
/// JSON-parse node-supplied *messages* (denial bodies). The decode is lossy on
/// purpose there — a denial is prose for a terminal, and a hostile byte becomes a
/// visible U+FFFD instead of raw output. Anything that parses a byte protocol out
/// of the body must take the bytes variant instead; see [`CappedBytes`].
pub(crate) async fn read_body_capped(resp: reqwest::Response, cap: usize) -> CappedBody {
    let raw = read_body_capped_bytes(resp, cap).await;
    CappedBody {
        text: String::from_utf8_lossy(&raw.bytes).into_owned(),
        truncated: raw.truncated,
        read_failed: raw.read_failed,
    }
}

/// Strip terminal-dangerous characters from (and cap the length of) a
/// node-supplied error string before surfacing it. The node a caller talks to
/// could be hostile and embed escape sequences in its error body; those must not
/// reach the terminal verbatim. We drop the C0/C1 control bytes (which
/// defangs ANSI/OSC escapes) AND the Unicode bidi/format controls (which
/// `char::is_control` does not cover — they can reorder the displayed line).
pub(crate) fn sanitize_node_msg(s: &str) -> String {
    gitlawb_core::sanitize::strip_terminal_controls(s)
        .chars()
        .take(NODE_MSG_CHARS)
        .collect()
}

/// Read a JSON response, surfacing a node denial/error instead of parsing it as
/// the requested resource. On a non-2xx status it returns an `Err` carrying the
/// node's sanitized `message` plus the status; on success it parses the
/// body and propagates a parse error, so a truncated/garbage 2xx body is an error
/// rather than a silently-empty success (the denial-as-success bug #123 fixes).
/// `what` names the resource for the error text (e.g. "repo", "commits").
///
/// Callers must route gated reads through this rather than `resp.json().await?`:
/// the bare parse renders a gated 404/5xx body back as the resource.
/// Cap on the error body `read_json` reads before parsing a node's `message`.
/// Matches the capped-read bound used on the sync error path; large enough for any
/// legitimate error, small enough that a hostile node cannot exhaust memory.
const ERROR_BODY_CAP: usize = 8 * 1024;

pub(crate) async fn read_json(resp: reqwest::Response, what: &str) -> Result<Value> {
    let status = resp.status();
    if !status.is_success() {
        // Bound the error read: `resp.json()` would buffer and parse the WHOLE
        // body, so a hostile node could stream an arbitrarily large valid JSON
        // error and exhaust this process's memory (#186). Read a small capped body
        // first, then best-effort extract `message`. The error body may also be
        // non-JSON (503 degraded, 413 body-limit from middleware), so a parse miss
        // falls back to the capped raw text; an empty body to the status alone.
        let raw = read_body_capped(resp, ERROR_BODY_CAP).await.text;
        // Preserve the prior contract: surface the JSON `message` when present in
        // the capped body, else the status alone ("request failed") — a non-JSON
        // or message-less body (503 degraded, 413 body-limit) never surfaces raw
        // node bytes. A body whose `message` sits past the cap parses as truncated
        // garbage here and correctly falls back rather than being buffered whole.
        //
        // Fall back to `error` before giving up: the node's shared AppError
        // envelope carries both keys, but the task API answers with `error` alone
        // (`{"error":"task not found"}` in gitlawb-node/src/api/tasks.rs), so
        // reading only `message` blanked every `gl task` denial to the generic
        // "request failed". `sync.rs`'s hand-rolled reader already reads both; this
        // matches it.
        let msg = serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|b| {
                b.get("message")
                    .or_else(|| b.get("error"))
                    .and_then(|m| m.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "request failed".to_owned());
        anyhow::bail!("{what} failed ({status}): {}", sanitize_node_msg(&msg));
    }
    // Success: a truncated/garbage 2xx body must be an `Err`, not `Ok(Null)` that
    // a caller then renders as an empty success.
    resp.json()
        .await
        .with_context(|| format!("invalid JSON in {what} response"))
}

/// Test helper for the signed read call sites: true when the request's signature
/// verifies over the target the server actually received. A signed target that
/// differs from the wire target (an unencoded non-ASCII query value that reqwest
/// then percent-encodes, say) makes the node 401 the request.
#[cfg(test)]
pub(crate) fn signature_binds_wire_target(req: &mockito::Request) -> bool {
    use gitlawb_core::http_sig::{build_signing_string, HttpSignature};
    use std::collections::HashMap;

    let header = |name: &str| -> Option<String> {
        req.header(name)
            .first()
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let (Some(input), Some(sig_header), Some(digest)) = (
        header("signature-input"),
        header("signature"),
        header("content-digest"),
    ) else {
        return false;
    };
    let Ok(sig) = HttpSignature::parse(&input, &sig_header) else {
        return false;
    };
    let Ok(vk) = sig.key_id.to_verifying_key() else {
        return false;
    };
    let mut values = HashMap::new();
    values.insert("@method".to_string(), "GET".to_string());
    values.insert("@path".to_string(), req.path_and_query().to_string());
    values.insert("content-digest".to_string(), digest);
    let params = input.strip_prefix("sig1=").unwrap_or(&input);
    let components: Vec<&str> = sig.components.iter().map(String::as_str).collect();
    let Ok(signing_string) = build_signing_string(&components, params, &values) else {
        return false;
    };
    let Ok(arr) = <[u8; 64]>::try_from(sig.signature_bytes.as_slice()) else {
        return false;
    };
    gitlawb_core::identity::verify(&vk, signing_string.as_bytes(), &arr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;
    use mockito::Server;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes the two integration tests that touch the process-global
    /// `GITLAWB_ICAPTCHA_URL` / `GITLAWB_ICAPTCHA_INSECURE` env vars so they
    /// never race.
    static ICAPTCHA_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn headers_from_pairs(pairs: &[(&str, &str)]) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                k.parse::<reqwest::header::HeaderName>().unwrap(),
                v.parse::<reqwest::header::HeaderValue>().unwrap(),
            );
        }
        h
    }

    // ── icaptcha_cfg ────────────────────────────────────────────────────

    #[test]
    fn icaptcha_cfg_returns_some_when_both_headers_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp.clone()));
        let headers = headers_from_pairs(&[
            ("x-icaptcha-url", "https://icaptcha.gitlawb.com"),
            ("x-icaptcha-level", "3"),
        ]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.did, kp.did().to_string());
        assert_eq!(cfg.level, 3);
    }

    #[test]
    fn icaptcha_cfg_defaults_level_when_only_url_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp));
        let headers = headers_from_pairs(&[("x-icaptcha-url", "https://icaptcha.gitlawb.com")]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, icaptcha_client::DEFAULT_LEVEL);
    }

    #[test]
    fn icaptcha_cfg_defaults_url_when_only_level_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp));
        let headers = headers_from_pairs(&[("x-icaptcha-level", "5")]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, 5);
    }

    #[test]
    fn icaptcha_cfg_returns_none_without_icaptcha_headers() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = reqwest::header::HeaderMap::new();
        assert!(client.icaptcha_cfg(&headers).unwrap().is_none());
    }

    #[test]
    fn icaptcha_cfg_returns_none_with_unrelated_headers() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = headers_from_pairs(&[("content-type", "application/json")]);
        assert!(client.icaptcha_cfg(&headers).unwrap().is_none());
    }

    #[test]
    fn icaptcha_cfg_errors_when_no_keypair() {
        let client = NodeClient::new("http://localhost", None);
        let headers = headers_from_pairs(&[("x-icaptcha-level", "3")]);
        let err = client.icaptcha_cfg(&headers).unwrap_err();
        assert!(err.to_string().contains("identity keypair"));
    }

    #[test]
    fn icaptcha_cfg_ignores_unparseable_level() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = headers_from_pairs(&[
            ("x-icaptcha-url", "https://icaptcha.gitlawb.com"),
            ("x-icaptcha-level", "not-a-number"),
        ]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, icaptcha_client::DEFAULT_LEVEL);
    }

    // ── send_once ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_once_attaches_proof_header_when_provided() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("x-icaptcha-proof", "test.proof.token")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", Some("test.proof.token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_omits_proof_header_when_not_provided() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("x-icaptcha-proof", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_signs_request_when_keypair_present() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("Signature", mockito::Matcher::Any)
            .match_header("Signature-Input", mockito::Matcher::Any)
            .match_header("Content-Digest", mockito::Matcher::Any)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_does_not_sign_when_no_keypair() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("Signature", mockito::Matcher::Missing)
            .match_header("Signature-Input", mockito::Matcher::Missing)
            .match_header("Content-Digest", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    // ── send_signed ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_signed_returns_non_icaptcha_403_without_retry() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"forbidden"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        m.assert();
    }

    #[tokio::test]
    async fn send_signed_returns_first_response_on_success() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        m.assert();
    }

    #[tokio::test]
    async fn send_signed_handles_405_not_icaptcha() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(405)
            .with_body(r#"{"error":"method not allowed"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 405);
        m.assert();
    }

    // ── send_signed signature-ledger rejections ─────────────────────────

    /// Mock one node reply and send a signed POST through `send_signed`,
    /// asserting the node was called exactly once (i.e. nothing retried).
    async fn send_signed_once(
        status: usize,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (Result<reqwest::Response>, mockito::ServerGuard) {
        let mut server = Server::new_async().await;
        let mut m = server
            .mock("POST", "/api/v1/repos")
            .with_status(status)
            .with_header("content-type", "application/json");
        for (k, v) in headers {
            m = m.with_header(*k, v);
        }
        let m = m.with_body(body).expect(1).create_async().await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client.send_signed("POST", "/api/v1/repos", b"{}").await;
        m.assert_async().await;
        (resp, server)
    }

    #[tokio::test]
    async fn send_signed_errors_on_replayed_signature_and_never_retries() {
        let (resp, _server) = send_signed_once(
            409,
            &[("x-gitlawb-error", "signature_replayed")],
            r#"{"error":"signature_replayed","message":"this signature was already used"}"#,
        )
        .await;
        let err = resp
            .expect_err("a replayed signature must surface as an error, not Ok(409)")
            .to_string();
        assert!(err.contains("signature_replayed"), "got: {err}");
        assert!(
            err.contains("already"),
            "message must tell the user the node already applied it, got: {err}"
        );
        assert!(
            err.contains("this signature was already used"),
            "must surface the node's message, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_ledger_full_and_never_retries() {
        let (resp, _server) = send_signed_once(
            429,
            &[("x-gitlawb-error", "signature_ledger_full")],
            r#"{"error":"signature_ledger_full","message":"ledger at capacity"}"#,
        )
        .await;
        let err = resp
            .expect_err("a full ledger must surface as an error")
            .to_string();
        assert!(err.contains("signature_ledger_full"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_ledger_unavailable_and_never_retries() {
        let (resp, _server) = send_signed_once(
            503,
            &[("x-gitlawb-error", "signature_ledger_unavailable")],
            r#"{"error":"signature_ledger_unavailable","message":"ledger down"}"#,
        )
        .await;
        let err = resp
            .expect_err("an unavailable ledger must surface as an error")
            .to_string();
        assert!(err.contains("signature_ledger_unavailable"), "got: {err}");
    }

    #[tokio::test]
    async fn send_signed_errors_on_nonce_required_and_never_retries() {
        let (resp, _server) = send_signed_once(
            400,
            &[("x-gitlawb-error", "signature_nonce_required")],
            r#"{"error":"signature_nonce_required","message":"this node requires a nonce"}"#,
        )
        .await;
        let err = resp
            .expect_err("a nonce-less signature must surface as an error, not Ok(400)")
            .to_string();
        assert!(err.contains("signature_nonce_required"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_identity_missing_and_never_retries() {
        let (resp, _server) = send_signed_once(
            500,
            &[("x-gitlawb-error", "signature_identity_missing")],
            r#"{"error":"signature_identity_missing","message":"no verified identity"}"#,
        )
        .await;
        let err = resp
            .expect_err("a missing signature identity must surface as an error, not Ok(500)")
            .to_string();
        assert!(err.contains("signature_identity_missing"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_nonce_too_short_and_never_retries() {
        let (resp, _server) = send_signed_once(
            400,
            &[("x-gitlawb-error", "signature_nonce_too_short")],
            r#"{"error":"signature_nonce_too_short","message":"the nonce must be at least 16 characters"}"#,
        )
        .await;
        let err = resp
            .expect_err("a too-short nonce must surface as an error, not Ok(400)")
            .to_string();
        assert!(err.contains("signature_nonce_too_short"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
        assert!(
            err.contains("the nonce must be at least 16 characters"),
            "must surface the node's message, got: {err}"
        );
    }

    /// Two unrelated conditions now share 429: the node's per-client flood
    /// brake and the spent-signature ledger's per-identity cap. They must reach
    /// the user as different errors, and neither may be retried.
    #[tokio::test]
    async fn send_signed_tells_a_rate_limit_brake_apart_from_a_full_ledger() {
        let (brake, _s1) = send_signed_once(
            429,
            &[("x-gitlawb-error", "rate_limited")],
            r#"{"error":"rate_limited","message":"rate limit exceeded — try again later"}"#,
        )
        .await;
        let brake = brake
            .expect_err("a rate-limit brake must surface as an error, not Ok(429)")
            .to_string();

        let (ledger, _s2) = send_signed_once(
            429,
            &[("x-gitlawb-error", "signature_ledger_full")],
            r#"{"error":"signature_ledger_full","message":"ledger at capacity"}"#,
        )
        .await;
        let ledger = ledger
            .expect_err("a full ledger must surface as an error")
            .to_string();

        assert!(brake.contains("rate_limited"), "got: {brake}");
        assert!(
            !brake.contains("signature_ledger_full"),
            "a brake must not be described as a ledger denial: {brake}"
        );
        assert!(
            brake.contains("a rate limit on the node"),
            "the brake hint must say a rate limit fired: {brake}"
        );
        // The code is shared by the per-IP brake, the per-DID quota and the
        // in-handler limits, so the hint must not claim which one fired.
        assert!(
            !brake.contains("network address") && !brake.contains("not about your identity"),
            "the brake hint must stay neutral about which limiter fired: {brake}"
        );
        assert!(ledger.contains("signature_ledger_full"), "got: {ledger}");
        assert!(
            !ledger.contains("rate_limited"),
            "a ledger denial must not be described as a brake: {ledger}"
        );
        assert!(
            ledger.contains("unexpired signatures"),
            "the ledger hint must say it is keyed on the identity: {ledger}"
        );
        assert_ne!(brake, ledger);
    }

    /// Every signature denial the node can return, as (status, code). Derived
    /// from the shared enum rather than retyped, so it cannot drift from what
    /// the node emits.
    fn all_denials() -> Vec<(usize, &'static str)> {
        NodeDenial::ALL
            .iter()
            .map(|d| (d.status() as usize, d.as_str()))
            .collect()
    }

    #[tokio::test]
    async fn send_signed_errors_on_every_denial_carrying_the_header() {
        for (status, code) in all_denials() {
            let body = format!(r#"{{"error":"{code}","message":"node says no"}}"#);
            let (resp, _server) =
                send_signed_once(status, &[("x-gitlawb-error", code)], &body).await;
            let err = match resp {
                Ok(r) => panic!("{code} returned Ok({}) instead of an error", r.status()),
                Err(e) => e.to_string(),
            };
            assert!(err.contains(code), "wrong code surfaced for {code}: {err}");
            assert!(
                err.contains("node says no"),
                "node message dropped for {code}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn send_signed_does_not_see_a_denial_carried_only_in_the_body() {
        // Documents a known limit rather than a wanted behaviour: detection is
        // header-keyed, so a proxy stripping `x-gitlawb-error` leaves the denial
        // to the caller (see `signature_rejection`). The callers that must not
        // read one as a success handle it themselves: `gl init` compares
        // `error` from the body, `gl task` checks the status before parsing.
        for (status, code) in all_denials() {
            let body = format!(r#"{{"error":"{code}","message":"node says no"}}"#);
            let (resp, _server) = send_signed_once(status, &[], &body).await;
            let resp = resp.unwrap_or_else(|e| panic!("{code} without the header: {e}"));
            assert_eq!(resp.status().as_u16(), status as u16);
            // The body is untouched, which is what lets the caller decide.
            let payload: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(payload["error"], code);
        }
    }

    #[tokio::test]
    async fn send_signed_sanitizes_and_caps_a_hostile_denial_message() {
        // The message that exists to say "your write was REFUSED" must not be
        // able to clear the screen and print a fake success line.
        let hostile = format!(
            "\u{1b}[2J\u{1b}[31mSUCCESS: task created\u{202e}{}",
            "A".repeat(5000)
        );
        let body = serde_json::json!({
            "error": "signature_replayed",
            "message": hostile,
        })
        .to_string();
        let (resp, _server) =
            send_signed_once(409, &[("x-gitlawb-error", "signature_replayed")], &body).await;
        let err = resp.expect_err("a replay must error").to_string();
        assert!(
            !err.contains('\u{1b}'),
            "ESC leaked to the terminal: {err:?}"
        );
        assert!(
            !err.contains('\u{202e}'),
            "RLO bidi override leaked: {err:?}"
        );
        assert!(err.contains("signature_replayed"), "got: {err}");
        assert!(
            err.chars().count() < 600,
            "denial message not bounded: {} chars",
            err.chars().count()
        );
    }

    #[tokio::test]
    async fn send_signed_returns_repo_exists_409_unchanged() {
        // The pre-existing 409. Callers (`gl init`, `gl repo create`) inspect the
        // status themselves, so it must keep returning Ok(resp).
        let (resp, _server) = send_signed_once(
            409,
            &[("x-node-marker", "kept")],
            r#"{"error":"repo_exists","message":"already exists"}"#,
        )
        .await;
        let resp = resp.expect("a non-replay 409 must still return Ok");
        assert_eq!(resp.status(), 409);
        // Status, headers and body must all survive the denial check: `gl init`
        // reads the code out of the body to decide "already exists, continue".
        assert_eq!(resp.headers().get("x-node-marker").unwrap(), "kept");
        let payload: serde_json::Value = resp.json().await.expect("body must survive intact");
        assert_eq!(payload["error"], "repo_exists");
        assert_eq!(payload["message"], "already exists");
    }

    #[tokio::test]
    async fn send_signed_returns_409_with_other_error_header_unchanged() {
        // Only the three signature_* codes are converted; any other
        // x-gitlawb-error on a 409 is left to the caller.
        let (resp, _server) = send_signed_once(
            409,
            &[("x-gitlawb-error", "repo_exists")],
            r#"{"error":"repo_exists"}"#,
        )
        .await;
        let resp = resp.expect("an unrelated 409 error code must still return Ok");
        assert_eq!(resp.status(), 409);
    }

    #[tokio::test]
    async fn send_signed_returns_401_invalid_signature_unchanged() {
        let (resp, _server) = send_signed_once(
            401,
            &[("x-gitlawb-error", "invalid_signature")],
            r#"{"error":"invalid_signature"}"#,
        )
        .await;
        let resp = resp.expect("a 401 must still return Ok, distinct from a replay error");
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn send_signed_returns_401_unsigned_request_unchanged() {
        // An unsigned write is rejected with human_detected; the client prints a
        // hint and returns the response, and must not be mistaken for a replay.
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/repos")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_header("x-gitlawb-error", "human_detected")
            .with_body(r#"{"error":"human_detected"}"#)
            .expect(1)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_signed("POST", "/api/v1/repos", b"{}")
            .await
            .expect("an unsigned-request rejection must still return Ok");
        assert_eq!(resp.status(), 401);
        m.assert_async().await;
    }

    #[tokio::test]
    async fn send_signed_does_not_convert_a_409_on_another_status() {
        // The header alone must not trigger the conversion: the status has to
        // match too, so a 200 carrying a stray header stays a success.
        let (resp, _server) = send_signed_once(
            200,
            &[("x-gitlawb-error", "signature_replayed")],
            r#"{"ok":true}"#,
        )
        .await;
        let resp = resp.expect("a 200 must stay Ok regardless of headers");
        assert_eq!(resp.status(), 200);
    }

    // ── send_signed iCaptcha retry (full integration) ────────────────────

    /// Set GITLAWB_ICAPTCHA_URL and GITLAWB_ICAPTCHA_INSECURE so the iCaptcha
    /// client trusts a local mockito HTTP server, restoring any prior values on
    /// drop so a test run launched with those variables keeps working.
    /// Holds [`ICAPTCHA_ENV_LOCK`] for its lifetime so concurrent tests don't
    /// race on the process-global env vars.
    struct IcaptchaEnv {
        _lock: MutexGuard<'static, ()>,
        prev_url: Option<OsString>,
        prev_insecure: Option<OsString>,
    }

    impl IcaptchaEnv {
        fn new(url: &str) -> Self {
            let lock = ICAPTCHA_ENV_LOCK.lock().unwrap();
            let prev_url = std::env::var_os("GITLAWB_ICAPTCHA_URL");
            let prev_insecure = std::env::var_os("GITLAWB_ICAPTCHA_INSECURE");
            std::env::set_var("GITLAWB_ICAPTCHA_URL", url);
            std::env::set_var("GITLAWB_ICAPTCHA_INSECURE", "1");
            IcaptchaEnv {
                _lock: lock,
                prev_url,
                prev_insecure,
            }
        }
    }

    impl Drop for IcaptchaEnv {
        fn drop(&mut self) {
            match self.prev_url.take() {
                Some(v) => std::env::set_var("GITLAWB_ICAPTCHA_URL", v),
                None => std::env::remove_var("GITLAWB_ICAPTCHA_URL"),
            }
            match self.prev_insecure.take() {
                Some(v) => std::env::set_var("GITLAWB_ICAPTCHA_INSECURE", v),
                None => std::env::remove_var("GITLAWB_ICAPTCHA_INSECURE"),
            }
        }
    }

    /// Set up a mock iCaptcha server that responds to challenge + answer.
    /// `hits` sets the expected call count for both endpoints so the test can
    /// verify the solve loop was entered the correct number of times.
    struct MockIcaptcha {
        challenge: mockito::Mock,
        answer: mockito::Mock,
        _guard: IcaptchaEnv,
        url: String,
    }

    impl MockIcaptcha {
        async fn new(server: &mut mockito::ServerGuard, hits: usize) -> Self {
            let url = server.url();
            let guard = IcaptchaEnv::new(&url);
            let challenge = server
                .mock("POST", "/v1/challenge")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"challengeId":"c1","type":"arithmetic","difficulty":1,"prompt":"What is 1 + 1?","token":"tk1"}"#,
                )
                .expect(hits)
                .create_async()
                .await;
            let answer = server
                .mock("POST", "/v1/answer")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"status":"passed","proof":"mock.proof"}"#)
                .expect(hits)
                .create_async()
                .await;
            Self {
                challenge,
                answer,
                _guard: guard,
                url,
            }
        }
    }

    #[tokio::test]
    async fn send_signed_solves_icaptcha_and_retries_to_success() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let ic = MockIcaptcha::new(&mut icaptcha, 1).await;

        let n1 = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(1)
            .create_async()
            .await;
        let n2 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", "mock.proof")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        n1.assert();
        n2.assert();
        ic.challenge.assert();
        ic.answer.assert();
    }

    #[tokio::test]
    async fn send_signed_signs_the_icaptcha_retry_afresh() {
        // What makes the 403 retry safe is that it is a NEW signature, not a
        // resend: `verify_request` runs inside the handler, so the ledger was
        // already charged for the first attempt. Each `send_once` signs again
        // and `sign_request` draws a fresh nonce, so the retry lands on a ledger
        // key the node has not seen. Pin that: the two attempts must not carry
        // the same `Signature-Input`.
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let ic = MockIcaptcha::new(&mut icaptcha, 1).await;

        let seen: std::sync::Arc<Mutex<Vec<String>>> = Default::default();
        let record = {
            let seen = seen.clone();
            move |req: &mockito::Request| {
                let v = req
                    .header("signature-input")
                    .first()
                    .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned())
                    .unwrap_or_default();
                seen.lock().unwrap().push(v);
                true
            }
        };

        let n1 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", mockito::Matcher::Missing)
            .match_request(record.clone())
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(1)
            .create_async()
            .await;
        let n2 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", "mock.proof")
            .match_request(record)
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        n1.assert();
        n2.assert();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "expected two attempts, got {seen:?}");
        assert!(
            !seen[0].is_empty() && !seen[1].is_empty(),
            "both attempts must be signed: {seen:?}"
        );
        assert_ne!(
            seen[0], seen[1],
            "the retry reused the first signature, so it would land on the same \
             ledger key the node already spent"
        );
    }

    #[tokio::test]
    async fn send_signed_returns_403_after_icaptcha_retries_exhausted() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        // MAX_ICAPTCHA_RETRIES = 2, so with every call returning 403 with
        // iCaptcha headers the solve loop runs twice (2 challenge + 2 answer).
        let ic = MockIcaptcha::new(&mut icaptcha, 2).await;

        // The original + 2 retries = 3 node calls before the loop gives up.
        let n = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(3)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        n.assert();
        ic.challenge.assert();
        ic.answer.assert();
    }

    // ── redirect policy ─────────────────────────────────────────────────

    /// The signed headers must not survive a redirect off the node's origin.
    ///
    /// reqwest strips only `Authorization`, `Cookie`, `Proxy-Authorization` and
    /// `WWW-Authenticate` across hosts, so `Signature` and `Signature-Input` used to
    /// ride a 302 straight to whatever origin the node named. The signature binds
    /// `@method`, `@path` and `content-digest` and nothing about the authority, so the
    /// receiving host holds a credential that reads path-scoped objects as the caller
    /// at any node until the clock-skew window closes.
    ///
    /// Two mockito servers are two ports on one host, which is exactly the boundary
    /// this policy draws (and the one reqwest's own header stripping draws). The
    /// second server answers everything and expects nothing: a followed redirect
    /// fails the expectation whether or not the signature came with it. MUTATION
    /// (RED): drop the `.redirect(...)` line and the second server is hit.
    #[tokio::test]
    async fn cross_origin_redirect_is_not_followed() {
        let mut elsewhere = Server::new_async().await;
        let never = elsewhere
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("bytes from the redirect target")
            .expect(0)
            .create_async()
            .await;
        let signature_seen = elsewhere
            .mock("GET", mockito::Matcher::Any)
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(302)
            .with_header("location", &format!("{}/api/v1/thing", elsewhere.url()))
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        assert_eq!(
            resp.status(),
            302,
            "a refused redirect stops rather than errors, so the caller sees the 3xx \
             and reports it through the status path it already has"
        );
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains("bytes from the redirect target"),
            "the redirect target's bytes must never reach the caller, got: {body}"
        );
        bounce.assert_async().await;
        never.assert_async().await;
        signature_seen.assert_async().await;
    }

    /// A node redirecting to itself is same-origin, so the origin predicate follows it
    /// every time and only the chain bound ends the loop. Deleting the bound left the
    /// whole suite green, because nothing here had ever built a cycle.
    ///
    /// It has a second job now. A redirect back to the identical path and query is the
    /// only same-origin hop the predicate still follows, so the eleven hits below are
    /// also this crate's executed proof that such a hop IS followed. The old positive
    /// fixture drove a trailing-slash rewrite, which the request-target rule refuses,
    /// and an http-to-https upgrade cannot be mocked over mockito's plain http.
    ///
    /// The route answers 301 pointing back at itself. Bounded, the handler is hit
    /// once for the original request plus `MAX_REDIRECTS` follows and the call returns
    /// the 301 (a refused redirect stops rather than errors). Unbounded, it runs until
    /// the client's total request timeout cuts it off, which is a 30 second spin at the
    /// shipped value and a request per round trip for the node.
    ///
    /// MUTATION (RED): delete the `previous().len()` check.
    #[tokio::test]
    async fn a_self_redirect_stops_at_the_chain_bound() {
        let mut node = Server::new_async().await;
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let loop_route = node
            .mock("GET", "/api/v1/loop")
            .with_status(301)
            .with_header("location", "/api/v1/loop")
            .with_body_from_request(move |_req| {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Vec::new()
            })
            .expect_at_least(1)
            .create_async()
            .await;

        let client = NodeClient::with_timeout(
            node.url(),
            Some(test_keypair()),
            std::time::Duration::from_secs(5),
        );
        let resp = client
            .get_signed("/api/v1/loop")
            .await
            .expect("the bound must end the chain, not the timeout");

        assert_eq!(
            resp.status(),
            301,
            "the chain ends by refusing the next hop, so the last 3xx is what comes back"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            gitlawb_core::redirect::MAX_REDIRECTS + 1,
            "one original request plus MAX_REDIRECTS follows, matching what \
             Policy::limited(MAX_REDIRECTS) would have permitted"
        );
        loop_route.assert_async().await;
    }

    /// A same-origin hop that REWRITES the request-target is refused, even though the
    /// origin never changes.
    ///
    /// The signature binds `@path` as the literal path-and-query the client signed, and
    /// the node rebuilds it from the URI it received. A `/api/v1/thing` to
    /// `/api/v1/thing/` bounce therefore presents a signature over a target the node
    /// never saw, and every signed read behind such a proxy 401s. Refusing the hop
    /// hands the caller the 3xx that names what happened instead.
    ///
    /// The target mock expects zero hits and is asserted: mockito only checks
    /// `.expect(N)` when `.assert()` runs, so an unbound or unasserted mock passes
    /// vacuously.
    #[tokio::test]
    async fn same_origin_path_changing_redirect_is_refused() {
        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(301)
            .with_header("location", "/api/v1/thing/")
            .expect(1)
            .create_async()
            .await;
        let target = node
            .mock("GET", "/api/v1/thing/")
            .with_status(200)
            .with_body("bytes from the rewritten target")
            .expect(0)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        assert_eq!(
            resp.status(),
            301,
            "a refused redirect stops rather than errors, so the caller sees the 3xx \
             and reports it through the status path it already has"
        );
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains("bytes from the rewritten target"),
            "the rewritten target's bytes must never reach the caller, got: {body}"
        );
        bounce.assert_async().await;
        target.assert_async().await;
    }

    // ── the node's own verification, run over what the client actually sent ──

    /// What the verifying mock made of a request that reached it.
    ///
    /// The empty slot (`None`) is its own state and means the mock was never hit at
    /// all, which is what the refusal test asserts. It must stay distinguishable from
    /// [`Verdict::WrongIdentity`], because "nobody verified anything" and "something
    /// verified against the wrong key" are opposite findings.
    ///
    /// The payloads are read through `Debug` in the assertion messages and nowhere
    /// else, which the dead-code pass does not count; they carry the detail that makes
    /// a failure legible, so they stay.
    #[derive(Debug)]
    #[allow(dead_code)]
    enum Verdict {
        /// The chain accepted the signature AND the key it resolved is the test's DID.
        Accepted,
        /// The chain refused it. Carries the error so a failure reads as the actual
        /// rejection rather than a bare hit count.
        Rejected(String),
        /// The chain accepted a signature made by somebody else. A key resolved from
        /// the parsed `key_id` is read out of the artifact under verification, so an
        /// accept on it alone proves consistency, never authenticity.
        WrongIdentity { expected: String, got: String },
    }

    /// The node's `require_signature` verification, over a request this crate did not
    /// build: parse the headers, recompute the content-digest from the body, rebuild
    /// the signing string over `@method`/`@path`/`content-digest`, Ed25519-verify.
    /// Returns the DID the signature resolved to, so a caller can pin the identity.
    ///
    /// A hand-copy of its twin in `crates/git-remote-gitlawb/src/main.rs`, which gl
    /// cannot import (`git-remote-gitlawb` is a binary crate and this is its test
    /// module). Keep the two textually identical apart from the mockito seam around
    /// them, so an edit to one is visibly an edit to both.
    ///
    /// The production verifier both copies mirror is `crate::auth::require_signature` in
    /// `crates/gitlawb-node/src/auth/mod.rs`. This is a re-implementation, not a call, so
    /// an edit to that middleware has to land here too: otherwise the copies drift and
    /// this test keeps passing against a rule the node has stopped applying.
    ///
    /// It asserts internally, which is deliberate but constrains its callers: inside
    /// `with_body_from_request` those assertions fire on the server thread and reach
    /// the client as a transport error, not as a recorded verdict. So the identity
    /// check lives in the caller as a [`Verdict`] variant, never as an assert in here.
    fn node_verifies(
        method: &str,
        path_and_query: &str,
        body: &[u8],
        sig_input: &str,
        sig_header: &str,
        content_digest: &str,
    ) -> anyhow::Result<String> {
        use gitlawb_core::http_sig::{build_signing_string, compute_content_digest, HttpSignature};
        use gitlawb_core::identity::verify;
        use std::collections::HashMap;

        let sig = HttpSignature::parse(sig_input, sig_header)?;
        sig.check_created()?;
        assert!(
            sig.missing_components().is_empty(),
            "signature must cover all required components"
        );
        assert_eq!(sig.alg, "ed25519");
        assert_eq!(
            content_digest,
            compute_content_digest(body),
            "content-digest must match the body"
        );
        let vk = sig.key_id.to_verifying_key()?;
        let mut values = HashMap::new();
        values.insert("@method".to_string(), method.to_uppercase());
        values.insert("@path".to_string(), path_and_query.to_string());
        values.insert("content-digest".to_string(), content_digest.to_string());
        let sig_params_value = sig_input.strip_prefix("sig1=").unwrap_or(sig_input);
        let components: Vec<&str> = sig.components.iter().map(String::as_str).collect();
        let signing_string = build_signing_string(&components, sig_params_value, &values)?;
        let sig_array: [u8; 64] = sig.signature_bytes.as_slice().try_into()?;
        verify(&vk, signing_string.as_bytes(), &sig_array)?;
        Ok(sig.key_id.to_string())
    }

    /// Pull a header value off a received mockito request, or explain which one the
    /// client failed to send.
    fn received_header(req: &mockito::Request, name: &str) -> String {
        req.header(name)
            .first()
            .unwrap_or_else(|| panic!("the client sent no {name} header"))
            .to_str()
            .unwrap()
            .to_string()
    }

    /// Run [`node_verifies`] over a GET that arrived at the mock and record what the
    /// node would have made of it, pinned to `expected_did`.
    fn record_get_verdict(
        req: &mockito::Request,
        expected_did: &str,
        slot: &std::sync::Arc<std::sync::Mutex<Option<Verdict>>>,
    ) {
        let verdict = match node_verifies(
            "GET",
            req.path_and_query(),
            b"",
            &received_header(req, "signature-input"),
            &received_header(req, "signature"),
            &received_header(req, "content-digest"),
        ) {
            Ok(did) if did == expected_did => Verdict::Accepted,
            Ok(did) => Verdict::WrongIdentity {
                expected: expected_did.to_string(),
                got: did,
            },
            Err(e) => Verdict::Rejected(e.to_string()),
        };
        *slot.lock().unwrap() = Some(verdict);
    }

    /// The finding's repro, now a guard: a rewritten same-origin target must never
    /// receive the signature, and the proof is the node's own verification, not a hit
    /// count.
    ///
    /// The target mock runs the full `require_signature` chain over the request it
    /// receives. Post-fix the hop is refused, so the slot stays empty. Pre-fix the hop
    /// is followed and the slot records the Ed25519 rejection of a signature made over
    /// `/api/v1/thing` and presented at `/api/v1/thing/`, which is the 401 an operator
    /// behind such a proxy actually sees. The verdict is asserted first, so a failure
    /// speaks about verification rather than about reachability.
    ///
    /// Its paired positive control is
    /// `a_direct_signed_get_verifies_under_the_node_verifier`: without it, an empty
    /// slot would be satisfied just as well by a harness that can never record
    /// anything.
    #[tokio::test]
    async fn a_rewritten_target_never_receives_the_signature() {
        let kp = test_keypair();
        let expected_did = kp.did().to_string();
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<Verdict>));

        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(301)
            .with_header("location", "/api/v1/thing/")
            .expect(1)
            .create_async()
            .await;
        let recorder = slot.clone();
        let did_for_target = expected_did.clone();
        let target = node
            .mock("GET", "/api/v1/thing/")
            .with_status(200)
            .with_body_from_request(move |req| {
                record_get_verdict(req, &did_for_target, &recorder);
                Vec::new()
            })
            .expect(0)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(kp));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        let verdict = slot.lock().unwrap().take();
        assert!(
            verdict.is_none(),
            "the node's own verifier must never see this request: the signature covers \
             /api/v1/thing and the rewritten target is /api/v1/thing/, so what arrives \
             there is a stale request-target; recorded verdict: {verdict:?}"
        );
        assert_eq!(
            resp.status(),
            301,
            "the caller sees the 3xx, not the rewritten target's answer"
        );
        bounce.assert_async().await;
        target.assert_async().await;
    }

    /// The positive control for the test above, and the proof that the client signs
    /// the query it sends.
    ///
    /// A direct signed GET, no redirect anywhere, through the same verifying mock. The
    /// verdict must be `Accepted`, which is what makes the refusal test's empty slot
    /// attributable to the refusal rather than to a harness that cannot record. The
    /// path carries a query, so a client that signed the bare path would land here as
    /// `Rejected`.
    #[tokio::test]
    async fn a_direct_signed_get_verifies_under_the_node_verifier() {
        let kp = test_keypair();
        let expected_did = kp.did().to_string();
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<Verdict>));

        let mut node = Server::new_async().await;
        let recorder = slot.clone();
        let did_for_target = expected_did.clone();
        let route = node
            .mock("GET", "/api/v1/thing?x=1")
            .with_status(200)
            .with_body_from_request(move |req| {
                record_get_verdict(req, &did_for_target, &recorder);
                Vec::new()
            })
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(kp));
        let resp = client.get_signed("/api/v1/thing?x=1").await.unwrap();
        assert_eq!(resp.status(), 200);

        let verdict = slot.lock().unwrap().take();
        assert!(
            matches!(verdict, Some(Verdict::Accepted)),
            "a direct signed GET must verify under the node's own chain and resolve to \
             {expected_did}, or the refusal test's empty slot proves nothing; recorded \
             verdict: {verdict:?}"
        );
        route.assert_async().await;
    }

    // ── read_body_capped ────────────────────────────────────────────────

    /// A body whose read FAILS mid-stream must be distinguishable from a body that
    /// ended. Both used to leave through the same `_ => break`, so a 500 whose body
    /// died in transit produced an empty message and the caller was told
    /// `node returned 500: ` with nothing after the colon.
    ///
    /// The fixture is a raw listener that promises 64 bytes in `Content-Length`,
    /// writes 5, and closes. mockito cannot express that: it always completes the
    /// response it advertises. MUTATION (RED): restore the single `_ => break` arm
    /// (or hard-code `read_failed: false`) and the flag reads false.
    #[tokio::test]
    async fn read_body_capped_flags_a_mid_body_read_failure() {
        let addr = spawn_short_body_listener().await;
        let resp = reqwest::get(format!("http://{addr}/truncated"))
            .await
            .expect("headers arrive before the body is cut");
        let body = read_body_capped(resp, 8192).await;

        assert!(
            body.read_failed,
            "a body cut off mid-stream must be reported as a failed read, not as a \
             body that ended: got {:?}",
            body.text
        );
        assert!(
            !body.truncated,
            "the cap did not cut this one; 5 bytes are nowhere near 8 KiB"
        );
    }

    /// The must-not half: a body that ends cleanly must NOT be flagged, or the flag
    /// means nothing and every terminal starts claiming the node went quiet.
    #[tokio::test]
    async fn read_body_capped_does_not_flag_a_clean_body() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/ok")
            .with_status(500)
            .with_body("node said this")
            .create_async()
            .await;
        let resp = reqwest::get(format!("{}/ok", server.url())).await.unwrap();
        let body = read_body_capped(resp, 8192).await;

        assert_eq!(body.text, "node said this");
        assert!(!body.read_failed, "a complete body is not a failed read");
        assert!(!body.truncated, "a complete body is not a truncated one");
    }

    /// Answer one request with headers promising more body than gets written, then
    /// close the connection. Returns the listener's address.
    async fn spawn_short_body_listener() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 64\r\n\r\nshort")
                .await;
            let _ = sock.flush().await;
            // Drop closes the socket with 59 of the promised bytes never sent.
        });
        addr
    }

    // ── total request timeout ───────────────────────────────────────────

    /// The client's timeout is a TOTAL request timeout, so it bounds a download and
    /// not just the handshake. `gl ipfs get`'s documentation leans on exactly that:
    /// the wall-clock deadline covers the search and deliberately stops at the
    /// response headers, and this timeout is the only thing left bounding the body.
    ///
    /// Driven at 250ms through `with_timeout`, the seam `new` itself calls with
    /// `TOTAL_REQUEST_TIMEOUT`, because a test at the shipped 30s has no place in this
    /// suite. What that costs is the value; what it proves is the SHAPE, which is the
    /// part in doubt: that the deadline keeps running once the headers have landed. A
    /// timeout that covered only the handshake would let this request hang until the
    /// listener gives up.
    #[tokio::test]
    async fn total_timeout_cuts_off_a_body_that_outruns_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            // Headers land immediately, then the body stalls indefinitely.
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\nfirst")
                .await;
            let _ = sock.flush().await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        let client = NodeClient::with_timeout(
            format!("http://{addr}"),
            None,
            std::time::Duration::from_millis(250),
        );
        let started = std::time::Instant::now();
        let resp = client.get("/slow").await.expect("headers arrive promptly");
        assert_eq!(
            resp.status(),
            200,
            "the stall is in the body, not the status"
        );
        let err = resp
            .bytes()
            .await
            .expect_err("a body still arriving past the total timeout must be cut off");
        let elapsed = started.elapsed();

        assert!(
            err.is_timeout(),
            "the body read must end in a timeout, got: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the timeout must fire on its own schedule, not wait out the listener; \
             took {elapsed:?}"
        );
    }

    #[test]
    fn shipped_client_uses_the_documented_total_timeout() {
        // The scaled-down test above proves the shape at 250ms. This pins the value
        // `new` actually ships, so the two together cover the documented behaviour.
        assert_eq!(TOTAL_REQUEST_TIMEOUT, std::time::Duration::from_secs(30));
    }

    #[test]
    fn sanitize_strips_controls_bidi_and_caps_length() {
        // C0 (ESC/BEL) and the Cf bidi override (U+202E) are both removed; the
        // printable text survives. (Note: a stripped ESC leaves any following
        // "[31m" as inert literal text — that is the point, so the input here
        // avoids that residue to keep the expectation unambiguous.)
        let out = sanitize_node_msg("a\u{1b}\u{07}b\u{202e}c");
        assert!(
            !out.chars().any(|c| c.is_control()),
            "control char leaked: {out:?}"
        );
        assert!(
            !out.contains('\u{202e}'),
            "RLO bidi override leaked: {out:?}"
        );
        assert_eq!(out, "abc");
        // Length is capped at 200 chars regardless of input size.
        let long = "x".repeat(250);
        assert_eq!(sanitize_node_msg(&long).chars().count(), 200);
    }

    #[test]
    fn sanitize_preserves_legitimate_and_rtl_text() {
        // Must not over-strip: a plain word, a genuine RTL SCRIPT letter (Arabic
        // U+0627, category Lo — NOT a format char), and ZWJ (U+200D, a legitimate
        // Cf char, e.g. emoji sequences) all survive. Guards the shared predicate
        // against being widened into a blanket Cf stripper.
        let out = sanitize_node_msg("ok \u{0627}\u{200D}b");
        assert_eq!(out, "ok \u{0627}\u{200D}b");
    }

    // ── #413 plaintext-remote signing guard ──────────────────────────────

    /// Holds [`ICAPTCHA_ENV_LOCK`] while it points `GITLAWB_ALLOW_INSECURE_HTTP`
    /// at `value` (or removes it), restoring the prior value on drop.
    struct InsecureHttpEnv {
        _lock: MutexGuard<'static, ()>,
        prev: Option<OsString>,
    }

    impl InsecureHttpEnv {
        fn set(value: Option<&str>) -> Self {
            let lock = ICAPTCHA_ENV_LOCK.lock().unwrap();
            let prev = std::env::var_os("GITLAWB_ALLOW_INSECURE_HTTP");
            match value {
                Some(v) => std::env::set_var("GITLAWB_ALLOW_INSECURE_HTTP", v),
                None => std::env::remove_var("GITLAWB_ALLOW_INSECURE_HTTP"),
            }
            InsecureHttpEnv { _lock: lock, prev }
        }
    }

    impl Drop for InsecureHttpEnv {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("GITLAWB_ALLOW_INSECURE_HTTP", v),
                None => std::env::remove_var("GITLAWB_ALLOW_INSECURE_HTTP"),
            }
        }
    }

    #[test]
    fn insecure_remote_flags_only_plaintext_off_machine() {
        // Loopback of every spelling is this machine and exempt.
        for url in [
            "http://localhost",
            "http://localhost:7545",
            "http://127.0.0.1:7545",
            "http://127.0.0.2",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
            // https to anywhere is encrypted; the guard is not its business.
            "https://node.gitlawb.com",
            // Not a URL: unparseable input fails later with its own error.
            "not a url",
        ] {
            assert!(!is_insecure_remote(url), "{url} must not be flagged");
        }
        // Plaintext http off this machine is the flagged shape.
        for url in [
            "http://10.0.0.36:7777",
            "http://node.example.com",
            "http://[fd00::1]",
            "http://127.0.0.1.evil.example",
        ] {
            assert!(is_insecure_remote(url), "{url} must be flagged");
        }
    }

    #[test]
    fn signing_transport_refuses_plaintext_remote() {
        let err = ensure_signing_transport("http://10.0.0.36:7777", false).unwrap_err();
        assert!(
            err.to_string().contains("plaintext http")
                && err.to_string().contains("GITLAWB_ALLOW_INSECURE_HTTP"),
            "the refusal names the risk and the opt-in: {err}"
        );
        // Opted in, loopback, and https all pass.
        assert!(ensure_signing_transport("http://10.0.0.36:7777", true).is_ok());
        assert!(ensure_signing_transport("http://localhost:7545", false).is_ok());
        assert!(ensure_signing_transport("https://node.gitlawb.com", false).is_ok());
    }

    /// A signed call against a plaintext remote errors out before any request
    /// leaves; the refusal must beat the send. `.invalid` NXDOMAINs fast, so a
    /// missed guard surfaces as a DNS error rather than a slow timeout.
    #[tokio::test]
    async fn get_signed_refuses_plaintext_remote_before_sending() {
        let _env = InsecureHttpEnv::set(None);
        let client = NodeClient::new("http://gl-nonexistent-node.invalid", Some(test_keypair()));
        let err = client.get_signed("/api/v1/x").await.unwrap_err();
        assert!(
            err.to_string().contains("plaintext http"),
            "expected the transport refusal, got: {err}"
        );
    }

    /// With the opt-in set, the same call passes the guard and fails later on
    /// the unresolvable host, proving the env var unblocks the send rather than
    /// merely being read.
    #[tokio::test]
    async fn get_signed_proceeds_when_insecure_http_opted_in() {
        let _env = InsecureHttpEnv::set(Some("1"));
        let client = NodeClient::new("http://gl-nonexistent-node.invalid", Some(test_keypair()));
        let err = client.get_signed("/api/v1/x").await.unwrap_err();
        assert!(
            !err.to_string().contains("plaintext http"),
            "the opt-in should let the request attempt the hop, got: {err}"
        );
    }

    /// Unsigned calls are not this guard's business: no keypair means no
    /// signature to leak, and the request proceeds to its own failure.
    #[tokio::test]
    async fn unsigned_call_to_plaintext_remote_is_ungated() {
        let _env = InsecureHttpEnv::set(None);
        let client = NodeClient::new("http://gl-nonexistent-node.invalid", None);
        let err = client.post("/api/v1/x", b"{}").await.unwrap_err();
        assert!(
            !err.to_string().contains("plaintext http"),
            "an unsigned request should not hit the signing guard, got: {err}"
        );
    }

    /// The opt-in is read as a value, not as presence, with the same contract as
    /// `git-remote-gitlawb` and `icaptcha-client`: `1` or `true`, case-insensitive
    /// after trim. `0`, `false`, empty and anything else leave the gate closed.
    #[test]
    fn insecure_http_opt_in_is_truthy_only() {
        for on in ["1", "true", "TRUE", "True", " 1 ", "\ttrue\n"] {
            assert!(allow_insecure_http_from_str(Some(on)), "{on:?} must opt in");
        }
        for off in ["0", "false", "", " ", "yes", "on", "2", "truee"] {
            assert!(
                !allow_insecure_http_from_str(Some(off)),
                "{off:?} must not opt in"
            );
        }
        assert!(!allow_insecure_http_from_str(None));
        let _env = InsecureHttpEnv::set(Some("0"));
        assert!(!insecure_http_allowed(), "=0 must not open the gate");
        drop(_env);
        let _env = InsecureHttpEnv::set(Some("1"));
        assert!(insecure_http_allowed());
    }

    /// Re-exec this test binary running exactly `child_test` under the given
    /// env, and prove the child actually ran one test rather than filter-
    /// matching nothing (a wrong `--exact` path exits 0 vacuously).
    fn run_env_child(child_test: &str, envs: &[(&str, &str)]) {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", child_test, "--nocapture"]);
        // Clear any inherited proxy state first, then apply the case's env;
        // env_remove after envs would silently undo a provided NO_PROXY.
        for k in [
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "GITLAWB_ALLOW_INSECURE_HTTP",
        ] {
            cmd.env_remove(k);
        }
        cmd.envs(envs.iter().copied());
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("1 passed"),
            "the child must run the test, not exit green on a filter miss. \
             stdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // ── #413 routing observed, not asserted ─────────────────────────────
    //
    // The guard and the client must agree on where a signed request goes. These
    // tests put a real listener where a proxy would be and a real listener where
    // the node is, run each signing site, and read off which one was contacted.

    /// Accept connections on `listener` for the rest of the process, recording
    /// each one's raw request head and answering `status_line` with an empty
    /// JSON body. Returns the shared record.
    fn serve_recording(
        listener: std::net::TcpListener,
        status_line: &'static str,
    ) -> std::sync::Arc<Mutex<Vec<String>>> {
        use std::io::{Read, Write};
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let rec = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                rec.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                let _ = conn.write_all(
                    format!("{status_line}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}")
                        .as_bytes(),
                );
            }
        });
        seen
    }

    /// Body of the child process: `GL_ROUTE_HOST` is the node host as written
    /// in the URL, `GL_ROUTE_NO_PROXY` the NO_PROXY value (empty means unset).
    /// A listener stands in for the proxy and another for the node; the proxy
    /// env is pointed at the first before the client is built. Every signing
    /// site must reach the node, signed, and never touch the proxy.
    #[tokio::test]
    async fn route_child_signed_requests_stay_off_the_proxy() {
        let Some(host) = std::env::var_os("GL_ROUTE_HOST") else {
            return; // only meaningful as a re-execed child
        };
        let host = host.to_string_lossy().into_owned();
        let no_proxy = std::env::var("GL_ROUTE_NO_PROXY").unwrap_or_default();

        let bind = if host.starts_with('[') {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let node = std::net::TcpListener::bind(bind).expect("bind node listener");
        let node_port = node.local_addr().unwrap().port();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let node_seen = serve_recording(node, "HTTP/1.1 200 OK");
        let proxy_seen = serve_recording(proxy, "HTTP/1.1 502 Bad Gateway");

        std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{proxy_port}"));
        if !no_proxy.is_empty() {
            std::env::set_var("NO_PROXY", &no_proxy);
        }
        let client = NodeClient::new(format!("http://{host}:{node_port}"), Some(test_keypair()));

        let r = client.get_signed("/api/v1/a").await;
        assert!(r.is_ok(), "get_signed: {:?}", r.err());
        let r = client.get_maybe_signed("/api/v1/b").await;
        assert!(r.is_ok(), "get_maybe_signed: {:?}", r.err());
        let r = client.post("/api/v1/c", b"{}").await;
        assert!(r.is_ok(), "send_once via post: {:?}", r.err());

        let proxy_seen = proxy_seen.lock().unwrap();
        assert!(
            proxy_seen.is_empty(),
            "the proxy must see no request, got: {proxy_seen:?}"
        );
        let node_seen = node_seen.lock().unwrap();
        assert_eq!(node_seen.len(), 3, "node requests: {node_seen:?}");
        assert!(
            node_seen.iter().all(|r| r.contains("\r\nsignature:")),
            "every request to the node is signed: {node_seen:?}"
        );
    }

    /// The table from the review, plus the bare proxied case. Each row is a
    /// loopback node reached with `HTTP_PROXY` set, the override unset, and a
    /// different `NO_PROXY`; every one must go straight to the node.
    #[test]
    fn signed_loopback_requests_never_reach_the_proxy() {
        let rows: &[(&str, &str)] = &[
            ("127.0.0.1", ""),
            ("127.0.0.1", "*"),
            ("localhost.", "localhost"),
            ("127.0.0.1", ".127.0.0.1"),
            ("127.0.0.1", "127.0.0.0/8"),
            ("[::1]", "0:0:0:0:0:0:0:1"),
            ("localhost.", "localhost."),
            ("127.0.0.1", "127.0.0.1"),
        ];
        for (host, no_proxy) in rows {
            if host.starts_with('[') && std::net::TcpListener::bind("[::1]:0").is_err() {
                eprintln!("skipping {host}: no IPv6 loopback on this machine");
                continue;
            }
            run_env_child(
                "http::tests::route_child_signed_requests_stay_off_the_proxy",
                &[("GL_ROUTE_HOST", host), ("GL_ROUTE_NO_PROXY", no_proxy)],
            );
        }
    }

    /// Body of the child process: a plaintext node that is NOT on this machine,
    /// reached through a proxy. Without the override the guard refuses before
    /// anything is sent; with it, the request goes via the proxy as configured.
    #[tokio::test]
    async fn route_child_remote_node_follows_the_override() {
        if std::env::var_os("GL_ROUTE_REMOTE").is_none() {
            return;
        }
        let allow = std::env::var_os("GL_ROUTE_ALLOW").is_some();
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let proxy_seen = serve_recording(proxy, "HTTP/1.1 502 Bad Gateway");
        std::env::set_var("HTTP_PROXY", format!("http://127.0.0.1:{proxy_port}"));
        let client = NodeClient::new("http://gl-remote-node.invalid:7777", Some(test_keypair()));
        let r = client.get_signed("/api/v1/a").await;
        let seen = proxy_seen.lock().unwrap();
        if allow {
            assert_eq!(seen.len(), 1, "the override sends via the proxy: {seen:?}");
        } else {
            let err = r.unwrap_err().to_string();
            assert!(err.contains("plaintext http"), "refusal expected: {err}");
            assert!(seen.is_empty(), "nothing may reach the proxy: {seen:?}");
        }
    }

    #[test]
    fn signed_remote_plaintext_is_refused_unless_overridden() {
        run_env_child(
            "http::tests::route_child_remote_node_follows_the_override",
            &[("GL_ROUTE_REMOTE", "1")],
        );
        run_env_child(
            "http::tests::route_child_remote_node_follows_the_override",
            &[
                ("GL_ROUTE_REMOTE", "1"),
                ("GL_ROUTE_ALLOW", "1"),
                ("GITLAWB_ALLOW_INSECURE_HTTP", "1"),
            ],
        );
    }

    // ── read_json (status-checked, bounded, sanitized read; #123) ────────

    /// Drive a real `reqwest::Response` off a mockito mock so `read_json` sees an
    /// actual HTTP status + body, the same shape the gated read arms produce.
    async fn response_for(
        server: &mut Server,
        status: usize,
        body: &str,
        json: bool,
    ) -> reqwest::Response {
        let mut m = server.mock("GET", "/x").with_status(status).with_body(body);
        if json {
            m = m.with_header("content-type", "application/json");
        }
        let _m = m.create_async().await;
        NodeClient::new(server.url(), None).get("/x").await.unwrap()
    }

    #[tokio::test]
    async fn read_json_returns_body_on_2xx() {
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            200,
            r#"{"name":"r","owner_did":"did:gitlawb:z"}"#,
            true,
        )
        .await;
        let v = read_json(resp, "repo").await.unwrap();
        assert_eq!(v["name"], "r");
    }

    #[tokio::test]
    async fn read_json_errs_on_404_surfacing_message_and_status() {
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            404,
            r#"{"message":"repository 'o/r' not found"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("404"), "err={err}");
        assert!(err.contains("not found"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_errs_on_500_surfacing_message() {
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 500, r#"{"message":"internal boom"}"#, true).await;
        let err = read_json(resp, "commits").await.unwrap_err().to_string();
        assert!(err.contains("500"), "err={err}");
        assert!(err.contains("internal boom"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_errs_on_non_json_error_body_with_fallback() {
        // 503 with a plain-text (middleware) body: no `message` field to surface.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 503, "service unavailable", false).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("503"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_sanitizes_control_and_bidi_in_message() {
        // A hostile node embeds ESC, BEL, and a right-to-left override in
        // the error message; none may reach the terminal verbatim.
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            404,
            r#"{"message":"a\u001b[31mb\u0007c\u202ed"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(!err.contains('\u{1b}'), "ESC leaked: {err:?}");
        assert!(!err.contains('\u{7}'), "BEL leaked: {err:?}");
        assert!(!err.contains('\u{202e}'), "bidi override leaked: {err:?}");
    }

    #[tokio::test]
    async fn read_json_errs_on_garbage_2xx_body() {
        // The #123 correctness point: a 200 with a non-JSON/truncated body must be
        // an `Err`, NOT `Ok(Null)` that a caller renders as an empty success.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 200, "this is not json", false).await;
        assert!(read_json(resp, "repo").await.is_err());
    }

    #[tokio::test]
    async fn read_json_errs_on_empty_2xx_body() {
        // A zero-byte 200 body must be an `Err`, not a silent `Ok(Null)`.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 200, "", false).await;
        assert!(read_json(resp, "repo").await.is_err());
    }

    #[tokio::test]
    async fn read_json_errs_on_non_2xx_json_without_message_or_error() {
        // A non-2xx JSON body carrying NEITHER key is the real fallback case.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 403, r#"{"detail":"forbidden"}"#, true).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("403"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
        // The body's own text must not leak when no recognised key carries it.
        assert!(!err.contains("forbidden"), "raw body leaked: {err}");
    }

    #[tokio::test]
    async fn read_json_surfaces_error_key_when_message_absent() {
        // The task API answers with `error` alone — see
        // gitlawb-node/src/api/tasks.rs `{"error":"task not found"}`. Reading only
        // `message` blanked those denials to the generic "request failed", so the
        // user was told nothing about why the call failed.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 404, r#"{"error":"task not found"}"#, true).await;
        let err = read_json(resp, "task show").await.unwrap_err().to_string();
        assert!(err.contains("404"), "err={err}");
        assert!(err.contains("task not found"), "reason not surfaced: {err}");
    }

    #[tokio::test]
    async fn read_json_prefers_message_over_error_key() {
        // The shared AppError envelope carries both; `message` is the human text
        // and must win over the machine code in `error`.
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            500,
            r#"{"error":"db_error","message":"database unavailable"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("database unavailable"), "err={err}");
        assert!(
            !err.contains("db_error"),
            "machine code won over message: {err}"
        );
    }

    #[tokio::test]
    async fn read_json_sanitizes_error_key_text() {
        // The `error` fallback goes through the same sanitizer as `message`; a
        // hostile node must not reach the terminal through the new path. The
        // controls are JSON \u escapes so the body stays VALID JSON — embedding
        // them raw would fail the parse and pass this test vacuously.
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            404,
            r#"{"error":"a\u001b[31mb\u0007c\u202ed"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "task show").await.unwrap_err().to_string();
        // Proves the parse succeeded and the `error` key was read, not the
        // "request failed" fallback (which would make the asserts below vacuous).
        assert!(err.contains("task show failed (404"), "err={err}");
        assert!(
            !err.contains("request failed"),
            "fell back, sanitizer untested: {err}"
        );
        assert!(
            err.contains('a') && err.contains('d'),
            "text dropped: {err}"
        );
        assert!(!err.contains('\u{1b}'), "ESC leaked: {err:?}");
        assert!(!err.contains('\u{7}'), "BEL leaked: {err:?}");
        assert!(!err.contains('\u{202e}'), "bidi override leaked: {err:?}");
    }

    /// #186 (F2): the non-2xx error path must read a CAPPED body, not buffer and
    /// parse the whole thing — a hostile node can stream an arbitrarily large valid
    /// JSON error. Place the `message` field AFTER more than the cap of padding: the
    /// bounded read stops before it, so it must be ABSENT from the surfaced error.
    /// RED before the fix (`resp.json()` parses the full body → the far message
    /// appears), GREEN after (capped read truncates → fallback → far message gone).
    /// The status is still surfaced, so a legitimate small error is unaffected.
    #[tokio::test]
    async fn read_json_bounds_the_error_body_read() {
        let mut server = Server::new_async().await;
        // >8 KiB of padding, then the marker message at the very end of the body.
        let big = format!(
            r#"{{"padding":"{}","message":"FARMARKER_BEYOND_CAP"}}"#,
            "A".repeat(16 * 1024)
        );
        let resp = response_for(&mut server, 500, &big, true).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("500"), "bounded read still errors: {err}");
        assert!(
            !err.contains("FARMARKER_BEYOND_CAP"),
            "the error body read must be capped: a message beyond the cap must not be surfaced, err={err}"
        );
    }

    /// #186 (F2): an EMPTY non-2xx body is its own input class — the capped read
    /// yields "", the JSON parse fails, and it falls back to the status alone
    /// ("request failed"), never a panic or a spurious success.
    #[tokio::test]
    async fn read_json_errs_on_empty_non_2xx_body() {
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 502, "", false).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("502"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
    }
}
