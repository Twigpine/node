//! The plaintext-http policy the git transport applies to a node URL, shared with
//! `twigpine doctor` so the diagnostic refuses exactly what the helper refuses.

/// Whether `url` is plaintext http, regardless of where it points.
pub fn is_http(url: &str) -> bool {
    url::Url::parse(url.trim())
        .map(|u| u.scheme() == "http")
        .unwrap_or(false)
}

/// Whether `url` would send git data off this machine in cleartext.
///
/// True only for `http://` to a non-loopback host. RFC 9421 signs the request
/// but does not encrypt it, so on a plaintext hop the pack contents and the
/// `Signature` header are both readable, and a captured signature is replayable
/// for its freshness window against any host.
///
/// Loopback is decided from the parsed address rather than a string match, so
/// `127.0.0.2`, `[::1]` and an IPv4-mapped `[::ffff:127.0.0.1]` are all
/// recognised as this machine. A value that does not parse, or that is not
/// http(s), is not this guard's business and returns false: it fails later with
/// its own error, and naming it a TLS problem would misdirect the reader.
pub fn is_insecure_remote(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url.trim()) else {
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

/// Whether a non-empty `TWIGPINE_ALLOW_INSECURE_HTTP` value opts in: only `1` or
/// `true` (case-insensitive, after trim). Presence alone is not consent.
pub fn allow_insecure_http_value(raw: &str) -> bool {
    let t = raw.trim();
    t.eq_ignore_ascii_case("1") || t.eq_ignore_ascii_case("true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_remote_is_plaintext_off_this_machine_only() {
        for u in [
            "http://node.example.com:7545",
            "http://10.0.0.5",
            "http://[2001:db8::1]",
        ] {
            assert!(is_insecure_remote(u), "{u}");
        }
        for u in [
            "http://127.0.0.1:7545",
            "http://localhost:7545",
            "http://[::1]:7545",
            "http://[::ffff:127.0.0.1]:7545",
            "https://node.example.com",
            "not a url",
        ] {
            assert!(!is_insecure_remote(u), "{u}");
        }
    }

    #[test]
    fn only_one_or_true_opts_in() {
        for v in ["1", " TRUE ", "true"] {
            assert!(allow_insecure_http_value(v), "{v:?}");
        }
        for v in ["", "0", "false", "yes", "11"] {
            assert!(!allow_insecure_http_value(v), "{v:?}");
        }
    }

    #[test]
    fn is_http_reads_the_scheme_only() {
        assert!(is_http("http://127.0.0.1"));
        assert!(!is_http("https://127.0.0.1"));
    }
}
