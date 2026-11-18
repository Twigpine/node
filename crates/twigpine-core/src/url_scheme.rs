//! The URL scheme of repository addresses and UCAN resources.
//!
//! It was `gitlawb://` before the rename to Twigpine and is `twigpine://` now.
//! Everything that reads one of these addresses accepts both, through the
//! functions here, so the rule lives in one place:
//!
//! - remote URLs: `twigpine://<owner-did>/<repo>` or `gitlawb://<owner-did>/<repo>`.
//!   Git picks the helper by scheme, and every install ships both
//!   `git-remote-twigpine` and `git-remote-gitlawb`.
//! - UCAN resources: `twigpine://repos/<owner>/<repo>` or `gitlawb://repos/...`.
//!   The two spellings name the same repository, so a delegation chain may mix
//!   them and still attenuate.
//!
//! Writers still produce the old scheme. Remote URLs switch in a later release;
//! UCAN resources keep it, because the node a user pushes to checks them and
//! may be one we do not run. See `docs/LEGACY-NAMES.md`.

/// The scheme, without `://`.
pub const SCHEME: &str = "twigpine";

/// The scheme before the rename, still accepted everywhere.
pub const LEGACY_SCHEME: &str = "gitlawb";

/// Both schemes, current first, each with `://`.
const PREFIXES: [&str; 2] = ["twigpine://", "gitlawb://"];

/// What follows the scheme in a remote URL, or `None` when `url` uses neither
/// scheme. Matched exactly, as before the rename: `GITLAWB://` was never a
/// repository address.
pub fn strip_scheme(url: &str) -> Option<&str> {
    PREFIXES.iter().find_map(|prefix| url.strip_prefix(prefix))
}

/// What follows `<scheme>://repos/` in a UCAN resource, or `None` for any other
/// shape.
pub fn strip_resource_prefix(with: &str) -> Option<&str> {
    strip_scheme(with)?.strip_prefix("repos/")
}

/// Whether two UCAN resources name the same thing: equal, or equal after
/// reading past either scheme. Any other difference, including case, keeps
/// them apart.
pub fn same_resource(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (strip_resource_prefix(a), strip_resource_prefix(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_schemes_are_read_and_nothing_else() {
        assert_eq!(
            strip_scheme("twigpine://did:key:z6Mk/r"),
            Some("did:key:z6Mk/r")
        );
        assert_eq!(
            strip_scheme("gitlawb://did:key:z6Mk/r"),
            Some("did:key:z6Mk/r")
        );
        for other in [
            "https://node.twigpine.com/r",
            "TWIGPINE://did:key:z6Mk/r",
            "twigpine:/did:key:z6Mk/r",
            "xtwigpine://did:key:z6Mk/r",
            "",
        ] {
            assert_eq!(strip_scheme(other), None, "{other:?}");
        }
    }

    #[test]
    fn resources_under_either_scheme() {
        assert_eq!(strip_resource_prefix("twigpine://repos/o/r"), Some("o/r"));
        assert_eq!(strip_resource_prefix("gitlawb://repos/o/r"), Some("o/r"));
        assert_eq!(strip_resource_prefix("twigpine://o/r"), None);
        assert_eq!(strip_resource_prefix("*"), None);
    }

    #[test]
    fn the_two_spellings_of_a_resource_are_the_same_resource() {
        assert!(same_resource("gitlawb://repos/o/r", "twigpine://repos/o/r"));
        assert!(same_resource(
            "twigpine://repos/o/r",
            "twigpine://repos/o/r"
        ));
        assert!(same_resource("*", "*"));
        assert!(!same_resource(
            "gitlawb://repos/o/r",
            "twigpine://repos/o/other"
        ));
        assert!(!same_resource(
            "gitlawb://repos/o/r",
            "twigpine://repos/O/r"
        ));
        assert!(!same_resource("*", "twigpine://repos/o/r"));
        assert!(!same_resource("https://repos/o/r", "twigpine://repos/o/r"));
    }
}
