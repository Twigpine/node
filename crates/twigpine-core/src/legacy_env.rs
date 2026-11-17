//! Settings were named `GITLAWB_*` before the rename to Twigpine. They are
//! `TWIGPINE_*` now, and the old names keep working.
//!
//! Rather than teach every read site two names, each binary calls [`adopt`]
//! once, first thing in `main`. After it returns, both names carry the same
//! value for every setting that was given under either, so the rest of the code
//! reads `TWIGPINE_*` only:
//!
//! - only the old name is set: the new name gets its value;
//! - both are set: the new name wins, and the old one is overwritten to match;
//! - only the new name is set: the old name gets its value too.
//!
//! The last two exist for child processes. `git` runs the remote helper, and the
//! helper on `PATH` may be an older build that reads only the old names.
//!
//! An empty new-name value counts as unset, the same rule the settings
//! themselves follow (a shell leaves `FOO=` behind for an unset variable
//! expanded into a wrapper script).
//!
//! Everything about the old prefix lives in this module, so dropping it later
//! is one deletion.

use std::ffi::{OsStr, OsString};
use std::sync::OnceLock;

/// Prefix of every setting.
pub const PREFIX: &str = "TWIGPINE_";

/// Prefix the settings had before the rename.
pub const LEGACY_PREFIX: &str = "GITLAWB_";

/// What [`adopt`] found. Names only, never values: settings include keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Settings given only under the old name, as their new names, sorted.
    pub legacy_only: Vec<String>,
    /// Settings given under both names with different values, as their new
    /// names, sorted. The new name's value was used.
    pub conflicts: Vec<String>,
}

impl Report {
    /// True when no old name was in use.
    pub fn is_empty(&self) -> bool {
        self.legacy_only.is_empty() && self.conflicts.is_empty()
    }
}

static REPORT: OnceLock<Report> = OnceLock::new();

/// Work out which variables to set so both prefixes agree. Pure, so the rules
/// are testable without touching the process environment.
pub fn plan<I>(vars: I) -> (Vec<(String, OsString)>, Report)
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    // Only names that are valid UTF-8 can carry either prefix.
    let vars: Vec<(String, OsString)> = vars
        .into_iter()
        .filter_map(|(k, v)| k.into_string().ok().map(|k| (k, v)))
        .collect();
    let get = |name: &str| -> Option<&OsStr> {
        vars.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_os_str())
    };

    let mut sets: Vec<(String, OsString)> = Vec::new();
    let mut report = Report::default();

    for (name, value) in &vars {
        if let Some(rest) = suffix(name, LEGACY_PREFIX) {
            let new_name = format!("{PREFIX}{rest}");
            match get(&new_name).filter(|v| !v.is_empty()) {
                None => {
                    sets.push((new_name.clone(), value.clone()));
                    report.legacy_only.push(new_name);
                }
                Some(new_value) if new_value != value.as_os_str() => {
                    sets.push((name.clone(), new_value.to_os_string()));
                    report.conflicts.push(new_name);
                }
                Some(_) => {}
            }
        } else if let Some(rest) = suffix(name, PREFIX) {
            if !value.is_empty() && get(&format!("{LEGACY_PREFIX}{rest}")).is_none() {
                sets.push((format!("{LEGACY_PREFIX}{rest}"), value.clone()));
            }
        }
    }

    report.legacy_only.sort();
    report.conflicts.sort();
    (sets, report)
}

/// The part of `name` after `prefix`, when there is one.
fn suffix<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.strip_prefix(prefix).filter(|rest| !rest.is_empty())
}

/// Make both prefixes agree in this process's environment. Call it once, first
/// thing in `main`, before any thread exists and before anything reads a
/// setting: changing the environment while another thread reads it is a data
/// race on most platforms.
///
/// Later calls change nothing and return the first call's report.
pub fn adopt() -> &'static Report {
    REPORT.get_or_init(|| {
        let (sets, report) = plan(std::env::vars_os());
        for (name, value) in sets {
            std::env::set_var(name, value);
        }
        report
    })
}

/// What [`adopt`] found, or an empty report when it has not run (a test that
/// calls library code directly).
pub fn report() -> Report {
    REPORT.get().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn sets(pairs: &[(&str, &str)]) -> Vec<(String, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect()
    }

    #[test]
    fn old_name_alone_feeds_the_new_name() {
        let (s, r) = plan(env(&[("GITLAWB_NODE", "https://n.example")]));
        assert_eq!(s, sets(&[("TWIGPINE_NODE", "https://n.example")]));
        assert_eq!(r.legacy_only, vec!["TWIGPINE_NODE"]);
        assert!(r.conflicts.is_empty());
    }

    #[test]
    fn new_name_alone_feeds_the_old_name_for_older_child_processes() {
        let (s, r) = plan(env(&[("TWIGPINE_NODE", "https://n.example")]));
        assert_eq!(s, sets(&[("GITLAWB_NODE", "https://n.example")]));
        assert!(r.is_empty());
    }

    #[test]
    fn new_name_wins_and_the_old_one_is_made_to_match() {
        let (s, r) = plan(env(&[("GITLAWB_PORT", "1"), ("TWIGPINE_PORT", "2")]));
        assert_eq!(s, sets(&[("GITLAWB_PORT", "2")]));
        assert!(r.legacy_only.is_empty());
        assert_eq!(r.conflicts, vec!["TWIGPINE_PORT"]);
    }

    #[test]
    fn equal_values_need_nothing_and_report_nothing() {
        let (s, r) = plan(env(&[("GITLAWB_PORT", "7"), ("TWIGPINE_PORT", "7")]));
        assert!(s.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_new_name_counts_as_unset() {
        let (s, r) = plan(env(&[("GITLAWB_KEY", "/k.pem"), ("TWIGPINE_KEY", "")]));
        assert_eq!(s, sets(&[("TWIGPINE_KEY", "/k.pem")]));
        assert_eq!(r.legacy_only, vec!["TWIGPINE_KEY"]);

        // And an empty new name on its own is not copied to the old one.
        let (s, r) = plan(env(&[("TWIGPINE_KEY", "")]));
        assert!(s.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_old_name_is_still_carried_over() {
        // `GITLAWB_KEY=` meant "unset" to the reader; it means the same under
        // the new name.
        let (s, _) = plan(env(&[("GITLAWB_KEY", "")]));
        assert_eq!(s, sets(&[("TWIGPINE_KEY", "")]));
    }

    #[test]
    fn other_variables_and_bare_prefixes_are_left_alone() {
        let (s, r) = plan(env(&[
            ("PATH", "/bin"),
            ("GITLAWB_", "x"),
            ("TWIGPINE_", "y"),
            ("MY_GITLAWB_NODE", "z"),
        ]));
        assert!(s.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn the_report_is_sorted_and_names_no_values() {
        let (_, r) = plan(env(&[
            ("GITLAWB_PORT", "1"),
            ("GITLAWB_KEY", "/secret/path"),
            ("GITLAWB_HOST", "a"),
            ("TWIGPINE_HOST", "b"),
        ]));
        assert_eq!(r.legacy_only, vec!["TWIGPINE_KEY", "TWIGPINE_PORT"]);
        assert_eq!(r.conflicts, vec!["TWIGPINE_HOST"]);
        assert!(!format!("{r:?}").contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_value_is_carried_over_untouched() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(vec![b'/', 0xff, b'k']);
        let (s, _) = plan(vec![(OsString::from("GITLAWB_KEY"), raw.clone())]);
        assert_eq!(s, vec![("TWIGPINE_KEY".to_string(), raw)]);
    }
}
