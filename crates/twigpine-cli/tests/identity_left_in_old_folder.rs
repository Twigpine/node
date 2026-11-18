//! A key left in `~/.gitlawb` from before the rename, beside a `~/.twigpine`
//! that has none, must never lead to a second identity.
//!
//! Once `~/.twigpine` exists it is the only folder read, so every command that
//! can create a key would otherwise find "no identity" and make a new one. The
//! user would end up with a DID their repositories and delegations do not
//! belong to. These run the real binary against a scratch home.

#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output};

/// A home with the key in the old folder and an empty new folder.
fn stranded_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join(".gitlawb")).unwrap();
    std::fs::write(home.path().join(".gitlawb/identity.pem"), b"not read").unwrap();
    std::fs::create_dir(home.path().join(".twigpine")).unwrap();
    home
}

/// `twigpine <args>` with only this home: no setting from the developer's
/// shell, under either name, reaches the run.
fn twigpine(home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_twigpine"));
    cmd.args(args)
        .env("HOME", home)
        .stdin(std::process::Stdio::null());
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("GITLAWB_") || upper.starts_with("TWIGPINE_") {
            cmd.env_remove(name);
        }
    }
    // Nothing here may reach a network; a node that refuses connections makes
    // any attempt fail fast instead of hanging.
    // doctor also looks up iCaptcha and the latest release; both go to the
    // same refusing address.
    cmd.env("TWIGPINE_NODE", "http://127.0.0.1:1")
        .env("TWIGPINE_ICAPTCHA_URL", "http://127.0.0.1:1")
        .env("TWIGPINE_GITHUB_API_URL", "http://127.0.0.1:1");
    cmd.output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_no_new_key(home: &Path) {
    assert!(
        !home.join(".twigpine/identity.pem").exists(),
        "a second identity was created in ~/.twigpine"
    );
    assert_eq!(
        std::fs::read(home.join(".gitlawb/identity.pem")).unwrap(),
        b"not read",
        "the original key must be untouched"
    );
}

/// The refusal names both folders, so the user knows where the key is and
/// what to do.
fn assert_points_at_old_folder(out: &Output) {
    let t = text(out);
    assert!(t.contains(".gitlawb") && t.contains(".twigpine"), "{t}");
}

#[test]
fn identity_new_refuses() {
    let home = stranded_home();
    let out = twigpine(home.path(), &["identity", "new"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_points_at_old_folder(&out);
    assert_no_new_key(home.path());
}

#[test]
fn identity_new_with_force_is_the_deliberate_way_to_start_over() {
    let home = stranded_home();
    let out = twigpine(home.path(), &["identity", "new", "--force"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(home.path().join(".twigpine/identity.pem").exists());
    assert_eq!(
        std::fs::read(home.path().join(".gitlawb/identity.pem")).unwrap(),
        b"not read",
        "the old key is left where it was"
    );
}

#[test]
fn quickstart_refuses_before_reaching_a_node() {
    let home = stranded_home();
    let out = twigpine(home.path(), &["quickstart", "--yes"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_points_at_old_folder(&out);
    assert_no_new_key(home.path());
}

#[test]
fn init_refuses_before_reaching_a_node() {
    let home = stranded_home();
    let repo = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_twigpine"))
        .arg("init")
        .current_dir(repo.path())
        .env("HOME", home.path())
        .env("TWIGPINE_NODE", "http://127.0.0.1:1")
        .env_remove("TWIGPINE_KEY")
        .env_remove("GITLAWB_KEY")
        .env_remove("GITLAWB_NODE")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", text(&out));
    assert_points_at_old_folder(&out);
    assert_no_new_key(home.path());
}

#[test]
fn identity_show_says_where_the_key_is() {
    let home = stranded_home();
    let out = twigpine(home.path(), &["identity", "show"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_points_at_old_folder(&out);
}

#[test]
fn doctor_points_at_the_old_folder_not_at_identity_new() {
    let home = stranded_home();
    let out = twigpine(home.path(), &["doctor"]);
    let t = text(&out);
    let identity_row = t
        .lines()
        .find(|l| l.contains("identity") && l.contains("not found"))
        .unwrap_or_else(|| panic!("no identity row:\n{t}"));
    assert!(identity_row.contains(".gitlawb"), "{identity_row}");
    assert!(
        !t.contains("twigpine identity new\n"),
        "doctor must not advise a new identity here:\n{t}"
    );
    assert_no_new_key(home.path());
}
