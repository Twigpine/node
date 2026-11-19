#![recursion_limit = "256"]

use anyhow::Result;
use clap::{Parser, Subcommand};

mod agent;
mod bounty;
mod cert;
mod changelog;
mod clone;
mod doctor;
mod http;
mod identity;
mod init;
mod ipfs_cmd;
mod issue;
mod mcp;
mod mirror;
mod model;
mod name;
mod node;
mod node_stake;
mod peer;
mod pr;
mod profile;
mod protect;
mod quickstart;
mod register;
mod repo;
mod secret_file;
mod star;
mod status;
mod sync;
mod task;
mod text;
mod ucan_cmd;
mod visibility;
mod webhook;
mod whoami;

#[derive(Parser)]
#[command(
    name = "twigpine",
    about = "Twigpine CLI — identity, repos, MCP server",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage your Twigpine identity (DID + keypair)
    Identity {
        #[command(subcommand)]
        cmd: identity::IdentityCmd,
    },

    /// Register this agent with a Twigpine node
    Register(register::RegisterArgs),

    /// Clone a Twigpine repo, handling private subtrees cleanly
    Clone(clone::CloneArgs),

    /// Manage repositories
    Repo(repo::RepoArgs),

    /// Manage issues (stored as git refs)
    Issue(issue::IssueArgs),

    /// Peer discovery — add and inspect known nodes
    Peer(peer::PeerArgs),

    /// Manage pull requests
    Pr(pr::PrArgs),

    /// Inspect signed ref-update certificates
    Cert(cert::CertArgs),

    /// IPFS pin management — list pinned CIDs and retrieve objects by CID
    Ipfs(ipfs_cmd::IpfsArgs),

    /// Node status and network info
    Node(node::NodeArgs),

    /// Manage webhooks for a repository
    Webhook(webhook::WebhookArgs),

    /// Mirror a public GitHub/GitLab/any-git repo into Twigpine
    Mirror(mirror::MirrorArgs),

    /// MCP server — expose Twigpine tools to LLM agents
    Mcp(mcp::McpArgs),

    /// Sync repos from peer nodes (HTTP fallback for p2p gossip)
    Sync(sync::SyncArgs),

    /// Manage agent task delegation
    Task(task::TaskArgs),

    /// Register and resolve names on Base L2
    Name(name::NameArgs),

    /// Check your Twigpine installation and connectivity
    Doctor(doctor::DoctorArgs),

    /// Zero-to-push in one command — init repo, identity, register, remote
    Init(init::InitArgs),

    /// Interactive setup wizard — identity, registration, first repo
    Quickstart(quickstart::QuickstartArgs),

    /// Star and unstar repositories
    Star(star::StarArgs),

    /// Snapshot of your current context: identity, node, repo, open work
    Status(status::StatusArgs),

    /// List and inspect registered agents on a node
    Agent(agent::AgentArgs),

    /// Manage your agent profile (name, bio, avatar, social links)
    Profile(profile::ProfileArgs),

    /// Manage branch protection rules
    Protect(protect::ProtectArgs),

    /// Manage path-scoped read visibility rules
    Visibility(visibility::VisibilityArgs),

    /// Show unified activity changelog for a repository
    Changelog(changelog::ChangelogArgs),

    /// Manage token-powered bounties on repositories
    Bounty(bounty::BountyArgs),

    /// Delegate, show, and verify UCAN capability tokens
    Ucan(ucan_cmd::UcanArgs),

    /// Print your current identity (DID) and optional node info
    Whoami(whoami::WhoamiArgs),

    /// Publish open-weight model releases
    Model {
        #[command(subcommand)]
        cmd: model::ModelCmd,
    },
}

/// The command was `gl` before the rename and still answers to it. Say so
/// once per run, on stderr, and only to a person: scripts and the MCP server
/// (which owns stdout and is never a terminal on stderr's side of a pipe) see
/// nothing.
fn old_command_name_notice() {
    use std::io::IsTerminal;
    let invoked_as_gl = std::env::args_os()
        .next()
        .map(std::path::PathBuf::from)
        .and_then(|p| p.file_stem().map(|s| s.to_os_string()))
        .is_some_and(|stem| stem == "gl");
    if invoked_as_gl && std::io::stderr().is_terminal() {
        eprintln!("note: `gl` is now `twigpine` (short: `twig`). `gl` still works for now.");
    }
}

/// The npm package was `@gitlawb/gl` and is `@twigpine/cli` now. A program
/// installed by the old package says so once per run, on a terminal only:
/// npm hides install-script output, and `npm update -g @gitlawb/gl` cannot
/// move anyone to a package with another name.
fn old_npm_package_notice() {
    use std::io::IsTerminal;
    let from_old_package = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .is_ok_and(|exe| installed_by_old_npm_package(&exe));
    if from_old_package && std::io::stderr().is_terminal() {
        eprintln!(
            "note: on npm, @gitlawb/gl is now @twigpine/cli. To keep getting updates:\n\
             \x20 npm uninstall -g @gitlawb/gl && npm install -g @twigpine/cli"
        );
    }
}

/// Whether `exe` lives inside an `@gitlawb/gl` npm install.
fn installed_by_old_npm_package(exe: &std::path::Path) -> bool {
    let parts: Vec<_> = exe.components().map(|c| c.as_os_str()).collect();
    parts.windows(3).any(|w| {
        w[0] == std::ffi::OsStr::new("node_modules")
            && w[1] == std::ffi::OsStr::new("@gitlawb")
            && w[2] == std::ffi::OsStr::new("gl")
    })
}

fn main() -> Result<()> {
    // Before the runtime starts its threads, and before anything reads a
    // setting: accept the names settings had before the rename.
    twigpine_core::legacy_env::adopt();
    run()
}

#[tokio::main]
async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("twigpine=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr) // keep stdout clean for MCP framing
        .init();

    old_command_name_notice();
    old_npm_package_notice();

    let cli = Cli::parse();
    match cli.command {
        Commands::Identity { cmd } => identity::run(cmd).await,
        Commands::Register(args) => register::run(args).await,
        Commands::Clone(args) => clone::run(args).await,
        Commands::Repo(args) => repo::run(args).await,
        Commands::Issue(args) => issue::run(args).await,
        Commands::Pr(args) => pr::run(args).await,
        Commands::Peer(args) => peer::run(args).await,
        Commands::Cert(args) => cert::run(args).await,
        Commands::Ipfs(args) => ipfs_cmd::run(args).await,
        Commands::Node(args) => node::run(args).await,
        Commands::Webhook(args) => webhook::run(args).await,
        Commands::Mirror(args) => mirror::run(args).await,
        Commands::Mcp(args) => mcp::run(args).await,
        Commands::Sync(args) => sync::run(args).await,
        Commands::Task(args) => task::run(args).await,
        Commands::Name(args) => name::run(args).await,
        Commands::Doctor(args) => doctor::run(args).await,
        Commands::Init(args) => init::run(args).await,
        Commands::Quickstart(args) => quickstart::run(args).await,
        Commands::Star(args) => star::run(args).await,
        Commands::Status(args) => status::run(args).await,
        Commands::Agent(args) => agent::run(args).await,
        Commands::Profile(args) => profile::run(args).await,
        Commands::Protect(args) => protect::run(args).await,
        Commands::Visibility(args) => visibility::run(args).await,
        Commands::Changelog(args) => changelog::run(args).await,
        Commands::Bounty(args) => bounty::run(args).await,
        Commands::Ucan(args) => ucan_cmd::run(args).await,
        Commands::Whoami(args) => whoami::run(args).await,
        Commands::Model { cmd } => model::run(cmd).await,
    }
}

#[cfg(test)]
mod npm_package_notice_tests {
    use super::installed_by_old_npm_package;
    use std::path::Path;

    #[test]
    fn only_an_install_under_the_old_package_name() {
        assert!(installed_by_old_npm_package(Path::new(
            "/usr/local/lib/node_modules/@gitlawb/gl/bin/gl"
        )));
        assert!(installed_by_old_npm_package(Path::new(
            "/home/a/.npm-global/lib/node_modules/@gitlawb/gl/bin/twigpine"
        )));
        for other in [
            "/usr/local/lib/node_modules/@twigpine/cli/node_modules/@twigpine/cli-linux-x64/twigpine",
            "/home/a/.local/bin/twigpine",
            "/opt/gitlawb/gl/bin/gl",
            "/usr/local/lib/node_modules/@gitlawb/glx/bin/gl",
        ] {
            assert!(!installed_by_old_npm_package(Path::new(other)), "{other}");
        }
    }
}
