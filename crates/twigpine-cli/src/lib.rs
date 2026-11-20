//! Library surface of the `twigpine` CLI.
//!
//! `main.rs` is a thin shell over these modules; the lib target exists so the
//! model fetch path is callable in-process (`model::fetch_model`, which the
//! node's end-to-end test drives after the node stops serving) and so command
//! modules can be exercised from integration tests without spawning the
//! binary.
#![recursion_limit = "256"]

pub mod agent;
pub mod bounty;
pub mod cert;
pub mod changelog;
pub mod clone;
pub mod doctor;
pub mod http;
pub mod identity;
pub mod init;
pub mod ipfs_cmd;
pub mod issue;
pub mod mcp;
pub mod mirror;
pub mod model;
pub mod name;
pub mod node;
pub mod node_stake;
pub mod peer;
pub mod pr;
pub mod profile;
pub mod protect;
pub mod quickstart;
pub mod register;
pub mod repo;
mod secret_file;
pub mod star;
pub mod status;
pub mod sync;
pub mod task;
mod text;
pub mod ucan_cmd;
pub mod visibility;
pub mod webhook;
pub mod whoami;
