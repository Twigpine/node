//! Thin binary entry point. All boot logic lives in the library crate
//! (`src/lib.rs`) so out-of-crate integration tests can link the same code.

fn main() -> anyhow::Result<()> {
    // Before the runtime starts its threads, and before anything reads a
    // setting: accept the names settings had before the rename.
    twigpine_core::legacy_env::adopt();
    run()
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    twigpine_node::run().await
}
