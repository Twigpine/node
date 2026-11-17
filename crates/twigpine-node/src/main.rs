//! Thin binary entry point. All boot logic lives in the library crate
//! (`src/lib.rs`) so out-of-crate integration tests can link the same code.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    twigpine_node::run().await
}
