mod config;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let config = config::Config::parse();
    config.validate().map_err(anyhow::Error::msg)?;
    config.read_token().map_err(anyhow::Error::msg)?;
    tracing::info!(target: "psy_bridge_reader", listen = %config.listen, "configuration valid");
    Err(anyhow::anyhow!("follow loop and server are not wired yet (Task 10b)"))
}
