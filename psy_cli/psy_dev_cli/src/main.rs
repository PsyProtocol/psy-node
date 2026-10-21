mod subcommand;

use cf_utils::logging::setup_logging;
use clap::Parser;

use crate::subcommand::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();
    if matches!(cli.command, Commands::FreshDevnetState(_)) {
        // This command's stdout is a JSON handshake. Its logs go to stderr, and
        // the shared logger is skipped because it claims the process subscriber.
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
            .init();
    } else {
        setup_logging()?;
    }
    match cli.command {
        Commands::InspectAnvilState(args) => {
            subcommand::inspect_anvil_state::run(args)?;
        }
        Commands::ReadWorkerBackup(args) => {
            subcommand::read_worker_backup::run(args).await?;
        }
        Commands::ReadCheckpointBackup(args) => {
            subcommand::read_checkpoint_backup::run(args).await?;
        }
        Commands::ReadRealmBackup(args) => {
            subcommand::read_realm_backup::run(args).await?;
        }
        Commands::RedisInspect(args) => {
            subcommand::redis_inspect::run(args).await?;
        }
        Commands::ScyllaInspect(args) => {
            subcommand::scylla_inspect::run(args).await?;
        }
        Commands::NatsInspect(args) => {
            subcommand::nats_inspect::run(args).await?;
        }
        Commands::ChainInfo(args) => {
            subcommand::chain_info::run(args).await?;
        }
        Commands::Rollback(args) => {
            subcommand::rollback::run(args).await?;
        }
        Commands::GenerateGenesisData(args) => {
            subcommand::generate_genesis::run(args).await?;
        }
        Commands::FreshDevnetState(args) => {
            subcommand::fresh_devnet_state::run(args.repo_root, args.guardians_root).await?;
        }
    }
    Ok(())
}
