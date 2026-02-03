mod subcommand;

use cf_utils::logging::setup_logging;
use clap::Parser;

use crate::subcommand::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    setup_logging()?;

    let cli = Cli::parse();
    match cli.command {
        Commands::ReadWorkerBackup(args) => {
            subcommand::read_worker_backup::run(args).await?;
        }
        Commands::ReadCheckpointBackup(args) => {
            subcommand::read_checkpoint_backup::run(args).await?;
        }
    }
    Ok(())
}
