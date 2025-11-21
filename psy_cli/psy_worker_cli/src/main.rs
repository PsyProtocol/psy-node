mod subcommand;

use clap::Parser;

use crate::subcommand::{
    Cli, Commands, keypair_helper, worker, worker_test
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    cf_utils::logging::setup_logging()?;

    let cli = Cli::parse();
    //psy_common::setup_logging()?;
    match cli.command {
        Commands::Worker {
            config,
            private_key,
            keystore_path,
            wallet_password,
            user,
            network,
        } => {
            worker::run(config, private_key, keystore_path, wallet_password, user, network).await?;
        }
        Commands::WorkerTest {
            config,
            private_key,
            keystore_path,
            wallet_password,
            user,
            network,
        } => {
            worker_test::run(config, private_key, keystore_path, wallet_password, user, network).await?;
        },
        Commands::GenerateKeypair => {
            keypair_helper::generate_keypair()?;
        },
        Commands::GetPublicKey { private_key } => {
            keypair_helper::get_public_key_for_private_key(&private_key)?;
        },
    };
    Ok::<_, anyhow::Error>(())
}
