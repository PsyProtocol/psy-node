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
            proving_backend,
        } => {
            worker::run(config, private_key, keystore_path, wallet_password, user, network, proving_backend).await?;
        }
        Commands::WorkerTest {
            config,
            private_key,
            keystore_path,
            wallet_password,
            user,
            network,
            proving_backend,
        } => {
            worker_test::run(config, private_key, keystore_path, wallet_password, user, network, proving_backend).await?;
        },
        Commands::GenerateKeypair => {
            keypair_helper::generate_keypair()?;
        },
        Commands::GetPublicKey { private_key } => {
            keypair_helper::get_public_key_for_private_key(&private_key)?;
        },
        Commands::DummyEndCapProver {
            api_url,
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            user_id,
            network,
            proving_backend,
        } => {
            subcommand::dummy_end_cap_prover::run(
                api_url,
                min_state_updates,
                max_state_updates,
                max_contract_calls,
                user_id,
                network,
                proving_backend,
            ).await?;
        },
    };
    Ok::<_, anyhow::Error>(())
}
