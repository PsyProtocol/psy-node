mod subcommand;

use clap::Parser;

use crate::subcommand::{keypair_helper, worker, worker_test, Cli, Commands};

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
            realm_api_urls,
            coordinator_api_urls,
        } => {
            worker::run(config, private_key, keystore_path, wallet_password, user, network, proving_backend, realm_api_urls, coordinator_api_urls).await?;
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
            realm_api_url,
            coordinator_api_url,
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            user_id,
            end_cap_count,
            network,
            proving_backend,
        } => {
            subcommand::dummy_end_cap_prover::run(
                coordinator_api_url,
                realm_api_url,
                min_state_updates,
                max_state_updates,
                max_contract_calls,
                user_id,
                end_cap_count,
                network,
                proving_backend,
            ).await?;
        },
        Commands::DummyEndCapProverLite { realm_api_url, coordinator_api_url, min_state_updates, max_state_updates, max_contract_calls, start_user_id, count, batches, network, proving_backend } => {
            subcommand::dummy_end_cap_prover_lite::run(
                realm_api_url,
                coordinator_api_url,
                min_state_updates,
                max_state_updates,
                max_contract_calls,
                start_user_id,
                count,
                batches,
                network,
                proving_backend,
            ).await?;
        },
    };
    Ok::<_, anyhow::Error>(())
}
