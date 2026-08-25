mod subcommand;

use clap::Parser;
use psy_core::constants::proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput};
use psy_node_core::config::node_cli_config::{CoordinatorEdgeCliConfig, CoordinatorProcessorCliConfig, RealmEdgeCliConfig, RealmProcessorCliConfig};

use crate::subcommand::{Cli, Commands, start_coordinator_edge, start_coordinator_processor, start_realm_edge, start_realm_processor};


fn get_proving_backend_from_input(
    input: Option<PsyChainProvingBackendTypeInput>,
) -> PsyChainProvingBackendType {
   input.unwrap_or(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks).into()
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    cf_utils::logging::setup_logging()?;

    let cli = Cli::parse();
    //psy_common::setup_logging()?;
    match cli.command {
        Commands::StartRealmProcessor {
            config,
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            realm_id,
            realm_sub_id,
            network,
            verbose,
            checkpoint_backup_path,
            coordinator_api_urls,
            genesis_data_path,
            proving_backend,
        } => {
            let config = RealmProcessorCliConfig::get_start_config(
                config,
                scylla_db_url,
                nats_jetstream_url,
                redis_url,
                db_namespace,
                realm_id,
                realm_sub_id,
                network,
                verbose,
                checkpoint_backup_path,
                coordinator_api_urls,
                genesis_data_path,
            )
            .await?;
            start_realm_processor::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
        Commands::StartRealmEdge {
            config,
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            realm_id,
            realm_sub_id,
            network,
            verbose,
            port,
            listen,
            proving_backend,
            worker_whitelist_config,
        } => {
            let config = RealmEdgeCliConfig::get_start_config(
                config,
                scylla_db_url,
                nats_jetstream_url,
                redis_url,
                db_namespace,
                realm_id,
                realm_sub_id,
                network,
                verbose,
                port,
                listen,
                worker_whitelist_config,
            )
            .await?;
            start_realm_edge::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
        Commands::StartCoordinatorProcessor {
            config,
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            coordinator_id,
            coordinator_sub_id,
            network,
            verbose,
            checkpoint_backup_path,
            genesis_data_path,
            proving_backend,
        } => {
            let config = CoordinatorProcessorCliConfig::get_start_config(
                config,
                scylla_db_url,
                nats_jetstream_url,
                redis_url,
                db_namespace,
                coordinator_id,
                coordinator_sub_id,
                network,
                verbose,
                checkpoint_backup_path,
                genesis_data_path,
            )
            .await?;
            start_coordinator_processor::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
        Commands::StartCoordinatorEdge {
            config,
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            coordinator_id,
            coordinator_sub_id,
            network,
            verbose,
            port,
            listen,
            proving_backend,
            worker_whitelist_config,
        } => {
            let config = CoordinatorEdgeCliConfig::get_start_config(
                config,
                scylla_db_url,
                nats_jetstream_url,
                redis_url,
                db_namespace,
                coordinator_id,
                coordinator_sub_id,
                network,
                verbose,
                port,
                listen,
                worker_whitelist_config,
            )
            .await?;
            start_coordinator_edge::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
