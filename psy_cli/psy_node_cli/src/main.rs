mod subcommand;

use clap::Parser;
use psy_core::constants::proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput};
use psy_node_core::config::node_cli_config::{CoordinatorEdgeCliConfig, CoordinatorProcessorCliConfig, RealmEdgeCliConfig, RealmProcessorCliConfig};

use crate::subcommand::{Cli, Commands, init_realm_p2p_keys, start_coordinator_edge, start_coordinator_processor, start_realm_edge, start_realm_processor};


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
            p2p_identity_key,
            p2p_bls_key,
            p2p_listen,
            p2p_bootnode,
            p2p_coordinator,
            p2p_validator_sub_ids,
            p2p_checkpoints_per_epoch,
            p2p_proposer_node_id,
            p2p_validator_user_id,
            p2p_roster_path,
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
                p2p_identity_key,
                p2p_bls_key,
                p2p_listen,
                p2p_bootnode,
                p2p_coordinator,
                p2p_validator_sub_ids,
                p2p_checkpoints_per_epoch,
                p2p_proposer_node_id,
                p2p_validator_user_id,
                p2p_roster_path,
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
            p2p_identity_key,
            p2p_bls_key,
            p2p_listen,
            p2p_bootnode,
            p2p_coordinator,
            p2p_validator_sub_ids,
            p2p_checkpoints_per_epoch,
            p2p_proposer_node_id,
            p2p_validator_user_id,
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
                p2p_identity_key,
                p2p_bls_key,
                p2p_listen,
                p2p_bootnode,
                p2p_coordinator,
                p2p_validator_sub_ids,
                p2p_checkpoints_per_epoch,
                p2p_proposer_node_id,
                p2p_validator_user_id,
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
            p2p_roster_path,
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
                p2p_roster_path,
            )
            .await?;
            start_coordinator_edge::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
        Commands::InitRealmP2pKeys {
            out_dir,
            realm_ids,
            sub_ids,
        } => {
            init_realm_p2p_keys::run(out_dir, realm_ids, sub_ids).await?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
