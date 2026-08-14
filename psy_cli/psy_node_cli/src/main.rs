mod subcommand;

use clap::Parser;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_core::constants::proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput};
use psy_node_core::config::node_cli_config::{CoordinatorEdgeCliConfig, CoordinatorProcessorCliConfig, RealmEdgeCliConfig, RealmProcessorCliConfig};
use psy_node_scylla::psy_setup::{
    deploy_pending_queue_sidecar_from_connection_string,
    inspect_realm_branch_exact_activation,
};
use psy_node_cli::node::inspect_realm_rollback_readiness;

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
        Commands::CheckRealmRollbackReadiness {
            scylla_db_url,
            db_namespace,
            network,
            realm_id,
            realm_sub_id,
            proving_backend,
        } => {
            let network = network.into();
            let summary = inspect_realm_rollback_readiness::inspect(
                &db_namespace,
                &scylla_db_url,
                network,
                realm_id,
                realm_sub_id,
                proving_backend.into(),
            )
            .await?;
            let activation = summary.activation();
            let startup = activation.startup_config();
            println!("Realm rollback startup preflight passed");
            println!("cutover_phase={:?}", activation.cutover_phase());
            println!("cutover_revision={}", activation.cutover_revision());
            println!("writer_revision={}", activation.writer_revision());
            println!("route_phase={:?}", summary.route_phase());
            println!("route_revision={}", summary.route_revision());
            println!(
                "readiness_digest={}",
                hex::encode(summary.readiness_digest())
            );
            println!("permit_digest={}", hex::encode(summary.permit_digest()));
            println!("branch_exact_startup:");
            println!("  generation: {}", startup.generation);
            println!("  binding_digest_hex: {}", startup.binding_digest_hex);
            println!(
                "  writer_activation_digest_hex: {}",
                startup.writer_activation_digest_hex
            );
        }
        Commands::InspectRealmRollbackActivation {
            scylla_db_url,
            db_namespace,
            network,
            realm_id,
            realm_sub_id,
        } => {
            let summary = inspect_realm_branch_exact_activation::<parth_core::PHash>(
                &db_namespace,
                &scylla_db_url,
                NetworkId::from_network_type(network.into()),
                realm_id,
                realm_sub_id,
            )
            .await?;
            let startup = summary.startup_config();
            println!("# cutover_phase={:?}", summary.cutover_phase());
            println!("# cutover_revision={}", summary.cutover_revision());
            println!("# writer_revision={}", summary.writer_revision());
            println!("branch_exact_startup:");
            println!("  generation: {}", startup.generation);
            println!("  binding_digest_hex: {}", startup.binding_digest_hex);
            println!(
                "  writer_activation_digest_hex: {}",
                startup.writer_activation_digest_hex
            );
        }
        Commands::DeployRealmRollbackSidecar {
            scylla_db_url,
            db_namespace,
            apply,
        } => {
            if !apply {
                anyhow::bail!(
                    "refusing to deploy without --apply; no Scylla connection was attempted"
                );
            }
            let summary = deploy_pending_queue_sidecar_from_connection_string(
                &db_namespace,
                &scylla_db_url,
            )
            .await?;
            println!("pending queue sidecar verified");
            println!("schema_version={}", summary.schema_version());
            println!("data_keyspace={}", summary.data_keyspace());
            println!("control_keyspace={}", summary.control_keyspace());
            println!(
                "schema_fingerprint={}",
                hex::encode(summary.schema_fingerprint())
            );
            println!("ready_digest={}", hex::encode(summary.ready_digest()));
        }
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
            coordinator_rollback_db_namespace,
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
                coordinator_rollback_db_namespace,
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
            rollback_admin_rpc_enabled,
            proving_backend,
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
                rollback_admin_rpc_enabled,
            )
            .await?;
            start_coordinator_edge::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
