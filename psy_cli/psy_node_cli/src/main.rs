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
            // A Realm cannot start without the Coordinator Edge, and the Edge
            // now restarts on a rollback.  Startup takes minutes -- loading the
            // global user tree alone -- and talks to the Edge at several points
            // along the way, so the few seconds it is away can land anywhere in
            // there, not only at the beginning where the bounded wait looks.
            //
            // Exit 75 rather than 1, which is what EX_TEMPFAIL means and what
            // the supervisor restarts on.  A Coordinator that is genuinely gone
            // still stops this node: the next attempt's bounded wait gives up
            // after two minutes and says so, so this cannot hide a real outage
            // behind a loop -- it only refuses to call a restarting Edge a
            // crash. realm-0 died on one twice, and stayed down while the chain
            // moved seven hundred checkpoints.
            if let Err(error) =
                start_realm_processor::run(config, get_proving_backend_from_input(proving_backend))
                    .await
            {
                if error
                    .chain()
                    .any(|cause| cause.to_string().contains("tcp connect error"))
                {
                    tracing::warn!(
                        "[REALM_STARTUP] could not reach the Coordinator Edge while starting \
                         ({error:#}); asking to be restarted rather than reporting a crash, since \
                         an Edge restarting for a rollback looks exactly like this (exit {})",
                        psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                    );
                    std::process::exit(
                        psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                    );
                }
                return Err(error);
            }
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
            )
            .await?;
            start_coordinator_edge::run(config, get_proving_backend_from_input(proving_backend)).await?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
