mod subcommand;

use clap::Parser;
use psy_node_core::config::node_cli_config::{CoordinatorEdgeCliConfig, CoordinatorProcessorCliConfig, RealmEdgeCliConfig, RealmProcessorCliConfig};

use crate::subcommand::{Cli, Commands, start_coordinator_edge, start_coordinator_processor, start_realm_edge, start_realm_processor};

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
            )
            .await?;
            start_realm_processor::run(config).await?;
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
            start_realm_edge::run(config).await?;
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
            )
            .await?;
            start_coordinator_processor::run(config).await?;
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
            start_coordinator_edge::run(config).await?;
        }
    };
    Ok::<_, anyhow::Error>(())
}
