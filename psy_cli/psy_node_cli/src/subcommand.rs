use clap::{Parser, Subcommand, command};
use psy_core::constants::{chain_id::PsyNetworkTypeInput, proving_backends::PsyChainProvingBackendTypeInput};

pub mod start_realm_processor;
pub mod start_realm_edge;
pub mod start_coordinator_processor;
pub mod start_coordinator_edge;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Explicitly deploy and verify the Realm rollback sidecar schema")]
    DeployRealmRollbackSidecar {
        #[arg(
            long = "scylla-db-url",
            env = "SCYLLA_DB_URL",
            help = "Comma-separated Scylla node addresses"
        )]
        scylla_db_url: String,

        #[arg(
            long = "db-namespace",
            env = "DB_NAMESPACE",
            help = "Existing Realm data keyspace; the control keyspace is <name>_no_tablet"
        )]
        db_namespace: String,

        #[arg(
            long = "apply",
            required = true,
            help = "Required acknowledgement that this command may create or verify sidecar tables"
        )]
        apply: bool,
    },
    #[command(about = "Start a realm processor node")]
    StartRealmProcessor {
        #[arg(long = "config", short = 'c', help = "Path to config.yaml/config.json file")]
        config: Option<String>,

        #[arg(long = "scylla-db-url", env = "SCYLLA_DB_URL", help = "Scylla DB URL/Connection string")]
        scylla_db_url: Option<String>,

        #[arg(long = "nats-jetstream-url", env = "NATS_JETSTREAM_URL", help = "NATS JetStream URL/Connection string")]
        nats_jetstream_url: Option<String>,

        #[arg(long = "redis-url", env = "REDIS_URL", help = "Redis URL/Connection string")]
        redis_url: Option<String>,
        
        #[arg(long = "db-namespace", env = "DB_NAMESPACE", help = "DB namespace used for scylla, redis and nats (dashes/underscores will be replaced according to the database")]
        db_namespace: Option<String>,

        #[arg(long = "realm-id", help = "The realm id for the node")]
        realm_id: Option<u64>,

        #[arg(long = "realm-sub-id", help = "The realm sub id for the node")]
        realm_sub_id: Option<u16>,

        #[arg(long = "network", help = "The network id for the node")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "verbose", short = 'v', help = "Enable verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(long = "checkpoint-backup-path", help = "Path to store checkpoint backups")]
        checkpoint_backup_path: Option<String>,

        #[arg(long = "coordinator-api-urls", value_parser, num_args = 1.., value_delimiter = ' ', help = "Coordinator Edge API URLs for the realm processor to connect to")]
        coordinator_api_urls: Vec<String>,

        #[arg(long = "genesis-data-path", help = "Path to store genesis data")]
        genesis_data_path: Option<String>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
    #[command(about = "Start a realm edge node")]
    StartRealmEdge {
        #[arg(long = "config", short = 'c', help = "Path to config.yaml/config.json file")]
        config: Option<String>,

        #[arg(long = "scylla-db-url", env = "SCYLLA_DB_URL", help = "Scylla DB URL/Connection string")]
        scylla_db_url: Option<String>,

        #[arg(long = "nats-jetstream-url", env = "NATS_JETSTREAM_URL", help = "NATS JetStream URL/Connection string")]
        nats_jetstream_url: Option<String>,

        #[arg(long = "redis-url", env = "REDIS_URL", help = "Redis URL/Connection string")]
        redis_url: Option<String>,
        
        #[arg(long = "db-namespace", env = "DB_NAMESPACE", help = "DB namespace used for scylla, redis and nats (dashes/underscores will be replaced according to the database")]
        db_namespace: Option<String>,

        #[arg(long = "realm-id", help = "The realm id for the node")]
        realm_id: Option<u64>,

        #[arg(long = "realm-sub-id", help = "The realm sub id for the node")]
        realm_sub_id: Option<u16>,

        #[arg(long = "network", help = "The network id for the node")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "verbose", short = 'v', help = "Enable verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(long = "port", help = "The port to run the edge server's HTTP API on (default: 8080)")]
        port: Option<u16>,

        #[arg(long = "listen", help = "The listen address to run the edge server's HTTP API on (default: 0.0.0.0)")]
        listen: Option<String>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
    #[command(about = "Start a coordinator processor node")]
    StartCoordinatorProcessor {
        #[arg(long = "config", short = 'c', help = "Path to config.yaml/config.json file")]
        config: Option<String>,

        #[arg(long = "scylla-db-url", env = "SCYLLA_DB_URL", help = "Scylla DB URL/Connection string")]
        scylla_db_url: Option<String>,

        #[arg(long = "nats-jetstream-url", env = "NATS_JETSTREAM_URL", help = "NATS JetStream URL/Connection string")]
        nats_jetstream_url: Option<String>,

        #[arg(long = "redis-url", env = "REDIS_URL", help = "Redis URL/Connection string")]
        redis_url: Option<String>,
        
        #[arg(long = "db-namespace", env = "DB_NAMESPACE", help = "DB namespace used for scylla, redis and nats (dashes/underscores will be replaced according to the database")]
        db_namespace: Option<String>,

        #[arg(long = "coordinator-id", help = "The coordinator id for the node")]
        coordinator_id: Option<u64>,

        #[arg(long = "coordinator-sub-id", help = "The coordinator sub id for the node")]
        coordinator_sub_id: Option<u16>,

        #[arg(long = "network", help = "The network id for the node")]
        network: Option<PsyNetworkTypeInput>,
        
        #[arg(long = "verbose", short = 'v', help = "Enable verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(long = "checkpoint-backup-path", help = "Path to store checkpoint backups")]
        checkpoint_backup_path: Option<String>,

        #[arg(long = "genesis-data-path", help = "Path to store genesis data")]
        genesis_data_path: Option<String>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
    #[command(about = "Start a coordinator edge node")]
    StartCoordinatorEdge {
        #[arg(long = "config", short = 'c', help = "Path to config.yaml/config.json file")]
        config: Option<String>,

        #[arg(long = "scylla-db-url", env = "SCYLLA_DB_URL", help = "Scylla DB URL/Connection string")]
        scylla_db_url: Option<String>,

        #[arg(long = "nats-jetstream-url", env = "NATS_JETSTREAM_URL", help = "NATS JetStream URL/Connection string")]
        nats_jetstream_url: Option<String>,

        #[arg(long = "redis-url", env = "REDIS_URL", help = "Redis URL/Connection string")]
        redis_url: Option<String>,
        
        #[arg(long = "db-namespace", env = "DB_NAMESPACE", help = "DB namespace used for scylla, redis and nats (dashes/underscores will be replaced according to the database")]
        db_namespace: Option<String>,

        #[arg(long = "coordinator-id", help = "The coordinator id for the node")]
        coordinator_id: Option<u64>,

        #[arg(long = "coordinator-sub-id", help = "The coordinator sub id for the node")]
        coordinator_sub_id: Option<u16>,

        #[arg(long = "network", help = "The network id for the node")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "verbose", short = 'v', help = "Enable verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(long = "port", help = "The port to run the edge server's HTTP API on (default: 8081)")]
        port: Option<u16>,

        #[arg(long = "listen", help = "The listen address to run the edge server's HTTP API on (default: 0.0.0.0)")]
        listen: Option<String>,

        #[arg(
            long = "rollback-admin-rpc-enabled",
            env = "ROLLBACK_ADMIN_RPC_ENABLED",
            help = "Enable the operator-only rollback inbox RPC (disabled by default)",
            default_value_t = false
        )]
        rollback_admin_rpc_enabled: bool,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
}

#[cfg(test)]
mod rollback_sidecar_command_tests {
    use super::*;

    #[test]
    fn deployment_command_requires_explicit_apply_acknowledgement() {
        let missing_apply = Cli::try_parse_from([
            "psy_node_cli",
            "deploy-realm-rollback-sidecar",
            "--scylla-db-url",
            "10.0.0.1:9042,10.0.0.2:9042,10.0.0.3:9042",
            "--db-namespace",
            "psy_realm_7",
        ]);
        assert!(missing_apply.is_err());

        let parsed = Cli::try_parse_from([
            "psy_node_cli",
            "deploy-realm-rollback-sidecar",
            "--scylla-db-url",
            "10.0.0.1:9042,10.0.0.2:9042,10.0.0.3:9042",
            "--db-namespace",
            "psy_realm_7",
            "--apply",
        ])
        .unwrap();
        let Commands::DeployRealmRollbackSidecar {
            scylla_db_url,
            db_namespace,
            apply,
        } = parsed.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(
            scylla_db_url,
            "10.0.0.1:9042,10.0.0.2:9042,10.0.0.3:9042"
        );
        assert_eq!(db_namespace, "psy_realm_7");
        assert!(apply);
    }
}
