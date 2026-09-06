use clap::{Parser, Subcommand, command};
use psy_core::constants::{chain_id::PsyNetworkTypeInput, proving_backends::PsyChainProvingBackendTypeInput};

pub mod start_realm_processor;
pub mod start_realm_edge;
pub mod start_coordinator_processor;
pub mod start_coordinator_edge;
pub mod init_realm_p2p_keys;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
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

        #[arg(long = "p2p-identity-key", help = "Path to a libp2p Ed25519 identity keypair file (protobuf). Enables Realm P2P when set with --p2p-listen.")]
        p2p_identity_key: Option<String>,

        #[arg(long = "p2p-bls-key", help = "Path to a BLS12-381 secret key file (64 hex chars). Validators only.")]
        p2p_bls_key: Option<String>,

        #[arg(long = "p2p-zk-key", help = "Path to a validator ZK private key file (64 hex chars).")]
        p2p_zk_key: Option<String>,

        #[arg(long = "p2p-listen", help = "libp2p listen multiaddr for the Realm P2P transport (e.g. /ip4/0.0.0.0/tcp/41000).")]
        p2p_listen: Option<String>,

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

        #[arg(long = "network", help = "The network id for the node")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "verbose", short = 'v', help = "Enable verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(long = "port", help = "The port to run the edge server's HTTP API on (default: 8080)")]
        port: Option<u16>,

        #[arg(long = "listen", help = "The listen address to run the edge server's HTTP API on (default: 0.0.0.0)")]
        listen: Option<String>,

        #[arg(long = "worker-whitelist-config", help = "Path to the worker whitelist genesis config file")]
        worker_whitelist_config: Option<String>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,

        #[arg(long = "p2p-identity-key", help = "Path to a libp2p Ed25519 identity keypair file (protobuf). Enables Realm P2P when set with --p2p-listen.")]
        p2p_identity_key: Option<String>,

        #[arg(long = "p2p-listen", help = "libp2p listen multiaddr for the Realm P2P transport.")]
        p2p_listen: Option<String>,

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

        #[arg(long = "worker-whitelist-config", help = "Path to the worker whitelist genesis config file")]
        worker_whitelist_config: Option<String>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,

    },
    #[command(about = "Generate Realm P2P identity/BLS keys and update the runtime network config")]
    InitRealmP2pKeys {
        #[arg(long = "out-dir", help = "Directory to write generated key files and config.json into.")]
        out_dir: String,

        #[arg(long = "realm-ids", value_delimiter = ',', help = "Comma-separated realm ids to generate keys for (e.g. 0,1,2).")]
        realm_ids: Vec<u64>,

        #[arg(long = "validators-per-realm", default_value_t = 2, help = "Number of ordered validators to generate per Realm.")]
        validators_per_realm: u16,

        #[arg(long = "edges-per-validator", default_value_t = 1, help = "Number of distinct public edge identities to generate for each validator.")]
        edges_per_validator: u16,

        #[arg(long = "validator-user-ids", required = true, value_delimiter = ',', help = "Comma-separated validator user ids in Realm/validator order.")]
        validator_user_ids: Vec<u64>,
    },
}
