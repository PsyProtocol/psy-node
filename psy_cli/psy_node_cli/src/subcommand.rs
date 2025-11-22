use clap::{Parser, Subcommand, command};
use psy_core::constants::chain_id::PsyNetworkTypeInput;

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
    #[command(about = "Start a realm processor node")]
    StartRealmProcessor {
        #[arg(long = "config", short = 'c', default_value = "./config.yaml", help = "Path to config.yaml/config.json file")]
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
    },
    #[command(about = "Start a realm edge node")]
    StartRealmEdge {
        #[arg(long = "config", short = 'c', default_value = "./config.yaml", help = "Path to config.yaml/config.json file")]
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
    },
    #[command(about = "Start a coordinator processor node")]
    StartCoordinatorProcessor {
        #[arg(long = "config", short = 'c', default_value = "./config.yaml", help = "Path to config.yaml/config.json file")]
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
    },
    #[command(about = "Start a coordinator edge node")]
    StartCoordinatorEdge {
        #[arg(long = "config", short = 'c', default_value = "./config.yaml", help = "Path to config.yaml/config.json file")]
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
    },
}
