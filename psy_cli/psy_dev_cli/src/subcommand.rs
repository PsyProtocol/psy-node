use clap::{Parser, Subcommand};

pub mod read_worker_backup;
pub mod read_checkpoint_backup;
pub mod read_realm_backup;
pub mod redis_inspect;
pub mod scylla_inspect;
pub mod nats_inspect;
pub mod chain_info;
pub mod rollback;

use chain_info::ChainInfoArgs;
use nats_inspect::NatsInspectArgs;
use read_checkpoint_backup::ReadCheckpointBackupArgs;
use read_realm_backup::ReadRealmBackupArgs;
use read_worker_backup::ReadWorkerBackupArgs;
use redis_inspect::RedisInspectArgs;
use scylla_inspect::ScyllaInspectArgs;
use rollback::RollbackArgs;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Read and parse worker completed jobs backup file")]
    ReadWorkerBackup(ReadWorkerBackupArgs),
    #[command(about = "Read and parse checkpoint tree backup file")]
    ReadCheckpointBackup(ReadCheckpointBackupArgs),
    #[command(about = "Read and parse realm end-cap gatherer backup file")]
    ReadRealmBackup(ReadRealmBackupArgs),
    #[command(about = "Inspect Redis/Valkey keys, types, and values")]
    RedisInspect(RedisInspectArgs),
    #[command(about = "Inspect ScyllaDB keyspaces, tables, and run queries")]
    ScyllaInspect(ScyllaInspectArgs),
    #[command(about = "Inspect NATS subjects and JetStream streams")]
    NatsInspect(NatsInspectArgs),
    #[command(about = "Config-driven chain info query across coordinator and realms")]
    ChainInfo(ChainInfoArgs),
    #[command(name = "rollback", about = "Generate or execute an offline role-local rollback plan")]
    Rollback(RollbackArgs),
}
