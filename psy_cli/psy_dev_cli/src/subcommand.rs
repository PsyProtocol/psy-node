use clap::{Parser, Subcommand};

pub mod read_worker_backup;
pub mod read_checkpoint_backup;
pub mod read_realm_backup;
pub mod redis_inspect;
pub mod scylla_inspect;
pub mod nats_inspect;
pub mod chain_info;
pub mod generate_genesis;
pub mod rollback;
pub mod inspect_anvil_state;
pub mod fresh_devnet_state;

use chain_info::ChainInfoArgs;
use generate_genesis::GenerateGenesisDataArgs;
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
    #[command(about = "Validate a retained Anvil JSON snapshot and extract genesis metadata (internal)")]
    InspectAnvilState(inspect_anvil_state::InspectAnvilStateArgs),
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
    #[command(name = "generate-genesis-data", about = "Write local-devnet genesis.json, private_keys.json, and faucetOperators.json, or write guardian authorization and runtime directories from the existing genesis with --guardians-root")]
    GenerateGenesisData(GenerateGenesisDataArgs),
    #[command(name = "fresh-devnet-state", about = "Reset owned devnet state and publish guardian authorization to the selected network configuration")]
    FreshDevnetState(FreshDevnetStateArgs),
}

#[derive(Parser, Debug)]
pub struct FreshDevnetStateArgs {
    /// Repository root the fresh devnet is reset inside.
    #[arg(long)]
    pub repo_root: std::path::PathBuf,
    /// Checkout-owned guardian runtime root whose databases are seeded.
    #[arg(long)]
    pub guardians_root: std::path::PathBuf,
}
