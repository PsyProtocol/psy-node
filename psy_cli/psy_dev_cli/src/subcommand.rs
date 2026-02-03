use clap::{Parser, Subcommand};

pub mod read_worker_backup;
pub mod read_checkpoint_backup;

use read_worker_backup::ReadWorkerBackupArgs;
use read_checkpoint_backup::ReadCheckpointBackupArgs;

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
}
