use std::path::PathBuf;

use clap::{Args, Subcommand};

pub mod account_pool;
pub mod report;
pub mod scenarios;

pub use scenarios::{ClaimArgs, DeployArgs, EndcapArgs, FaucetArgs, PoolCreateArgs, RegisterArgs};

/// Shared arguments for every benchmark scenario.
#[derive(Args, Clone)]
pub struct BenchmarkCommonArgs {
    /// Directory holding the account pool index and keystores.
    #[arg(long)]
    pub pool_dir: PathBuf,
    /// Network configuration file selecting the benchmark target network.
    #[arg(long, default_value = "config.json", env = "PSY_CONFIG_PATH")]
    pub rpc_config: String,
    /// Password for the pooled account keystores.
    #[arg(long, env = "WALLET_PASSWORD", hide_env_values = true)]
    pub wallet_password: Option<String>,
    /// Optional path the secret-free JSON report is written to; the run itself
    /// prints a human-readable summary.
    #[arg(long)]
    pub report_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum BenchmarkCommands {
    /// Create missing pool accounts and register them.
    #[command(name = "pool-create")]
    PoolCreate(PoolCreateArgs),
    /// Register or confirm registration of pooled accounts.
    Register(RegisterArgs),
    /// Deploy a compiled contract artifact using pooled accounts.
    Deploy(DeployArgs),
    /// Execute real EndCaps (trace + Plonky2 proof + inclusion wait).
    Endcap(EndcapArgs),
    /// Fund every registered pool account through the network faucet service.
    Faucet(FaucetArgs),
    /// Claim faucet funds into the spendable balance (token claim EndCap).
    Claim(ClaimArgs),
}

#[derive(Args)]
pub struct BenchmarkArgs {
    #[command(subcommand)]
    pub command: BenchmarkCommands,
}

pub async fn run(args: BenchmarkArgs) -> anyhow::Result<()> {
    let (report_file, report) = match args.command {
        BenchmarkCommands::PoolCreate(args) => {
            (args.common.report_file.clone(), scenarios::run_pool_create(args).await?)
        }
        BenchmarkCommands::Register(args) => {
            (args.common.report_file.clone(), scenarios::run_register(args).await?)
        }
        BenchmarkCommands::Deploy(args) => {
            (args.common.report_file.clone(), scenarios::run_deploy(args).await?)
        }
        BenchmarkCommands::Endcap(args) => {
            (args.common.report_file.clone(), scenarios::run_endcap(args).await?)
        }
        BenchmarkCommands::Faucet(args) => {
            (args.common.report_file.clone(), scenarios::run_faucet(args).await?)
        }
        BenchmarkCommands::Claim(args) => {
            (args.common.report_file.clone(), scenarios::run_claim(args).await?)
        }
    };
    report::print_summary(&report)?;
    if let Some(path) = report_file {
        std::fs::write(&path, serde_json::to_string_pretty(&report)?)?;
    }
    Ok(())
}
