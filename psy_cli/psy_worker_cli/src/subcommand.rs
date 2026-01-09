use clap::{Parser, Subcommand};
use psy_core::constants::{chain_id::PsyNetworkTypeInput, proving_backends::PsyChainProvingBackendTypeInput, url_rotation::PsyAPIURLRotationStrategyInput};

pub mod worker;
pub mod worker_test;
pub mod keypair_helper;
pub mod dummy_end_cap_prover;
pub mod dummy_end_cap_prover_lite;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Run a proof mining worker")]
    Worker {
        #[arg(long = "config", help = "Path to config.yaml/config.json file")]
        config: Option<String>,

        #[arg(long = "private-key", env = "PRIVATE_KEY", help = "Private key hex string")]
        private_key: Option<String>,

        #[arg(long = "keystore-path", env = "KEYSTORE_PATH", help = "Path to wallet keystore file")]
        keystore_path: Option<String>,

        #[arg(long = "wallet-password", env = "WALLET_PASSWORD", help = "Wallet password")]
        wallet_password: Option<String>,

        #[arg(long = "user", help = "The user id which receives mining rewards")]
        user: Option<u64>,

        #[arg(long = "network", help = "The network id to connect to")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,

        #[arg(long = "completed-jobs-log-file", help = "Path to file for logging completed jobs (for reward claiming)")]
        completed_jobs_log_file: Option<String>,

        #[arg(long = "coordinator-api-url", help = "Coordinator Edge API URLs for the worker to connect to (supports many)")]
        coordinator_api_urls: Vec<String>,

        #[arg(long = "realm-api-url", help = "Realm Edge API URLs for the worker to connect to (supports many)")]
        realm_api_urls: Vec<String>,

        #[arg(long = "url-rotation-strategy", default_value = "random", help = "URL rotation strategy (round-robin, random, continue-until-failure, continue-until-failure-or-no-work-for-3-seconds, smart-swap-v1)")]
        url_rotation_strategy: PsyAPIURLRotationStrategyInput,

        #[arg(long = "batch-size", default_value = "4", help = "Number of jobs to fetch and process concurrently")]
        batch_size: usize,
    },
    #[command(about = "Run a proof mining worker in test mode")]
    WorkerTest {
        #[arg(long = "config", default_value = "./config.yaml", help = "Path to config.yaml/config.json file")]
        config: String,

        #[arg(long = "private-key", env = "PRIVATE_KEY", help = "Private key hex string")]
        private_key: Option<String>,

        #[arg(long = "keystore-path", env = "KEYSTORE_PATH", help = "Path to wallet keystore file")]
        keystore_path: Option<String>,

        #[arg(long = "wallet-password", env = "WALLET_PASSWORD", help = "Wallet password")]
        wallet_password: Option<String>,

        #[arg(long = "user", help = "The user id which receives mining rewards")]
        user: Option<u64>,

        #[arg(long = "network", help = "The network id to connect to")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
    #[command(about = "Generate a new secp256k1 keypair")]
    GenerateKeypair,
    #[command(about = "Get the public key from a given private key")]
    GetPublicKey {
        #[arg(long = "private-key", env = "PRIVATE_KEY", help = "Private key hex string")]
        private_key: String,
    },

    #[command(about = "Run a proof mining worker")]
    DummyEndCapProver {
        #[arg(long = "realm-api-url", alias = "url",  help = "Realm RPC URL to submit end caps to")]
        realm_api_url: String,

        #[arg(long = "coordinator-url",  help = "Coordinator RPC URL to fetch user public keys from")]
        coordinator_api_url: String,
        
        #[arg(long = "min-state-updates", help = "Minimum number of state updates to include per transaction in end cap", default_value_t = 1)]
        min_state_updates: u32,

        #[arg(long = "max-state-updates", help = "Maximum number of state updates to include per transaction in end cap", default_value_t = 2)]
        max_state_updates: u32,

        #[arg(long = "max-contract-calls", help = "Maximum number of contract calls to include in end cap", default_value_t = 1)]
        max_contract_calls: u32,

        #[arg(long = "user", help = "The user id to submit end caps for")]
        user_id: u64,
        
        #[arg(long = "end-cap-count", help = "Number of end caps to submit before exiting (0 = forever)", default_value_t = 0)]
        end_cap_count: u32,

        #[arg(long = "network", help = "The network id to connect to")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },

    #[command(about = "Run a prover that generates non-ups end cap proofs using the dummy prover")]
    DummyEndCapProverLite {
        #[arg(long = "realm-api-url", alias = "url", help = "Realm RPC URL to submit end caps to")]
        realm_api_url: String,

        #[arg(long = "coordinator-url",  help = "Coordinator RPC URL to fetch user public keys from")]
        coordinator_api_url: String,
        
        #[arg(long = "min-state-updates", help = "Minimum number of state updates to include per transaction in end cap", default_value_t = 1)]
        min_state_updates: u32,

        #[arg(long = "max-state-updates", help = "Maximum number of state updates to include per transaction in end cap", default_value_t = 2)]
        max_state_updates: u32,

        #[arg(long = "max-contract-calls", help = "Maximum number of contract calls to include in end cap", default_value_t = 1)]
        max_contract_calls: u32,

        #[arg(long = "start-user-id", help = "The start user id to submit end caps for", default_value_t = 0)]
        start_user_id: u64,
        
        #[arg(long = "count", help = "How many users to submit end caps for, starting from start-user-id", default_value_t = 1)]
        count: u64,
        
        #[arg(long = "batches", help = "Number of batches to submit before exiting (0 = forever)", default_value_t = 0)]
        batches: u32,

        #[arg(long = "network", help = "The network id to connect to")]
        network: Option<PsyNetworkTypeInput>,

        #[arg(long = "proving-backend", help = "The proving backend to use (plonky2-poseidon-goldilocks, jtmb-poseidon-goldilocks, jtmb-sha256-u64, etc.)")]
        proving_backend: Option<PsyChainProvingBackendTypeInput>,
    },
}
