use clap::{Parser, Subcommand};
use psy_core::constants::chain_id::PsyNetworkTypeInput;

pub mod worker;
pub mod worker_test;
pub mod keypair_helper;
pub mod dummy_end_cap_prover;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Run a proof mining worker")]
    Worker {
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
        #[arg(long = "url",  help = "Realm RPC URL to submit end caps to")]
        api_url: String,

        #[arg(long = "min-state-updates", help = "Minimum number of state updates to include per transaction in end cap", default_value_t = 1)]
        min_state_updates: u32,

        #[arg(long = "max-state-updates", help = "Maximum number of state updates to include per transaction in end cap", default_value_t = 100)]
        max_state_updates: u32,

        #[arg(long = "max-contract-calls", help = "Maximum number of contract calls to include in end cap", default_value_t = 3)]
        max_contract_calls: u32,

        #[arg(long = "user", help = "The user id to submit end caps for")]
        user_id: u64,

        #[arg(long = "network", help = "The network id to connect to")]
        network: Option<PsyNetworkTypeInput>,
    },
}
