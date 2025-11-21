use clap::{Parser, Subcommand, ValueEnum, command};
use psy_core::constants::chain_id::PsyNetworkTypeInput;
use serde::{Deserialize, Serialize};

pub mod worker;
pub mod worker_test;
pub mod keypair_helper;

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
}
