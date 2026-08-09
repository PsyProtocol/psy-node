use std::collections::HashMap;

use anyhow;
use clap::{Args, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Deserialize, Serialize, Parser, TS)]
#[ts(export)]
pub struct ContractCallArgs {
    #[arg(long, default_value = "0", env)]
    pub contract_id: u64,
    #[arg(long, default_value = "main", env)]
    pub method_name: String,
    #[arg(long, env)]
    pub inputs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, ValueEnum, Deserialize, Serialize, Parser, TS)]
pub enum SignType {
    #[clap(name = "zk")]
    ZKSign,
    #[clap(name = "secp256k1")]
    SECP256K1Sign,
    #[clap(name = "eth-personal-secp256k1")]
    EthPersonalSECP256K1Sign,
    #[clap(name = "software-defined-dpn")]
    SoftwareDefinedDPNSign,
    #[clap(name = "software-defined-plonky2")]
    SoftwareDefinedPlonky2Sign,
    #[clap(name = "sd-key")]
    SDKeySign,
}

impl SignType {
    pub fn from_str(s: &str, _ignore_case: bool) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "zk" => Ok(SignType::ZKSign),
            "secp256k1" => Ok(SignType::SECP256K1Sign),
            "eth-personal-secp256k1" => Ok(SignType::EthPersonalSECP256K1Sign),
            "software-defined-dpn" => Ok(SignType::SoftwareDefinedDPNSign),
            "software-defined-plonky2" => Ok(SignType::SoftwareDefinedPlonky2Sign),
            "sd-key" => Ok(SignType::SDKeySign),
            _ => Err(format!("Unknown sign type: {}", s)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug, Default)]
pub struct DPNSoftwareDefinedCallData {
    pub inputs: Vec<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContractCallData {
    pub contract_calls: Vec<ContractCallArgs>,
    pub software_defined_call: DPNSoftwareDefinedCallData,
}

impl ContractCallData {
    pub fn new(contract_calls: Vec<ContractCallArgs>) -> Self {
        Self {
            contract_calls,
            software_defined_call: DPNSoftwareDefinedCallData { inputs: vec![] },
        }
    }

    pub fn with_software_defined(contract_calls: Vec<ContractCallArgs>, software_defined_call: DPNSoftwareDefinedCallData) -> Self {
        Self {
            contract_calls,
            software_defined_call: software_defined_call,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ViewCallData {
    pub contract_calls: Vec<ContractCallArgs>,
}

impl ViewCallData {
    pub fn new(contract_calls: Vec<ContractCallArgs>) -> Self {
        Self { contract_calls }
    }
}

pub fn parse_contract_call_args(s: &str) -> anyhow::Result<Vec<ContractCallArgs>> {
    serde_json::from_str(s).map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}", e))
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct WalletSourceArgs {
    #[clap(long, default_value = "zk")]
    pub sign_type: SignType,
    #[clap(short, long, env = "PRIVATE_KEY", conflicts_with = "keystore_path")]
    pub private_key: Option<String>,
    #[clap(long, env = "KEYSTORE_PATH", conflicts_with = "private_key")]
    pub keystore_path: Option<String>,
    #[clap(long, env = "WALLET_PASSWORD")]
    pub wallet_password: Option<String>,
    #[clap(long)]
    pub fingerprint: Option<String>,
    #[clap(long, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub sd_key_allowed_contract_id: Vec<u64>,
    #[clap(long, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub sd_key_allowed_method_id: Vec<u32>,
    #[clap(long, default_value_t = 2)]
    #[serde(default)]
    pub sd_key_expected_tx_count: u64,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct WalletSessionArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,

    #[clap(long, action = clap::ArgAction::Append)]
    pub contract_id: Vec<u64>,
    #[clap(long, action = clap::ArgAction::Append)]
    pub method_name: Vec<String>,
    #[clap(long, action = clap::ArgAction::Append)]
    pub inputs: Vec<String>,

    #[clap(long)]
    pub sign_inputs: Vec<u64>,

    #[clap(long)]
    pub contract_calls_file: Option<String>,

    #[clap(long, action = clap::ArgAction::Append)]
    pub external_proof_file: Vec<String>,

    #[clap(long)]
    #[serde(default)]
    pub wait_until_confirmation: bool,
}

impl WalletSessionArgs {
    pub fn to_contract_call_data(&self) -> anyhow::Result<ContractCallData> {
        let mut contract_calls = Vec::new();

        if let Some(file_path) = &self.contract_calls_file {
            let file_calls: Vec<ContractCallArgs> = serde_json::from_str(&std::fs::read_to_string(file_path)?)?;
            contract_calls.extend(file_calls);
        }

        if !self.contract_id.is_empty() {
            if self.contract_id.len() != self.method_name.len() || self.method_name.len() != self.inputs.len() {
                anyhow::bail!("contract_id, method_name, and inputs must have the same length");
            }

            for (i, &contract_id) in self.contract_id.iter().enumerate() {
                let method_name = self.method_name[i].clone();
                let inputs_str = &self.inputs[i];
                let inputs: Vec<u64> =
                    serde_json::from_str(inputs_str).map_err(|e| anyhow::anyhow!("Invalid inputs JSON '{}': {}", inputs_str, e))?;

                contract_calls.push(ContractCallArgs {
                    contract_id,
                    method_name,
                    inputs,
                });
            }
        }

        if contract_calls.is_empty() {
            anyhow::bail!("Must specify either --contract-calls-file or --contract-id parameters");
        }

        Ok(ContractCallData {
            contract_calls,
            software_defined_call: DPNSoftwareDefinedCallData {
                inputs: self.sign_inputs.clone(),
            },
        })
    }
}

#[derive(Clone, Debug, Parser)]
pub struct ProverArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(env = "PROVER_LISTEN_ADDR", long, default_value = "0.0.0.0:8888")]
    pub listen_addr: String,
    #[clap(long, default_value = "17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")]
    pub private_key: String,
    #[clap(long, default_value = "9f5cb6b51fd293bbc95f94013d65c566d7adeebb7e1cc77c89b9ccd73571b5c0")]
    pub api_key: String,
}

#[derive(Clone, Debug, Parser)]
pub struct ProveProxyArgs {
    #[clap(env = "PROVE_PROXY_LISTEN_ADDR", long, default_value = "0.0.0.0:9999")]
    pub listen_addr: String,
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
}

#[derive(Clone, Debug, Parser)]
pub struct PsyFaucetServerArgs {
    #[clap(env = "PSY_FAUCET_LISTEN_ADDR", long, default_value = "0.0.0.0:9998")]
    pub listen_addr: String,
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
}

#[derive(Clone, Debug, Args)]
pub struct InterpreterArgs {
    #[clap(short, env, long)]
    pub file: String,

    #[clap(short, env, long, default_value = None)]
    pub contract_name: Option<String>,

    #[clap(short, env, long, num_args = 1.., default_values = &["main"])]
    pub method_names: Vec<String>,

    #[clap(short, env, long, value_parser = parse_vec_u64, num_args = 0..)]
    pub parameters: Vec<Vec<u64>>,
}

fn parse_vec_u64(s: &str) -> Result<Vec<u64>, String> {
    s.split(',').map(|num| num.parse::<u64>().map_err(|e| e.to_string())).collect()
}

#[derive(Clone, Debug, Args)]
pub struct CompilerArgs {
    #[clap(short, env, long)]
    pub file: String,

    #[clap(short, env, long, default_value = None)]
    pub contract_name: Option<String>,

    #[clap(short, env, long, num_args = 1.., default_values = &["main"])]
    pub method_names: Vec<String>,
}

#[derive(Clone, Debug, Args)]
pub struct TestArgs {
    #[clap(short, env, long)]
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmJobData {
    pub id: u32,
    pub checkpoints: HashMap<u64, Vec<String>>,
}

#[derive(Clone, Debug, Parser)]
pub struct ExportKeyStoreArgs {
    #[clap(long, env = "KEYSTORE_PATH")]
    pub keystore_path: String,
    #[clap(long, env = "WALLET_PASSWORD")]
    pub wallet_password: String,
}
