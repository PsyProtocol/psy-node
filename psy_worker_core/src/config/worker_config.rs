use psy_core::constants::chain_id::PsyNetworkTypeInput;
use serde::{Deserialize, Serialize};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStartupConfig {
    pub miner_user_id: u64,
    pub network: PsyNetworkTypeInput,
    pub private_key: [u8; 32],
    pub coordinator_api_urls: Vec<String>,
    pub realm_api_urls: Vec<String>,
}