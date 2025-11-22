use psy_core::constants::chain_id::PsyChainNetworkType;
use serde::{Deserialize, Serialize};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStartupConfig {
    pub miner_user_id: u64,
    pub network: PsyChainNetworkType,
    pub private_key: [u8; 32],
    pub worker_completed_jobs_log_file_path: Option<String>,
    pub coordinator_api_urls: Vec<String>,
    pub realm_api_urls: Vec<String>,
}