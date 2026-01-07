use psy_core::constants::{chain_id::PsyChainNetworkType, url_rotation::PsyAPIURLRotationStrategy};
use serde::{Deserialize, Serialize};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerStartupConfig {
    pub miner_user_id: u64,
    pub network: PsyChainNetworkType,
    pub private_key: [u8; 32],
    pub worker_completed_jobs_log_file_path: Option<String>,
    pub coordinator_api_urls: Vec<String>,
    pub realm_api_urls: Vec<String>,
    pub url_rotation_strategy: PsyAPIURLRotationStrategy,
}

impl WorkerStartupConfig {
    pub fn with_unique_api_urls(mut self) -> Self {
        let mut unique_coordinator_urls = Vec::new();
        for url in &self.coordinator_api_urls {
            if !unique_coordinator_urls.contains(url) {
                unique_coordinator_urls.push(url.clone());
            }
        }
        self.coordinator_api_urls = unique_coordinator_urls;

        let mut unique_realm_urls = Vec::new();
        for url in &self.realm_api_urls {
            if !unique_realm_urls.contains(url) {
                unique_realm_urls.push(url.clone());
            }
        }
        self.realm_api_urls = unique_realm_urls;
        self
    }
}