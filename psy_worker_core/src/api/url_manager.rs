use std::sync::Arc;

use dashmap::DashMap;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::{crypto::secp256k1::{CompressedPublicKey, Secp256K1WalletProvider}, node::realm_identifier::{self, QRealmIdentifier}, protocol::core_types::Q256BitHash};
use psy_api_core::worker::standard_worker_rpc::NodeEdgeWorkerRpcClient;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::worker::proving_work_history::PsyProvingJobClaimMetadata;
use tokio::sync::RwLock;

use crate::utils::api_url::hash_api_url_to_32_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum APIURLRotationStrategy {
    RoundRobin,
    Random,
    ContinueUntilFailure,
}

#[derive(Debug, Clone)]
pub struct PsyWorkerAPIURLManager{
    pub api_url_hash_to_string: DashMap<[u8; 32], String>,
    pub api_url_string_to_hash: DashMap<String, [u8; 32]>,
    pub api_url_hash_to_client: DashMap<[u8; 32], HttpClient>,
    pub api_url_failed_attempts: DashMap<[u8; 32], u32>,
    pub api_url_realm_identifiers: DashMap<[u8; 32], QRealmIdentifier>,
    pub api_url_list: Arc<RwLock<Vec<String>>>,
    pub current_api_url_index: Arc<RwLock<usize>>,
    pub rotation_strategy: APIURLRotationStrategy,
}

impl PsyWorkerAPIURLManager {
    pub fn new(rotation_strategy: APIURLRotationStrategy) -> Self {
        Self {
            api_url_hash_to_string: DashMap::new(),
            api_url_string_to_hash: DashMap::new(),
            api_url_hash_to_client: DashMap::new(),
            api_url_failed_attempts: DashMap::new(),
            api_url_realm_identifiers: DashMap::new(),
            api_url_list: Arc::new(RwLock::new(Vec::new())),
            current_api_url_index: Arc::new(RwLock::new(0)),
            rotation_strategy,
        }
    }
    pub fn get_total_api_urls(&self) -> usize {
        self.api_url_hash_to_string.len()
    }
    pub fn has_urls(&self) -> bool {
        !self.api_url_hash_to_string.is_empty()
    }
    pub fn remove_api_url_by_hash(&self, api_url_hash: &[u8; 32]) -> anyhow::Result<()> {
        if let Some(api_url) = self.api_url_hash_to_string.get(api_url_hash) {
            let api_url = api_url.value().clone();
            self.api_url_hash_to_string.remove(api_url_hash);
            self.api_url_string_to_hash.remove(&api_url);
            self.api_url_hash_to_client.remove(api_url_hash);
            self.api_url_realm_identifiers.remove(api_url_hash);
            let mut api_url_list = self.api_url_list.blocking_write();
            if let Some(pos) = api_url_list.iter().position(|x| x == &api_url) {
                api_url_list.remove(pos);
            }
        }
        Ok(())
    }
    pub fn remove_api_url(&self, api_url: &str) -> anyhow::Result<()> {
        if let Some(api_url_hash) = self.api_url_string_to_hash.get(api_url) {
            let api_url_hash = *api_url_hash;
            self.api_url_hash_to_string.remove(&api_url_hash);
            self.api_url_string_to_hash.remove(api_url);
            self.api_url_hash_to_client.remove(&api_url_hash);
            self.api_url_realm_identifiers.remove(&api_url_hash);
            let mut api_url_list = self.api_url_list.blocking_write();
            if let Some(pos) = api_url_list.iter().position(|x| x == api_url) {
                api_url_list.remove(pos);
            }
        }
        Ok(())
    }
    pub async fn add_api_urls<Hash: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static, JobId: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static>(&self, api_urls: &[impl AsRef<str>]) -> anyhow::Result<()> {
        for api_url in api_urls {
            let client = HttpClientBuilder::default().build(api_url.as_ref())?;
            let realm_identifier = <HttpClient as NodeEdgeWorkerRpcClient<Hash, JobId>>::get_realm_identifier_worker_api(&client).await;
            if realm_identifier.is_err() {
                tracing::error!("Failed to get realm identifier from API URL: {} ({:?})", api_url.as_ref(), realm_identifier.err());
                continue;
            }
            let realm_identifier = realm_identifier.unwrap();

            let api_url_hash = hash_api_url_to_32_bytes(api_url.as_ref());
            self.api_url_hash_to_string.insert(api_url_hash, api_url.as_ref().to_string());
            self.api_url_string_to_hash.insert(api_url.as_ref().to_string(), api_url_hash);
            self.api_url_realm_identifiers.insert(api_url_hash, realm_identifier);
            self.api_url_hash_to_client.insert(api_url_hash, client);
            self.api_url_list.blocking_write().push(api_url.as_ref().to_string());
        }
        Ok(())
    }
    pub fn report_api_url_failure(&self, api_url_hash: &[u8; 32]) {
        let mut entry = self.api_url_failed_attempts.entry(*api_url_hash).or_insert(0);
        *entry += 1;
    }
    pub fn report_api_url_success(&self, api_url_hash: &[u8; 32]) {
        // reset the failure count on success
        self.api_url_failed_attempts.remove(api_url_hash);
    }
    pub fn get_next_api_url_hash(&self) -> Option<[u8; 32]> {
        let api_url_list = self.api_url_list.blocking_read();
        if api_url_list.is_empty() {
            return None;
        }
        match self.rotation_strategy {
            APIURLRotationStrategy::RoundRobin => {
                let mut index = self.current_api_url_index.blocking_write();
                let api_url = &api_url_list[*index % api_url_list.len()];
                *index += 1;
                self.api_url_string_to_hash.get(api_url).map(|h| *h)
            }
            APIURLRotationStrategy::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let random_index = rng.gen_range(0..api_url_list.len());
                let api_url = &api_url_list[random_index];
                self.api_url_string_to_hash.get(api_url).map(|h| *h)
            }
            APIURLRotationStrategy::ContinueUntilFailure => {
                let current_index = *self.current_api_url_index.blocking_read();
                let api_url = &api_url_list[current_index % api_url_list.len()];
                let api_url_hash = match self.api_url_string_to_hash.get(api_url) {
                    Some(h) => *h,
                    None => return None,
                };

                if self.api_url_failed_attempts.get(&api_url_hash).is_some() {
                    // If there was a failure reported, move to the next URL
                    let mut index = self.current_api_url_index.blocking_write();
                    *index += 1;
                    let next_api_url = &api_url_list[*index % api_url_list.len()];
                    self.api_url_string_to_hash.get(next_api_url).map(|h| *h)
                } else {
                    Some(api_url_hash)
                }
            },
        }
    }

}