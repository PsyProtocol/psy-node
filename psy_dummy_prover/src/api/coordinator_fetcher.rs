use async_trait::async_trait;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::time::Duration;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, protocol::core_types::QNetworkTypesConfig};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_data::v1::qdata::public_key::PZKPublicKeyInfo;

#[async_trait]
pub trait PsyCoordinatorFetcher<Hash> {
    async fn cf_get_user_public_key(&self, user_id: u64) -> anyhow::Result<PZKPublicKeyInfo<Hash>>;
    async fn cf_get_user_public_key_hashes(&self, user_ids: &[u64]) -> anyhow::Result<Vec<Hash>>;
    async fn cf_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
}

#[derive(Clone)]
pub struct PsyCoordinatorAPIFetcher<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<N::F>,
}

pub fn new_coordinator_fetcher_from_url<N: QNetworkTypesConfig + 'static>(api_url: &str) -> anyhow::Result<PsyCoordinatorAPIFetcher<N, HttpClient>> {
    let http_client: HttpClient = HttpClientBuilder::default().set_keep_alive(Some(Duration::from_secs(10))).build(&api_url)?;
    Ok(PsyCoordinatorAPIFetcher::new(http_client))
}

impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static>
    PsyCoordinatorAPIFetcher<N, C>
{
    pub fn new(client: C) -> Self {
        Self {
            client,
            _phantom_f: std::marker::PhantomData,
        }
    }
    pub fn get_client(&self) -> &C {
        &self.client
    }
}

#[async_trait]
impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static>
    PsyCoordinatorFetcher<N::QHash> for PsyCoordinatorAPIFetcher<N, C>
{
    async fn cf_get_user_public_key(&self, user_id: u64) -> anyhow::Result<PZKPublicKeyInfo<N::QHash>> {
        self.client
            .get_public_key_for_user_id(user_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
        async fn cf_get_user_public_key_hashes(&self, user_ids: &[u64]) -> anyhow::Result<Vec<N::QHash>>{
            // TODO: convert these to registration ids
            let ids = user_ids.iter().map(|user_id| *user_id).collect::<Vec<u64>>();
            println!("cf_get_user_public_key_hashes called with user_ids: {:?}, converted to registration ids: {:?}", user_ids, ids);
            self.client.get_user_registration_tree_leaf_hashes(u64::MAX-0xffff, ids).await.map_err(|e| anyhow::anyhow!("{:?}", e))

        }
    async fn cf_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.client
            .get_checkpoint_tree_merkle_proof(checkpoint_id + 10, checkpoint_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
}
