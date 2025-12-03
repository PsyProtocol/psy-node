use async_trait::async_trait;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::{
    crypto::hash::merkle_proof::MerkleProofCore,
    data::hash::merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreSingleIdKey},
    protocol::core_types::QNetworkTypesConfig,
};
use psy_api_core::{realm::standard_edge_rpc::RealmEdgeRpcClient};
use psy_data::{proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, v1::qdata::user::PQEDUserLeaf};

#[async_trait]
pub trait PsyUserContractDataFetcher<F, Hash> {
    async fn df_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_latest_checkpoint(&self) -> anyhow::Result<u64>;
    async fn df_get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<F, Hash>>;
    async fn df_get_global_user_tree_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_contract_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>>;
    async fn df_get_contract_state_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreDoubleIdKey>) -> anyhow::Result<Vec<Hash>>;
    async fn df_get_contract_state_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u64, height: u8, slot_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_user_contract_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreSingleIdKey>) -> anyhow::Result<Vec<Hash>>;
    async fn df_submit_end_cap_proof(&self, user_ec_input: SubmitUserEndCapNonProofInput<F, Hash>, proof: Vec<u8>) -> anyhow::Result<()>;
}


#[derive(Clone)]
pub struct PsyRealmAPIUserContractDataFetcher<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<N::F>,
}

pub fn new_contract_data_fetcher_from_url<
    N: QNetworkTypesConfig + 'static,
>(api_url: &str) -> anyhow::Result<PsyRealmAPIUserContractDataFetcher<N, HttpClient>> {
    let http_client: HttpClient = HttpClientBuilder::default().build(&api_url)?;
    Ok(PsyRealmAPIUserContractDataFetcher::new(http_client))
}

impl<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static>
    PsyRealmAPIUserContractDataFetcher<N, C>
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
impl<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static>
    PsyUserContractDataFetcher<N::F, N::QHash> for PsyRealmAPIUserContractDataFetcher<N, C>
{
    async fn df_get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        self.client
            .get_user_leaf_data(checkpoint_id, user_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
        async fn df_get_contract_state_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u64, height: u8, slot_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
            self.client.get_user_contract_state_tree_merkle_proof(checkpoint_id, user_id, contract_id as u32, height, slot_id).await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
        }
            async fn df_get_global_user_tree_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>{
        self.client.get_user_bottom_tree_merkle_proof(N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, checkpoint_id, user_id).await.map_err(|e| anyhow::anyhow!("{:?}", e))

            }
    async fn df_get_contract_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
       self.client.get_contract_tree_state_heights(
            checkpoint_id,
            contract_ids,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn df_get_user_contract_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreSingleIdKey>) -> anyhow::Result<Vec<N::QHash>> {
        self.client
            .get_user_contract_tree_nodes(checkpoint_id, node_keys)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn df_get_contract_state_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreDoubleIdKey>) -> anyhow::Result<Vec<N::QHash>> {
        self.client
            .get_user_contract_state_tree_nodes(checkpoint_id, node_keys)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn df_submit_end_cap_proof(&self, user_ec_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>, proof: Vec<u8>) -> anyhow::Result<()> {
        self.client
            .submit_user_end_cap(user_ec_input, proof)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Ok(())
    }

    async fn df_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        Ok(self.client
            .get_checkpoint_tree_merkle_proof(u64::MAX-0xFF, checkpoint_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?.to_append_proof::<N::HasherBase>())
    }

    async fn df_get_latest_checkpoint(&self) -> anyhow::Result<u64> {
        self.client.get_latest_checkpoint_id()
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
}
