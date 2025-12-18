use async_trait::async_trait;
use jsonrpsee::http_client::HttpClient;
use parth_core::{
    crypto::hash::merkle_proof::MerkleProofCore,
    data::hash::merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey},
    protocol::core_types::QNetworkTypesConfig,
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    v1::qdata::{public_key::PZKPublicKeyInfo, user::PQEDUserLeaf},
};

use crate::api::{
    coordinator_fetcher::{new_coordinator_fetcher_from_url, PsyCoordinatorAPIFetcher, PsyCoordinatorFetcher},
    data_fetcher::{new_contract_data_fetcher_from_url, PsyRealmAPIUserContractDataFetcher, PsyUserContractDataFetcher},
};

pub trait PsyDummyProverComboFetcher<F, Hash>: PsyCoordinatorFetcher<Hash> + PsyUserContractDataFetcher<F, Hash> {}

impl<T, F, Hash> PsyDummyProverComboFetcher<F, Hash> for T where T: PsyCoordinatorFetcher<Hash> + PsyUserContractDataFetcher<F, Hash> {}

#[derive(Clone)]
pub struct PsyDummyComboAPIFetcher<
    N: QNetworkTypesConfig + 'static,
    CC: PsyCoordinatorFetcher<N::QHash>,
    RC: PsyUserContractDataFetcher<N::F, N::QHash>,
> {
    pub cc: CC,
    pub rc: RC,
    _phantom_f: std::marker::PhantomData<N::F>,
}

impl<N: QNetworkTypesConfig + 'static, CC: PsyCoordinatorFetcher<N::QHash>, RC: PsyUserContractDataFetcher<N::F, N::QHash>>
    PsyDummyComboAPIFetcher<N, CC, RC>
{
    pub fn new(cc: CC, rc: RC) -> Self {
        Self {
            cc,
            rc,
            _phantom_f: std::marker::PhantomData,
        }
    }
}
#[async_trait]
impl<
        N: QNetworkTypesConfig + 'static,
        CC: PsyCoordinatorFetcher<N::QHash> + Send + Sync + 'static,
        RC: PsyUserContractDataFetcher<N::F, N::QHash> + Send + Sync + 'static,
    > PsyUserContractDataFetcher<N::F, N::QHash> for PsyDummyComboAPIFetcher<N, CC, RC>
{
    async fn df_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.rc.df_get_checkpoint_tree_merkle_proof(checkpoint_id).await
    }
    async fn df_get_latest_checkpoint(&self) -> anyhow::Result<u64> {
        self.rc.df_get_latest_checkpoint().await
    }
    async fn df_get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        self.rc.df_get_user_leaf(checkpoint_id, user_id).await
    }
    async fn df_get_global_user_tree_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.rc.df_get_global_user_tree_proof(checkpoint_id, user_id).await
    }
    async fn df_get_contract_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
        self.rc.df_get_contract_state_heights(checkpoint_id, contract_ids).await
    }
    async fn df_get_contract_state_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreDoubleIdKeyWithHeight>) -> anyhow::Result<Vec<N::QHash>> {
        self.rc.df_get_contract_state_tree_nodes(checkpoint_id, node_keys).await
    }
        async fn df_get_user_leaves_batch(&self, checkpoint_id: u64, user_ids: Vec<u64>) -> anyhow::Result<Vec<PQEDUserLeaf<N::F, N::QHash>>>{
        self.rc.df_get_user_leaves_batch(checkpoint_id, user_ids).await
        }
    async fn df_get_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        height: u8,
        slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.rc
            .df_get_contract_state_tree_merkle_proof(checkpoint_id, user_id, contract_id, height, slot_id)
            .await
    }
    async fn df_get_user_contract_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreSingleIdKey>) -> anyhow::Result<Vec<N::QHash>> {
        self.rc.df_get_user_contract_tree_nodes(checkpoint_id, node_keys).await
    }
    async fn df_submit_end_cap_proof(&self, user_ec_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>, proof: Vec<u8>) -> anyhow::Result<()> {
        self.rc.df_submit_end_cap_proof(user_ec_input, proof).await
    }
}
#[async_trait]
impl<
        N: QNetworkTypesConfig + 'static,
        CC: PsyCoordinatorFetcher<N::QHash> + Send + Sync + 'static,
        RC: PsyUserContractDataFetcher<N::F, N::QHash> + Send + Sync + 'static,
    > PsyCoordinatorFetcher<N::QHash> for PsyDummyComboAPIFetcher<N, CC, RC>
{
    async fn cf_get_user_public_key_hashes(&self, user_ids: &[u64]) -> anyhow::Result<Vec<N::QHash>> {
        self.cc.cf_get_user_public_key_hashes(user_ids).await
    }
    async fn cf_get_user_public_key(&self, user_id: u64) -> anyhow::Result<PZKPublicKeyInfo<N::QHash>> {
        self.cc.cf_get_user_public_key(user_id).await
    }
    async fn cf_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.cc.cf_get_checkpoint_tree_merkle_proof(checkpoint_id).await
    }
}

pub fn new_combo_fetcher_from_urls<N: QNetworkTypesConfig + 'static>(
    coordinator_api_url: &str,
    realm_api_url: &str,
) -> anyhow::Result<PsyDummyComboAPIFetcher<N, PsyCoordinatorAPIFetcher<N, HttpClient>, PsyRealmAPIUserContractDataFetcher<N, HttpClient>>> {
    println!("coordinator api url: {}", coordinator_api_url);
    println!("realm api url: {}", realm_api_url);
    let cc = new_coordinator_fetcher_from_url::<N>(coordinator_api_url)?;
    let rc = new_contract_data_fetcher_from_url::<N>(realm_api_url)?;
    Ok(PsyDummyComboAPIFetcher::new(cc, rc))
}
