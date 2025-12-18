use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_common::tree_sync::traits::FastTreeSyncAsyncSource;
use parth_core::{
    crypto::hash::merkle_proof::MerkleProofCore,
    data::hash::{
        merkle_node_key::SimpleMerkleNodeKey,
        merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreSingleIdKey},
    },
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_api_core::realm::standard_edge_rpc::RealmEdgeRpcClient;
use psy_data::{proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, v1::qdata::user::PQEDUserLeaf};

#[async_trait]
pub trait PsyUserContractDataFetcher<F, Hash> {
    async fn df_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_latest_checkpoint(&self) -> anyhow::Result<u64>;
    async fn df_get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<F, Hash>>;
    async fn df_get_user_leaves_batch(&self, checkpoint_id: u64, user_ids: Vec<u64>) -> anyhow::Result<Vec<PQEDUserLeaf<F, Hash>>>;
    async fn df_get_global_user_tree_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_contract_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>>;
    async fn df_get_contract_state_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreDoubleIdKey>) -> anyhow::Result<Vec<Hash>>;
    async fn df_get_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        height: u8,
        slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn df_get_user_contract_tree_nodes(&self, checkpoint_id: u64, node_keys: Vec<QMerkleStoreSingleIdKey>) -> anyhow::Result<Vec<Hash>>;
    async fn df_submit_end_cap_proof(&self, user_ec_input: SubmitUserEndCapNonProofInput<F, Hash>, proof: Vec<u8>) -> anyhow::Result<()>;
}

pub struct PsyUserContractTreeDataSyncHelper<F, Hash, Fetcher> {
    pub user_id: u64,
    pub checkpoint_id: u64,
    pub fetcher: Arc<Fetcher>,
    pub _phantom_f: std::marker::PhantomData<F>,
    pub _phantom_hash: std::marker::PhantomData<Hash>,
}
impl<F, Hash, Fetcher> PsyUserContractTreeDataSyncHelper<F, Hash, Fetcher> {
    pub fn new(user_id: u64, checkpoint_id: u64, fetcher: Fetcher) -> Self {
        Self {
            user_id,
            checkpoint_id,
            fetcher: Arc::new(fetcher),
            _phantom_f: std::marker::PhantomData,
            _phantom_hash: std::marker::PhantomData,
        }
    }
}
#[async_trait]
impl<Hash: Q256BitHash + Send + Sync + 'static, F: Send + Sync + 'static, Fetcher: PsyUserContractDataFetcher<F, Hash> + Send + Sync + 'static>
    FastTreeSyncAsyncSource<Hash> for PsyUserContractTreeDataSyncHelper<F, Hash, Fetcher>
{
    async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let nodes = self
            .fetcher
            .df_get_user_contract_tree_nodes(
                self.checkpoint_id,
                vec![QMerkleStoreSingleIdKey {
                    tree_id: self.user_id,
                    level: key.level,
                    index: key.index,
                }],
            )
            .await?;
        if nodes.len() != 1 {
            return Err(anyhow::anyhow!(
                "Expected exactly one node returned for key {:?}, got {}",
                key,
                nodes.len()
            ));
        }
        Ok(nodes[0])
    }
    async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        let node_keys: Vec<QMerkleStoreSingleIdKey> = keys
            .iter()
            .map(|key| QMerkleStoreSingleIdKey {
                tree_id: self.user_id,
                level: key.level,
                index: key.index,
            })
            .collect();
        self.fetcher.df_get_user_contract_tree_nodes(self.checkpoint_id, node_keys).await
    }
}
pub struct PsyContractStateTreeDataSyncHelper<F, Hash, Fetcher> {
    pub user_id: u64,
    pub contract_id: u64,
    pub checkpoint_id: u64,
    pub fetcher: Arc<Fetcher>,
    pub _phantom_f: std::marker::PhantomData<F>,
    pub _phantom_hash: std::marker::PhantomData<Hash>,
}
impl<F, Hash, Fetcher> PsyContractStateTreeDataSyncHelper<F, Hash, Fetcher> {
    pub fn new(user_id: u64, contract_id: u64, checkpoint_id: u64, fetcher: Fetcher) -> Self {
        Self {
            user_id,
            contract_id,
            checkpoint_id,
            fetcher: Arc::new(fetcher),
            _phantom_f: std::marker::PhantomData,
            _phantom_hash: std::marker::PhantomData,
        }
    }
}
#[async_trait]
impl<Hash: Q256BitHash + Send + Sync + 'static, F: Send + Sync + 'static, Fetcher: PsyUserContractDataFetcher<F, Hash> + Send + Sync + 'static>
    FastTreeSyncAsyncSource<Hash> for PsyContractStateTreeDataSyncHelper<F, Hash, Fetcher>
{
    async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let nodes = self
            .fetcher
            .df_get_contract_state_tree_nodes(
                self.checkpoint_id,
                vec![QMerkleStoreDoubleIdKey {
                    tree_id: self.user_id,
                    tree_sub_id: self.contract_id,
                    level: key.level,
                    index: key.index,
                }],
            )
            .await?;
        if nodes.len() != 1 {
            return Err(anyhow::anyhow!(
                "Expected exactly one node returned for key {:?}, got {}",
                key,
                nodes.len()
            ));
        }
        Ok(nodes[0])
    }
    async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        let node_keys: Vec<QMerkleStoreDoubleIdKey> = keys
            .iter()
            .map(|key| QMerkleStoreDoubleIdKey {
                tree_id: self.user_id,
                tree_sub_id: self.contract_id,
                level: key.level,
                index: key.index,
            })
            .collect();
        self.fetcher.df_get_contract_state_tree_nodes(self.checkpoint_id, node_keys).await
    }
}

#[derive(Clone)]
pub struct PsyRealmAPIUserContractDataFetcher<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<N::F>,
}

pub fn new_contract_data_fetcher_from_url<N: QNetworkTypesConfig + 'static>(
    api_url: &str,
) -> anyhow::Result<PsyRealmAPIUserContractDataFetcher<N, HttpClient>> {
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
    async fn df_get_user_leaves_batch(&self, checkpoint_id: u64, user_ids: Vec<u64>) -> anyhow::Result<Vec<PQEDUserLeaf<N::F, N::QHash>>> {
        println!("df_get_user_leaves_batch");
        let result = self
            .client
            .get_user_leaves_batch(checkpoint_id, user_ids)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        println!("fetched {} user leaves", result.len());
        Ok(result)
    }
    async fn df_get_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        height: u8,
        slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.client
            .get_user_contract_state_tree_merkle_proof(checkpoint_id, user_id, contract_id as u32, height, slot_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn df_get_global_user_tree_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.client
            .get_user_bottom_tree_merkle_proof(N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, checkpoint_id, user_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn df_get_contract_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
        self.client
            .get_contract_tree_state_heights(checkpoint_id, contract_ids)
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
        Ok(self
            .client
            .get_checkpoint_tree_merkle_proof(u64::MAX - 0xFF, checkpoint_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?
            .to_append_proof::<N::HasherBase>())
    }

    async fn df_get_latest_checkpoint(&self) -> anyhow::Result<u64> {
        self.client.get_latest_checkpoint_id().await.map_err(|e| anyhow::anyhow!("{:?}", e))
    }
}
