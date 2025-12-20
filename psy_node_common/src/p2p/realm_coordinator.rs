use async_trait::async_trait;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, data::hash::checkpointed_merkle_node::CheckpointedMerkleHash, protocol::core_types::QNetworkTypesConfig};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, prepared_block::realm::PsyRealmCoordinatorUpdate};
use psy_node_core::p2p::traits::realm_coordinantor::RealmCoordinatorClient;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti;

pub struct PsyRealmCoordinatorClientAPI<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<N::F>,
}

impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> PsyRealmCoordinatorClientAPI<N, C> {
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
impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync>
    RealmCoordinatorClient<N::F, N::QHash> for PsyRealmCoordinatorClientAPI<N, C>
{
        async fn rc_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>{
            self.client.get_checkpoint_tree_merkle_proof(checkpoint_id, checkpoint_id).await.map_err(|e| anyhow::anyhow!("{:?}", e))
        }
    async fn rc_get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        self.client.get_latest_checkpoint_id().await.map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn rc_wait_for_next_checkpoint(&self) -> anyhow::Result<u64> {
        let start = self.client.get_latest_checkpoint_id().await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let mut current = start;
        while current == start {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            current = self.client.get_latest_checkpoint_id().await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        Ok(current)
    }
    async fn rc_get_realm_sync_info(&self, checkpoint_id: u64, realm_id: u64) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        self.client
            .get_realm_sync_info(checkpoint_id, realm_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn rc_get_checkpoint_leaves_batch(&self, start_checkpoint_id: u64, count: u32) -> anyhow::Result<Vec<N::QHash>> {
        let raw = self.client.get_checkpoint_leaves_batch_raw(start_checkpoint_id, count).await?;
        if raw.len() == 0 {
            return Ok(vec![]);
        }
        if raw.len() % 32 != 0 {
            return Err(anyhow::anyhow!("Invalid byte length for checkpoint leaves batch"));
        }
        Ok(N::QHash::psy_ser_deserialize_vec_of_self_owned(raw, false)?)
    }
    async fn rc_get_realm_root_and_last_modified_checkpoint(
        &self,
        checkpoint_id: u64,
        realm_id: u64,
    ) -> anyhow::Result<CheckpointedMerkleHash<N::QHash>> {
        self.client
            .get_realm_root_and_last_modified_checkpoint(checkpoint_id, realm_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
    async fn rc_submit_guta_proof(
        &self,
        input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        proof: Vec<u8>,
        realm_id: u64,
    ) -> anyhow::Result<()> {
        self.client
            .submit_guta(input, proof, realm_id)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Ok(())
    }
    async fn rc_get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
        self.client
            .get_contract_tree_state_heights(checkpoint_id, contract_ids)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
    }
}
