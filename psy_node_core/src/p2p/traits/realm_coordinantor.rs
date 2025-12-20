use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, data::hash::checkpointed_merkle_node::CheckpointedMerkleHash};
use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, prepared_block::realm::PsyRealmCoordinatorUpdate};


#[async_trait]
#[auto_impl(&, Box, Arc)]
pub trait RealmCoordinatorClient<F, Hash> {
    async fn rc_get_latest_checkpoint_id(&self) -> anyhow::Result<u64>;
    async fn rc_wait_for_next_checkpoint(&self) -> anyhow::Result<u64>;
    async fn rc_get_realm_sync_info(&self, checkpoint_id: u64, realm_id: u64) -> anyhow::Result<PsyRealmCoordinatorUpdate<F, Hash>>;
    async fn rc_get_checkpoint_leaves_batch(&self, start_checkpoint_id: u64, count: u32) -> anyhow::Result<Vec<Hash>>;
    async fn rc_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn rc_get_realm_root_and_last_modified_checkpoint(&self, checkpoint_id: u64, realm_id: u64) -> anyhow::Result<CheckpointedMerkleHash<Hash>>;
    async fn rc_submit_guta_proof(&self, input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>, proof: Vec<u8>, realm_id: u64) -> anyhow::Result<()>;
    async fn rc_get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>>;
}

