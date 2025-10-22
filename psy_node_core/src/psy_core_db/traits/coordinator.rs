use async_trait::async_trait;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, protocol::core_types::QNetworkDatabaseTypes, QCoreProcCheckpointUniqueId};
use psy_data::v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::{ContractCodeDefinition, PQEDContractLeaf}};
use crate::data::pending::coordinator::{CoordinatorPendingCheckpointDatabase, CoordinatorPendingCheckpointSync};


#[async_trait]
pub trait QEDCoordinatorObjectStoreReaderAsync<N: QNetworkDatabaseTypes> {
    async fn get_contract_leaf_data(&self, contract_id: u64) -> anyhow::Result<PQEDContractLeaf<N::F, N::QHash>>;
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>>;
    async fn get_contract_code_definition(&self, contract_id: u64) -> anyhow::Result<ContractCodeDefinition>;
    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState>;
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<QEDL2BlockState>;
    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointGlobalStateRoots<N::QHash>>;
    async fn get_checkpoint_sync_info_compact(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointSyncInfoCompact<N::F, N::QHash>>;


}

#[async_trait]
pub trait QEDCoordinatorTreeStoreReaderAsync<N: QNetworkDatabaseTypes> {
    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_registration_tree_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_registration_tree_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_sub_tree_merkle_proof(&self, checkpoint_id: u64, root_level: u8, leaf_level: u8, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_top_tree_merkle_proof(&self, checkpoint_id: u64, leaf_level: u8, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_top_tree_cap_root(&self, checkpoint_id: u64, cap_level: u8, cap_index: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_latest_top_tree_cap_root(&self, cap_level: u8, cap_index: u64) -> anyhow::Result<N::QHash>;


    async fn get_contract_function_tree_root(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_contract_function_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_contract_function_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> anyhow::Result<MerkleProofCore<N::QHash>>;


    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_contract_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_contract_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<MerkleProofCore<N::QHash>>;



    async fn get_deposit_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_deposit_tree_leaf_hash(&self, checkpoint_id: u64, deposit_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_deposit_tree_merkle_proof(&self, checkpoint_id: u64, deposit_id: u32) -> anyhow::Result<MerkleProofCore<N::QHash>>;

    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_withdrawal_tree_leaf_hash(&self, checkpoint_id: u64, withdrawal_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_withdrawal_tree_merkle_proof(&self, checkpoint_id: u64, withdrawal_id: u32) -> anyhow::Result<MerkleProofCore<N::QHash>>;

    async fn get_latest_checkpoint_tree_root(&self) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>;
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>>;
    async fn get_current_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;

}

pub trait QEDCoordinatorStoreReaderAsync<N: QNetworkDatabaseTypes>: QEDCoordinatorObjectStoreReaderAsync<N> + QEDCoordinatorTreeStoreReaderAsync<N> {}
impl<N: QNetworkDatabaseTypes, T: QEDCoordinatorObjectStoreReaderAsync<N> + QEDCoordinatorTreeStoreReaderAsync<N>> QEDCoordinatorStoreReaderAsync<N> for T {}


#[async_trait]
pub trait QEDCoordinatorObjectStoreWriterAsync<N: QNetworkDatabaseTypes> {
    async fn apply_block_from_peer(&self, peer_block_update: &CoordinatorPendingCheckpointSync<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn apply_pending_block_update(&self, pending_block_update: &CoordinatorPendingCheckpointDatabase<N::F, N::QHash>) -> anyhow::Result<()>;    
    async fn inc_unique_pending_id(&self, amount: u64) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
    async fn set_unique_pending_id_checkpoint_id_mapping(&self, unique_pending_id: u64, checkpoint_id: u64) -> anyhow::Result<()>;
}
