use async_trait::async_trait;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, data::hash::{merkle_node_key::SimpleMerkleNode, merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode}}, felt::ToU64Value, protocol::core_types::QNetworkDatabaseTypes, QCoreProcCheckpointUniqueId};
use psy_data::v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, user::PQEDUserLeaf};

#[async_trait]
pub trait QEDRealmStoreReaderAsync<N: QNetworkDatabaseTypes> {

    
    //get_user_ids_for_public_key is a replacement for async fn get_first_user_id(&self, public_key: N::QHash) -> anyhow::Result<u64>;
    // paginates through the user ids for a given public key starting from start_user_id (inclusive), restrict count to some reasonable number to avoid large data transfers
    async fn get_user_ids_for_public_key(&self, public_key:  N::QHash, start_user_id: u64, count: usize) -> anyhow::Result<Vec<u64>>;
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>>;
    async fn get_checkpoint_leaf_data_f(&self, checkpoint_id: N::F) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_checkpoint_leaf_data(self, checkpoint_id.to_u64_value()).await
    }
    async fn get_latest_checkpoint_leaf_data(&self) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>>;

    async fn get_checkpoint_id_for_checkpoint_root_hash(&self, checkpoint_root: &N::QHash) -> anyhow::Result<Option<u64>>;

    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState>;

    async fn get_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<QEDL2BlockState>;
    async fn get_l2_block_state_f(&self, checkpoint_id: N::F) -> anyhow::Result<QEDL2BlockState> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_l2_block_state(self, checkpoint_id.to_u64_value()).await
    }


    //async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;


    async fn get_latest_checkpoint_tree_root(&self) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_root_f(&self, checkpoint_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_checkpoint_tree_root(self, checkpoint_id.to_u64_value()).await
    }
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_checkpoint_tree_leaf_hash_f(&self, checkpoint_id: N::F, leaf_checkpoint_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_checkpoint_tree_leaf_hash(self, checkpoint_id.to_u64_value(), leaf_checkpoint_id.to_u64_value()).await
    }
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_checkpoint_tree_merkle_proof_f(&self, checkpoint_id: N::F, leaf_checkpoint_id: N::F) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_checkpoint_tree_merkle_proof(self, checkpoint_id.to_u64_value(), leaf_checkpoint_id.to_u64_value()).await
    }

    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointGlobalStateRoots<N::QHash>>;



    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>>;
    async fn get_user_leaf_data_f(&self, checkpoint_id: N::F, user_id: N::F) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_leaf_data(self, checkpoint_id.to_u64_value(), user_id.to_u64_value()).await
    }


    async fn get_user_contract_state_tree_root(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_user_contract_state_tree_root_f(&self, checkpoint_id: N::F, user_id: N::F, contract_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_state_tree_root(self, checkpoint_id.to_u64_value(), user_id.to_u64_value(), contract_id.to_u64_value() as u32).await
    }
    async fn get_user_contract_state_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32, height: u8, leaf_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_contract_state_tree_leaf_hash_f(&self, checkpoint_id: N::F, user_id: N::F, contract_id: N::F, height: u8, leaf_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_state_tree_leaf_hash(
            self,
            checkpoint_id.to_u64_value(),
            user_id.to_u64_value(),
            contract_id.to_u64_value() as u32,
            height,
            leaf_id.to_u64_value()
        ).await
    }
    async fn get_user_contract_state_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u32, height: u8, leaf_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_contract_state_tree_merkle_proof_f(&self, checkpoint_id: N::F, user_id: N::F, contract_id: N::F, height: u8, leaf_id: N::F) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_state_tree_merkle_proof(
            self,
            checkpoint_id.to_u64_value(),
            user_id.to_u64_value(),
            contract_id.to_u64_value() as u32,
            height,
            leaf_id.to_u64_value()
        ).await
    }


    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_contract_tree_root_f(&self, checkpoint_id: N::F, user_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_tree_root(self, checkpoint_id.to_u64_value(), user_id.to_u64_value()).await
    }
    async fn get_user_contract_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<N::QHash>;
    async fn get_user_contract_tree_leaf_hash_f(&self, checkpoint_id: N::F, user_id: N::F, contract_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_tree_leaf_hash(
            self,
            checkpoint_id.to_u64_value(),
            user_id.to_u64_value(),
            contract_id.to_u64_value() as u32
        ).await
    }
    async fn get_user_contract_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_contract_tree_merkle_proof_f(&self, checkpoint_id: N::F, user_id: N::F, contract_id: N::F) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_contract_tree_merkle_proof(
            self,
            checkpoint_id.to_u64_value(),
            user_id.to_u64_value(),
            contract_id.to_u64_value() as u32
        ).await
    }



    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_tree_root_f(&self, checkpoint_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_tree_root(self, checkpoint_id.to_u64_value()).await
    }
    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<N::QHash>;
    async fn get_user_tree_leaf_hash_f(&self, checkpoint_id: N::F, user_id: N::F) -> anyhow::Result<N::QHash> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_tree_leaf_hash(self, checkpoint_id.to_u64_value(), user_id.to_u64_value()).await
    }
    async fn get_user_bottom_tree_merkle_proof(&self, root_level: u8,checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;
    async fn get_user_bottom_tree_merkle_proof_f(&self, root_level: u8, checkpoint_id: N::F, user_id: N::F) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_bottom_tree_merkle_proof(self, root_level, checkpoint_id.to_u64_value(), user_id.to_u64_value()).await
    }
    async fn get_user_sub_tree_merkle_proof(&self, checkpoint_id: u64, root_level: u8, leaf_level: u8, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>;

    async fn get_user_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> ;

    async fn get_user_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        <Self as QEDRealmStoreReaderAsync<N>>::get_user_tree_merkle_proof(self, checkpoint_id.to_u64_value(), user_id.to_u64_value()).await
    }
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>;
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>>;

    async fn get_current_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
}

#[async_trait]
pub trait QEDRealmStoreWriterAsyncImm<N: QNetworkDatabaseTypes> {
    /*
    async fn apply_only_global_block_update_dangerous(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn apply_only_pending_realm_update_dangerous(&self, pending_realm_update: &RealmPendingCheckpoint<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn apply_realm_checkpoint_update(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>, pending_realm_update: &RealmPendingCheckpoint<N::F, N::QHash>) -> anyhow::Result<()>;
    */
    
    async fn inc_unique_pending_id(&self, amount: u64) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
    async fn set_unique_pending_id_checkpoint_id_mapping(&self, unique_pending_id: u64, checkpoint_id: u64) -> anyhow::Result<()>;

    async fn set_checkpoint_id_to_unique_pending_id_mapping(&self, checkpoint_id: u64, unique_pending_id: u64, unique_id_struct: &QCoreProcCheckpointUniqueId) -> anyhow::Result<()>;
    async fn set_latest_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<()>;
    async fn set_checkpoint_leaf_data(&self, checkpoint_id: u64, leaf_data: &PQEDCheckpointLeaf<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn set_checkpoint_root_hash_to_id_mapping(&self, checkpoint_root: &N::QHash, checkpoint_id: u64) -> anyhow::Result<()>;
    async fn set_l2_block_state(&self, checkpoint_id: u64, block_state: &QEDL2BlockState) -> anyhow::Result<()>;
    async fn set_user_leaf_data(&self, checkpoint_id: u64, leaf_data: &PQEDUserLeaf<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn set_checkpoint_global_state_roots(&self, checkpoint_id: u64, roots: &PQEDCheckpointGlobalStateRoots<N::QHash>) -> anyhow::Result<()>;

    async fn set_checkpoint_tree_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()>;
    async fn set_checkpoint_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()>;
    async fn set_user_tree_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()>;
    async fn set_user_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()>;
    async fn set_user_contract_tree_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<N::QHash>]) -> anyhow::Result<()>;
    async fn set_user_contract_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()>;
    async fn set_user_contract_state_tree_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreDoubleIdNode<N::QHash>]) -> anyhow::Result<()>;
    async fn set_user_contract_state_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()>;
}



