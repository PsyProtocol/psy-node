use std::sync::Arc;

use anyhow::Ok;
use async_trait::async_trait;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, data::hash::{fast_node_serializer::{QMerkleStoreFastDoubleNodeSerializer, QMerkleStoreFastSingleNodeSerializer}, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode}}, felt::ToU64Value, protocol::core_types::QNetworkDatabaseTypes, QCoreProcCheckpointUniqueId
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, checkpoint_sync::PQEDCheckpointSyncInfo, user::PQEDUserLeaf
};
use crate::{psy_core_db::traits::realm::QEDRealmStoreWriterAsyncImm, store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalU64U128MappingReader,
    CoreDatabaseKivReader, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore,
    CoreDatabaseU64Reader, CoreDatabaseZeroIdMerkleReader,
}};

use crate::psy_core_db::{
    core_implementation::constants::{
        CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF, LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID,
    },
    traits::realm::QEDRealmStoreReaderAsync,
};

#[derive(Clone)]
pub struct QRealmStoreBase<
    N: QNetworkDatabaseTypes,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
    S: CoreDatabaseStore<
            N::QHash,
            N::HasherBase,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
        > + Send + Sync,
> {
    pub store: Arc<S>,
    // start objects
    pub checkpoint_leaf_table: Arc<KivTableIdentifier>,
    pub checkpoint_root_to_checkpoint_id_table: Arc<BiDirectionalMappingTableIdentifier>,
    pub checkpoint_leaf_to_checkpoint_id_table: Arc<BiDirectionalMappingTableIdentifier>,
    pub l2_block_state_table: Arc<KivTableIdentifier>,
    pub checkpoint_id_to_realm_root_table: Arc<KivTableIdentifier>,
    pub latest_info_table: Arc<KivTableIdentifier>,
    pub checkpointed_object_table: Arc<SingleIdTableIdentifier>,
    pub checkpoint_state_roots_table: Arc<KivTableIdentifier>,
    pub user_leaf_table: Arc<SingleIdTableIdentifier>,
    pub user_public_key_table: Arc<SingleIdTableIdentifier>,
    pub u64_singleton_table: Arc<U64TableIdentifier>,
    pub checkpoint_id_to_pending_id_table: Arc<U64TableIdentifier>,
    pub pending_id_to_checkpoint_id_table: Arc<U64TableIdentifier>,
    pub pending_id_to_pending_proc_id_table: Arc<BiDirectionalU64U128MappingTableIdentifier>,


    // mappings
    pub public_key_hash_to_user_ids_table: Arc<HashToManyIdsTableIdentifier>,

    // start trees
    pub global_user_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
    pub user_contract_tree_table: Arc<SingleIdMerkleTableIdentifier>,
    pub contract_state_tree_table: Arc<DoubleIdMerkleTableIdentifier>,
    pub global_checkpoint_tree_table: Arc<ZeroIdMerkleTableIdentifier>,

    // start reward tree table
    pub guta_reward_tag_tree_table: Arc<TagTreeTableIdentifier>,

    // start unused table types
    pub _phantom_double_id_table: std::marker::PhantomData<DoubleIdTableIdentifier>,

    // start phantom N
    pub _phantom_n: std::marker::PhantomData<N>,
}

//#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
            > + Send + Sync
    >
    QRealmStoreBase<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
    >
{
    // start merkle helpers

    async fn db_select_double_id_merkle_proof_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
    }

    async fn db_select_single_id_merkle_proof_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node value found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            siblings: results,
            index: key.index,
        })
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint_to_root_level(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        root_level: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(key.parent_at_level(root_level));
        let mut results = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
    }
    // end merkle helpers
    async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        let v = self
            .store
            .db_select_u64_value(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID)
            .await?;
        match v {
            Some(id) => Ok(id),
            None => Ok(0),
        }
    }
    async fn get_latest_pending_id(&self) -> anyhow::Result<u64> {
        let v = self
            .store
            .db_select_u64_value(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID)
            .await?;
        match v {
            Some(id) => Ok(id),
            None => Ok(0),
        }
    }


    async fn _apply_global_block_update_internal(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>) -> anyhow::Result<()>{
        let _latest_pending_id = self.get_latest_pending_id().await?;
        let latest_checkpoint_id = self.get_latest_checkpoint_id().await?;
        let new_checkpoint_id = global_block_update.core.l2_block_state.checkpoint_id;
        if new_checkpoint_id != (latest_checkpoint_id + 1) {
            anyhow::bail!("Global block update checkpoints MUST be applied in order, got a global checkpoint with id {} while our latest checkpoint is {}", new_checkpoint_id, latest_checkpoint_id);
        }







        Ok(())
    }

}
#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
            > + Send + Sync,
    >
    QEDRealmStoreReaderAsync<N> for 
    QRealmStoreBase<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
    >
{
    async fn get_user_ids_for_public_key(&self, public_key: N::QHash, start_user_id: u64, count: usize) -> anyhow::Result<Vec<u64>> {
        let user_ids = self
            .store
            .db_select_value_u64_ids_for_hash(
                &self.public_key_hash_to_user_ids_table,
                public_key,
                count,
                start_user_id,
            )
            .await?;
        Ok(user_ids)
    }
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>> {
        let maybe_leaf = self
            .store
            .db_select_one_kiv_value::<PQEDCheckpointLeaf<N::F, N::QHash>>(&self.checkpoint_leaf_table, checkpoint_id)
            .await?;
        match maybe_leaf {
            Some(leaf) => Ok(leaf),
            None => anyhow::bail!("Checkpoint leaf not found for checkpoint_id {}", checkpoint_id),
        }
    }

    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState> {
        let maybe_state = self
            .store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE)
            .await?;
        match maybe_state {
            Some(state) => Ok(state),
            None => anyhow::bail!("Latest L2 block state not found"),
        }
    }
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<QEDL2BlockState> {
        let maybe_state = self
            .store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.l2_block_state_table, checkpoint_id)
            .await?;
        match maybe_state {
            Some(state) => Ok(state),
            None => anyhow::bail!("L2 block state not found for checkpoint_id {}", checkpoint_id),
        }
    }
    async fn get_latest_checkpoint_tree_root(&self) -> anyhow::Result<N::QHash> {
        let maybe_root = self
            .store
            .db_select_one_kiv_value::<N::QHash>(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT)
            .await?;
        match maybe_root {
            Some(root) => Ok(root),
            None => anyhow::bail!("Latest checkpoint tree root not found"),
        }
    }
    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointGlobalStateRoots<N::QHash>> {
        let maybe_roots = self
            .store
            .db_select_one_kiv_value::<PQEDCheckpointGlobalStateRoots<N::QHash>>(&self.checkpoint_state_roots_table, checkpoint_id)
            .await?;
        match maybe_roots {
            Some(roots) => Ok(roots),
            None => anyhow::bail!("Checkpoint global state roots not found for checkpoint_id {}", checkpoint_id),
        }
    }
    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        let maybe_leaf = self
            .store
            .db_select_one_single_checkpointed_object_value::<PQEDUserLeaf<N::F, N::QHash>>(&self.user_leaf_table, user_id, checkpoint_id)
            .await?;
        match maybe_leaf {
            Some(leaf) => Ok(leaf),
            None => anyhow::bail!("User leaf not found for checkpoint_id {}, user_id {}", checkpoint_id, user_id),
        }
    }
    async fn get_user_contract_state_tree_root(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id as u64);

        self.store
            .db_select_single_id_merkle_node_max_checkpoint(
                &self.user_contract_tree_table,
                checkpoint_id,
                user_id,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
                key,
            )
            .await
    }
    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(height, leaf_id);
        self.store
            .db_select_double_id_merkle_node_max_checkpoint(&self.contract_state_tree_table, checkpoint_id, user_id, contract_id as u64, height, key)
            .await
    }
    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(height, leaf_id);
        self.db_select_double_id_merkle_proof_max_checkpoint(
            &self.contract_state_tree_table,
            checkpoint_id,
            user_id,
            contract_id as u64,
            height,
            &key,
        )
        .await
    }
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let result = self
            .store
            .db_select_one_single_checkpointed_object_value::<MerkleProofCore<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                checkpoint_id,
            )
            .await?;
        match result {
            Some(p) => Ok(p.root),
            None => Ok(N::HasherBase::get_zero_hash(N::GLOBAL_USER_TREE_HEIGHT as usize)),
        }
    }

    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, user_id);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
            .await
    }
    async fn get_user_bottom_tree_merkle_proof(&self, root_level: u8, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, user_id);
        self.db_select_zero_id_merkle_proof_max_checkpoint_to_root_level(&self.global_user_tree_table, checkpoint_id, root_level, &key)
            .await
    }
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(leaf_level, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint_to_root_level(&self.global_user_tree_table, checkpoint_id, root_level, &key)
            .await
    }

    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let top_proof = self
            .store
            .db_select_one_single_checkpointed_object_value::<MerkleProofCore<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                checkpoint_id,
            )
            .await?;
        if top_proof.is_none() {
            return Err(anyhow::anyhow!("No top proof found for checkpoint_id {}", checkpoint_id));
        }
        let top_proof = top_proof.unwrap();
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, user_id);
        let bottom_proof = self
            .db_select_zero_id_merkle_proof_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
            .await?;
        // combine proofs
        Ok(MerkleProofCore {
            root: top_proof.root,
            value: bottom_proof.value,
            index: bottom_proof.index,
            siblings: [top_proof.siblings, bottom_proof.siblings].concat(),
        })
    }
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>> {
        let pending_id = self
            .store
            .db_select_u64_value(&self.checkpoint_id_to_pending_id_table, checkpoint_id)
            .await?;
        match pending_id {
            Some(pid) => {
                let unique_id = self
                    .store
                    .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pid)
                    .await?;
                match unique_id {
                    Some(uid) => Ok(Some((pid, uid))),
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        let checkpoint_id = self
            .store
            .db_select_u64_value(&self.pending_id_to_checkpoint_id_table, unique_pending_id)
            .await?;
        Ok(checkpoint_id)
    }
    async fn get_current_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let pending_id = self.get_latest_pending_id().await?;
        let unique_id = self
            .store
            .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pending_id)
            .await?;
        match unique_id {
            Some(uid) => Ok((pending_id, uid)),
            None => anyhow::bail!("No unique id found for pending id {}", pending_id),
        }
    }
    async fn get_latest_checkpoint_leaf_data(&self) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>> {
        let latest_checkpoint_id = self.get_latest_checkpoint_id().await?;
        self.get_checkpoint_leaf_data(latest_checkpoint_id).await
    }
    async fn get_checkpoint_id_for_checkpoint_root_hash(&self, checkpoint_root_hash: &N::QHash) -> anyhow::Result<Option<u64>> {
        let maybe_id = self
            .store
            .db_select_one_by_k1::<N::QHash, u64>(&self.checkpoint_root_to_checkpoint_id_table, checkpoint_root_hash)
            .await?;
        Ok(maybe_id)
    }
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let root_key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &root_key)
            .await
    }
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_checkpoint_id);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_checkpoint_id);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }
    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<N::QHash> {
        self.store
            .db_select_single_id_merkle_node_max_checkpoint(
                &self.user_contract_tree_table,
                checkpoint_id,
                user_id,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
                SimpleMerkleNodeKey::new_root(),
            )
            .await
    }
    async fn get_user_contract_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id as u64);
        self.store
            .db_select_single_id_merkle_node_max_checkpoint(
                &self.user_contract_tree_table,
                checkpoint_id,
                user_id,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
                key,
            )
            .await
    }
    async fn get_user_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id as u64);
        self.db_select_single_id_merkle_proof_max_checkpoint(
            &self.user_contract_tree_table,
            checkpoint_id,
            user_id,
            N::GLOBAL_CONTRACT_TREE_HEIGHT,
            key,
        )
        .await
    }
}




#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
            > + Send + Sync,
    >
    QEDRealmStoreWriterAsyncImm<N> for 
    QRealmStoreBase<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
    >
{

    /*
    async fn apply_only_global_block_update_dangerous(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn apply_only_pending_realm_update_dangerous(&self, pending_realm_update: &RealmPendingCheckpoint<N::F, N::QHash>) -> anyhow::Result<()>;
    async fn apply_realm_checkpoint_update(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>, pending_realm_update: &RealmPendingCheckpoint<N::F, N::QHash>) -> anyhow::Result<()>;
    */
    
    async fn inc_unique_pending_id(&self, amount: u64) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let new_pending_id = self
            .store
            .db_inc_counter(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID, amount as i64)
            .await?;
        let unique_id = rand::random::<u128>();
        self.store
            .db_insert_u64_u128_mapping_pair(&self.pending_id_to_pending_proc_id_table, new_pending_id, unique_id)
            .await?;
        Ok((new_pending_id, unique_id))
    }

    async fn set_unique_pending_id_checkpoint_id_mapping(&self, unique_pending_id: u64, checkpoint_id: u64) -> anyhow::Result<()> {
        self.store
            .db_set_u64_value(&self.pending_id_to_checkpoint_id_table, unique_pending_id, checkpoint_id)
            .await
    }

    async fn set_checkpoint_id_to_unique_pending_id_mapping(
        &self,
        checkpoint_id: u64,
        unique_pending_id: u64,
        unique_id_struct: &QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<()> {
        self.store
            .db_set_u64_value(&self.checkpoint_id_to_pending_id_table, checkpoint_id, unique_pending_id)
            .await?;
        self.store
            .db_insert_u64_u128_mapping_pair(&self.pending_id_to_pending_proc_id_table, unique_pending_id, *unique_id_struct)
            .await
    }

    async fn set_latest_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<()> {
        self.store
            .db_set_u64_value(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, checkpoint_id)
            .await
    }

    async fn set_checkpoint_leaf_data(&self, checkpoint_id: u64, leaf_data: &PQEDCheckpointLeaf<N::F, N::QHash>) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(&self.checkpoint_leaf_table, checkpoint_id, leaf_data).await
    }

    async fn set_checkpoint_root_hash_to_id_mapping(&self, checkpoint_root: &N::QHash, checkpoint_id: u64) -> anyhow::Result<()> {
        self.store
            .db_insert_pair_ref(&self.checkpoint_root_to_checkpoint_id_table, checkpoint_root, &checkpoint_id)
            .await
    }

    async fn set_l2_block_state(&self, checkpoint_id: u64, block_state: &QEDL2BlockState) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(&self.l2_block_state_table, checkpoint_id, block_state).await
    }

    async fn set_user_leaf_data(&self, checkpoint_id: u64, leaf_data: &PQEDUserLeaf<N::F, N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.user_leaf_table, leaf_data.user_id.to_u64_value(), checkpoint_id, leaf_data)
            .await
    }

    async fn set_checkpoint_global_state_roots(&self, checkpoint_id: u64, roots: &PQEDCheckpointGlobalStateRoots<N::QHash>) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(&self.checkpoint_state_roots_table, checkpoint_id, roots).await
    }

    async fn set_checkpoint_tree_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_checkpoint_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn set_checkpoint_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_from_fast_serialized(&self.global_checkpoint_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn set_user_tree_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store.db_set_zero_id_merkle_nodes_batch(&self.global_user_tree_table, checkpoint_id, nodes).await
    }

    async fn set_user_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_from_fast_serialized(&self.global_user_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn set_user_contract_tree_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<N::QHash>]) -> anyhow::Result<()> {
        let data = QMerkleStoreFastSingleNodeSerializer::serialize_single_id_many_nodes(nodes);

        self.store.db_set_single_id_merkle_nodes_from_fast_serialized(&self.user_contract_tree_table, checkpoint_id, &data).await
    }

    async fn set_user_contract_tree_nodes_ffs(&self, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_single_id_merkle_nodes_from_fast_serialized(&self.user_contract_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn set_user_contract_state_tree_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreDoubleIdNode<N::QHash>]) -> anyhow::Result<()> {
        let data = QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_many_nodes(nodes);

        self.store
            .db_set_double_id_merkle_nodes_from_fast_serialized(&self.contract_state_tree_table, checkpoint_id, &data)
            .await
    }

    async fn set_user_contract_state_tree_nodes_ffs(
        &self,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()> {
        self.store
            .db_set_double_id_merkle_nodes_from_fast_serialized(&self.contract_state_tree_table, checkpoint_id, nodes)
            .await
    }
}