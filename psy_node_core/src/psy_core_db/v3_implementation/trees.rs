use std::sync::Arc;

use anyhow::Ok;
use async_trait::async_trait;
use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::MerkleZeroHasher},
    data::hash::{fast_node_serializer::{QMerkleStoreFastDoubleNodeSerializer, QMerkleStoreFastSingleNodeSerializer}, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode}},
    protocol::core_types::QNetworkDatabaseTypes,
    QCoreProcCheckpointUniqueId,
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, checkpoint_sync::PQEDCheckpointSyncInfo, user::PQEDUserLeaf
};
use crate::{psy_core_db::traits::realm::QEDRealmStoreWriterAsyncImm, store::traits::{core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalU64U128MappingReader,
    CoreDatabaseKivReader, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore,
    CoreDatabaseU64Reader, CoreDatabaseZeroIdMerkleReader,
}, helpers::{db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize, }}};

use crate::psy_core_db::{
    core_implementation::constants::{
        CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF, LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID,
    },
    traits::realm::QEDRealmStoreReaderAsync,
};
use crate::psy_core_db::traits::full::*;
#[derive(Clone)]
pub struct PsyUnifiedCoreDatabaseStore<
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
    PsyUnifiedCoreDatabaseStore<
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
    PsyNodeCheckpointTreeDatabaseReader<N::QHash> for 
    PsyUnifiedCoreDatabaseStore<
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
    async fn checkpoint_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash>{
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_index);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }
    async fn checkpoint_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash>{
        let root_key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &root_key)
            .await

    }
    async fn checkpoint_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>{
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key).await
    }
    async fn checkpoint_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<N::QHash>>{
        let hashes = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, keys)
            .await?;
        Ok(hashes)
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
    PsyNodeCheckpointTreeDatabaseWriter<N::QHash> for 
    PsyUnifiedCoreDatabaseStore<
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
    async fn checkpoint_tree_set_leaf_hash(&self, checkpoint_id: u64, value: N::QHash) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>>{
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &self.store,
            &self.global_checkpoint_tree_table,
            checkpoint_id,
            0,
            2*N::CHECKPOINT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, 0),
                value,
            }],
        ).await?;
       Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof returned after setting leaf"))?)
    }
    async fn checkpoint_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()>{
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_checkpoint_tree_table, checkpoint_id, nodes)
            .await
    }
}



