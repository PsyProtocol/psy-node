use std::sync::Arc;

use anyhow::Ok;
use async_trait::async_trait;
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
    }, data::{
        db::row::{QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowNoCheckpointId},
        hash::{
            merkle_node_key::{PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY, SimpleMerkleNode, SimpleMerkleNodeKey},
            merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode},
        },
    }, felt::ToU64Value, protocol::core_types::QNetworkDatabaseTypes
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
    checkpoint_sync::PQEDCheckpointSyncInfo,
    contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeaf},
    ffs_sizes::{PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_USER_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY},
    public_key::PZKPublicKeyInfo,
    user::PQEDUserLeaf,
};

use crate::{
    psy_core_db::{
        core_implementation::constants::{
            CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
            CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
            U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID,
        },
        traits::full::*,
    },
    store::traits::{
        core_db::{
            CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseKivReader,
            CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore, CoreDatabaseU64Reader,
            CoreDatabaseZeroIdMerkleReader,
        },
        helpers::*,
    },
};

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
        > + Send
        + Sync,
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
    pub contract_state_tree_height_table: Arc<SingleIdTableIdentifier>,
    pub checkpoint_id_to_pending_id_table: Arc<U64TableIdentifier>,
    pub pending_id_to_checkpoint_id_table: Arc<U64TableIdentifier>,
    pub pending_id_to_pending_proc_id_table: Arc<BiDirectionalU64U128MappingTableIdentifier>,
    pub realm_rewards_tree_node_key: Arc<SingleIdTableIdentifier>,
    // mappings
    pub public_key_hash_to_user_ids_table: Arc<HashToManyIdsTableIdentifier>,
    // start trees
    pub global_user_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
    pub user_contract_tree_table: Arc<SingleIdMerkleTableIdentifier>,
    pub contract_state_tree_table: Arc<DoubleIdMerkleTableIdentifier>,
    pub global_checkpoint_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
    // start reward tree table
    pub guta_reward_tag_tree_table: Arc<TagTreeTableIdentifier>,
    // added tables for completeness
    pub user_registration_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
    pub global_contract_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
    pub contract_function_tree_table: Arc<SingleIdMerkleTableIdentifier>,
    pub contract_leaf_table: Arc<SingleIdTableIdentifier>,
    pub contract_code_definition_table: Arc<SingleIdTableIdentifier>,
    // start unused table types
    pub _phantom_double_id_table: std::marker::PhantomData<DoubleIdTableIdentifier>,
    // start phantom N
    pub _phantom_n: std::marker::PhantomData<N>,
}

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
            > + Send
            + Sync,
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
    pub fn new(
        store: Arc<S>,

        checkpoint_leaf_table: Arc<KivTableIdentifier>,
        checkpoint_root_to_checkpoint_id_table: Arc<BiDirectionalMappingTableIdentifier>,
        checkpoint_leaf_to_checkpoint_id_table: Arc<BiDirectionalMappingTableIdentifier>,
        l2_block_state_table: Arc<KivTableIdentifier>,
        checkpoint_id_to_realm_root_table: Arc<KivTableIdentifier>,
        latest_info_table: Arc<KivTableIdentifier>,
        checkpointed_object_table: Arc<SingleIdTableIdentifier>,
        checkpoint_state_roots_table: Arc<KivTableIdentifier>,
        user_leaf_table: Arc<SingleIdTableIdentifier>,
        user_public_key_table: Arc<SingleIdTableIdentifier>,
        u64_singleton_table: Arc<U64TableIdentifier>,
        contract_state_tree_height_table: Arc<SingleIdTableIdentifier>,
        checkpoint_id_to_pending_id_table: Arc<U64TableIdentifier>,
        pending_id_to_checkpoint_id_table: Arc<U64TableIdentifier>,
        pending_id_to_pending_proc_id_table: Arc<BiDirectionalU64U128MappingTableIdentifier>,
        realm_rewards_tree_node_key: Arc<SingleIdTableIdentifier>,
        // mappings
        public_key_hash_to_user_ids_table: Arc<HashToManyIdsTableIdentifier>,
        // start trees
        global_user_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
        user_contract_tree_table: Arc<SingleIdMerkleTableIdentifier>,
        contract_state_tree_table: Arc<DoubleIdMerkleTableIdentifier>,
        global_checkpoint_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
        // start reward tree table
        guta_reward_tag_tree_table: Arc<TagTreeTableIdentifier>,
        // added tables for completeness
        user_registration_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
        global_contract_tree_table: Arc<ZeroIdMerkleTableIdentifier>,
        contract_function_tree_table: Arc<SingleIdMerkleTableIdentifier>,
        contract_leaf_table: Arc<SingleIdTableIdentifier>,
        contract_code_definition_table: Arc<SingleIdTableIdentifier>,
    ) -> Self {
        Self {
            store,
            checkpoint_leaf_table,
            checkpoint_root_to_checkpoint_id_table,
            checkpoint_leaf_to_checkpoint_id_table,
            l2_block_state_table,
            checkpoint_id_to_realm_root_table,
            latest_info_table,
            checkpointed_object_table,
            checkpoint_state_roots_table,
            user_leaf_table,
            user_public_key_table,
            u64_singleton_table,
            contract_state_tree_height_table,
            checkpoint_id_to_pending_id_table,
            pending_id_to_checkpoint_id_table,
            pending_id_to_pending_proc_id_table,
            realm_rewards_tree_node_key,
            public_key_hash_to_user_ids_table,
            global_user_tree_table,
            user_contract_tree_table,
            contract_state_tree_table,
            global_checkpoint_tree_table,
            guta_reward_tag_tree_table,
            user_registration_tree_table,
            global_contract_tree_table,
            contract_function_tree_table,
            contract_leaf_table,
            contract_code_definition_table,
            _phantom_double_id_table: std::marker::PhantomData {},
            _phantom_n: std::marker::PhantomData {},
        }
    }
    async fn db_select_double_id_merkle_proof_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        db_helper_select_double_id_merkle_proof_max_checkpoint(&self.store, table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, key).await
    }
    async fn db_select_single_id_merkle_proof_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        db_helper_select_single_id_merkle_proof_max_checkpoint(&self.store, table, checkpoint_id, tree_id, tree_height, key).await
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        db_helper_select_zero_id_merkle_proof_max_checkpoint(&self.store, table, max_checkpoint_id, key).await
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint_to_root_level(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        root_level: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        db_helper_select_zero_id_merkle_proof_max_checkpoint_to_root_level(&self.store, table, max_checkpoint_id, root_level, key).await
    }
    // end merkle helpers
    pub async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        let v = self
            .store
            .db_select_u64_value(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID)
            .await?;
        match v {
            Some(id) => Ok(id),
            None => Ok(0),
        }
    }
    pub async fn get_latest_pending_id(&self) -> anyhow::Result<u64> {
        let v = self
            .store
            .db_select_u64_value(&self.u64_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID)
            .await?;
        match v {
            Some(id) => Ok(id),
            None => Ok(0),
        }
    }
    async fn _apply_global_block_update_internal(&self, global_block_update: &PQEDCheckpointSyncInfo<N::F, N::QHash>) -> anyhow::Result<()> {
        let _latest_pending_id = self.get_latest_pending_id().await?;
        let latest_checkpoint_id = self.get_latest_checkpoint_id().await?;
        let new_checkpoint_id = global_block_update.core.l2_block_state.checkpoint_id.to_u64_value();
        if new_checkpoint_id != (latest_checkpoint_id + 1) {
            anyhow::bail!(
                "Global block update checkpoints MUST be applied in order, got a global checkpoint with id {} while our latest checkpoint is {}",
                new_checkpoint_id,
                latest_checkpoint_id
            );
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
            > + Send
            + Sync,
    > PsyNodeCheckpointTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn checkpoint_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_index);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }

    async fn checkpoint_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }

    async fn checkpoint_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, &key)
            .await
    }

    async fn checkpoint_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<N::QHash>> {
        self.store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.global_checkpoint_tree_table, checkpoint_id, keys)
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
            > + Send
            + Sync,
    > PsyNodeCheckpointTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn checkpoint_tree_set_leaf_hash(&self, checkpoint_id: u64, value: N::QHash) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_checkpoint_tree_table,
            checkpoint_id,
            0,
            2 * N::CHECKPOINT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, 0),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn checkpoint_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_checkpoint_tree_table, checkpoint_id, nodes)
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
            > + Send
            + Sync,
    > PsyNodeUserRegistrationTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn user_registration_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.user_registration_tree_table, checkpoint_id, &key)
            .await
    }

    async fn user_registration_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.user_registration_tree_table, checkpoint_id, &key)
            .await
    }

    async fn user_registration_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.user_registration_tree_table, checkpoint_id, &key)
            .await
    }

    async fn user_registration_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<N::QHash>> {
        self.store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.user_registration_tree_table, checkpoint_id, keys)
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
            > + Send
            + Sync,
    > PsyNodeUserRegistrationTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn user_registration_tree_set_leaf_hash(&self, checkpoint_id: u64, value: N::QHash) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.user_registration_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_USER_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, 0),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn user_registration_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.user_registration_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn user_registration_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_from_fast_serialized(&self.user_registration_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeGlobalUserTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn global_user_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_user_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_user_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_user_tree_get_merkle_proof_sub_tree(
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

    async fn global_user_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<N::QHash>> {
        self.store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.global_user_tree_table, checkpoint_id, keys)
            .await
    }

    async fn global_user_tree_get_node(&self, checkpoint_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<N::QHash> {
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_user_tree_table, checkpoint_id, &key)
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
            > + Send
            + Sync,
    > PsyNodeGlobalUserTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn global_user_tree_set_top_tree_merkle_proof(&self, checkpoint_id: u64, merkle_proof: &MerkleProofCore<N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                checkpoint_id,
                merkle_proof,
            )
            .await
    }

    async fn global_user_tree_set_leaf_hash(&self, checkpoint_id: u64, value: N::QHash) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_user_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_USER_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, 0),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn global_user_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_user_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn global_user_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_from_fast_serialized(&self.global_user_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeUserContractTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn user_contract_tree_get_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id);
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

    async fn user_contract_tree_get_root_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
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

    async fn user_contract_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id);
        self.db_select_single_id_merkle_proof_max_checkpoint(
            &self.user_contract_tree_table,
            checkpoint_id,
            user_id,
            N::GLOBAL_CONTRACT_TREE_HEIGHT,
            key,
        )
        .await
    }

    async fn user_contract_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreSingleIdKey]) -> anyhow::Result<Vec<N::QHash>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let tree_id = keys[0].tree_id;
        if keys.iter().any(|k| k.tree_id != tree_id) {
            anyhow::bail!("All keys must have the same tree_id");
        }
        let simple_keys: Vec<SimpleMerkleNodeKey> = keys
            .iter()
            .map(|k| SimpleMerkleNodeKey {
                level: k.level,
                index: k.index,
            })
            .collect();
        self.store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(
                &self.user_contract_tree_table,
                checkpoint_id,
                tree_id,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
                &simple_keys,
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
            > + Send
            + Sync,
    > PsyNodeUserContractTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn user_contract_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.user_contract_tree_table,
            checkpoint_id,
            user_id,
            N::GLOBAL_CONTRACT_TREE_HEIGHT,
            0,
            2 * N::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, contract_id),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn user_contract_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<N::QHash>]) -> anyhow::Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let tree_id = nodes[0].key.tree_id;
        if nodes.iter().any(|n| n.key.tree_id != tree_id) {
            anyhow::bail!("All nodes must have the same tree_id");
        }
        let simple_nodes: Vec<SimpleMerkleNode<N::QHash>> = nodes
            .iter()
            .map(|n| SimpleMerkleNode {
                key: SimpleMerkleNodeKey {
                    level: n.key.level,
                    index: n.key.index,
                },
                value: n.value,
            })
            .collect();
        self.store
            .db_set_single_id_merkle_nodes_batch(&self.user_contract_tree_table, checkpoint_id, tree_id, &simple_nodes)
            .await
    }

    async fn user_contract_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_single_id_merkle_nodes_from_fast_serialized(&self.user_contract_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeContractStateTreeTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn contract_state_tree_get_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        state_slot_id: u64,
    ) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::MAX_CONTRACT_STATE_TREE_HEIGHT, state_slot_id);
        self.store
            .db_select_double_id_merkle_node_max_checkpoint(
                &self.contract_state_tree_table,
                checkpoint_id,
                user_id,
                contract_id,
                N::MAX_CONTRACT_STATE_TREE_HEIGHT,
                key,
            )
            .await
    }

    async fn contract_state_tree_get_root_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_double_id_merkle_node_max_checkpoint(
                &self.contract_state_tree_table,
                checkpoint_id,
                user_id,
                contract_id,
                N::MAX_CONTRACT_STATE_TREE_HEIGHT,
                key,
            )
            .await
    }

    async fn contract_state_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        state_slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::MAX_CONTRACT_STATE_TREE_HEIGHT, state_slot_id);
        self.db_select_double_id_merkle_proof_max_checkpoint(
            &self.contract_state_tree_table,
            checkpoint_id,
            user_id,
            contract_id,
            N::MAX_CONTRACT_STATE_TREE_HEIGHT,
            &key,
        )
        .await
    }

    async fn contract_state_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreDoubleIdKey]) -> anyhow::Result<Vec<N::QHash>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let tree_id = keys[0].tree_id;
        let tree_sub_id = keys[0].tree_sub_id;
        if keys.iter().any(|k| k.tree_id != tree_id || k.tree_sub_id != tree_sub_id) {
            anyhow::bail!("All keys must have the same tree_id and tree_sub_id");
        }
        let simple_keys: Vec<SimpleMerkleNodeKey> = keys
            .iter()
            .map(|k| SimpleMerkleNodeKey {
                level: k.level,
                index: k.index,
            })
            .collect();
        self.store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(
                &self.contract_state_tree_table,
                checkpoint_id,
                tree_id,
                tree_sub_id,
                N::MAX_CONTRACT_STATE_TREE_HEIGHT,
                &simple_keys,
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
            > + Send
            + Sync,
    > PsyNodeContractStateTreeTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn contract_state_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_double_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.contract_state_tree_table,
            checkpoint_id,
            user_id,
            contract_id,
            N::MAX_CONTRACT_STATE_TREE_HEIGHT,
            0,
            2 * N::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::MAX_CONTRACT_STATE_TREE_HEIGHT, 0),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn contract_state_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreDoubleIdNode<N::QHash>]) -> anyhow::Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let tree_id = nodes[0].key.tree_id;
        let tree_sub_id = nodes[0].key.tree_sub_id;
        if nodes.iter().any(|n| n.key.tree_id != tree_id || n.key.tree_sub_id != tree_sub_id) {
            anyhow::bail!("All nodes must have the same tree_id and tree_sub_id");
        }
        let simple_nodes: Vec<SimpleMerkleNode<N::QHash>> = nodes
            .iter()
            .map(|n| SimpleMerkleNode {
                key: SimpleMerkleNodeKey {
                    level: n.key.level,
                    index: n.key.index,
                },
                value: n.value,
            })
            .collect();
        self.store
            .db_set_double_id_merkle_nodes_batch(&self.contract_state_tree_table, checkpoint_id, tree_id, tree_sub_id, &simple_nodes)
            .await
    }

    async fn contract_state_tree_set_top_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        merkle_proof: &MerkleProofCore<N::QHash>,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(
                &self.checkpointed_object_table,
                3, // Assume a constant for contract state top proof
                checkpoint_id,
                merkle_proof,
            )
            .await
    }

    async fn contract_state_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_double_id_merkle_nodes_from_fast_serialized(&self.contract_state_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeGlobalContractTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn global_contract_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, leaf_index);
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_contract_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_contract_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_contract_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_contract_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, leaf_index);
        self.db_select_zero_id_merkle_proof_max_checkpoint(&self.global_contract_tree_table, checkpoint_id, &key)
            .await
    }

    async fn global_contract_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<N::QHash>> {
        self.store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.global_contract_tree_table, checkpoint_id, keys)
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
            > + Send
            + Sync,
    > PsyNodeGlobalContractTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn global_contract_tree_set_leaf_hash(&self, checkpoint_id: u64, value: N::QHash) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_contract_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, 0),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn global_contract_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_contract_tree_table, checkpoint_id, nodes)
            .await
    }

    async fn global_contract_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_from_fast_serialized(&self.global_contract_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeContractFunctionTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn contract_function_tree_get_leaf_hash(&self, checkpoint_id: u64, contract_id: u64, function_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(N::CONTRACT_FUNCTION_TREE_HEIGHT, function_id);
        self.store
            .db_select_single_id_merkle_node_max_checkpoint(
                &self.contract_function_tree_table,
                checkpoint_id,
                contract_id,
                N::CONTRACT_FUNCTION_TREE_HEIGHT,
                key,
            )
            .await
    }

    async fn contract_function_tree_get_root_hash(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_single_id_merkle_node_max_checkpoint(
                &self.contract_function_tree_table,
                checkpoint_id,
                contract_id,
                N::CONTRACT_FUNCTION_TREE_HEIGHT,
                key,
            )
            .await
    }

    async fn contract_function_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        function_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(N::CONTRACT_FUNCTION_TREE_HEIGHT, function_id);
        self.db_select_single_id_merkle_proof_max_checkpoint(
            &self.contract_function_tree_table,
            checkpoint_id,
            contract_id,
            N::CONTRACT_FUNCTION_TREE_HEIGHT,
            key,
        )
        .await
    }

    async fn contract_function_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreSingleIdKey]) -> anyhow::Result<Vec<N::QHash>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let tree_id = keys[0].tree_id;
        if keys.iter().any(|k| k.tree_id != tree_id) {
            anyhow::bail!("All keys must have the same tree_id");
        }
        let simple_keys: Vec<SimpleMerkleNodeKey> = keys
            .iter()
            .map(|k| SimpleMerkleNodeKey {
                level: k.level,
                index: k.index,
            })
            .collect();
        self.store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(
                &self.contract_function_tree_table,
                checkpoint_id,
                tree_id,
                N::CONTRACT_FUNCTION_TREE_HEIGHT,
                &simple_keys,
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
            > + Send
            + Sync,
    > PsyNodeContractFunctionTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn contract_function_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        function_id: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.contract_function_tree_table,
            checkpoint_id,
            contract_id,
            N::CONTRACT_FUNCTION_TREE_HEIGHT,
            0,
            2 * N::CONTRACT_FUNCTION_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::CONTRACT_FUNCTION_TREE_HEIGHT, function_id),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn contract_function_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<N::QHash>]) -> anyhow::Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let tree_id = nodes[0].key.tree_id;
        if nodes.iter().any(|n| n.key.tree_id != tree_id) {
            anyhow::bail!("All nodes must have the same tree_id");
        }
        let simple_nodes: Vec<SimpleMerkleNode<N::QHash>> = nodes
            .iter()
            .map(|n| SimpleMerkleNode {
                key: SimpleMerkleNodeKey {
                    level: n.key.level,
                    index: n.key.index,
                },
                value: n.value,
            })
            .collect();
        self.store
            .db_set_single_id_merkle_nodes_batch(&self.contract_function_tree_table, checkpoint_id, tree_id, &simple_nodes)
            .await
    }

    async fn contract_function_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_set_single_id_merkle_nodes_from_fast_serialized(&self.contract_function_tree_table, checkpoint_id, data)
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
            > + Send
            + Sync,
    > PsyNodeCheckpointObjectDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        self.get_latest_checkpoint_id().await
    }

    async fn get_checkpoint_id_for_checkpoint_root_hash(&self, root_hash: N::QHash) -> anyhow::Result<Option<u64>> {
        self.store
            .db_select_one_by_k1::<N::QHash, u64>(&self.checkpoint_root_to_checkpoint_id_table, &root_hash)
            .await
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointLeaf<N::F, N::QHash>> {
        self.store
            .db_select_one_kiv_value::<PQEDCheckpointLeaf<N::F, N::QHash>>(&self.checkpoint_leaf_table, checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Checkpoint leaf not found for id {}", checkpoint_id))
    }

    async fn get_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<QEDL2BlockState> {
        self.store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.l2_block_state_table, checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("L2 block state not found for id {}", checkpoint_id))
    }

    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState> {
        self.store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Latest L2 block state not found"))
    }

    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointGlobalStateRoots<N::QHash>> {
        self.store
            .db_select_one_kiv_value::<PQEDCheckpointGlobalStateRoots<N::QHash>>(&self.checkpoint_state_roots_table, checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Global state roots not found for id {}", checkpoint_id))
    }

    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>> {
        let pending_id = self
            .store
            .db_select_u64_value(&self.checkpoint_id_to_pending_id_table, checkpoint_id)
            .await?;
        if let Some(pid) = pending_id {
            let uid = self
                .store
                .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pid)
                .await?;
            if let Some(u) = uid {
                return Ok(Some((pid, u)));
            }
        }
        Ok(None)
    }

    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.store
            .db_select_u64_value(&self.pending_id_to_checkpoint_id_table, unique_pending_id)
            .await
    }

    async fn get_current_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let pending_id = self.get_latest_pending_id().await?;
        let uid = self
            .store
            .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pending_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Unique ID not found for pending ID {}", pending_id))?;
        Ok((pending_id, uid))
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
            > + Send
            + Sync,
    > PsyNodeCoordinatorSpecificDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_realm_guta_reward_tree_node_key(
        &self,
        unique_pending_id: u64,
        realm_id: u64,
    ) -> anyhow::Result<Option<SimpleMerkleNodeKey>>{
        let res: Option<QDatabaseSingleIdTableRow<SimpleMerkleNodeKey>> = self.store.db_select_one_single_checkpointed_object_value_and_ids(&self.realm_rewards_tree_node_key, realm_id, unique_pending_id).await?;
        match res {
            Some(row) => {
                if row.checkpoint_id == unique_pending_id {
                    Ok(Some(row.value))
                } else {
                    Ok(None)
                }
            },
            None => Ok(None),
        }


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
            > + Send
            + Sync,
    > PsyNodeCoordinatorSpecificDatabaseWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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

    async fn set_realm_guta_reward_tree_node_key(
        &self,
        unique_pending_id: u64,
        realm_id: u64,
        node_key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<()>{
        self.store.db_insert_one_single_checkpointed_object(
            &self.realm_rewards_tree_node_key,
            realm_id,
            unique_pending_id,
            &node_key,
        ).await
    }
    async fn set_realm_guta_reward_tree_node_keys_ffs(
        &self,
        unique_pending_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()>{
        self.store.db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
            &self.realm_rewards_tree_node_key,
            PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY,
            unique_pending_id,
            data,
        ).await

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
            > + Send
            + Sync,
    > PsyNodeCheckpointRealmSpecificDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
    ) -> anyhow::Result<TagTreeMerkleProof<N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<TagTreeMerkleProof<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
                unique_pending_id,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("Rewards tree proof not found for unique_pending_id {}", unique_pending_id))
    }

    async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<TagTreeMerkleProof<N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<TagTreeMerkleProof<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
                checkpoint_id,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("Rewards tree proof not found for checkpoint_id {}", checkpoint_id))
    }

    async fn get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<MerkleProofCore<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                checkpoint_id,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("User tree proof not found for checkpoint_id {}", checkpoint_id))
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
            > + Send
            + Sync,
    > PsyNodeCheckpointObjectDatabaseWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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

    async fn set_checkpoint_root_hash_to_id_mapping(&self, checkpoint_root: N::QHash, checkpoint_id: u64) -> anyhow::Result<()> {
        self.store
            .db_insert_pair_ref(&self.checkpoint_root_to_checkpoint_id_table, &checkpoint_root, &checkpoint_id)
            .await
    }
    async fn set_l2_latest_block_state(&self, block_state: &QEDL2BlockState) -> anyhow::Result<()>{
        self.store.db_insert_one_kiv(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, block_state).await
    }
    async fn set_l2_block_state(&self, checkpoint_id: u64, block_state: &QEDL2BlockState) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(&self.l2_block_state_table, checkpoint_id, block_state).await
    }

    async fn set_checkpoint_global_state_roots(&self, checkpoint_id: u64, roots: &PQEDCheckpointGlobalStateRoots<N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_kiv(&self.checkpoint_state_roots_table, checkpoint_id, roots)
            .await
    }

    async fn set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        merkle_proof: &TagTreeMerkleProof<N::QHash>,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
                unique_pending_id,
                merkle_proof,
            )
            .await
    }

    async fn set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(
        &self,
        checkpoint_id: u64,
        merkle_proof: &TagTreeMerkleProof<N::QHash>,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
                checkpoint_id,
                merkle_proof,
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseUserStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_zk_public_key(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PZKPublicKeyInfo<N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<PZKPublicKeyInfo<N::QHash>>(&self.user_public_key_table, user_id, checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("ZK public key not found for user_id {} at checkpoint_id {}", user_id, checkpoint_id))
    }

    async fn get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<PQEDUserLeaf<N::F, N::QHash>>(&self.user_leaf_table, user_id, checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User leaf not found for user_id {} at checkpoint_id {}", user_id, checkpoint_id))
    }

    async fn get_user_ids_for_public_key(&self, public_key: N::QHash, start_user_id: u64, count: usize) -> anyhow::Result<Vec<u64>> {
        self.store
            .db_select_value_u64_ids_for_hash(&self.public_key_hash_to_user_ids_table, public_key, count, start_user_id)
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseUserStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn set_user_leaf_(&self, checkpoint_id: u64, leaf_data: &PQEDUserLeaf<N::F, N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.user_leaf_table, leaf_data.user_id.to_u64_value(), checkpoint_id, leaf_data)
            .await
    }

    async fn set_user_leaves_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        // Assume id at end or specific location, here using with_id_at_index, assume
        // location = 0 for example
        let object_size = PSY_OBJECT_FFS_SIZE_USER_LEAF;
        let object_id_location = 96; // Assume id at offset 96
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(
                &self.user_leaf_table,
                object_size,
                object_id_location,
                checkpoint_id,
                data,
            )
            .await
    }

    async fn set_zk_public_key(&self, checkpoint_id: u64, user_id: u64, public_key_info: &PZKPublicKeyInfo<N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.user_public_key_table, user_id, checkpoint_id, public_key_info)
            .await
    }

    async fn set_zk_public_keys_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        let object_size = PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY;
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
                &self.user_public_key_table,
                object_size,
                checkpoint_id,
                data,
            )
            .await
    }

    async fn set_public_key_for_user_id(&self, user_id: u64, public_key: N::QHash) -> anyhow::Result<()>{
        self.store
            .db_insert_one_hash_to_u64(&self.public_key_hash_to_user_ids_table, public_key, user_id)
            .await
    }
    async fn set_public_key_for_user_ids_ffs(&self, data: &[u8]) -> anyhow::Result<()>{
        self.store
            .db_set_hash_256_to_u64_pairs_from_fast_serialized_data(&self.public_key_hash_to_user_ids_table, data)
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseBasicContractInfoStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_contract_tree_heights(&self, checkpoint_id: u64, contract_ids: &[u64]) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .store
            .db_select_many_single_checkpointed_object_values::<u8>(&self.contract_state_tree_height_table, contract_ids, checkpoint_id)
            .await?
            .into_iter()
            .map(|opt| opt.unwrap_or_default())
            .collect())
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseBasicContractInfoStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn set_contract_tree_heights(&self, checkpoint_id: u64, contract_ids: &[(u64, u8)]) -> anyhow::Result<()> {
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_t::<u8, (u64, u8)>(
                &self.contract_state_tree_height_table,
                checkpoint_id,
                contract_ids,
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn get_contract_leaf(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<PQEDContractLeaf<N::F, N::QHash>> {
        self.store
            .db_select_one_single_checkpointed_object_value::<PQEDContractLeaf<N::F, N::QHash>>(&self.contract_leaf_table, contract_id, checkpoint_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Contract leaf not found for contract_id {} at checkpoint_id {}",
                    contract_id,
                    checkpoint_id
                )
            })
    }

    async fn get_contract_code_definition(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<ContractCodeDefinition> {
        self.store
            .db_select_one_single_checkpointed_object_value::<ContractCodeDefinition>(
                &self.contract_code_definition_table,
                contract_id,
                checkpoint_id,
            )
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Contract code definition not found for contract_id {} at checkpoint_id {}",
                    contract_id,
                    checkpoint_id
                )
            })
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
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseContractObjectStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn set_contract_leaf(&self, checkpoint_id: u64, contract_id: u64, leaf: &PQEDContractLeaf<N::F, N::QHash>) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.contract_leaf_table, contract_id, checkpoint_id, leaf)
            .await
    }

    async fn set_contract_leaves_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
                &self.contract_leaf_table,
                PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
                checkpoint_id,
                data,
            )
            .await
    }

    async fn set_contract_code_definition(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        code_definition: &ContractCodeDefinition,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.contract_code_definition_table, contract_id, checkpoint_id, code_definition)
            .await
    }

    async fn set_many_contract_code_definitions(
        &self,
        checkpoint_id: u64,
        inserts: &[ContractCodeDefinitionWithContractId],
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_t(&self.contract_code_definition_table, checkpoint_id, inserts)
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
            > + Send
            + Sync,
    > PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn rewards_tag_tree_get_root_at_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<N::QHash> {
        let root = self
            .store
            .db_get_tag_tree_root(&self.guta_reward_tag_tree_table, unique_pending_id)
            .await?;
        root.ok_or_else(|| anyhow::anyhow!("Root not found"))
    }

    async fn rewards_tag_tree_get_node_at_unique_pending_id(&self, unique_pending_id: u64, node: SimpleMerkleNodeKey) -> anyhow::Result<N::QHash> {
        self.store
            .db_get_tag_tree_node_value(&self.guta_reward_tag_tree_table, unique_pending_id, &node)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Node not found"))
    }

    async fn rewards_tag_tree_get_node_values_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<N::QHash>>> {
        self.store
            .db_get_tag_tree_node_values(&self.guta_reward_tag_tree_table, unique_pending_id, nodes)
            .await
    }

    async fn rewards_tag_tree_get_node_tags_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<N::QHash>>> {
        self.store
            .db_get_tag_tree_node_tags(&self.guta_reward_tag_tree_table, unique_pending_id, nodes)
            .await
    }

    async fn rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<TagTreeMerkleProof<N::QHash>>> {
        // The trait has get_tag_tree_merkle_proof_at_unique_pending_id, but param
        // nodes, but return Vec<Option<Hash>>, perhaps typo, probably for proof
        // Perhaps it's get node values or something.
        // To implement, assume get node values
        let futures = nodes.iter().map(|n| {
            self.store
                .db_get_tag_tree_merkle_proof(&self.guta_reward_tag_tree_table, unique_pending_id, n)
        });
        let results = futures::future::join_all(futures).await;
        results.into_iter().collect()
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
            > + Send
            + Sync,
    > PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
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
    async fn rewards_tag_tree_set_node_tag(
        &self,
        unique_pending_id: u64,
        key: SimpleMerkleNodeKey,
        tag: N::QHash,
        value: N::QHash,
    ) -> anyhow::Result<()> {
        self.store
            .db_set_tag_tree_tag_value(&self.guta_reward_tag_tree_table, unique_pending_id, &key, &tag, &value)
            .await
    }
    async fn rewards_tag_tree_set_node_tag_only(&self, unique_pending_id: u64, key: SimpleMerkleNodeKey, tag: N::QHash) -> anyhow::Result<()> {
        self.store
            .db_set_tag_tree_tag(&self.guta_reward_tag_tree_table, unique_pending_id, &key, &tag)
            .await
    }
}
