use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Ok;
use async_trait::async_trait;
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
    },
    data::{
        db::row::QDatabaseSingleIdTableRow,
        hash::{
            checkpointed_merkle_node::CheckpointedMerkleHash,
            hash256::Hash256,
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY},
            merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode},
        },
        serializable::QPDSerializable,
    },
    felt::ToU64Value,
    protocol::core_types::QNetworkDatabaseTypes,
    QCoreProcCheckpointUniqueId,
};
use psy_data::{
    protocol::{
        chain_context::AuthorityObservation,
        verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
        checkpoint_sync::PQEDCheckpointSyncInfo,
        contract::{
            deserialize_imt_leaf_ffs_entry_v2, encode_imt_key_for_sorting, imt_key_bucket, imt_key_bucket_to_i16, ContractCodeDefinition,
            ContractCodeDefinitionWithContractId, IMTContractStateLeaf, PQEDContractLeaf,
            IMT_LEAF_FFS_ENTRY_SIZE_V2,
        },
        ffs_sizes::{PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_USER_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY},
        public_key::PZKPublicKeyInfo,
        user::PQEDUserLeaf,
    },
};

use crate::{
    psy_core_db::{
        core_implementation::constants::{
            CHECKPOINTED_OBJECT_TABLE_OBJ_ID_BRIDGE_DEPOSIT_LEAF_BASE,
            CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF,
            CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
            LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION,
            U64_SINGLETON_TABLE_OBJ_ID_BRIDGE_DEPOSIT_NEXT_INDEX_BASE, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID,
        },
        traits::full::*,
    },
    store::traits::{
        core_db::{
            CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseIMTKeyIndexWriter,
            CoreDatabaseIMTLeafWriter, CoreDatabaseKivReader, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdMerkleReader,
            CoreDatabaseStore, CoreDatabaseU64Reader, CoreDatabaseZeroIdMerkleReader,
        },
        helpers::*,
    },
};

fn bridge_deposit_leaf_obj_id(chain_id: u64, deposit_index: u64) -> anyhow::Result<u64> {
    if chain_id > u32::MAX as u64 || deposit_index > u32::MAX as u64 {
        anyhow::bail!(
            "bridge deposit id overflow: chain_id={}, deposit_index={}, max_supported={}",
            chain_id,
            deposit_index,
            u32::MAX
        );
    }
    Ok(CHECKPOINTED_OBJECT_TABLE_OBJ_ID_BRIDGE_DEPOSIT_LEAF_BASE | (chain_id << 32) | deposit_index)
}

fn bridge_chain_tree_node_obj_id(chain_id: u64, level: u8, index: u64) -> anyhow::Result<u64> {
    if chain_id > ((1u64 << 24) - 1) {
        anyhow::bail!("bridge chain_id overflow: {}, max {}", chain_id, (1u64 << 24) - 1);
    }
    if level > 63 {
        anyhow::bail!("bridge chain tree level overflow: {}, max 63", level);
    }
    if index > u32::MAX as u64 {
        anyhow::bail!("bridge chain tree index overflow: {}, max {}", index, u32::MAX);
    }
    // Prefix 0b11 in the top two bits, then [chain_id:24 | level:6 | index:32].
    let payload = (chain_id << 38) | ((level as u64) << 32) | index;
    Ok((0b11u64 << 62) | payload)
}

fn bridge_global_tree_node_obj_id(level: u8, index: u64) -> anyhow::Result<u64> {
    if level > 63 {
        anyhow::bail!("bridge global tree level overflow: {}, max 63", level);
    }
    if index > ((1u64 << 56) - 1) {
        anyhow::bail!("bridge global tree index overflow: {}, max {}", index, (1u64 << 56) - 1);
    }
    // Prefix 0b00 with subtype=1 in [61..56], then [level:6 | index:56].
    let subtype = 1u64;
    Ok((subtype << 56) | ((level as u64) << 50) | index)
}

#[derive(Clone)]
pub struct PsyUnifiedCoreDatabaseStore<
    N: QNetworkDatabaseTypes,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    U64CounterTableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
    IMTLeafTableIdentifier: Clone + Send + Sync,
    IMTKeyIndexTableIdentifier: Clone + Send + Sync,
    IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
    S: CoreDatabaseStore<
            N::QHash,
            N::HasherBase,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            U64CounterTableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
            IMTLeafTableIdentifier,
            IMTKeyIndexTableIdentifier,
            IMTNextAppendIndexTableIdentifier,
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
    pub u64_counter_singleton_table: Arc<U64CounterTableIdentifier>,
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

    pub checkpoint_zk_proof_and_transition_table: Arc<KivTableIdentifier>,
    // IMT tables
    pub imt_leaf_table: Arc<IMTLeafTableIdentifier>,
    pub imt_key_index_table: Arc<IMTKeyIndexTableIdentifier>,
    pub imt_next_append_index_table: Arc<IMTNextAppendIndexTableIdentifier>,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    >
    PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        u64_counter_singleton_table: Arc<U64CounterTableIdentifier>,
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
        checkpoint_zk_proof_and_transition_table: Arc<KivTableIdentifier>,
        // IMT tables
        imt_leaf_table: Arc<IMTLeafTableIdentifier>,
        imt_key_index_table: Arc<IMTKeyIndexTableIdentifier>,
        imt_next_append_index_table: Arc<IMTNextAppendIndexTableIdentifier>,
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
            u64_counter_singleton_table,
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
            checkpoint_zk_proof_and_transition_table,
            imt_leaf_table,
            imt_key_index_table,
            imt_next_append_index_table,
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
            .db_select_u64_counter_value(&self.u64_counter_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID)
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
                key: SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, checkpoint_id),
                value,
            }],
        )
        .await?;
        Ok(res.pop().ok_or_else(|| anyhow::anyhow!("No delta merkle proof found"))?)
    }

    async fn checkpoint_tree_set_nodes(&self, _checkpoint_id: u64, nodes: &[SimpleMerkleNode<N::QHash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch_checkpoint_is_index(&self.global_checkpoint_tree_table, nodes)
            .await
    }
    async fn checkpoint_tree_injest_merkle_proof(&self, checkpoint_id: u64, merkle_proof: &MerkleProofCore<N::QHash>) -> anyhow::Result<()> {
        /*
            let mut siblings = Vec::with_capacity(merkle_proof.siblings.len());
            let leaf_key = SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, merkle_proof.index);
            let siblings_keys = leaf_key.get_siblings_keys_to_height(0);
            for (i, sibling_hash) in merkle_proof.siblings.iter().enumerate() {
                siblings.push(SimpleMerkleNode{
                    key: siblings_keys[i].clone(),
                    value: *sibling_hash,
                });
            }
            let path_nodes = merkle_proof.get_append_root(&leaf_key);
            self.store
                .db_set_zero_id_merkle_nodes_batch_checkpoint_is_index(&self.global_checkpoint_tree_table, &siblings)
                .await?;
         db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_checkpoint_tree_table,
            checkpoint_id,
            0,
            2 * N::CHECKPOINT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::CHECKPOINT_TREE_HEIGHT, checkpoint_id),
                value: merkle_proof.value,
            }],
        )
        .await?;
        Ok(())*/

        let nodes: Vec<SimpleMerkleNode<N::QHash>> = merkle_proof.get_all_merkle_nodes_and_verify::<N::HasherBase>()?;
        self.store
            .db_set_zero_id_merkle_nodes_batch(&self.global_checkpoint_tree_table, checkpoint_id, &nodes)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeUserRegistrationTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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

    async fn user_registration_tree_get_node(&self, checkpoint_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<N::QHash> {
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.user_registration_tree_table, checkpoint_id, &key)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeUserRegistrationTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn user_registration_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_index: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.user_registration_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_USER_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index),
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeGlobalUserTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
    async fn global_user_tree_dump_all_leaves(&self, checkpoint_id: u64) -> anyhow::Result<HashMap<u64, N::QHash>> {
        self.store
            .db_dump_all_zero_id_merkle_node_leaves_chunked(&self.global_user_tree_table, checkpoint_id)
            .await
    }

    async fn global_user_tree_get_node_and_checkpoint_id_max_checkpoint(
        &self,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<CheckpointedMerkleHash<N::QHash>> {
        self.store
            .db_select_zero_id_merkle_node_and_checkpoint_max_checkpoint(&self.global_user_tree_table, max_checkpoint_id, key)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeGlobalUserTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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

    async fn global_user_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_index: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_user_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_USER_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, leaf_index),
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeUserContractTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeUserContractTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractStateTreeTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn contract_state_tree_get_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        tree_height: u8,
        state_slot_id: u64,
    ) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new(tree_height, state_slot_id);
        self.store
            .db_select_double_id_merkle_node_max_checkpoint(
                &self.contract_state_tree_table,
                checkpoint_id,
                user_id,
                contract_id,
                tree_height,
                key,
            )
            .await
    }

    async fn contract_state_tree_get_root_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64, tree_height: u8) -> anyhow::Result<N::QHash> {
        let key = SimpleMerkleNodeKey::new_root();
        self.store
            .db_select_double_id_merkle_node_max_checkpoint(
                &self.contract_state_tree_table,
                checkpoint_id,
                user_id,
                contract_id,
                tree_height,
                key,
            )
            .await
    }

    async fn contract_state_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        tree_height: u8,
        state_slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let key = SimpleMerkleNodeKey::new(tree_height, state_slot_id);
        self.db_select_double_id_merkle_proof_max_checkpoint(&self.contract_state_tree_table, checkpoint_id, user_id, contract_id, tree_height, &key)
            .await
    }

    async fn contract_state_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreDoubleIdKeyWithHeight]) -> anyhow::Result<Vec<N::QHash>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        self.store
            .db_select_many_double_id_merkle_nodes_with_height_max_checkpoint(&self.contract_state_tree_table, checkpoint_id, keys)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractStateTreeTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn contract_state_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        tree_height: u8,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_double_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.contract_state_tree_table,
            checkpoint_id,
            user_id,
            contract_id,
            tree_height,
            0,
            2 * tree_height as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(tree_height, 0),
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeGlobalContractTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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

    async fn global_contract_tree_get_node(&self, checkpoint_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<N::QHash> {
        self.store
            .db_select_zero_id_merkle_node_max_checkpoint(&self.global_contract_tree_table, checkpoint_id, &key)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeGlobalContractTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn global_contract_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_index: u64,
        value: N::QHash,
    ) -> anyhow::Result<DeltaMerkleProofCore<N::QHash>> {
        let mut res = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<N::QHash, N::HasherBase, _, _>(
            &*self.store,
            &self.global_contract_tree_table,
            checkpoint_id,
            0,
            2 * N::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            &[SimpleMerkleNode {
                key: SimpleMerkleNodeKey::new(N::GLOBAL_CONTRACT_TREE_HEIGHT, leaf_index),
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractFunctionTreeDatabaseReader<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractFunctionTreeDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointObjectDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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

    async fn try_get_complete_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<Option<QEDL2BlockState>> {
        // A checkpoint's metadata is written across several non-transactional steps (see
        // `write_checkpoint_state_records` / `persist_checkpoint_metadata_range`). We treat it as usable only when
        // ALL of the per-checkpoint dependency records exist, so a partially-written checkpoint left by a crash —
        // under either the old "L2 first" ordering or the new "L2 last" ordering — is never mistaken for complete:
        //   - L2 block state, global state roots, checkpoint leaf  (kiv, keyed by checkpoint_id)
        //   - checkpoint root -> id mapping                        (proves the checkpoint-tree proof was ingested)
        //   - global-user-tree -> realm-root top proof             (needed by witness / merkle-proof queries)
        // Any genuine read/deserialization error is propagated; only true absence yields `Ok(None)`.
        let block_state = match self
            .store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.l2_block_state_table, checkpoint_id)
            .await?
        {
            Some(block_state) => block_state,
            None => return Ok(None),
        };
        let has_state_roots = self
            .store
            .db_select_one_kiv_value::<PQEDCheckpointGlobalStateRoots<N::QHash>>(&self.checkpoint_state_roots_table, checkpoint_id)
            .await?
            .is_some();
        let has_checkpoint_leaf = self
            .store
            .db_select_one_kiv_value::<PQEDCheckpointLeaf<N::F, N::QHash>>(&self.checkpoint_leaf_table, checkpoint_id)
            .await?
            .is_some();
        // Reverse lookup (id -> root) over the bidirectional mapping; present only once the checkpoint-tree proof
        // was ingested and the root mapping written.
        let has_root_mapping = self
            .store
            .db_select_one_by_k2::<N::QHash, u64>(&self.checkpoint_root_to_checkpoint_id_table, &checkpoint_id)
            .await?
            .is_some();
        let has_global_user_proof = self
            .store
            .db_select_one_single_checkpointed_object_value::<MerkleProofCore<N::QHash>>(
                &self.checkpointed_object_table,
                CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                checkpoint_id,
            )
            .await?
            .is_some();
        if has_state_roots && has_checkpoint_leaf && has_root_mapping && has_global_user_proof {
            Ok(Some(block_state))
        } else {
            Ok(None)
        }
    }

    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState> {
        self.store
            .db_select_one_kiv_value::<QEDL2BlockState>(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Latest L2 block state not found"))
    }

    async fn get_realm_authority_observation(
        &self,
    ) -> anyhow::Result<Option<AuthorityObservation<N::QHash>>> {
        self.store
            .db_select_one_kiv_value::<AuthorityObservation<N::QHash>>(
                &self.latest_info_table,
                LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION,
            )
            .await
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
        if pending_id == 0 {
            return Ok((0, 0));
        }
        let uid = self
            .store
            .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pending_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Unique ID not found for pending ID {}", pending_id))?;
        Ok((pending_id, uid))
    }

    async fn get_latest_mapped_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let latest_pending_id = self.get_latest_pending_id().await?;
        if latest_pending_id == 0 {
            return Ok((0, 0));
        }
        for pending_id in (1..=latest_pending_id).rev() {
            if let Some(proc_checkpoint_unique_id) = self
                .store
                .db_select_one_u128_value_by_u64(&self.pending_id_to_pending_proc_id_table, pending_id)
                .await?
            {
                return Ok((pending_id, proc_checkpoint_unique_id));
            }
        }
        anyhow::bail!(
            "No mapped unique pending ID found at or below pending counter {}",
            latest_pending_id
        )
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoordinatorSpecificDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn get_realm_guta_reward_tree_node_key(&self, unique_pending_id: u64, realm_id: u64) -> anyhow::Result<Option<SimpleMerkleNodeKey>> {
        let res: Option<QDatabaseSingleIdTableRow<SimpleMerkleNodeKey>> = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids(&self.realm_rewards_tree_node_key, realm_id, unique_pending_id)
            .await?;
        match res {
            Some(row) => {
                if row.checkpoint_id <= unique_pending_id {
                    Ok(Some(row.value))
                } else {
                    Ok(None)
                }
            }
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoordinatorSpecificDatabaseWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn set_realm_guta_reward_tree_node_key(&self, unique_pending_id: u64, realm_id: u64, node_key: SimpleMerkleNodeKey) -> anyhow::Result<()> {
        self.store
            .db_insert_one_single_checkpointed_object(&self.realm_rewards_tree_node_key, realm_id, unique_pending_id, &node_key)
            .await
    }
    async fn set_realm_guta_reward_tree_node_keys_ffs(&self, unique_pending_id: u64, data: &[u8]) -> anyhow::Result<()> {
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
                &self.realm_rewards_tree_node_key,
                PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY,
                unique_pending_id,
                data,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointRealmSpecificDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointObjectDatabaseWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn reserve_next_unique_pending_generation_without_mapping(
        &self,
    ) -> anyhow::Result<crate::store::pending_generation::ReservedPendingGeneration> {
        let new_pending_id = self
            .store
            .db_inc_u64_counter(&self.u64_counter_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID, 1)
            .await?;
        let unique_id = rand::random::<u128>();
        crate::store::pending_generation::ReservedPendingGeneration::try_new(
            new_pending_id,
            unique_id,
        )
        .map_err(Into::into)
    }

    async fn inc_unique_pending_id(&self, amount: u64) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let new_pending_id = self
            .store
            .db_inc_u64_counter(&self.u64_counter_singleton_table, U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID, amount as i64)
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
    async fn set_l2_latest_block_state(&self, block_state: &QEDL2BlockState) -> anyhow::Result<()> {
        self.store
            .db_insert_one_kiv(&self.latest_info_table, LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, block_state)
            .await
    }
    async fn set_realm_authority_observation(
        &self,
        observation: &AuthorityObservation<N::QHash>,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_kiv(
                &self.latest_info_table,
                LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION,
                observation,
            )
            .await
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseUserStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
    async fn get_user_leaves_batch(&self, checkpoint_id: u64, user_ids: &[u64]) -> anyhow::Result<Vec<Option<PQEDUserLeaf<N::F, N::QHash>>>> {
        self.store
            .db_select_many_single_checkpointed_object_values::<PQEDUserLeaf<N::F, N::QHash>>(&self.user_leaf_table, user_ids, checkpoint_id)
            .await
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseUserStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn set_user_leaf(&self, checkpoint_id: u64, leaf_data: &PQEDUserLeaf<N::F, N::QHash>) -> anyhow::Result<()> {
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

    async fn set_public_key_for_user_id(&self, user_id: u64, public_key: N::QHash) -> anyhow::Result<()> {
        self.store
            .db_insert_one_hash_to_u64(&self.public_key_hash_to_user_ids_table, public_key, user_id)
            .await
    }
    async fn set_public_key_for_user_ids_ffs(&self, data: &[u8]) -> anyhow::Result<()> {
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseBasicContractInfoStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseBasicContractInfoStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreDatabaseContractObjectStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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

    async fn set_many_contract_code_definitions(&self, checkpoint_id: u64, inserts: &[ContractCodeDefinitionWithContractId]) -> anyhow::Result<()> {
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
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
    async fn rewards_tag_tree_set_node_value_only(&self, unique_pending_id: u64, key: SimpleMerkleNodeKey, value: N::QHash) -> anyhow::Result<()> {
        self.store
            .db_set_tag_tree_value_only(&self.guta_reward_tag_tree_table, unique_pending_id, &key, &value)
            .await
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointTransitionZKProofDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn get_verifiable_checkpoint_state_transition_and_zkp(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<PsyVerifiableCheckpointTransitionWithProof<N::F, N::QHash>> {
        let proof = self
            .store
            .db_select_one_kiv_value(&self.checkpoint_zk_proof_and_transition_table, checkpoint_id)
            .await?;
        if let Some(proof) = proof {
            Ok(proof)
        } else {
            anyhow::bail!("proof not found for checkpoint {}", checkpoint_id)
        }
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeCheckpointTransitionZKProofDatabaseWriter<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn set_verifiable_checkpoint_state_transition_and_zkp(
        &self,
        checkpoint_id: u64,
        verifiable_transition_and_proof: &PsyVerifiableCheckpointTransitionWithProof<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        self.store
            .db_insert_one_kiv(
                &self.checkpoint_zk_proof_and_transition_table,
                checkpoint_id,
                verifiable_transition_and_proof,
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
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractStateIMTDatabaseWriter<N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn contract_state_imt_set_leaves_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() % IMT_LEAF_FFS_ENTRY_SIZE_V2 != 0 {
            anyhow::bail!(
                "Invalid IMT leaves FFS data size: {} is not a multiple of {}",
                data.len(),
                IMT_LEAF_FFS_ENTRY_SIZE_V2
            );
        }
        let entry_count = data.len() / IMT_LEAF_FFS_ENTRY_SIZE_V2;

        let mut next_index_by_pair: HashMap<(u64, u64), u64> = HashMap::new();

        let mut latest_leaf_written: HashSet<(u64, u64, u64)> = HashSet::new();

        // Parse and insert all entries. The end-cap encoder emits IMT updates
        // newest-to-oldest so root-chain validation can walk backwards. The
        // leaf table is only versioned by checkpoint_id, not by intra-checkpoint
        // op_seq, so duplicate leaf updates in one checkpoint must keep the
        // first entry (the checkpoint-final preimage).
        for i in 0..entry_count {
            let offset = i * IMT_LEAF_FFS_ENTRY_SIZE_V2;
            let entry_data = &data[offset..offset + IMT_LEAF_FFS_ENTRY_SIZE_V2];
            let (tree_id, tree_sub_id, leaf_index, leaf_hash, leaf_key, leaf_value, next_key, next_index, is_new_key) =
                deserialize_imt_leaf_ffs_entry_v2(entry_data)?;

            // For each new key, query DB and update if new value is larger
            tracing::debug!(
                "contract_state_imt_set_leaves_ffs: processing entry {}: tree_id={}, tree_sub_id={}, leaf_index={}, leaf_hash={}, leaf_key={}, leaf_value={}, next_key={}, next_index={}, is_new_key={}",
                i, tree_id, tree_sub_id, leaf_index, hex::encode(&leaf_hash), hex::encode(&leaf_key), hex::encode(&leaf_value), hex::encode(&next_key), next_index, is_new_key
            );
            if latest_leaf_written.insert((tree_id, tree_sub_id, leaf_index)) {
                self.store
                    .db_insert_imt_leaf(
                        &self.imt_leaf_table,
                        tree_id as i64,
                        tree_sub_id as i64,
                        leaf_index as i64,
                        checkpoint_id as i64,
                        &leaf_hash,
                        &leaf_key,
                        &leaf_value,
                        &next_key,
                        next_index as i64,
                    )
                    .await?;
            } else {
                tracing::debug!(
                    "contract_state_imt_set_leaves_ffs: skipped older duplicate entry {} for tree_id={}, tree_sub_id={}, leaf_index={}, checkpoint_id={}",
                    i,
                    tree_id,
                    tree_sub_id,
                    leaf_index,
                    checkpoint_id
                );
            }

            if let Some(existing_idx) = next_index_by_pair.get(&(tree_id, tree_sub_id)) {
                if leaf_index + 1 > *existing_idx {
                    next_index_by_pair.insert((tree_id, tree_sub_id), leaf_index + 1);
                }
            } else {
                next_index_by_pair.insert((tree_id, tree_sub_id), leaf_index + 1);
            }

            // Insert into key index table if this is a new key OR if this is a sentinel (zero key/value)
            let is_zero_key = leaf_key.iter().all(|&b| b == 0);
            let is_zero_value = leaf_value.iter().all(|&b| b == 0);
            let is_sentinel_initially = is_zero_key && is_zero_value;
            if is_new_key || is_sentinel_initially {
                // Compute key_bucket from the sort-encoded key
                let encoded_key = encode_imt_key_for_sorting::<N::F, N::QHash>(&N::QHash::from_bytes(&leaf_key).unwrap());
                // Compute as u16 first, then convert to i16 for ScyllaDB
                let key_bucket_u16 = u16::from_be_bytes([encoded_key[0], encoded_key[1]]);
                let key_bucket = imt_key_bucket_to_i16(key_bucket_u16);

                self.store
                    .db_insert_imt_key_index(
                        &self.imt_key_index_table,
                        tree_id as i64,
                        tree_sub_id as i64,
                        key_bucket,
                        &encoded_key,
                        &leaf_key,
                        checkpoint_id as i64,
                        leaf_index as i64,
                    )
                    .await?;
            }
        }

        for ((tree_id, tree_sub_id), slot_index) in next_index_by_pair {
            let current_next_append_index = self
                .store
                .db_select_imt_next_append_index(
                    &self.imt_next_append_index_table,
                    tree_id as i64,
                    tree_sub_id as i64,
                )
                .await?
                .unwrap_or(0) as u64;
            let merged_next_append_index = current_next_append_index.max(slot_index);

            tracing::debug!(
                "contract_state_imt_set_leaves_ffs set: user_id={}, contract_id={:?}, slot_index(batch)={}, slot_index(current)={}, slot_index(merged)={}",
                tree_id, tree_sub_id, slot_index, current_next_append_index, merged_next_append_index
            );

            self.store
                .db_insert_imt_next_append_index(
                    &self.imt_next_append_index_table,
                    tree_id as i64,
                    tree_sub_id as i64,
                    merged_next_append_index as i64,
                )
                .await?;
        }

        tracing::debug!(
            "contract_state_imt_set_leaves_ffs: inserted {} IMT leaf entries for checkpoint {}",
            entry_count,
            checkpoint_id
        );
        Ok(())
    }

    async fn contract_state_imt_set_next_append_index(
        &self,
        user_id: u64,
        contract_id: u64,
        next_append_index: u64,
    ) -> anyhow::Result<()> {
        tracing::debug!(
            "contract_state_imt_set_next_append_index: user_id={}, contract_id={}, next_append_index={}",
            user_id, contract_id, next_append_index
        );

        self.store
            .db_insert_imt_next_append_index(
                &self.imt_next_append_index_table,
                user_id as i64,
                contract_id as i64,
                next_append_index as i64,
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl<
        N: QNetworkDatabaseTypes,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        U64CounterTableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        IMTLeafTableIdentifier: Clone + Send + Sync,
        IMTKeyIndexTableIdentifier: Clone + Send + Sync,
        IMTNextAppendIndexTableIdentifier: Clone + Send + Sync,
        S: CoreDatabaseStore<
                N::QHash,
                N::HasherBase,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                U64CounterTableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
                IMTLeafTableIdentifier,
                IMTKeyIndexTableIdentifier,
                IMTNextAppendIndexTableIdentifier,
            > + Send
            + Sync,
    > PsyNodeContractStateIMTDatabaseReader<N::F, N::QHash>
    for PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        U64CounterTableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        IMTLeafTableIdentifier,
        IMTKeyIndexTableIdentifier,
        IMTNextAppendIndexTableIdentifier,
        S,
    >
{
    async fn contract_state_imt_get_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        leaf_index: u64,
    ) -> anyhow::Result<Option<IMTContractStateLeaf<N::F, N::QHash>>> {
        let result = self.store
            .db_select_imt_leaf(
                &self.imt_leaf_table,
                user_id as i64,
                contract_id as i64,
                leaf_index as i64,
                checkpoint_id as i64,
            )
            .await?;

        if let Some((_leaf_hash, leaf_key, leaf_value, next_key, next_index)) = result {
            use parth_core::data::serializable::QPDSerializable;
            use parth_core::felt::ToU64Value;

            let key = N::QHash::from_bytes(&leaf_key)?;
            let value = N::QHash::from_bytes(&leaf_value)?;
            let next_key_hash = N::QHash::from_bytes(&next_key)?;
            let next_index_felt = N::F::from_owned_u64(next_index as u64);

            Ok(Some(IMTContractStateLeaf {
                key,
                value,
                next_key: next_key_hash,
                next_index: next_index_felt,
            }))
        } else {
            Ok(None)
        }
    }

    async fn contract_state_imt_get_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &N::QHash,
    ) -> anyhow::Result<Option<u64>> {
        // Compute key bucket from sort-encoded key (must match how it's stored)
        let key_bytes = key.to_bytes()?;
        let encoded_key = encode_imt_key_for_sorting::<N::F, N::QHash>(&N::QHash::from_bytes(&key_bytes).unwrap());
        // Compute as u16 first, then convert to i16 for ScyllaDB
        let key_bucket_u16 = u16::from_be_bytes([encoded_key[0], encoded_key[1]]);
        let key_bucket = imt_key_bucket_to_i16(key_bucket_u16);

        // Look up the exact key
        let exact_result = self.store
            .db_select_imt_key_index_exact(
                &self.imt_key_index_table,
                user_id as i64,
                contract_id as i64,
                key_bucket,
                &encoded_key,
            )
            .await?;

        if let Some((leaf_index, birth_checkpoint)) = exact_result {
            // Check if the key was born before or at the checkpoint
            if birth_checkpoint <= checkpoint_id as i64 {
                return Ok(Some(leaf_index as u64));
            }
        }

        Ok(None)
    }

    async fn contract_state_imt_find_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &N::QHash,
    ) -> anyhow::Result<(u64, IMTContractStateLeaf<N::F, N::QHash>)> {
        use parth_core::data::serializable::QPDSerializable;
        use parth_core::felt::ToU64Value;

        // Compute key bucket from sort-encoded key (must match how it's stored)
        let key_bytes = key.to_bytes()?;
        let encoded_key = encode_imt_key_for_sorting::<N::F, N::QHash>(&N::QHash::from_bytes(&key_bytes).unwrap());
        // Compute as u16 first, then convert to i16 for ScyllaDB
        let key_bucket_u16 = u16::from_be_bytes([encoded_key[0], encoded_key[1]]);
        let key_bucket = imt_key_bucket_to_i16(key_bucket_u16);

        // Try predecessor in same bucket
        let predecessor_result = self.store
            .db_select_imt_key_index_predecessor(
                &self.imt_key_index_table,
                user_id as i64,
                contract_id as i64,
                key_bucket,
                &encoded_key,
            )
            .await?;

        // Find the predecessor that was born before the checkpoint
        for (_encoded_key_result, leaf_key, leaf_index, birth_checkpoint) in predecessor_result {
            if birth_checkpoint <= checkpoint_id as i64 {
                // Get the leaf preimage
                let leaf_result = self.store
                    .db_select_imt_leaf(
                        &self.imt_leaf_table,
                        user_id as i64,
                        contract_id as i64,
                        leaf_index,
                        checkpoint_id as i64,
                    )
                    .await?;

                if let Some((_, _, leaf_value, next_key, next_index)) = leaf_result {
                    let key = N::QHash::from_bytes(&leaf_key)?;
                    let value = N::QHash::from_bytes(&leaf_value)?;
                    let next_key_hash = N::QHash::from_bytes(&next_key)?;
                    let next_index_felt = N::F::from_owned_u64(next_index as u64);

                    return Ok((leaf_index as u64, IMTContractStateLeaf {
                        key,
                        value,
                        next_key: next_key_hash,
                        next_index: next_index_felt,
                    }));
                }
            }
        }

        // Try previous buckets
        for prev_bucket_u16 in (0..key_bucket_u16).rev() {
            let prev_bucket = imt_key_bucket_to_i16(prev_bucket_u16);
            let bucket_result = self.store
                .db_select_imt_key_index_predecessor_full_bucket(
                    &self.imt_key_index_table,
                    user_id as i64,
                    contract_id as i64,
                    prev_bucket,
                )
                .await?;

            // Find the largest key in this bucket that was born before/at checkpoint
            for (_, leaf_key, leaf_index, birth_checkpoint) in bucket_result.iter().rev() {
                if *birth_checkpoint <= checkpoint_id as i64 {
                    let leaf_result = self.store
                        .db_select_imt_leaf(
                            &self.imt_leaf_table,
                            user_id as i64,
                            contract_id as i64,
                            *leaf_index,
                            checkpoint_id as i64,
                        )
                        .await?;

                    if let Some((_, _, leaf_value, next_key, next_index)) = leaf_result {
                        let key = N::QHash::from_bytes(leaf_key)?;
                        let value = N::QHash::from_bytes(&leaf_value)?;
                        let next_key_hash = N::QHash::from_bytes(&next_key)?;
                        let next_index_felt = N::F::from_owned_u64(next_index as u64);

                        return Ok((*leaf_index as u64, IMTContractStateLeaf {
                            key,
                            value,
                            next_key: next_key_hash,
                            next_index: next_index_felt,
                        }));
                    }
                }
            }
        }

        let sentinel_key = N::QHash::default();
        let sentinel_encoded_key = encode_imt_key_for_sorting::<N::F, N::QHash>(&sentinel_key);
        let sentinel_bucket_u16 = u16::from_be_bytes([sentinel_encoded_key[0], sentinel_encoded_key[1]]);
        let sentinel_bucket = imt_key_bucket_to_i16(sentinel_bucket_u16);
        let sentinel_exact = self.store
            .db_select_imt_key_index_exact(
                &self.imt_key_index_table,
                user_id as i64,
                contract_id as i64,
                sentinel_bucket,
                &sentinel_encoded_key,
            )
            .await?;
        if let Some((leaf_index, birth_checkpoint)) = sentinel_exact {
            if birth_checkpoint <= checkpoint_id as i64 {
                let leaf_result = self.store
                    .db_select_imt_leaf(
                        &self.imt_leaf_table,
                        user_id as i64,
                        contract_id as i64,
                        leaf_index,
                        checkpoint_id as i64,
                    )
                    .await?;
                if let Some((_, leaf_key, leaf_value, next_key, next_index)) = leaf_result {
                    let key = N::QHash::from_bytes(&leaf_key)?;
                    let value = N::QHash::from_bytes(&leaf_value)?;
                    let next_key_hash = N::QHash::from_bytes(&next_key)?;
                    let next_index_felt = N::F::from_owned_u64(next_index as u64);
                    return Ok((leaf_index as u64, IMTContractStateLeaf {
                        key,
                        value,
                        next_key: next_key_hash,
                        next_index: next_index_felt,
                    }));
                }
            }
        }

        anyhow::bail!("No predecessor found for key")
    }

    async fn contract_state_imt_get_next_append_index(&self, user_id: u64, contract_id: u64) -> anyhow::Result<u64> {
        let result = self.store
            .db_select_imt_next_append_index(
                &self.imt_next_append_index_table,
                user_id as i64,
                contract_id as i64,
            )
            .await?;

        Ok(result.unwrap_or(0) as u64)
    }
}
