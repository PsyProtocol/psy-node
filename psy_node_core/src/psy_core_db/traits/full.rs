use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
    }, data::{
        db::row::{QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowNoCheckpointId},
        hash::{
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
            merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode},
        },
    }, node::traits::realm
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
    contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeaf},
    public_key::PZKPublicKeyInfo,
    user::PQEDUserLeaf,
};

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCheckpointTreeDatabaseReader<Hash> {
    async fn checkpoint_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash>;
    async fn checkpoint_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<Hash>;
    async fn checkpoint_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn checkpoint_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCheckpointTreeDatabaseWriter<Hash> {
    async fn checkpoint_tree_set_leaf_hash(&self, checkpoint_id: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn checkpoint_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeUserRegistrationTreeDatabaseReader<Hash> {
    async fn user_registration_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash>;
    async fn user_registration_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<Hash>;
    async fn user_registration_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn user_registration_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeUserRegistrationTreeDatabaseWriter<Hash> {
    async fn user_registration_tree_set_leaf_hash(&self, checkpoint_id: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn user_registration_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()>;
    async fn user_registration_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeGlobalUserTreeDatabaseReader<Hash> {
    async fn global_user_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash>;
    async fn global_user_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<Hash>;
    async fn global_user_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn global_user_tree_get_merkle_proof_sub_tree(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn global_user_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
    async fn global_user_tree_get_node(&self, checkpoint_id: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeGlobalUserTreeDatabaseWriter<Hash> {
    async fn global_user_tree_set_top_tree_merkle_proof(&self, checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash>) -> anyhow::Result<()>;
    async fn global_user_tree_set_leaf_hash(&self, checkpoint_id: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn global_user_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()>;
    async fn global_user_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeUserContractTreeDatabaseReader<Hash> {
    async fn user_contract_tree_get_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64) -> anyhow::Result<Hash>;
    async fn user_contract_tree_get_root_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<Hash>;
    async fn user_contract_tree_get_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn user_contract_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreSingleIdKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeUserContractTreeDatabaseWriter<Hash> {
    async fn user_contract_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn user_contract_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<Hash>]) -> anyhow::Result<()>;
    async fn user_contract_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeContractStateTreeTreeDatabaseReader<Hash> {
    async fn contract_state_tree_get_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64, state_slot_id: u64)
        -> anyhow::Result<Hash>;
    async fn contract_state_tree_get_root_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u64) -> anyhow::Result<Hash>;
    async fn contract_state_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        state_slot_id: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn contract_state_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreDoubleIdKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeContractStateTreeTreeDatabaseWriter<Hash> {
    async fn contract_state_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn contract_state_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreDoubleIdNode<Hash>]) -> anyhow::Result<()>;
    async fn contract_state_tree_set_top_tree_merkle_proof(&self, checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash>) -> anyhow::Result<()>;
    async fn contract_state_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeGlobalContractTreeDatabaseReader<Hash> {
    async fn global_contract_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash>;
    async fn global_contract_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<Hash>;
    async fn global_contract_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn global_contract_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeGlobalContractTreeDatabaseWriter<Hash> {
    async fn global_contract_tree_set_leaf_hash(&self, checkpoint_id: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn global_contract_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()>;
    async fn global_contract_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeContractFunctionTreeDatabaseReader<Hash> {
    async fn contract_function_tree_get_leaf_hash(&self, checkpoint_id: u64, contract_id: u64, function_id: u64) -> anyhow::Result<Hash>;
    async fn contract_function_tree_get_root_hash(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<Hash>;
    async fn contract_function_tree_get_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        function_id: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn contract_function_tree_get_nodes(&self, checkpoint_id: u64, keys: &[QMerkleStoreSingleIdKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeContractFunctionTreeDatabaseWriter<Hash> {
    async fn contract_function_tree_set_leaf_hash(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        function_id: u64,
        value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>>;
    async fn contract_function_tree_set_nodes(&self, checkpoint_id: u64, nodes: &[QMerkleStoreSingleIdNode<Hash>]) -> anyhow::Result<()>;
    async fn contract_function_tree_set_nodes_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCheckpointObjectDatabaseReader<F, Hash> {
    async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64>;
    async fn get_checkpoint_id_for_checkpoint_root_hash(&self, root_hash: Hash) -> anyhow::Result<Option<u64>>;
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointLeaf<F, Hash>>;
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<QEDL2BlockState>;
    async fn get_latest_l2_block_state(&self) -> anyhow::Result<QEDL2BlockState>;
    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<PQEDCheckpointGlobalStateRoots<Hash>>;
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>;
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>>;
    async fn get_current_unique_pending_id(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCheckpointRealmSpecificDatabaseReader<F, Hash> {
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>>;
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<TagTreeMerkleProof<Hash>>;
    async fn get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash>>;
}


#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoordinatorSpecificDatabaseReader<F, Hash> {
    async fn get_realm_guta_reward_tree_node_key(
        &self,
        unique_pending_id: u64,
        realm_id: u64,
    ) -> anyhow::Result<Option<SimpleMerkleNodeKey>>;
}
#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoordinatorSpecificDatabaseWriter<F, Hash> {
    async fn set_realm_guta_reward_tree_node_key(
        &self,
        unique_pending_id: u64,
        realm_id: u64,
        node_key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<()>;
    async fn set_realm_guta_reward_tree_node_keys_ffs(
        &self,
        unique_pending_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCheckpointObjectDatabaseWriter<F, Hash> {
    async fn inc_unique_pending_id(&self, amount: u64) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>;
    async fn set_unique_pending_id_checkpoint_id_mapping(&self, unique_pending_id: u64, checkpoint_id: u64) -> anyhow::Result<()>;
    async fn set_checkpoint_id_to_unique_pending_id_mapping(
        &self,
        checkpoint_id: u64,
        unique_pending_id: u64,
        unique_id_struct: &QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<()>;
    async fn set_latest_checkpoint_id(&self, checkpoint_id: u64) -> anyhow::Result<()>;
    async fn set_checkpoint_leaf_data(&self, checkpoint_id: u64, leaf_data: &PQEDCheckpointLeaf<F, Hash>) -> anyhow::Result<()>;
    async fn set_checkpoint_root_hash_to_id_mapping(&self, checkpoint_root: Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    async fn set_l2_latest_block_state(&self, block_state: &QEDL2BlockState) -> anyhow::Result<()>;
    async fn set_l2_block_state(&self, checkpoint_id: u64, block_state: &QEDL2BlockState) -> anyhow::Result<()>;
    async fn set_checkpoint_global_state_roots(&self, checkpoint_id: u64, roots: &PQEDCheckpointGlobalStateRoots<Hash>) -> anyhow::Result<()>;
    async fn set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        merkle_proof: &TagTreeMerkleProof<Hash>,
    ) -> anyhow::Result<()>;
    async fn set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(
        &self,
        checkpoint_id: u64,
        merkle_proof: &TagTreeMerkleProof<Hash>,
    ) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseUserStoreReader<F, Hash> {
    async fn get_zk_public_key(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PZKPublicKeyInfo<Hash>>;
    async fn get_user_leaf(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<F, Hash>>;
    async fn get_user_ids_for_public_key(&self, public_key: Hash, start_user_id: u64, count: usize) -> anyhow::Result<Vec<u64>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseUserStoreWriter<F, Hash> {
    async fn set_user_leaf_(&self, checkpoint_id: u64, leaf_data: &PQEDUserLeaf<F, Hash>) -> anyhow::Result<()>;
    async fn set_user_leaves_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;

    async fn set_zk_public_key(&self, checkpoint_id: u64, user_id: u64, public_key_info: &PZKPublicKeyInfo<Hash>) -> anyhow::Result<()>;
    async fn set_zk_public_keys_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;

    async fn set_public_key_for_user_id(&self, user_id: u64, public_key: Hash) -> anyhow::Result<()>;
    async fn set_public_key_for_user_ids_ffs(&self, data: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash> {
    async fn get_contract_tree_heights(&self, checkpoint_id: u64, contract_ids: &[u64]) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseBasicContractInfoStoreWriter<F, Hash> {
    async fn set_contract_tree_heights(&self, checkpoint_id: u64, contract_ids: &[(u64, u8)]) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>: PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash> {
    async fn get_contract_leaf(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<PQEDContractLeaf<F, Hash>>;
    async fn get_contract_code_definition(&self, checkpoint_id: u64, contract_id: u64) -> anyhow::Result<ContractCodeDefinition>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreDatabaseContractObjectStoreWriter<F, Hash>: PsyNodeCoreDatabaseBasicContractInfoStoreWriter<F, Hash> {
    async fn set_contract_leaf(&self, checkpoint_id: u64, contract_id: u64, leaf: &PQEDContractLeaf<F, Hash>) -> anyhow::Result<()>;
    async fn set_contract_leaves_ffs(&self, checkpoint_id: u64, data: &[u8]) -> anyhow::Result<()>;
    async fn set_contract_code_definition(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        code_definition: &ContractCodeDefinition,
    ) -> anyhow::Result<()>;
    async fn set_many_contract_code_definitions(
        &self,
        checkpoint_id: u64,
        inserts: &[ContractCodeDefinitionWithContractId],
    ) -> anyhow::Result<()>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreRewardsTagTreeStoreReader<F, Hash> {
    async fn rewards_tag_tree_get_root_at_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Hash>;
    async fn rewards_tag_tree_get_node_at_unique_pending_id(&self, unique_pending_id: u64, node: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn rewards_tag_tree_get_node_values_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>>;
    async fn rewards_tag_tree_get_node_tags_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>>;
    async fn rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(
        &self,
        unique_pending_id: u64,
        nodes: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<TagTreeMerkleProof<Hash>>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait PsyNodeCoreRewardsTagTreeStoreWriter<F, Hash> {
    async fn rewards_tag_tree_set_node_tag(&self, unique_pending_id: u64, key: SimpleMerkleNodeKey, tag: Hash, value: Hash) -> anyhow::Result<()>;
    async fn rewards_tag_tree_set_node_tag_only(&self, unique_pending_id: u64, key: SimpleMerkleNodeKey, tag: Hash) -> anyhow::Result<()>;
}

pub trait PsyRealmEdgeAPIStoreReader<F, Hash>:
    PsyNodeCheckpointTreeDatabaseReader<Hash>
    + PsyNodeGlobalUserTreeDatabaseReader<Hash>
    + PsyNodeUserContractTreeDatabaseReader<Hash>
    + PsyNodeContractStateTreeTreeDatabaseReader<Hash>
    + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
    + PsyNodeCheckpointRealmSpecificDatabaseReader<F, Hash>
    + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
    + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
    + PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash>
{
}
impl<
        T: PsyNodeCheckpointTreeDatabaseReader<Hash>
            + PsyNodeGlobalUserTreeDatabaseReader<Hash>
            + PsyNodeUserContractTreeDatabaseReader<Hash>
            + PsyNodeContractStateTreeTreeDatabaseReader<Hash>
            + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
            + PsyNodeCheckpointRealmSpecificDatabaseReader<F, Hash>
            + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
            + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
            + PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash>,
        F,
        Hash,
    > PsyRealmEdgeAPIStoreReader<F, Hash> for T
{
}

pub trait PsyCoordinatorEdgeAPIStoreReader<F, Hash>:
    PsyNodeCheckpointTreeDatabaseReader<Hash>
    + PsyNodeUserRegistrationTreeDatabaseWriter<Hash>
    + PsyNodeGlobalUserTreeDatabaseReader<Hash>
    + PsyNodeUserContractTreeDatabaseReader<Hash>
    + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
    + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
    + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
    + PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash>
    + PsyNodeContractFunctionTreeDatabaseReader<Hash>
    + PsyNodeGlobalContractTreeDatabaseReader<Hash>
    + PsyNodeUserRegistrationTreeDatabaseReader<Hash>
{
}
impl<
        T: PsyNodeCheckpointTreeDatabaseReader<Hash>
            + PsyNodeUserRegistrationTreeDatabaseWriter<Hash>
            + PsyNodeGlobalUserTreeDatabaseReader<Hash>
            + PsyNodeUserContractTreeDatabaseReader<Hash>
            + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
            + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
            + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
            + PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash>
            + PsyNodeContractFunctionTreeDatabaseReader<Hash>
            + PsyNodeGlobalContractTreeDatabaseReader<Hash>
            + PsyNodeUserRegistrationTreeDatabaseReader<Hash>,
        F,
        Hash,
    > PsyCoordinatorEdgeAPIStoreReader<F, Hash> for T
{
}
pub trait PsyCoordinatorProcessorStore<F, Hash>:
    // 1. Checkpoint Tree (R/W)
    PsyNodeCheckpointTreeDatabaseReader<Hash>
    + PsyNodeCheckpointTreeDatabaseWriter<Hash>
    // 2. User Registration Tree (R/W)
    + PsyNodeUserRegistrationTreeDatabaseReader<Hash>
    + PsyNodeUserRegistrationTreeDatabaseWriter<Hash>
    // 3. Global User Tree (R/W)
    + PsyNodeGlobalUserTreeDatabaseReader<Hash>
    + PsyNodeGlobalUserTreeDatabaseWriter<Hash>
    // 4. Global Contract Tree (R/W)
    + PsyNodeGlobalContractTreeDatabaseReader<Hash>
    + PsyNodeGlobalContractTreeDatabaseWriter<Hash>
    // 5. Contract Function Tree (R/W)
    + PsyNodeContractFunctionTreeDatabaseReader<Hash>
    + PsyNodeContractFunctionTreeDatabaseWriter<Hash>
    // 6. Rewards Tag Tree (R/W)
    + PsyNodeCoreRewardsTagTreeStoreReader<F, Hash>
    + PsyNodeCoreRewardsTagTreeStoreWriter<F, Hash>
    // 7. Object/Metadata (R/W)
    + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
    + PsyNodeCheckpointObjectDatabaseWriter<F, Hash>
    // 8. User Store (R/W)
    + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
    + PsyNodeCoreDatabaseUserStoreWriter<F, Hash>
    // 9. Contract Object Store (R/W) (includes Basic Info R/W)
    + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
    + PsyNodeCoreDatabaseContractObjectStoreWriter<F, Hash>
{
}

impl<
        T: PsyNodeCheckpointTreeDatabaseReader<Hash>
            + PsyNodeCheckpointTreeDatabaseWriter<Hash>
            + PsyNodeUserRegistrationTreeDatabaseReader<Hash>
            + PsyNodeUserRegistrationTreeDatabaseWriter<Hash>
            // All other traits needed for the processor
            + PsyNodeGlobalUserTreeDatabaseReader<Hash>
            + PsyNodeGlobalUserTreeDatabaseWriter<Hash>
            + PsyNodeUserContractTreeDatabaseReader<Hash>
            + PsyNodeUserContractTreeDatabaseWriter<Hash>
            + PsyNodeContractStateTreeTreeDatabaseReader<Hash>
            + PsyNodeContractStateTreeTreeDatabaseWriter<Hash>
            + PsyNodeGlobalContractTreeDatabaseReader<Hash>
            + PsyNodeGlobalContractTreeDatabaseWriter<Hash>
            + PsyNodeContractFunctionTreeDatabaseReader<Hash>
            + PsyNodeContractFunctionTreeDatabaseWriter<Hash>
            + PsyNodeCoreRewardsTagTreeStoreReader<F, Hash>
            + PsyNodeCoreRewardsTagTreeStoreWriter<F, Hash>
            + PsyNodeCheckpointObjectDatabaseReader<F, Hash>
            + PsyNodeCheckpointObjectDatabaseWriter<F, Hash>
            + PsyNodeCheckpointRealmSpecificDatabaseReader<F, Hash>
            + PsyNodeCoreDatabaseUserStoreReader<F, Hash>
            + PsyNodeCoreDatabaseUserStoreWriter<F, Hash>
            + PsyNodeCoreDatabaseContractObjectStoreReader<F, Hash>
            + PsyNodeCoreDatabaseContractObjectStoreWriter<F, Hash>,
        F,
        Hash,
    > PsyCoordinatorProcessorStore<F, Hash> for T
{
}