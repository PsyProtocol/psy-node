use parth_core::{data::{db::row::QDatabaseSingleIdTableRowNoCheckpointId, hash::{merkle_node_key::SimpleMerkleNode, merkle_store_key::QMerkleStoreSingleIdNode}}, felt::QFelt, protocol::core_types::QHashBase, QCoreProcCheckpointUniqueId};
use psy_data::v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, contract::{ContractCodeDefinition, PQBCDeployContractWithRoot}, public_key::PZKPublicKeyInfo};



#[pderive::serialize_copy_f_hash]
pub struct CoordinatorPendingCheckpointBase<F: QFelt, Hash: QHashBase> {
    pub block_state: QEDL2BlockState,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub checkpoint_leaf_hash: Hash,
    pub checkpoint_tree_root: Hash,
}

#[pderive::serialize_clone_f_hash]
pub struct CoordinatorPendingCheckpointDatabase<F: QFelt, Hash: QHashBase> {
    pub coordinator_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_base: CoordinatorPendingCheckpointBase<F, Hash>,
    pub new_base: CoordinatorPendingCheckpointBase<F, Hash>,

    pub update_global_user_tree_nodes: Vec<SimpleMerkleNode<Hash>>,
    pub update_global_contract_tree_nodes: Vec<SimpleMerkleNode<Hash>>,
    pub update_user_regsistration_tree_nodes: Vec<SimpleMerkleNode<Hash>>,
    pub update_user_public_keys: Vec<QDatabaseSingleIdTableRowNoCheckpointId<PZKPublicKeyInfo<Hash>>>,
    pub update_contract_function_tree_nodes: Vec<QMerkleStoreSingleIdNode<Hash>>,
    pub update_contract_code_definitions: Vec<QDatabaseSingleIdTableRowNoCheckpointId<ContractCodeDefinition>>,
}




#[pderive::serialize_clone_f_hash]
pub struct CoordinatorPendingCheckpointSync<F: QFelt, Hash: QHashBase> {
    pub coordinator_id: u64,
    pub old_base: CoordinatorPendingCheckpointBase<F, Hash>,
    pub new_base: CoordinatorPendingCheckpointBase<F, Hash>,

    pub updated_realm_roots: Vec<SimpleMerkleNode<Hash>>,
    pub deployed_contracts: Vec<PQBCDeployContractWithRoot<Hash>>,
    pub registered_users: Vec<PZKPublicKeyInfo<Hash>>,
}



