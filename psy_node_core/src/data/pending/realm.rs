use parth_core::{data::hash::{merkle_node_key::SimpleMerkleNode, merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode}}, felt::QFelt, protocol::core_types::QHashBase, QCoreProcCheckpointUniqueId};
use psy_data::v1::qdata::user::PQEDUserLeaf;


#[pderive::serialize_clone_f_hash]
pub struct RealmPendingCheckpoint<F: QFelt, Hash: QHashBase> {
    pub realm_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub update_user_leaves: Vec<PQEDUserLeaf<F, Hash>>,
    pub update_user_tree_nodes: Vec<SimpleMerkleNode<Hash>>,
    pub update_user_contract_tree_nodes: Vec<Vec<QMerkleStoreSingleIdNode<Hash>>>,
    pub update_user_contract_state_tree_nodes: Vec<Vec<QMerkleStoreDoubleIdNode<Hash>>>,
    pub old_realm_root: Hash,
    pub new_realm_root: Hash,
}