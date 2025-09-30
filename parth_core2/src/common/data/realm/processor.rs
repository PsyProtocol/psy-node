use crate::common::data::{core::hash::hash256::Hash256, user::QPUserDataRecord};
use crate::common::data::core::merkle::node::SimpleMerkleNode;
use crate::common::traits::serializable::QPDSerializable;
use crate::impl_qpq_serialize_bincode;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct QPRealmProcessorPendingCompressedStateFromWorker {
    pub user_id: u64,
    pub compressed_data: Vec<u8>,
}

impl_qpq_serialize_bincode!(QPRealmProcessorPendingCompressedStateFromWorker);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct QPRealmProcessorPendingCheckpointStateDelta {
    pub realm_id: u64,
    pub old_realm_root_hash: Hash256,
    pub new_realm_root_hash: Hash256,
    pub user_data_deltas: Vec<QPUserDataRecord>,
    pub realm_user_tree_deltas: Vec<SimpleMerkleNode<Hash256>>,
    pub compressed_user_data_from_workers: Vec<QPRealmProcessorPendingCompressedStateFromWorker>,
}

impl_qpq_serialize_bincode!(QPRealmProcessorPendingCheckpointStateDelta);