use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::common::data::{core::hash::hash256::Hash256, protocol::core::QPCoordinatorGlobalCheckpointState};
use crate::common::data::core::merkle::node::SimpleMerkleNode;
use crate::common::traits::serializable::QPDSerializable;
use crate::impl_qpq_serialize_bincode;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord, Copy)]

pub struct QPCoordinatorRealmMetadata {
    pub realm_id: u64,
    pub last_submitted_checkpoint_id: u64,
    pub new_realm_root: Hash256,
}

impl_qpq_serialize_bincode!(QPCoordinatorRealmMetadata);

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct QPCoordinatorProcessorPendingCheckpointStateDelta {
    pub realm_metadata_updates: Vec<QPCoordinatorRealmMetadata>,
    pub global_user_tree_deltas: Vec<SimpleMerkleNode<Hash256>>,
    pub realm_submission_mini_tree_root: Hash256,
    pub checkpoint_state: QPCoordinatorGlobalCheckpointState,
}
impl_qpq_serialize_bincode!(QPCoordinatorProcessorPendingCheckpointStateDelta);




#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord, Copy)]

pub struct QPCoordinatorRealmUpdateMessage {
    pub realm_id: u64,
    pub new_realm_root: Hash256,
}

impl_qpq_serialize_bincode!(QPCoordinatorRealmUpdateMessage);
