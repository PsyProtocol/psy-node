use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::{common::{data::{core::{hash::hash256::Hash256, merkle::merkle_proof::MerkleProofCore}, protocol::job::QPWorkerJobDataID}, job_manager::QPJobManagerRequestJobResponse, traits::serializable::QPDSerializable}, impl_qpq_serialize_bincode};


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, Copy, PartialOrd, Ord)]
pub struct UniqueCheckpointId {
    pub checkpoint_id: u64,
    pub uuid: u64,
}
impl Display for UniqueCheckpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.checkpoint_id, self.uuid)
    }
}

impl_qpq_serialize_bincode!(UniqueCheckpointId);


// a merkle proof connecting the realm merkle tree root to the root of the top half of the global user tree stored by the coordinator (finalized)
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct RealmMerkleProofWithLatestSubmittedCheckpoint {
    // most recent finalized checkpoint id for the coordinator, might be greater than last_submitted_checkpoint_id
    pub last_finalized_checkpoint_id: u64,
    pub realm_id: u64,
    // the last checkpoint id that the realm root was updated for the coordinator (ie. the last time the leaf cooresponding to this realm realm root was updated in the coordinator tree)
    pub last_submitted_checkpoint_id: u64,
    pub merkle_proof: MerkleProofCore<Hash256>, // leaf == realm root hash, root == global user tree root at last_finalized_checkpoint_id
}


impl_qpq_serialize_bincode!(RealmMerkleProofWithLatestSubmittedCheckpoint);




// a merkle proof connecting the realm merkle tree root to the root of the top half of the global user tree stored by the coordinator (finalized)
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct QPCoordinatorGlobalCheckpointState {
    // most recent finalized checkpoint id for the coordinator
    pub checkpoint_id: u64,
    // the time at which the last finalized checkpoint was committed by the coordinator processor
    pub time_since_epoch_ms: u64,
    // last finalized global user tree root hash
    pub global_user_tree_root: Hash256,
}


impl_qpq_serialize_bincode!(QPCoordinatorGlobalCheckpointState);




// a merkle proof connecting the realm merkle tree root to the root of the top half of the global user tree stored by the coordinator (finalized)
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct QPCoordinatorGlobalCheckpointStateForRealm {
    pub global_state: QPCoordinatorGlobalCheckpointState,
    pub realm_id: u64,
    // the last checkpoint id that the realm root was updated for the coordinator (ie. the last time the leaf cooresponding to this realm realm root was updated in the coordinator tree)
    pub last_submitted_checkpoint_id: u64,
    pub merkle_proof: MerkleProofCore<Hash256>, // leaf == realm root hash, root == global user tree root at last_finalized_checkpoint_id
}


impl_qpq_serialize_bincode!(QPCoordinatorGlobalCheckpointStateForRealm);



#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPEdgeWorkerJobResponse {
    pub job_response: QPJobManagerRequestJobResponse,
    pub wip_checkpoint_id: UniqueCheckpointId,
    pub data: Vec<u8>,
}
impl_qpq_serialize_bincode!(QPEdgeWorkerJobResponse);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPEdgeWorkerSubmitJobRequest {
    pub job_id: QPWorkerJobDataID,
    pub worker_id: u64,
    pub wip_checkpoint_id: UniqueCheckpointId,
    pub data: Vec<u8>,
}
impl_qpq_serialize_bincode!(QPEdgeWorkerSubmitJobRequest);


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPEdgeWorkerSubmitJobResponse {
    pub has_error: bool,
    pub error_message: String,
}
impl_qpq_serialize_bincode!(QPEdgeWorkerSubmitJobResponse);



#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPRealmToCoordinatorUpdateMessage {
    pub realm_id: u64,
    pub old_realm_root: Hash256,
    pub new_realm_root: Hash256,
}
impl_qpq_serialize_bincode!(QPRealmToCoordinatorUpdateMessage);

