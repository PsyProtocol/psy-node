use crate::common::data::{coordinator::core::{QPCoordinatorProcessorPendingCheckpointStateDelta, QPCoordinatorRealmUpdateMessage}, core::{hash::hash256::Hash256, merkle::merkle_proof::MerkleProofCore}, protocol::core::{QPCoordinatorGlobalCheckpointState, QPCoordinatorGlobalCheckpointStateForRealm, UniqueCheckpointId}};
use async_trait::async_trait;

#[async_trait]
pub trait QPCoordinatorJobDataTempStateStoreEdge {
    async fn get_mini_tree_leaves(&self) -> anyhow::Result<Vec<Hash256>>;
    async fn set_mini_tree_root(&self, root: Hash256, wip_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<()>;
}
#[async_trait]
pub trait QPCoordinatorJobDataTempStateStoreProcessor {
    async fn set_mini_tree_leaves(&self, leaves: &[Hash256]) -> anyhow::Result<()>;
    async fn get_mini_tree_root(&self, wip_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<Hash256>;
}
#[async_trait]
pub trait QPCoordinatorEdgeStateReaderBase {

    /// The checkpoint for which realms are currently accepting user data submissions, aka the next checkpoint for the processor to process, will often be after the  work in progress checkpoint, but will have the same checkpoint id while we are waiting for the coordinator to process and finalize the block (after the realm processor submits our changes to the coordinator and before the realm processor starts working on the next checkpoint)
    async fn get_current_unique_checkpoint_id(&self) -> anyhow::Result<UniqueCheckpointId>;
    
    /// this checkpoint id will be before the checkpoint in get_current_unique_checkpoint_id, as the UniqueCheckpointId is incremented when a new checkpoint is started, this is the current checkpoint being worked on by the realm processor
    async fn get_work_in_progress_checkpoint_id(&self) -> anyhow::Result<UniqueCheckpointId>;

    /// this checkpoint id will be before the checkpoint in get_current_unique_checkpoint_id, as the UniqueCheckpointId is incremented when a new checkpoint is started, but the last finalized checkpoint id is the last checkpoint which was fully processed and finalized by both the realm AND the COORDINATOR
    async fn get_last_finalized_checkpoint_id(&self) -> anyhow::Result<u64>;
    

    async fn get_total_coordinator_worker_jobs(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
    async fn get_checkpoint_unique_id(&self) -> anyhow::Result<UniqueCheckpointId>;
    async fn get_latest_global_checkpoint_state(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_global_checkpoint_state_at_checkpoint_id(&self, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_last_realm_submitted_checkpoint_id(&self, realm_id: u64) -> anyhow::Result<u64>;
    async fn get_checkpoint_id_for_realm_root(&self, realm_id: u64, realm_root: Hash256) -> anyhow::Result<Option<u64>>;
    // the root of the miniature merkle tree hashed by combining the new realm roots into a new merkle tree and computed by a worker, if empty, then the hash is 0
    async fn get_combined_realm_mini_tree_root_for_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<Hash256>;
    async fn get_merkle_proof_in_coordinator_tree(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    async fn get_latest_merkle_proof_in_coordinator_tree(&self, realm_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
}



#[async_trait]
pub trait QPCoordinatorEdgeTempStateStore {
    async fn has_submitted_update_to_api_in_checkpoint(&self, realm_id: u64, unique_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<u64>;
    async fn set_submitted_update_to_api_in_checkpoint(&self, realm_id: u64, unique_checkpoint_id: UniqueCheckpointId, random_number: u64) -> anyhow::Result<()>;
    async fn increment_submitted_jobs_counter(&self, wip_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<u64>;
}

#[async_trait]
pub trait QPCoordinatorProcessorStateStore: QPCoordinatorEdgeStateReaderBase {
    async fn set_work_in_progress_checkpoint_id(&self, work_in_progress_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<()>;
    async fn set_current_unique_checkpoint_id(&self, unique_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<()>;

    async fn set_total_coordinator_worker_jobs(&self, checkpoint_id: UniqueCheckpointId, total_jobs: u64) -> anyhow::Result<u64>;
    async fn set_checkpoint_unique_id(&self, checkpoint_unique_id: UniqueCheckpointId) -> anyhow::Result<()>;
    async fn apply_processor_checkpoint_delta(&self, delta: &QPCoordinatorProcessorPendingCheckpointStateDelta) -> anyhow::Result<()>;

}



#[async_trait]
pub trait CoordinatorEdgeAPI {


    async fn get_merkle_proof_in_coordinator_tree(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    /// Gets the latest merkle proof for the realm in the coordinator tree, 
    async fn get_latest_merkle_proof_in_coordinator_tree(&self, realm_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    
    /// Gets the latest merkle proof for threalm in the coordinator tree and the submission metadata for the last submitted checkpoint id for the realm
    async fn get_latest_coordinator_state_for_realm(&self, realm_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm>;
    async fn get_coordinator_state_for_realm_at_checkpoint(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm>;

    async fn get_latest_coordinator_checkpoint_state(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_coordinator_checkpoint_state_for_checkpoint(&self, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_coordinator_checkpoint_for_realm_root(&self, realm_id: u64, realm_root: &Hash256) -> anyhow::Result<Option<u64>>;
    async fn get_latest_combined_realm_mini_tree_root_for_checkpoint(&self) -> anyhow::Result<Hash256>;

    async fn submit_realm_update(&self, realm_id: u64, old_realm_root: Hash256, new_realm_root: Hash256) -> anyhow::Result<()>;
}


#[async_trait]
pub trait QPCoordinatorUpdateQueueClientForCoordinatorProcessor {
    async fn dump_realm_update_messaages(&self, checkpoint_queue_id: UniqueCheckpointId) -> anyhow::Result<Vec<QPCoordinatorRealmUpdateMessage>>;
}


#[async_trait]
pub trait QPCoordinatorUpdateQueueClientForCoordinatorEdge {
    async fn enqueue_realm_update_message_for_processor(&self, checkpoint_queue_id: UniqueCheckpointId, update: QPCoordinatorRealmUpdateMessage) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QPCoordinatorProcessorBlockCompletionNotifier {
    async fn notify_block_completed(&self, new_checkpoint: &QPCoordinatorGlobalCheckpointState) -> anyhow::Result<()>;
}