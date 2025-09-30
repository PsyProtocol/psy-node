
use crate::common::data::{core::{hash::hash256::Hash256, merkle::merkle_proof::MerkleProofCore}, protocol::{core::{QPCoordinatorGlobalCheckpointState, QPCoordinatorGlobalCheckpointStateForRealm, QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest, QPEdgeWorkerSubmitJobResponse, UniqueCheckpointId}, job::QPWorkerJobDataID}, realm::{core::{ RealmEdgeRegisterUserMessageForProcessor, RealmEdgeUpdateUserDataMessageForProcessor, RealmEdgeUserAtUniqueCheckpointKey}, edge_api::{RealmEdgeAPIGetHistoricalUserDataRequest, RealmEdgeAPIGetLastFinalizedCheckpointIdResponse, RealmEdgeAPIGetLatestUserDataRequest, RealmEdgeAPIGetRealmInfoResponse, RealmEdgeAPIGetUserDataResponse, RealmEdgeAPIGetUserDataWithMerkleProofResponse, RealmEdgeAPIGetUserMerkleProofRequest, RealmEdgeAPIGetUserMerkleProofResponse, RealmEdgeAPIRegisterUserRequest, RealmEdgeAPIRegisterUserResponse, RealmEdgeAPISubmitUserDataRequest, RealmEdgeAPISubmitUserDataResponse}, processor::QPRealmProcessorPendingCheckpointStateDelta}, user::QPUserDataRecord};
use async_trait::async_trait;

/// Trait defining the API for a QP Realm Edge node.
/// This API is used by clients (e.g., end-users and workers) to interact with a specific realm via an HTTP API
#[async_trait]
pub trait QPRealmEdgeAPI {
    /// Retrieves a merkle proof for a user's data leaf at a specific checkpoint in time.
    /// The proof is from the global user tree root to the user leaf.
    async fn get_historical_user_merkle_proof(&self, request: &RealmEdgeAPIGetUserMerkleProofRequest) -> anyhow::Result<RealmEdgeAPIGetUserMerkleProofResponse>;
    
    /// Retrieves the latest merkle proof for a user's data leaf.
    async fn get_latest_user_merkle_proof(&self, request: &RealmEdgeAPIGetUserMerkleProofRequest) -> anyhow::Result<RealmEdgeAPIGetUserMerkleProofResponse>;
    
    /// Gets the most recent checkpoint ID that has been finalized for the realm.
    async fn get_last_finalized_checkpoint_id(&self) -> anyhow::Result<RealmEdgeAPIGetLastFinalizedCheckpointIdResponse>;
    
    /// Gets core information about the realm, including its ID, last finalized checkpoint, and root hash.
    async fn get_realm_info(&self) -> anyhow::Result<RealmEdgeAPIGetRealmInfoResponse>;
    
    /// Retrieves a user's data as it existed at or before a specified checkpoint ID.
    async fn get_historical_user_data(&self, request: &RealmEdgeAPIGetHistoricalUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataResponse>;
    
    /// Retrieves the latest version of a user's data.
    async fn get_latest_user_data(&self, user_id: u64) -> anyhow::Result<RealmEdgeAPIGetUserDataResponse>;
    
    /// Retrieves a user's data and its corresponding merkle proof for a specific historical checkpoint.
    async fn get_historical_user_data_with_proof(&self, request: &RealmEdgeAPIGetHistoricalUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataWithMerkleProofResponse>;
    
    /// Retrieves the latest version of a user's data along with its corresponding merkle proof.
    async fn get_latest_user_data_with_proof(&self, request: &RealmEdgeAPIGetLatestUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataWithMerkleProofResponse>;

    /// Submits new data for an existing user. The data must be signed by the user's registered key.
    async fn submit_user_data(&self, request: &RealmEdgeAPISubmitUserDataRequest) -> anyhow::Result<RealmEdgeAPISubmitUserDataResponse>;
    
    /// Registers a new user with the realm, setting their public key and initial data.
    /// This will fail if the user ID is already taken.
    async fn register_user(&self, request: &RealmEdgeAPIRegisterUserRequest) -> anyhow::Result<RealmEdgeAPIRegisterUserResponse>;

    /// Gets the latest merkle proof linking the realm's root to the global user tree root.
    /// This proof is essential for verifying user data against the global state.
    async fn get_latest_realm_merkle_proof(&self) -> anyhow::Result<MerkleProofCore<Hash256>>;

    /// Reports the result of work performed by a worker node (the compressed user data).
    async fn submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse>;

    async fn request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse>;
}


// The trait defining the functions needed by the edge api servers to read/write to the STORE_DB_TEMP_SUBMITTED_COMPRESSED_USER_DATA which stores the user data submitted in the submit_user_data api call
#[async_trait]
pub trait QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmEdgeClient {
    async fn put_compressed_data_from_worker(&self, job_data_id: QPWorkerJobDataID, data: &[u8]) -> anyhow::Result<()>;
    async fn increment_submitted_jobs_counter(&self, wip_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<u64>;
}


// The trait defining the functions needed by the edge api servers to use STORE_DB_REALM_EDGE_CACHE
#[async_trait]
pub trait QPRealmEdgeCacheDatabaseClient {
    /// marks that a user has submitted data for a given unique checkpoint id, with a random number, also is used for registration
    async fn put_user_submission_marker(&self, user_at_checkpoint_id: &RealmEdgeUserAtUniqueCheckpointKey, random_number: u64) -> anyhow::Result<()>;
    // if this number is 0, it means the user has not submitted data for this checkpoint yet
    async fn get_user_submission_marker(&self, user_at_checkpoint_id: &RealmEdgeUserAtUniqueCheckpointKey) -> anyhow::Result<u64>;
    //
    async fn put_raw_user_data_for_job_id(&self, job_data_id: QPWorkerJobDataID, data: &[u8]) -> anyhow::Result<()>;
    async fn get_raw_user_data_for_job_id(&self, job_data_id: QPWorkerJobDataID) -> anyhow::Result<Vec<u8>>;
}
// the trait defining the functions needed by the edge api servers to read from STORE_DB_REALM_CORE
#[async_trait]
pub trait QPRealmCoreDatabaseClientBase {
    /// The checkpoint for which realms are currently accepting user data submissions, aka the next checkpoint for the processor to process, will often be after the  work in progress checkpoint, but will have the same checkpoint id while we are waiting for the coordinator to process and finalize the block (after the realm processor submits our changes to the coordinator and before the realm processor starts working on the next checkpoint)
    async fn get_current_unique_checkpoint_id(&self) -> anyhow::Result<UniqueCheckpointId>;
    
    /// this checkpoint id will be before the checkpoint in get_current_unique_checkpoint_id, as the UniqueCheckpointId is incremented when a new checkpoint is started, this is the current checkpoint being worked on by the realm processor
    async fn get_work_in_progress_checkpoint_id(&self) -> anyhow::Result<UniqueCheckpointId>;

    /// this checkpoint id will be before the checkpoint in get_current_unique_checkpoint_id, as the UniqueCheckpointId is incremented when a new checkpoint is started, but the last finalized checkpoint id is the last checkpoint which was fully processed and finalized by both the realm AND the COORDINATOR
    async fn get_last_finalized_checkpoint_id(&self) -> anyhow::Result<u64>;
    
    /// the last finalized realm root hash, at checkpoint==get_last_finalized_checkpoint_id()
    async fn get_latest_realm_root_hash(&self) -> anyhow::Result<Hash256>;

    /// the last finalized realm root hash, at checkpoint==get_last_finalized_checkpoint_id()
    async fn get_realm_root_hash_at_checkpoint(&self, max_checkpoint_id: u64) -> anyhow::Result<Hash256>;


    /// Gets the latest user data record for a user
    async fn get_latest_user_data_record(&self, user_id: u64) -> anyhow::Result<QPUserDataRecord>;
    /// Gets a merkle proof linking the user leaf hash to the REALM ROOT (not the full checkpoint tree root), returns an empty proof if the user does not exist, for the latest FINALIZED checkpoint
    async fn get_latest_user_merkle_proof_in_realm(&self, user_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;



    async fn get_latest_global_state(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_global_state_for_checkpoint(&self, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;



}

// the trait defining the functions needed by the edge api servers to read from STORE_DB_REALM_CORE
#[async_trait]
pub trait QPRealmEdgeRealmCoreDatabaseClient: QPRealmCoreDatabaseClientBase {
    // total number of worker jobs that need to be completed before the work in progress checkpoint can be sent off to the coordinator by the realm processor, might be useful for notifying the processor, or we can just have the processor poll the counter in STORE_DB_TEMP_SUBMITTED_COMPRESSED_USER_DATA
    async fn get_total_realm_worker_jobs(&self, checkpoint_id: u64) -> anyhow::Result<u64>;

    /// the merkle proof linking the last finalized realm root to the global user tree root, at checkpoint==get_last_finalized_checkpoint_id()
    /// note: this is fetched by the realm processor from the coordinator after the coordinator finalizes the block and the realm finishes waiting for the coordinator
    async fn get_realm_root_to_global_user_tree_merkle_proof(&self, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    async fn get_latest_realm_root_to_global_user_tree_merkle_proof(&self) -> anyhow::Result<MerkleProofCore<Hash256>>;
    

    /// sets the current realm root to global user tree merkle proof
    async fn set_realm_root_to_global_user_tree_merkle_proof(&self, finalized_checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash256>) -> anyhow::Result<()>;


    async fn user_exists(&self, user_id: u64) -> anyhow::Result<bool>;
    /*
    See: A checkpointed data store of users, key: user_id, value: QPUserDataRecord (which contains the user's public key, last submitted checkpoint id and data hash), supports historical queries with max_checkpoint_id 
    * {[user_id: u64] => QPUserDataRecord} , supports historical queries with max_checkpoint_id
     */
    /// Gets the user data record for a user as it was at a specific checkpoint or earlier
    async fn get_finalized_user_data_record(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<QPUserDataRecord>;
    
    /*
    See: A checkpointed store of each user's data in gzipped form, key: user_id, value: Vec<u8>, supports historical queries with max_checkpoint_id 
    * {[user_id: u64] => Vec<u8>}, supports historical queries with max_checkpoint_id
    */
    /// Get the gzip compressed user data for a specific user, at a checkpoin at or earlier than max_checkpoint_id
    /// if the user does not exist, return an empty vec
    async fn get_compressed_user_data(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Vec<u8>>;
    /// Gets the latest gzip compressed user data for a specific user
    /// if the user does not exist, return an empty vec
    async fn get_latest_compressed_user_data(&self, user_id: u64) -> anyhow::Result<Vec<u8>>;

    /*
    See: A checkpointed merkle tree whose leaves are the user leaf hashes within the realm (has a height of QP_REALM_GUSER_TREE_HEIGHT)
    * {[level: u8, index: u64] => Hash256}, supports historical queries with max_checkpoint_id
    
    */
    /// Gets a merkle proof linking the user leaf hash to the REALM ROOT (not the full checkpoint tree root), returns an empty proof if the user does not exist, for a checkpoint no later than max_checkpoint_id
    async fn get_user_merkle_proof_in_realm(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;






}



// the trait defining the functions needed by the edge api servers to read from STORE_DB_REALM_CORE
#[async_trait]
pub trait QPRealmProcessorRealmCoreDatabaseClient: QPRealmCoreDatabaseClientBase {
    
    // atomically applies the entire realm checkpoint delta to the realm core store and applies the coordinator state to the realm core store. Uses the checkpoint id in the QPCoordinatorGlobalCheckpointState.checkpoint_id to set the checkpoint_ids for the various deltas for the realm
    async fn apply_realm_checkpoint_delta(&self, coordinator_state: &QPCoordinatorGlobalCheckpointStateForRealm, delta: &QPRealmProcessorPendingCheckpointStateDelta) -> anyhow::Result<()>;
    // used to fast forward the realm core store when no user data has been submitted in a checkpoint, just applies the coordinator state
    async fn apply_only_checkpoint_data_from_coordinator(&self, coordinator_state: &QPCoordinatorGlobalCheckpointStateForRealm) -> anyhow::Result<()>;

    async fn set_total_realm_worker_jobs(&self, checkpoint_id: u64, total_jobs: u64) -> anyhow::Result<()>;

    /// The checkpoint for which realms are currently accepting user data submissions, aka the next checkpoint for the processor to process, will often be after the  work in progress checkpoint, but will have the same checkpoint id while we are waiting for the coordinator to process and finalize the block (after the realm processor submits our changes to the coordinator and before the realm processor starts working on the next checkpoint)
    async fn set_current_unique_checkpoint_id(&self, unique_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<()>;
    
    /// this checkpoint id will be before the checkpoint in get_current_unique_checkpoint_id, as the UniqueCheckpointId is incremented when a new checkpoint is started, this is the current checkpoint being worked on by the realm processor
    async fn set_work_in_progress_checkpoint_id(&self, work_in_progress_checkpoint_id: UniqueCheckpointId) -> anyhow::Result<()>;


}


#[async_trait]
pub trait QPRealmUpdateQueueClientForRealmEdge {
    /// sends a message to the realm processor to register a new user, checkpoint_queue_id defines a unique queue for the current checkpoint
    async fn enqueue_register_user_message_for_processor(&self, checkpoint_queue_id: UniqueCheckpointId, message: &RealmEdgeRegisterUserMessageForProcessor) -> anyhow::Result<()>;
    /// sends a message to the realm processor that new user data has been submitted for processing, checkpoint_queue_id defines a unique queue for the current checkpoint
    async fn enqueue_update_user_data_message_for_processor(&self, checkpoint_queue_id: UniqueCheckpointId, message: &RealmEdgeUpdateUserDataMessageForProcessor) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QPRealmUpdateQueueClientForRealmProcessor {
    async fn dump_register_user_messages(&self, checkpoint_queue_id: UniqueCheckpointId) -> anyhow::Result<Vec<RealmEdgeRegisterUserMessageForProcessor>>;
    async fn dump_new_user_data_submitted_messages(&self, checkpoint_queue_id: UniqueCheckpointId) -> anyhow::Result<Vec<RealmEdgeUpdateUserDataMessageForProcessor>>;
}


// The trait defining the functions needed by the realm processor to read from the compresssed data from the workers STORE_DB_TEMP_SUBMITTED_COMPRESSED_USER_DATA
#[async_trait]
pub trait QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmProcessorClient {
    async fn get_compressed_data_from_worker(&self, job_data_id: QPWorkerJobDataID) -> anyhow::Result<Vec<u8>>;
}



// The trait defining the functions needed by the realm processor to read from the compresssed data from the workers STORE_DB_TEMP_SUBMITTED_COMPRESSED_USER_DATA
#[async_trait]
pub trait QPRealmProcessorToCoordinatorClient {
    async fn get_merkle_proof_in_coordinator_tree(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    /// Gets the latest merkle proof for the realm in the coordinator tree, 
    async fn get_latest_merkle_proof_in_coordinator_tree(&self, realm_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>>;
    
    /// Gets the latest merkle proof for threalm in the coordinator tree and the submission metadata for the last submitted checkpoint id for the realm
    async fn get_latest_coordinator_state_for_realm(&self, realm_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm>;
    async fn get_coordinator_state_for_realm_at_checkpoint(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm>;

    async fn get_latest_coordinator_checkpoint_state(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_coordinator_checkpoint_state_for_checkpoint(&self, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
    async fn get_coordinator_checkpoint_for_realm_root(&self, realm_id: u64, realm_root: Hash256) -> anyhow::Result<Option<u64>>;


    async fn submit_realm_update(&self, realm_id: u64, old_realm_root: Hash256, new_realm_root: Hash256) -> anyhow::Result<()>;

    // waits until the coordinator finalizes the next checkpoint, and returns the new global checkpoint state
    async fn wait_until_next_finalized_checkpoint(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState>;
}


#[async_trait]
pub trait QPRealmProcessorPendingDeltasBackupDatabase {
    async fn insert_pending_checkpoint_delta(&self, delta: &QPRealmProcessorPendingCheckpointStateDelta) -> anyhow::Result<()>;
    async fn get_pending_checkpoint_delta_for_realm_root(&self, realm_root: &Hash256) -> anyhow::Result<Option<QPRealmProcessorPendingCheckpointStateDelta>>;
}