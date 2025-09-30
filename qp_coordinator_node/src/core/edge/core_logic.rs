use std::sync::Arc;
use qp_core::common::data::coordinator::core::QPCoordinatorRealmUpdateMessage;
use qp_core::common::data::core::hash::hash256::Hash256;
use qp_core::common::data::protocol::core::{QPCoordinatorGlobalCheckpointState, QPCoordinatorGlobalCheckpointStateForRealm, QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest, QPEdgeWorkerSubmitJobResponse};
use qp_core::common::data::core::merkle::merkle_proof::MerkleProofCore;
use qp_core::common::job_manager::{QPJobManagerEdge, QPRequestJobFailedReason};
use qp_core::common::traits::coordinator::{QPCoordinatorEdgeStateReaderBase, QPCoordinatorEdgeTempStateStore, QPCoordinatorJobDataTempStateStoreEdge, QPCoordinatorUpdateQueueClientForCoordinatorEdge};
use qp_core::common::traits::serializable::QPDSerializable;

pub const BUILD_MINI_TREE_JOB_MAX_TIMEOUT_MS: u64 = 15000; // 15 seconds


pub struct QPCoordinatorEdgeNodeLogic<
    SharedJobDataTempStateStore: QPCoordinatorJobDataTempStateStoreEdge,
    EdgeTempStateStore: QPCoordinatorEdgeTempStateStore,
    CoreDB: QPCoordinatorEdgeStateReaderBase,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorEdge,
    JobManager: QPJobManagerEdge,

>{
    pub shared_job_data_db: Arc<SharedJobDataTempStateStore>,
    pub tss_db: Arc<EdgeTempStateStore>,
    pub core_db: Arc<CoreDB>,
    pub update_queue: Arc<UpdateQueue>,
    pub job_manager: Arc<JobManager>,
}

impl<
    SharedJobDataTempStateStore: QPCoordinatorJobDataTempStateStoreEdge,
    EdgeTempStateStore: QPCoordinatorEdgeTempStateStore,
    CoreDB: QPCoordinatorEdgeStateReaderBase,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorEdge,
    JobManager: QPJobManagerEdge,
> QPCoordinatorEdgeNodeLogic<SharedJobDataTempStateStore, EdgeTempStateStore, CoreDB, UpdateQueue, JobManager>{
    pub fn new(
        shared_job_data_db: Arc<SharedJobDataTempStateStore>,
        tss_db: Arc<EdgeTempStateStore>,
        core_db: Arc<CoreDB>,
        update_queue: Arc<UpdateQueue>,
        job_manager: Arc<JobManager>,
    ) -> Self {
        Self {
            shared_job_data_db,
            tss_db,
            core_db,
            update_queue,
            job_manager,
        }
    }
}

impl<
    SharedJobDataTempStateStore: QPCoordinatorJobDataTempStateStoreEdge,
    EdgeTempStateStore: QPCoordinatorEdgeTempStateStore,
    CoreDB: QPCoordinatorEdgeStateReaderBase,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorEdge,
    JobManager: QPJobManagerEdge,
> QPCoordinatorEdgeNodeLogic<SharedJobDataTempStateStore, EdgeTempStateStore, CoreDB, UpdateQueue, JobManager>{



    pub async fn get_merkle_proof_in_coordinator_tree(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>> {
        self.core_db.get_merkle_proof_in_coordinator_tree(realm_id, max_checkpoint_id).await
    }
    /// Gets the latest merkle proof for the realm in the coordinator tree, 
    pub async fn get_latest_merkle_proof_in_coordinator_tree(&self, realm_id: u64) -> anyhow::Result<MerkleProofCore<Hash256>> {
        self.core_db.get_latest_merkle_proof_in_coordinator_tree(realm_id).await
    }
    
    /// Gets the latest merkle proof for threalm in the coordinator tree and the submission metadata for the last submitted checkpoint id for the realm
    pub async fn get_latest_coordinator_state_for_realm(&self, realm_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm> {
        
        let mut checkpoint_state = self.core_db.get_latest_global_checkpoint_state().await?;

        let realm_last_submission = self.core_db.get_last_realm_submitted_checkpoint_id(realm_id).await?;
        

        // race condition
        if checkpoint_state.checkpoint_id < realm_last_submission {
            checkpoint_state = self.core_db.get_global_checkpoint_state_at_checkpoint_id(realm_last_submission).await?;
        }

        let merkle_proof = self.core_db.get_merkle_proof_in_coordinator_tree(realm_id, checkpoint_state.checkpoint_id).await?;

        let latest_coordinator_state_for_realm = QPCoordinatorGlobalCheckpointStateForRealm{
            global_state: checkpoint_state,
            realm_id,
            last_submitted_checkpoint_id: realm_last_submission,
            merkle_proof,
        };

        Ok(latest_coordinator_state_for_realm)
    }
    pub async fn get_coordinator_state_for_realm_at_checkpoint(&self, realm_id: u64, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm> {
        let checkpoint_state = self.core_db.get_global_checkpoint_state_at_checkpoint_id(max_checkpoint_id).await?;
        let realm_last_submission = self.core_db.get_last_realm_submitted_checkpoint_id(realm_id).await?;
        if checkpoint_state.checkpoint_id < realm_last_submission {
            anyhow::bail!("the requested checkpoint id {} is less than the last submitted checkpoint id {} for the realm {}", max_checkpoint_id, realm_last_submission, realm_id);
        }
        let merkle_proof = self.core_db.get_merkle_proof_in_coordinator_tree(realm_id, checkpoint_state.checkpoint_id).await?;
        let coordinator_state_for_realm = QPCoordinatorGlobalCheckpointStateForRealm{
            global_state: checkpoint_state,
            realm_id,
            last_submitted_checkpoint_id: realm_last_submission,
            merkle_proof,
        };
        Ok(coordinator_state_for_realm)
    }

    pub async fn get_latest_coordinator_checkpoint_state(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState> {
        self.core_db.get_latest_global_checkpoint_state().await
    }
    pub async fn get_coordinator_checkpoint_state_for_checkpoint(&self, max_checkpoint_id: u64) -> anyhow::Result<QPCoordinatorGlobalCheckpointState> {
        self.core_db.get_global_checkpoint_state_at_checkpoint_id(max_checkpoint_id).await
    }
    pub async fn get_coordinator_checkpoint_for_realm_root(&self, realm_id: u64, realm_root: Hash256) -> anyhow::Result<Option<u64>> {
        self.core_db.get_checkpoint_id_for_realm_root(realm_id, realm_root).await
    }
    pub async fn get_latest_combined_realm_mini_tree_root_for_checkpoint(&self) -> anyhow::Result<Hash256> {
        self.core_db.get_combined_realm_mini_tree_root_for_checkpoint(
            self.core_db.get_latest_global_checkpoint_state().await?.checkpoint_id
        ).await
    }

    pub async fn submit_realm_update(&self, realm_id: u64, old_realm_root: Hash256, new_realm_root: Hash256) -> anyhow::Result<()> {
        let last_realm_root = self.core_db.get_latest_merkle_proof_in_coordinator_tree(realm_id).await?.value;
        if last_realm_root != old_realm_root {
            anyhow::bail!("the old realm root does not match the latest realm root in the coordinator tree");
        }
        let unique_checkpoint_id = self.core_db.get_current_unique_checkpoint_id().await?;
        let has_submitted = self.tss_db.has_submitted_update_to_api_in_checkpoint(realm_id, unique_checkpoint_id).await?;
        if has_submitted != 0 {
            anyhow::bail!("the realm {} has already submitted an update for the current checkpoint {}", realm_id, unique_checkpoint_id.checkpoint_id);
        }
        let rand_val = rand::random::<u64>();
        self.tss_db.set_submitted_update_to_api_in_checkpoint(realm_id, unique_checkpoint_id, rand_val).await?;
        // check for race condition?
        if self.tss_db.has_submitted_update_to_api_in_checkpoint(realm_id, unique_checkpoint_id).await? != rand_val {
            anyhow::bail!("the realm {} submission errored due to a mismatch in the submitted random value", realm_id);
        }
        let update = QPCoordinatorRealmUpdateMessage {
            realm_id,
            new_realm_root,
        };
        self.update_queue.enqueue_realm_update_message_for_processor(unique_checkpoint_id, update).await?;
        Ok(())
    }


    pub async fn request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse>{
        let job_response = self.job_manager.request_job_id_for_worker_id(worker_id, BUILD_MINI_TREE_JOB_MAX_TIMEOUT_MS).await?;
        let wip_checkpoint_id = self.core_db.get_work_in_progress_checkpoint_id().await?;
        if job_response.failed_reason != QPRequestJobFailedReason::Success {
            //anyhow::bail!("failed to get job for worker id {}, reason: {}", worker_id, job_response.failed_reason);
            tracing::error!("failed to get job for worker id {}, reason: {}", worker_id, job_response.failed_reason);
            Ok(QPEdgeWorkerJobResponse {
                job_response,
                wip_checkpoint_id,
                data: Vec::new(),
            })
        }else{
            let leaves = self.shared_job_data_db.get_mini_tree_leaves().await?;
            let data = bincode::serialize(&leaves)?;
            
            Ok(QPEdgeWorkerJobResponse {
                job_response,
                wip_checkpoint_id,
                data,
            })
        }

    }

    /// Reports the result of work performed by a worker node (the compressed user data).
    pub async fn submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse>{
        
        let current_wip_checkpoint_id = self.core_db.get_work_in_progress_checkpoint_id().await?;
        if current_wip_checkpoint_id != request.wip_checkpoint_id {
            //anyhow::bail!("the work in progress checkpoint id {} in the request does not match the current work in progress checkpoint id {}", request.wip_checkpoint_id, current_wip_checkpoint_id);
            return Ok(QPEdgeWorkerSubmitJobResponse {
                has_error: true,
                error_message: format!("the work in progress checkpoint id {} in the request does not match the current work in progress checkpoint id {}", request.wip_checkpoint_id, current_wip_checkpoint_id),
            });
        }
        if request.data.len() != 32 {
            //anyhow::bail!("compressed data size {} exceeds maximum allowed size of 10 MB", request.data.len());
            return Ok(QPEdgeWorkerSubmitJobResponse {
                has_error: true,
                error_message: format!("you must submit a 32 byte merkle root"),
            });
        }

        let root_hash = Hash256::from_bytes(&request.data)?;

        self.shared_job_data_db.set_mini_tree_root(root_hash, current_wip_checkpoint_id).await?;
        self.tss_db.increment_submitted_jobs_counter(current_wip_checkpoint_id).await?;
        self.job_manager.submit_job_result(request.worker_id, request.job_id.get_output_id()).await?;
        Ok(QPEdgeWorkerSubmitJobResponse { has_error: false, error_message: "ok".to_string() })
    }
}
