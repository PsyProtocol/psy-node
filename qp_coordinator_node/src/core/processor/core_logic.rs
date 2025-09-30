use std::{sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use qp_core::{common::{crypto::merkle::simple_delta_builder::SimpleMerkleDeltaBuilder, data::{coordinator::core::{QPCoordinatorProcessorPendingCheckpointStateDelta, QPCoordinatorRealmMetadata}, core::{hash::hash256::Hash256, merkle::node::SimpleMerkleNodeKey}, protocol::{core::{QPCoordinatorGlobalCheckpointState, UniqueCheckpointId}, job::QPWorkerJobDataID}}, job_manager::QPJobManagerProcessor, traits::coordinator::{QPCoordinatorJobDataTempStateStoreProcessor, QPCoordinatorProcessorBlockCompletionNotifier, QPCoordinatorProcessorStateStore, QPCoordinatorUpdateQueueClientForCoordinatorProcessor}}, constants::protocol_constants::QP_COORDINATOR_BLOCK_TIME_MS, crypto::hash::sha256::CoreSha256Hasher};
use tokio::time::sleep;

pub struct QPCoordinatorProcessorNodeLogic<
    JobDataTempStore: QPCoordinatorJobDataTempStateStoreProcessor,
    CoreDB: QPCoordinatorProcessorStateStore,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorProcessor,
    JobManager: QPJobManagerProcessor,
    Notifier: QPCoordinatorProcessorBlockCompletionNotifier,


>{
    pub job_data_temp_store: Arc<JobDataTempStore>,
    pub core_db: Arc<CoreDB>,
    pub update_queue: Arc<UpdateQueue>,
    pub job_manager: Arc<JobManager>,
    pub notifier: Arc<Notifier>,
}

fn get_timestamp_in_milliseconds() -> u64 {
    let current_system_time = SystemTime::now();
    let duration_since_epoch = current_system_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards"); // Handle potential errors if the system clock goes backward
    let milliseconds_timestamp = duration_since_epoch.as_millis();
    milliseconds_timestamp as u64
}

impl<
    JobDataTempStore: QPCoordinatorJobDataTempStateStoreProcessor,
    CoreDB: QPCoordinatorProcessorStateStore,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorProcessor,
    JobManager: QPJobManagerProcessor,
    Notifier: QPCoordinatorProcessorBlockCompletionNotifier,
> QPCoordinatorProcessorNodeLogic<JobDataTempStore, CoreDB, UpdateQueue, JobManager, Notifier> {
    pub fn new(
        job_data_temp_store: Arc<JobDataTempStore>,
        core_db: Arc<CoreDB>,
        update_queue: Arc<UpdateQueue>,
        job_manager: Arc<JobManager>,
        notifier: Arc<Notifier>,
    ) -> Self {
        Self {
            job_data_temp_store,
            core_db,
            update_queue,
            job_manager,
            notifier,
        }
    }
}

impl<
    JobDataTempStore: QPCoordinatorJobDataTempStateStoreProcessor,
    CoreDB: QPCoordinatorProcessorStateStore,
    UpdateQueue: QPCoordinatorUpdateQueueClientForCoordinatorProcessor,
    JobManager: QPJobManagerProcessor,
    Notifier: QPCoordinatorProcessorBlockCompletionNotifier,
> QPCoordinatorProcessorNodeLogic<JobDataTempStore, CoreDB, UpdateQueue, JobManager, Notifier> {
    
    pub async fn inc_checkpoint_id(&self) -> anyhow::Result<UniqueCheckpointId> {
        let last_finalized_checkpoint_id = self.core_db.get_last_finalized_checkpoint_id().await?;
        let random_uuid_value = rand::random::<u64>();
        let unique_checkpoint_id = UniqueCheckpointId { checkpoint_id: last_finalized_checkpoint_id + 2, uuid: random_uuid_value };
        self.core_db.set_current_unique_checkpoint_id(unique_checkpoint_id).await?;
        let random_uuid_value = rand::random::<u64>();
        self.core_db.set_work_in_progress_checkpoint_id(UniqueCheckpointId{checkpoint_id: last_finalized_checkpoint_id + 1, uuid: random_uuid_value}).await?;
        Ok(unique_checkpoint_id)
    }
    pub async fn initialize(&self) -> anyhow::Result<()> {





        Ok(())
    }
    pub async fn ensure_synced(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointState> {
        let latest_coordinator_state = self.core_db.get_latest_global_checkpoint_state().await?;
        Ok(latest_coordinator_state)
    }
    pub async fn process_next_checkpoint(&self) -> anyhow::Result<()> {
        let last_coordinator_state_finalized = self.ensure_synced().await?;

        let old_unique_checkpoint_id = self.core_db.get_current_unique_checkpoint_id().await?;
        self.inc_checkpoint_id().await?;
        let new_checkpoint_id = last_coordinator_state_finalized.checkpoint_id + 1;



        let mut deltas = QPCoordinatorProcessorPendingCheckpointStateDelta {
            realm_metadata_updates: vec![],
            global_user_tree_deltas: vec![],
            realm_submission_mini_tree_root: Hash256::ZERO,
            checkpoint_state: last_coordinator_state_finalized,
        };
        deltas.checkpoint_state.checkpoint_id = new_checkpoint_id;
        deltas.checkpoint_state.time_since_epoch_ms = get_timestamp_in_milliseconds();




        let mut dumped_update_realms = self.update_queue.dump_realm_update_messaages(old_unique_checkpoint_id).await?;
        
        let total_jobs = 1;
        
        if total_jobs == 0 {
            // no work to do, just return
            self.ensure_synced().await?;
            return Ok(());
        }
        let mut job_ids = Vec::with_capacity(total_jobs as usize);



        // this is not guarenteed to be the checkpoint id that the realm updates are included at, but it does guarentee that the checkpoint id will be at least this value, which is what we care about for moving forward in time (no replays)
        let wip_checkpoint_id = new_checkpoint_id;
        let wip_unique_checkpoint_id = UniqueCheckpointId{checkpoint_id: wip_checkpoint_id, uuid: rand::random::<u64>()};


        self.core_db.set_work_in_progress_checkpoint_id(wip_unique_checkpoint_id).await?;


        dumped_update_realms.sort_by(|x,y| x.realm_id.cmp(&y.realm_id));
        let leaves = dumped_update_realms.iter().map(|x| x.new_realm_root).collect::<Vec<_>>();

        self.job_data_temp_store.set_mini_tree_leaves(&leaves).await?;
        job_ids.push(QPWorkerJobDataID::compute_combined_realm_root_update_merkle_root(new_checkpoint_id, 0, 0, 0));




        self.core_db.set_total_coordinator_worker_jobs(wip_unique_checkpoint_id, total_jobs as u64).await?;
        self.job_manager.enqueue_new_jobs(&job_ids).await?;
        let mut delta_builder = SimpleMerkleDeltaBuilder::<Hash256, CoreSha256Hasher>::new();

        for update_realm in dumped_update_realms.iter() {
            
            deltas.realm_metadata_updates.push(
                QPCoordinatorRealmMetadata {
                    realm_id: update_realm.realm_id,
                    last_submitted_checkpoint_id: wip_checkpoint_id,
                    new_realm_root: update_realm.new_realm_root,
                }
            );
            let realm_id = update_realm.realm_id;

            let old_merkle_proof = self.core_db.get_latest_merkle_proof_in_coordinator_tree(realm_id).await?;
            
            delta_builder.add_leaf_with_stored_node_or_merkle_proof(&old_merkle_proof, update_realm.new_realm_root);
        }


        let new_coordinator_root_hash = delta_builder.get_node_value(&SimpleMerkleNodeKey::new_root()).unwrap().to_owned();

        deltas.checkpoint_state.global_user_tree_root = new_coordinator_root_hash;
        deltas.global_user_tree_deltas = delta_builder.finalize();



        self.job_manager.wait_for_all_jobs_to_be_completed().await?;
        let new_mini_hash = self.job_data_temp_store.get_mini_tree_root(wip_unique_checkpoint_id).await?;
        deltas.realm_submission_mini_tree_root = new_mini_hash;
        self.core_db.apply_processor_checkpoint_delta(&deltas).await?;

        let latest = self.core_db.get_latest_global_checkpoint_state().await?;


        self.notifier.notify_block_completed(&latest).await?;


        sleep(Duration::from_millis(QP_COORDINATOR_BLOCK_TIME_MS)).await;







        Ok(())
    }
}
