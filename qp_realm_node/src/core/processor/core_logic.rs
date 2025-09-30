use std::sync::Arc;

use qp_core::{common::{crypto::merkle::simple_delta_builder::SimpleMerkleDeltaBuilder, data::{core::{hash::hash256::Hash256, merkle::node::SimpleMerkleNodeKey}, protocol::core::{QPCoordinatorGlobalCheckpointStateForRealm, UniqueCheckpointId}, realm::processor::{QPRealmProcessorPendingCheckpointStateDelta, QPRealmProcessorPendingCompressedStateFromWorker}, user::QPUserDataRecord}, job_manager::QPJobManagerProcessor, traits::realm::{QPRealmProcessorPendingDeltasBackupDatabase, QPRealmProcessorRealmCoreDatabaseClient, QPRealmProcessorToCoordinatorClient, QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmProcessorClient, QPRealmUpdateQueueClientForRealmProcessor}}, crypto::hash::sha256::CoreSha256Hasher};

pub struct QPRealmProcessorNodeLogic<
    PendingDeltasDB: QPRealmProcessorPendingDeltasBackupDatabase,
    TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmProcessorClient,
    CoreDB: QPRealmProcessorRealmCoreDatabaseClient,
    UpdateQueue: QPRealmUpdateQueueClientForRealmProcessor,
    JobManager: QPJobManagerProcessor,
    CoordinatorClient: QPRealmProcessorToCoordinatorClient,


>{
    pub realm_id: u64,
    pub pending_deltas_db: Arc<PendingDeltasDB>,
    pub tsc_db: Arc<TSCDB>,
    pub core_db: Arc<CoreDB>,
    pub update_queue: Arc<UpdateQueue>,
    pub job_manager: Arc<JobManager>,
    pub coordinator_client: Arc<CoordinatorClient>,
}

impl<
    PendingDeltasDB: QPRealmProcessorPendingDeltasBackupDatabase,
    TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmProcessorClient,
    CoreDB: QPRealmProcessorRealmCoreDatabaseClient,
    UpdateQueue: QPRealmUpdateQueueClientForRealmProcessor,
    JobManager: QPJobManagerProcessor,
    CoordinatorClient: QPRealmProcessorToCoordinatorClient,
> QPRealmProcessorNodeLogic<PendingDeltasDB, TSCDB, CoreDB, UpdateQueue, JobManager, CoordinatorClient> {
    pub fn new(
        realm_id: u64,
        pending_deltas_db: Arc<PendingDeltasDB>,
        tsc_db: Arc<TSCDB>,
        core_db: Arc<CoreDB>,
        update_queue: Arc<UpdateQueue>,
        job_manager: Arc<JobManager>,
        coordinator_client: Arc<CoordinatorClient>,
    ) -> Self {
        Self {
            realm_id,
            pending_deltas_db,
            tsc_db,
            core_db,
            update_queue,
            job_manager,
            coordinator_client,
        }
    }
}

impl<
    PendingDeltasDB: QPRealmProcessorPendingDeltasBackupDatabase,
    TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmProcessorClient,
    CoreDB: QPRealmProcessorRealmCoreDatabaseClient,
    UpdateQueue: QPRealmUpdateQueueClientForRealmProcessor,
    JobManager: QPJobManagerProcessor,
    CoordinatorClient: QPRealmProcessorToCoordinatorClient,
> QPRealmProcessorNodeLogic<PendingDeltasDB, TSCDB, CoreDB, UpdateQueue, JobManager, CoordinatorClient> {
    async fn ensure_synced_inner(&self) -> anyhow::Result<(QPCoordinatorGlobalCheckpointStateForRealm, bool)> {
        let last_finalized_checkpoint_id = self.core_db.get_last_finalized_checkpoint_id().await?;
        let last_root = self.core_db.get_latest_realm_root_hash().await?;
        let coordinator_state_for_realm = self.coordinator_client.get_latest_coordinator_state_for_realm(self.realm_id).await?;

        if last_root != coordinator_state_for_realm.merkle_proof.value {
            anyhow::bail!("Realm root hash in core db does not match the last submitted realm root hash from the coordinator, resync chain needed");
        }

        let coordinator_checkpoint_id = coordinator_state_for_realm.global_state.checkpoint_id;

        if last_finalized_checkpoint_id < coordinator_checkpoint_id {
            for i in (last_finalized_checkpoint_id + 1)..=coordinator_checkpoint_id {
                let coordinator_state_for_realm = self.coordinator_client.get_coordinator_state_for_realm_at_checkpoint(self.realm_id, i).await?;
                self.core_db.apply_only_checkpoint_data_from_coordinator(&coordinator_state_for_realm).await?;
            }
        }
        let coordinator_state_for_realm = self.coordinator_client.get_latest_coordinator_state_for_realm(self.realm_id).await?;

        let last_finalized_checkpoint_id = self.core_db.get_last_finalized_checkpoint_id().await?;

        let is_finished_syncing = coordinator_state_for_realm.global_state.checkpoint_id == last_finalized_checkpoint_id;
        Ok((coordinator_state_for_realm, is_finished_syncing))
    }
    pub async fn ensure_synced(&self) -> anyhow::Result<QPCoordinatorGlobalCheckpointStateForRealm>{
        let (mut coordinator_state_for_realm, mut is_finished_syncing) = self.ensure_synced_inner().await?;
        while !is_finished_syncing {
            (coordinator_state_for_realm, is_finished_syncing) = self.ensure_synced_inner().await?;
        }
        Ok(coordinator_state_for_realm)
    }
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
        let last_local_finalized_checkpoint_id = self.core_db.get_last_finalized_checkpoint_id().await?;
        let last_local_realm_root = self.core_db.get_realm_root_hash_at_checkpoint(last_local_finalized_checkpoint_id).await?;


        //let last_coordinator_state = self.coordinator_client.get_latest_coordinator_checkpoint_state().await?;
        let last_realm_submission = self.coordinator_client.get_latest_coordinator_state_for_realm(self.realm_id).await?;

        // if the last finalized checkpoint on the coordinator is less than the last finalized checkpoint in the realm core db, resync chain needed as the database has been corrupted
        // it should be IMPOSSIBLE for the coordinator to have a last finalized checkpoint id that is less than the last finalized checkpoint id in the realm core db, as we only apply deltas AFTER the coordinator has finalized them

        let coordinator_last_finalized_checkpoint_id = last_realm_submission.global_state.checkpoint_id;
        let last_realm_submission_checkpoint_id = last_realm_submission.last_submitted_checkpoint_id;

        if coordinator_last_finalized_checkpoint_id < last_local_finalized_checkpoint_id {
            anyhow::bail!("Realm's last finalized checkpoint id from coordinator is greater than the last finalized checkpoint id in the realm core db, resync chain needed");
        }else if coordinator_last_finalized_checkpoint_id > last_local_finalized_checkpoint_id {
            if last_local_realm_root != last_realm_submission.merkle_proof.value {
                // might be recoverable from here by applying deltas from the pending deltas db
                let delta = self.pending_deltas_db.get_pending_checkpoint_delta_for_realm_root(&last_realm_submission.merkle_proof.value).await?;
                if delta.is_none() {
                    anyhow::bail!("Realm's last finalized checkpoint id from coordinator is greater than the last finalized checkpoint id in the realm core db, and no pending delta found to recover from, resync chain needed");
                }
                let delta = delta.unwrap();
                for i in (last_local_finalized_checkpoint_id +1)..=coordinator_last_finalized_checkpoint_id { 
                    let coordinator_state = self.coordinator_client.get_coordinator_state_for_realm_at_checkpoint(self.realm_id, i).await?;
                    if i == last_realm_submission_checkpoint_id {
                        self.core_db.apply_realm_checkpoint_delta(&coordinator_state, &delta).await?;
                    }else{
                        self.core_db.apply_only_checkpoint_data_from_coordinator(&coordinator_state).await?;
                    }
                }
            }else{
                // no deltas to apply, just apply the checkpoint data from the coordinator
                self.ensure_synced().await?;
            }
        }

        // ensure we are synced up to the latest submitted checkpoint for the realm for good measure, incase blocks were created while we were syncing above
        self.ensure_synced().await?;





        Ok(())
    }
    pub async fn process_next_checkpoint(&self) -> anyhow::Result<()> {
        let last_realm_state_finalized = self.ensure_synced().await?;

        let old_unique_checkpoint_id = self.core_db.get_current_unique_checkpoint_id().await?;
        self.inc_checkpoint_id().await?;

        let old_realm_root_hash = self.core_db.get_latest_realm_root_hash().await?;


        let mut deltas = QPRealmProcessorPendingCheckpointStateDelta {
            realm_id: self.realm_id,
            old_realm_root_hash,
            new_realm_root_hash: old_realm_root_hash,
            user_data_deltas: Vec::new(),
            realm_user_tree_deltas: Vec::new(),
            compressed_user_data_from_workers: Vec::new(),
        };


        let dumped_register_users = self.update_queue.dump_register_user_messages(old_unique_checkpoint_id).await?;
        let dumped_user_updates = self.update_queue.dump_new_user_data_submitted_messages(old_unique_checkpoint_id).await?;
        let total_jobs = dumped_register_users.len() + dumped_user_updates.len();
        
        if total_jobs == 0 {
            // no work to do, just return
            self.ensure_synced().await?;
            return Ok(());
        }
        let mut job_ids = Vec::with_capacity(total_jobs);



        // this is not guarenteed to be the checkpoint id that the realm updates are included at, but it does guarentee that the checkpoint id will be at least this value, which is what we care about for moving forward in time (no replays)
        let wip_checkpoint_id = last_realm_state_finalized.global_state.checkpoint_id+1;
        let random_uuid_value = rand::random::<u64>();
        self.core_db.set_work_in_progress_checkpoint_id(UniqueCheckpointId{checkpoint_id: wip_checkpoint_id, uuid: random_uuid_value}).await?;







        for register_user in dumped_register_users.iter() {
            job_ids.push(register_user.job_id.get_output_id());
        }
        for user_update in dumped_user_updates.iter() {
            job_ids.push(user_update.job_id.get_output_id());
        }
        self.core_db.set_total_realm_worker_jobs(wip_checkpoint_id, total_jobs as u64).await?;
        self.job_manager.enqueue_new_jobs(&job_ids).await?;
        self.job_manager.wait_for_all_jobs_to_be_completed().await?;
        let mut delta_builder = SimpleMerkleDeltaBuilder::<Hash256, CoreSha256Hasher>::new();

        for register_user in dumped_register_users.iter() {
            let compressed_data = self.tsc_db.get_compressed_data_from_worker(register_user.job_id.get_output_id()).await?;
            if compressed_data.len() == 0  {
                // this should never happen as the edge apis prevent this
                anyhow::bail!("No compressed data found for job id {}", register_user.job_id);
            }
            let data_hash = CoreSha256Hasher::hash_bytes(&compressed_data);
            
            deltas.compressed_user_data_from_workers.push(
                QPRealmProcessorPendingCompressedStateFromWorker {
                    user_id: register_user.user_id,
                    compressed_data,
                }
            );
            let user_id = register_user.user_id;
            let user_data_record = QPUserDataRecord::new(user_id, data_hash, register_user.public_key, wip_checkpoint_id);
            let user_leaf_hash = user_data_record.get_user_leaf_hash();
            deltas.user_data_deltas.push(user_data_record);

            let old_merkle_proof = self.core_db.get_latest_user_merkle_proof_in_realm(user_id).await?;
            if !old_merkle_proof.value.is_zero() {
                // this should never happen as the edge apis prevent this
                anyhow::bail!("User ID {} already exists in the current realm user tree", user_id);
            }
            delta_builder.add_leaf_with_stored_node_or_merkle_proof(&old_merkle_proof, user_leaf_hash);
        }


        for update_user in dumped_user_updates.iter() {
            let compressed_data = self.tsc_db.get_compressed_data_from_worker(update_user.job_id.get_output_id()).await?;
            if compressed_data.len() == 0  {
                // this should never happen as the edge apis prevent this
                anyhow::bail!("No compressed data found for job id {}", update_user.job_id);
            }
            let data_hash = CoreSha256Hasher::hash_bytes(&compressed_data);
            
            deltas.compressed_user_data_from_workers.push(
                QPRealmProcessorPendingCompressedStateFromWorker {
                    user_id: update_user.user_id,
                    compressed_data,
                }
            );
            let user_id = update_user.user_id;

            let user_data_record = QPUserDataRecord::new(user_id, data_hash, update_user.public_key, wip_checkpoint_id);
            let user_leaf_hash = user_data_record.get_user_leaf_hash();
            deltas.user_data_deltas.push(user_data_record);

            let old_merkle_proof = self.core_db.get_latest_user_merkle_proof_in_realm(user_id).await?;
            if old_merkle_proof.value.is_zero() {
                // this should never happen as the edge apis prevent this
                anyhow::bail!("User ID {} doesn't exist in the current realm user tree", user_id);
            }
            delta_builder.add_leaf_with_stored_node_or_merkle_proof(&old_merkle_proof, user_leaf_hash);
        }

        let new_realm_root_hash = delta_builder.get_node_value(&SimpleMerkleNodeKey::new_root()).unwrap().to_owned();

        deltas.new_realm_root_hash = new_realm_root_hash;
        deltas.realm_user_tree_deltas = delta_builder.finalize();


        // ensure the state delta is backed up locally, so even if our node crashes after we submit to the coordinator, we can recover the state delta and not put the node in an irrecoverable state
        self.pending_deltas_db.insert_pending_checkpoint_delta(&deltas).await?;

        // now that the state delta is fully backed up locally, we send our update to the coordinator
        self.coordinator_client.submit_realm_update(self.realm_id, old_realm_root_hash, new_realm_root_hash).await?;

        // now that the update has been submitted to the coordinator, we wait for the coordinator to finalize the next checkpoint
        self.coordinator_client.wait_until_next_finalized_checkpoint().await?;


        let last_finalized_checkpoint_id = self.core_db.get_last_finalized_checkpoint_id().await?;
        // now check if the coordinator included our update in the finalized checkpoint
        let mut latest_coordinator_state_for_realm = self.coordinator_client.get_latest_coordinator_state_for_realm(self.realm_id).await?;

        // if the coordinator was building the block when we submitted, it is possible that we need to wait for another block to get included
        if latest_coordinator_state_for_realm.merkle_proof.value != new_realm_root_hash {
            self.coordinator_client.wait_until_next_finalized_checkpoint().await?;
            latest_coordinator_state_for_realm = self.coordinator_client.get_latest_coordinator_state_for_realm(self.realm_id).await?;
        }
        
        // did we get included?
        if latest_coordinator_state_for_realm.merkle_proof.value == new_realm_root_hash {
            for i in (last_finalized_checkpoint_id + 1)..=latest_coordinator_state_for_realm.global_state.checkpoint_id {
                if i == latest_coordinator_state_for_realm.global_state.checkpoint_id {
                    // save a network request
                    if latest_coordinator_state_for_realm.last_submitted_checkpoint_id == i {
                        self.core_db.apply_realm_checkpoint_delta(&latest_coordinator_state_for_realm, &deltas).await?;
                    }else{
                        self.core_db.apply_only_checkpoint_data_from_coordinator(&latest_coordinator_state_for_realm).await?;
                    }
                }else{
                    let state_for_realm = self.coordinator_client.get_coordinator_state_for_realm_at_checkpoint(self.realm_id, i).await?;
                    if latest_coordinator_state_for_realm.last_submitted_checkpoint_id == i {
                        self.core_db.apply_realm_checkpoint_delta(&state_for_realm, &deltas).await?;
                    }else{
                        self.core_db.apply_only_checkpoint_data_from_coordinator(&state_for_realm).await?;
                    }
                }
            }
            // we are done with the deltas now, we can remove them from the pending deltas db
            // for now just keep them for historical purposes
            // self.pending_deltas_db.remove_pending_checkpoint_delta(&deltas.old_realm_root_hash).await?;
            

        }else{
            // we waited two blocks, we are not getting included, abandon the deltas and move on (users need to resubmit, but our node is not in an irrecoverable state)
            self.ensure_synced().await?;

        }

        






        Ok(())
    }
}
