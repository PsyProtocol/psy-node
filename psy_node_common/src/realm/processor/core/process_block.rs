use cf_utils::timer::TraceTimer;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    worker::
        metadata_with_job_id::PsyProvingJobMetadataWithJobId
    ,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::
    realm::{
        processor::{core::PsyRealmProcessor, gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput},
        queue_key::RealmProvingWorkQueueKey,
    }
;
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    FileSystem::File: Send + Sync,
{
    pub async fn publish_all_worker_jobs(
        &self,
        queue_key: &RealmProvingWorkQueueKey<N::QHash, N::JobId>,
        jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<()> {
        for level in 0..jobs.len() {
            println!("Publishing {} jobs at level {}", jobs[level].len(), level);
            self.db
                .proof_work_queue
                .publish_many_worker_queue_items(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    self.db.state.processing_proc_checkpoint_unique_id,
                    0,
                    &jobs[level],
                )
                .await?;
            self.db
                .proof_work_queue
                .wait_until_all_jobs_complete_or_timeout_worker(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    self.db.state.processing_proc_checkpoint_unique_id,
                    0,
                    self.proof_worker_queue_max_time_ms,
                )
                .await?;
        }
        Ok(())
    }
    pub fn get_root_job_id(&self, guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>]) -> anyhow::Result<Option<N::JobId>> {
        let guta_root_job = guta_jobs.last().and_then(|jobs_at_level| jobs_at_level.first());
        if guta_root_job.is_none() {
            return Ok(None);
        } else {
            Ok(Some(guta_root_job.unwrap().job_id.clone()))
        }
    }

    pub async fn wait_for_jobs_completion(&self) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.state.realm_id_u64,
                self.db.state.realm_sub_id_u64,
                self.db.state.processing_proc_checkpoint_unique_id,
                0,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        Ok(())
    }

    pub async fn get_results_from_gatherers(&mut self) -> anyhow::Result<RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>> {
        if self.db.state.gathering_proc_checkpoint_unique_id == self.db.state.processing_proc_checkpoint_unique_id
            || self.db.state.gathering_unique_pending_id == self.db.state.processing_unique_pending_id
        {
            tracing::info!("detected gathering unique ids: gathering_proc_checkpoint_unique_id = {}, current proc_checkpoint_unique_id = {}, gathering_unique_pending_id = {}, current unique_pending_id = {}. Updating unique ids before gathering results.", self.db.state.gathering_proc_checkpoint_unique_id, self.db.state.processing_proc_checkpoint_unique_id, self.db.state.gathering_unique_pending_id, self.db.state.processing_unique_pending_id);
            if self.db.state.last_committed_checkpoint_id == 0 {
                tracing::info!("At genesis checkpoint, setting unique ids ahead of genesis.");
                self.db.set_new_unique_ids(None).await?;

                let _ = self
                    .guta_queue_gatherer
                    .finalize_gathering_and_update_queue_key(self.db.state.gathering_proc_checkpoint_unique_id)
                    .await?;
            } else {
                anyhow::bail!("Cannot gather results when unique ids have not been updated.");
            }
        }
        self.db.set_new_unique_ids(None).await?;
        if self.db.needs_revert {
            self.db.needs_revert = false;
        }
        let guta_result = self
            .guta_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.state.gathering_proc_checkpoint_unique_id)
            .await?;

        /*
        tracing::info!("Gathering results from GUTA, Register Users, and Deploy Contracts gatherers...");
        let guta_result = self.guta_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("GUTA gatherer results obtained.");
        let deploy_contract_result = self.deploy_contract_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Deploy Contracts gatherer results obtained.");
        let register_users_result = self.register_user_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Register Users gatherer results obtained.");
        */

        Ok(guta_result)
    }

    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        let mut timer = TraceTimer::new("process_block");
        tracing::info!(
            "Starting to process new coordinator block with checkpoint_id = {}...",
            self.db.state.processing_checkpoint_id
        );
        self.db.sync_with_coordinator().await?;
        timer.lap("sync_with_coordinator");
        let guta_output = self.get_results_from_gatherers().await?;
        let guta_jobs = guta_output.job_ids;
        let guta_update = guta_output.db_output;

        timer.lap("get_results_from_gatherers");
        let root_job_id = self.get_root_job_id(&guta_jobs)?;
        if root_job_id.is_none() {
            tracing::info!("No GUTA jobs to process in this block, skipping.");
            return Ok(());
        }
        let root_job_id = root_job_id.unwrap();
        timer.lap("get_root_job_ids");
        self.publish_all_worker_jobs(&self.db.get_proof_worker_queue_key(), &guta_jobs).await?;
        timer.lap("publish_all_worker_jobs and wait for completion");
        tracing::info!("GUTA jobs completed!");
        let root_job_proof = self.db.proof_store.get_proof_bytes_by_job_id(root_job_id).await?;
        if root_job_proof.is_none() {
            anyhow::bail!("No proof found for root GUTA job id: {:?}", root_job_id);
        }
        let root_job_proof = root_job_proof.unwrap();
        timer.lap("get_root_job_proof");
        let rewards_root = self
            .db
            .get_reward_tree_root(
                self.db.state.processing_checkpoint_id,
                self.db.state.processing_unique_pending_id,
                root_job_id,
            )
            .await?;
        let submission_header = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: guta_update.guta_header.header,
                new_tag_tree_node_value: rewards_root,
            },
            job_type_u32: root_job_id.circuit_type as u32,
        };
        timer.lap("get rewards root and build submission header");

        self.db
            .coordinator_client
            .rc_submit_guta_proof(submission_header, root_job_proof.clone(), self.db.state.realm_id_u64)
            .await?;

        timer.lap("submit_guta_proof to coordinator");
        let sync_info = self.db.wait_for_realm_update_sync_with_coordinator(guta_update.new_realm_root).await?;
        timer.lap("wait_for_realm_update_sync_with_coordinator");

        let db_output = PsyPreparedRealmBlockStateUpdates {
            unique_pending_id: self.db.state.processing_unique_pending_id,
            proc_checkpoint_unique_id: self.db.state.processing_proc_checkpoint_unique_id,

            realm_id: self.db.state.realm_id_u64,
            realm_sub_id: self.db.state.realm_sub_id_u64,
            old_realm_root: guta_update.old_realm_root,
            new_realm_root: guta_update.new_realm_root,
            update_user_contract_tree_nodes_ffs: guta_update.update_user_contract_tree_nodes_ffs,
            update_contract_state_tree_nodes_ffs: guta_update.update_contract_state_tree_nodes_ffs,
            update_user_leaves_ffs: guta_update.update_user_leaves_ffs,
            update_global_user_tree_nodes_ffs: guta_update.update_global_user_tree_nodes_ffs,
        };
        tracing::info!("GUTA Update sent and synced to coordinator!");
        self.db
            .commit_state(&sync_info, &db_output, root_job_id.circuit_type, root_job_proof)
            .await?;
        timer.lap("commit_state");
        tracing::info!(
            "Committed new coordinator block with checkpoint_id = {}.",
            self.db.state.processing_checkpoint_id
        );
        self.db.print_coordinator_processor_state();
        self.db.sync_to_coordinator_set_checkpoint_id().await?;
        timer.lap("sync_to_coordinator_set_checkpoint_id");

        Ok(())
    }
}
