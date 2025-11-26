use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::FromPrimitiveValuesFelt, node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::AggStateTransitionWithStats, guta::{self, header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, sub_tree_transition::SubTreeNodeStateTransition}, protocol::{circuit_inputs::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput, verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof}, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            contract::{DashMapContractHeightCache, PsyDeployContractQueueItem},
            public_key::PZKPublicKeyInfo,
        },
    }, worker::{metadata::{PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, PsyProvingJobMetadata}, metadata_with_job_id::PsyProvingJobMetadataWithJobId}
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorEdgeAPIStoreReader, PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::{StandardEdgeAPITempDBStoreBase, StandardProcessorTempDBStoreBase},
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    backup::coordinator::load_coordinator_memory_trees_from_db,
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    },
    coordinator::{
        processor::{
            data::CoordinatorProcessorInitData,
            db::PsyCoordinatorDatabaseProcessor,
            gatherers::{
                coordinator_guta_update_gatherer::{
                    CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig, CoordinatorGUTAUpdateGathererOutput,
                },
                deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig, DeployContractGathererOutput},
                register_user_gatherer::{RegisterUserGatherer, RegisterUserGathererConfig, RegisterUserGathererOutput},
            },
            PsyCoordinatorProcessor,
        },
        queue_key::CoordinatorProvingWorkQueueKey,
    },
    queue::gatherer::EphemeralQueueGathererWithTree,
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    >
{
    pub async fn publish_worker_jobs_if_exists(
        &self,
        queue_key: &CoordinatorProvingWorkQueueKey<N::QHash, N::JobId>,
        level: usize,
        jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<()> {
        if level < jobs.len() {
            self.db
                .proof_work_queue
                .publish_many_worker_queue_items(
                    queue_key,
                    self.db.realm_id_u64,
                    self.db.realm_sub_id_u64,
                    self.db.current_core_proc_unique_pending_id,
                    0,
                    &jobs[level],
                )
                .await?;
        }
        Ok(())
    }
    pub fn get_root_job_ids(
        &self,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<Option<(QProvingJobDataID, QProvingJobDataID, QProvingJobDataID)>> {


        let guta_root_job = guta_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found at last level"))?;
        let register_user_root_job = register_user_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found at last level"))?;
        let deploy_contract_root_job = deploy_contract_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found at last level"))?;

        if guta_root_job.job_id.circuit_type == ProvingJobCircuitType::GUTANoChange 
            && register_user_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
            && deploy_contract_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyBatchDeployContractsAggregate
        {
            tracing::info!("No changes detected in GUTA, Register User, and Deploy Contract jobs.");
            return Ok(None);
        }
        Ok(Some((
            guta_root_job.job_id,
            register_user_root_job.job_id,
            deploy_contract_root_job.job_id,
        )))
    }
    pub async fn publish_jobs(
        &self,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        min_level: Option<usize>,
        max_level: Option<usize>,
        wait_for_jobs_completion: bool,
    ) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        let max_level = guta_jobs.len().max(register_user_jobs.len()).max(deploy_contract_jobs.len()).min(max_level.unwrap_or(usize::MAX));
        let min_level = min_level.unwrap_or(0).min(max_level);

        for i in min_level..max_level {
            self.publish_worker_jobs_if_exists(&queue_key, i, guta_jobs).await?;
            self.publish_worker_jobs_if_exists(&queue_key, i, register_user_jobs).await?;
            self.publish_worker_jobs_if_exists(&queue_key, i, deploy_contract_jobs).await?;
            if wait_for_jobs_completion {
                self.db
                    .proof_work_queue
                    .wait_until_all_jobs_complete_or_timeout_worker(
                        &queue_key,
                        self.db.realm_id_u64,
                        self.db.realm_sub_id_u64,
                        self.db.current_core_proc_unique_pending_id,
                        0,
                        self.proof_worker_queue_max_time_ms,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn wait_for_jobs_completion(&self) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.realm_id_u64,
                self.db.realm_sub_id_u64,
                self.db.current_core_proc_unique_pending_id,
                0,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        Ok(())
    }
    pub async fn publish_and_wait_for_job_completion(&self, job: &PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        self.db
            .proof_work_queue
            .publish_worker_queue_item_ref(
                &queue_key,
                self.db.realm_id_u64,
                self.db.realm_sub_id_u64,
                self.db.current_core_proc_unique_pending_id,
                0,
                job,
            )
            .await?;
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.realm_id_u64,
                self.db.realm_sub_id_u64,
                self.db.current_core_proc_unique_pending_id,
                0,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        Ok(())
    }


    pub async fn get_results_from_gatherers(
        &mut self,
    ) -> anyhow::Result<(
        CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        RegisterUserGathererOutput<N::QHash, N::JobId>,
        DeployContractGathererOutput<N::QHash, N::JobId>,
    )> {
        self.db.set_new_unique_ids().await?;
        self.db.shared_status.update_status(
            self.db.gathering_unique_pending_id,
            self.db.last_committed_checkpoint_id,
            self.db.last_committed_checkpoint_leaf.clone(),
            self.db.last_committed_checkpoint_state_roots.clone(),
            self.db.last_committed_l2_state.clone(),
            self.db.needs_revert,
        )?;
        if self.db.needs_revert {
            self.db.needs_revert = false;
        }

        let (guta_result, register_users_result, deploy_contract_result) = tokio::try_join!(
            self.guta_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.gathering_core_proc_unique_pending_id),
            self.register_user_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.gathering_core_proc_unique_pending_id),
            self.deploy_contract_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.gathering_core_proc_unique_pending_id),
        )?;
        Ok((guta_result, register_users_result, deploy_contract_result))
    }
    pub async fn plan_agg_guta_register_users_deploy_contracts_job(
        &self,
        guta_gatherer_result: &CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: &RegisterUserGathererOutput<N::QHash, N::JobId>,
        deploy_contract_gatherer_result: &DeployContractGathererOutput<N::QHash, N::JobId>,
    ) -> anyhow::Result<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> {
        let total_guta_jobs = guta_gatherer_result
            .job_ids
            .iter()
            .map(|level| level.len())
            .sum::<usize>();
        let total_register_user_jobs = register_users_gatherer_result
            .job_ids
            .iter()
            .map(|level| level.len())
            .sum::<usize>();
        let total_deploy_contract_jobs = deploy_contract_gatherer_result
            .job_ids
            .iter()
            .map(|level| level.len())
            .sum::<usize>();

        let witness = QCAggUserRegistartionDeployContractsGUTAInput {
            register_users_state_transition: AggStateTransitionWithStats {
                state_transition_start: register_users_gatherer_result.db_output.start_user_registration_tree_hash,
                state_transition_end: register_users_gatherer_result.db_output.end_user_registration_tree_hash,
                total_proofs_generated: total_register_user_jobs as u64,
            },
            deploy_contracts_state_transition: AggStateTransitionWithStats {
                state_transition_start: deploy_contract_gatherer_result.db_output.start_global_contract_tree_root,
                state_transition_end: deploy_contract_gatherer_result.db_output.end_global_contract_tree_root,
                total_proofs_generated: total_deploy_contract_jobs as u64,
            },
            guta_proof_header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: self.coordinator_guta_updates_circuit_whitelist,
                checkpoint_tree_root: self.db.last_committed_checkpoint_root,
                stats: guta_gatherer_result.db_output.guta_stats,
                total_aggregation_proofs_generated: N::F::from_u64_value(total_guta_jobs as u64),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: guta_gatherer_result.db_output.start_global_user_tree_root,
                    new_node_value: guta_gatherer_result.db_output.end_global_user_tree_root,
                    node_index: N::F::from_u64_value(0),
                    node_level: N::F::from_u64_value(0),
                }
            }
        };

        let root_guta_job = guta_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found at last level"))?;
        let root_register_user_job = register_users_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found at last level"))?;
        let root_deploy_contract_job = deploy_contract_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found at last level"))?;

        let job_id = QProvingJobDataID::block_agg_state_part_1_input_witness(self.db.current_unique_pending_id, 0);
        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: witness.get_public_inputs_hash_no_rewards_tag::<N::HasherBase>(),
                reward_tree_node_index: 0,
                reward_tree_node_level: 1,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD,
                reward_tree_node_children: 3,
                dependencies: vec![
                    root_guta_job.job_id,
                    root_register_user_job.job_id,
                    root_deploy_contract_job.job_id,
                ]
            }
        };
        let witness_data = witness.psy_ser_into_bytes_vec()?;
        self.db.temp_db.set_tdb_proof_witnesses_tuple_owned_raw(&self.db.realm_identifier, self.db.current_unique_pending_id, vec![(job_id, witness_data)]).await?;
        Ok(job_metadata)
    }

    pub async fn plan_checkpoint_state_transition(
        &self,
        guta_gatherer_result: &CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: &RegisterUserGathererOutput<N::QHash, N::JobId>,
        deploy_contract_gatherer_result: &DeployContractGathererOutput<N::QHash, N::JobId>,
    ) -> anyhow::Result<()> {

        let proof = self.db.db.get_verifiable_checkpoint_state_transition_and_zkp(self.db.last_committed_checkpoint_id).await?;

        Ok(())
    }
    
    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        let (guta_gatherer_result, register_users_gatherer_result, deploy_contract_gatherer_result) = self.get_results_from_gatherers().await?;

        let has_jobs = self.get_root_job_ids(
            &guta_gatherer_result.job_ids,
            &register_users_gatherer_result.job_ids,
            &deploy_contract_gatherer_result.job_ids,
        )?;
        if has_jobs.is_none() {
            tracing::info!("No jobs to process in this block, skipping.");
            return Ok(());
        }
        let (guta_root_job_id, register_user_root_job_id, deploy_contract_root_job_id) = has_jobs.unwrap();
        
        // publish the first level of jobs
        self
            .publish_jobs(
                &guta_gatherer_result.job_ids,
                &register_users_gatherer_result.job_ids,
                &deploy_contract_gatherer_result.job_ids,
                Some(0),
                Some(1),
                false,
            )
            .await?;

        // while the first level of jobs are processing, plan the agg job
        let agg_job_metadata = self
            .plan_agg_guta_register_users_deploy_contracts_job(
                &guta_gatherer_result,
                &register_users_gatherer_result,
                &deploy_contract_gatherer_result,
            )
            .await?;


        // wait for the first level of jobs to finish
        self.wait_for_jobs_completion().await?;

        // publish the rest of the jobs and wait for them to finish
        self
            .publish_jobs(
                &guta_gatherer_result.job_ids,
                &register_users_gatherer_result.job_ids,
                &deploy_contract_gatherer_result.job_ids,
                Some(1),
                None,
                true,
            )
            .await?;

        // wait for the Aggregate GUTA, User Registation and Deploy Contracts Proof to finish being proved
        self.publish_and_wait_for_job_completion(&agg_job_metadata).await?;






        Ok(())
    }
}
