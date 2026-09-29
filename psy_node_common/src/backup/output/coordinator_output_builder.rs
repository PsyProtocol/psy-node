use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QJobIdBase, crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, compute_root_merkle_proof_generic},
        traits::{QFieldHashable, ZeroableHash},
    }, felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt}, protocol::core_types::{Q256BitHash, QNetworkTypesConfig}
};
use psy_core::{
    constants::protocol::DA_CHALLENGE_WINDOW,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    agg::AggStateTransitionWithStats,
    config::network_config::PsyNodeCircuitFingerprintConfig,
    guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition},
    node::{coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState}, node_proving_state::PsyNodeProvingState},
    prepared_block::{common::PsyCoordinatorPendingCheckpointBase, coordinator::PsyPreparedCoordinatorBlockStateUpdates},
    protocol::circuit_inputs::{
        agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
        checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial},
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState},
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        pm_rewards_commitment::PPMRewardCommitment,
        populated_checkpoint::PsyCheckpointLeafPopulated,
    },
    worker::{
        metadata::{PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, PsyProvingJobMetadata},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::coordinator::processor::gatherers::{
    contract_gatherer::ContractGathererOutput,
    coordinator_guta_update_gatherer::{CoordinatorGUTAUpdateGathererOutput, CoordinatorGUTAUpdateGathererOutputDatabase},
    deploy_contract_gatherer::DeployContractGathererOutputDatabase,
    register_user_gatherer::{RegisterUserGathererOutput, RegisterUserGathererOutputDatabase},
    update_contract_gatherer::UpdateContractGathererOutputDatabase,
};

pub struct CoordinatorOutputBuilder<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> {
    pub guta_gatherer_result: CoordinatorGUTAUpdateGathererOutputDatabase<N::F, N::QHash>,
    pub register_users_gatherer_result: RegisterUserGathererOutputDatabase<N::QHash>,
    pub deploy_contract_gatherer_result: DeployContractGathererOutputDatabase<N::QHash>,
    pub update_contract_gatherer_result: UpdateContractGathererOutputDatabase<N::QHash>,

    pub total_guta_jobs: usize,
    pub total_register_user_jobs: usize,
    pub total_deploy_contract_jobs: usize,
    pub total_update_contract_jobs: usize,

    pub root_guta_job_id: N::JobId,
    pub root_register_user_job_id: N::JobId,
    pub root_deploy_contract_job_id: N::JobId,
    pub root_update_contract_job_id: N::JobId,

    pub agg_state_part_1_job_id: N::JobId,
    pub checkpoint_state_transition_job_id: N::JobId,
    pub last_checkpoint_state_transition_job_id: N::JobId,
    pub append_checkpoint_tree_siblings: Vec<N::QHash>,
    pub agg_state_part_1_witness: Option<QCAggUserRegistartionDeployContractsGUTAInput<N::F, N::QHash>>,
}

impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> CoordinatorOutputBuilder<N> {
    pub fn get_output_for_backup(
        coordinator_ids: &CoordinatorProcessorIdState,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        reward_tree_root: N::QHash,
        guta_gatherer_result: CoordinatorGUTAUpdateGathererOutputDatabase<N::F, N::QHash>,
        register_users_gatherer_result: RegisterUserGathererOutputDatabase<N::QHash>,
        deploy_contract_gatherer_result: DeployContractGathererOutputDatabase<N::QHash>,
        update_contract_gatherer_result: UpdateContractGathererOutputDatabase<N::QHash>,
        append_checkpoint_tree_siblings: Vec<N::QHash>,
        block_time: u64,
    ) -> anyhow::Result<PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>> {
let root_guta_job = QProvingJobDataID::new_invalid_job_id();
        let root_register_user_job = QProvingJobDataID::new_invalid_job_id();
        let root_deploy_contract_job = QProvingJobDataID::new_invalid_job_id();
        let root_update_contract_job = QProvingJobDataID::new_invalid_job_id();
        let total_guta_jobs = guta_gatherer_result.total_guta_proofs_generated.to_u64_value();//guta_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_register_user_jobs = register_users_gatherer_result.total_jobs;//register_users_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_deploy_contract_jobs = deploy_contract_gatherer_result.total_jobs;//deploy_contract_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_update_contract_jobs = update_contract_gatherer_result.total_jobs;

        let last_checkpoint_state_transition_job_id = if coordinator_ids.checkpoint_id == 0 {
            QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0)
        } else {
            QProvingJobDataID::get_checkpoint_state_transition_job_id(coordinator_ids.checkpoint_id)
        }
        .get_output_id();
        let agg_state_part_1_job_id = QProvingJobDataID::block_agg_state_part_1_input_witness(coordinator_ids.unique_pending_id, 0).get_output_id();
        let checkpoint_state_transition_job_id = QProvingJobDataID::get_checkpoint_state_transition_job_id(
            coordinator_ids.next_checkpoint_id
        )
        .get_output_id();

        let builder = Self {
            total_guta_jobs: total_guta_jobs as usize,
            total_register_user_jobs: total_register_user_jobs as usize,
            total_deploy_contract_jobs: total_deploy_contract_jobs as usize,
            total_update_contract_jobs: total_update_contract_jobs as usize,
            root_guta_job_id: root_guta_job,
            root_register_user_job_id: root_register_user_job,
            root_deploy_contract_job_id: root_deploy_contract_job,
            root_update_contract_job_id: root_update_contract_job,
            agg_state_part_1_job_id,
            checkpoint_state_transition_job_id,
            last_checkpoint_state_transition_job_id,
            guta_gatherer_result: guta_gatherer_result,
            register_users_gatherer_result: register_users_gatherer_result,
            deploy_contract_gatherer_result: deploy_contract_gatherer_result,
            update_contract_gatherer_result: update_contract_gatherer_result,
            agg_state_part_1_witness: None,
            append_checkpoint_tree_siblings,
        };
        builder.finalize(
            coordinator_ids,
            last_committed,
            reward_tree_root,
            block_time,
        )
    }
    pub fn new(
        coordinator_ids: &CoordinatorProcessorIdState,
        guta_gatherer_result: CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: RegisterUserGathererOutput<N::QHash, N::JobId>,
        contract_gatherer_result: ContractGathererOutput<N::QHash, N::JobId>,
    ) -> anyhow::Result<(PsyNodeProvingState, Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>, Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>, Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>, Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>, Self)> {
        let deploy_contract_gatherer_result = contract_gatherer_result.deploy;
        let update_contract_gatherer_result = contract_gatherer_result.update;
        let root_guta_job = guta_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found at last level"))?.job_id.get_output_id();
        let root_register_user_job = register_users_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found at last level"))?.job_id.get_output_id();
        let root_deploy_contract_job = deploy_contract_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found at last level"))?.job_id.get_output_id();
        let root_update_contract_job = update_contract_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Update Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Update Contract jobs found at last level"))?.job_id.get_output_id();
        let total_guta_jobs = guta_gatherer_result.db_output.total_guta_proofs_generated.to_u64_value();//guta_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_register_user_jobs = register_users_gatherer_result.db_output.total_jobs;//register_users_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_deploy_contract_jobs = deploy_contract_gatherer_result.db_output.total_jobs;//deploy_contract_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_update_contract_jobs = update_contract_gatherer_result.db_output.total_jobs;


        let proving_state = PsyNodeProvingState::new_standard_coordinator(
            coordinator_ids.realm_id_u64,
            coordinator_ids.realm_sub_id_u64 as u32,
            coordinator_ids.unique_pending_id,
            coordinator_ids.checkpoint_id,
            guta_gatherer_result.db_output.total_guta_inputs,
            total_guta_jobs,
            register_users_gatherer_result.db_output.next_user_id-register_users_gatherer_result.db_output.start_next_user_id,
            total_register_user_jobs,
            deploy_contract_gatherer_result.db_output.next_contract_id-deploy_contract_gatherer_result.db_output.start_next_contract_id,
            total_deploy_contract_jobs,
        );
        let last_checkpoint_state_transition_job_id = if coordinator_ids.checkpoint_id == 0 {
            QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0).get_output_id()
        } else {
            QProvingJobDataID::get_checkpoint_state_transition_job_id(
                coordinator_ids.checkpoint_id
            ).get_output_id()
        }
        .get_output_id();
        let agg_state_part_1_job_id = QProvingJobDataID::block_agg_state_part_1_input_witness(coordinator_ids.unique_pending_id, 0).get_output_id();
        let checkpoint_state_transition_job_id = QProvingJobDataID::get_checkpoint_state_transition_job_id(
            coordinator_ids.next_checkpoint_id,
        )
        .get_output_id();

    let (guta_gatherer_result, guta_jobs) = {
        (guta_gatherer_result.db_output, guta_gatherer_result.job_ids)
    };
    let (register_users_gatherer_result, register_user_jobs) = {
        (register_users_gatherer_result.db_output, register_users_gatherer_result.job_ids)
    };
    let (deploy_contract_gatherer_result, deploy_contract_jobs) = {
        (deploy_contract_gatherer_result.db_output, deploy_contract_gatherer_result.job_ids)
    };
    let (update_contract_gatherer_result, update_contract_jobs) = {
        (update_contract_gatherer_result.db_output, update_contract_gatherer_result.job_ids)
    };
        Ok((proving_state,guta_jobs, register_user_jobs, deploy_contract_jobs, update_contract_jobs, Self {
            total_guta_jobs: total_guta_jobs as usize,
            total_register_user_jobs: total_register_user_jobs as usize,
            total_deploy_contract_jobs: total_deploy_contract_jobs as usize,
            total_update_contract_jobs: total_update_contract_jobs as usize,
            root_guta_job_id: root_guta_job.get_output_id(),
            root_register_user_job_id: root_register_user_job.get_output_id(),
            root_deploy_contract_job_id: root_deploy_contract_job.get_output_id(),
            root_update_contract_job_id: root_update_contract_job.get_output_id(),
            agg_state_part_1_job_id,
            checkpoint_state_transition_job_id,
            last_checkpoint_state_transition_job_id,
            guta_gatherer_result: guta_gatherer_result,
            register_users_gatherer_result: register_users_gatherer_result,
            deploy_contract_gatherer_result: deploy_contract_gatherer_result,
            update_contract_gatherer_result: update_contract_gatherer_result,
            agg_state_part_1_witness: None,
            append_checkpoint_tree_siblings: vec![],
        }))
    }

    /// The final global contract tree root after applying this block's deploys
    /// and then its contract code updates.
    pub fn final_contract_tree_root(&self) -> N::QHash {
        if self.update_contract_gatherer_result.has_updates() {
            self.update_contract_gatherer_result.end_global_contract_tree_root
        } else {
            self.deploy_contract_gatherer_result.end_global_contract_tree_root
        }
    }

    pub fn get_part_1_header(
        &self,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
    ) -> QCAggUserRegistartionDeployContractsGUTAInput<N::F, N::QHash> {
        let guta_proof_header = self.guta_gatherer_result.root_guta_header.unwrap_or(GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: circuit_fingerprint_config.guta_circuit_whitelist_root,
            checkpoint_tree_root: last_committed.checkpoint_root,
            stats: self.guta_gatherer_result.guta_stats,
            total_aggregation_proofs_generated: N::F::from_u64_value(self.total_guta_jobs as u64),
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.guta_gatherer_result.start_global_user_tree_root,
                new_node_value: self.guta_gatherer_result.end_global_user_tree_root,
                node_index: N::F::from_u64_value(0),
                node_level: N::F::from_u64_value(0),
            },
        });

        let witness = QCAggUserRegistartionDeployContractsGUTAInput {
            register_users_state_transition: AggStateTransitionWithStats {
                state_transition_start: self.register_users_gatherer_result.start_user_registration_tree_hash,
                state_transition_end: self.register_users_gatherer_result.end_user_registration_tree_hash,
                total_proofs_generated: self.total_register_user_jobs as u64,
            },
            deploy_contracts_state_transition: AggStateTransitionWithStats {
                state_transition_start: self.deploy_contract_gatherer_result.start_global_contract_tree_root,
                state_transition_end: self.deploy_contract_gatherer_result.end_global_contract_tree_root,
                total_proofs_generated: self.total_deploy_contract_jobs as u64,
            },
            // the update transition starts where the deploy transition ended
            // (for blocks without updates it is a no-op: start == end)
            update_contracts_state_transition: AggStateTransitionWithStats {
                state_transition_start: self.update_contract_gatherer_result.start_global_contract_tree_root,
                state_transition_end: self.update_contract_gatherer_result.end_global_contract_tree_root,
                total_proofs_generated: self.total_update_contract_jobs as u64,
            },
            guta_proof_header,
        };
        witness
    }

    pub fn get_agg_guta_register_users_deploy_contracts_job(
        &mut self,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
    ) -> anyhow::Result<(PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>, (N::JobId, Vec<u8>))> {
        let witness = self.get_part_1_header(last_committed, circuit_fingerprint_config);

        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id: self.agg_state_part_1_job_id.get_output_id(),
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: witness.get_public_inputs_hash_no_rewards_tag::<N::HasherBase>(),
                reward_tree_node_index: 0,
                reward_tree_node_level: 1,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN,
                reward_tree_node_children: 4,
                dependencies: vec![
                    self.root_guta_job_id.get_output_id(),
                    self.root_register_user_job_id.get_output_id(),
                    self.root_deploy_contract_job_id.get_output_id(),
                    self.root_update_contract_job_id.get_output_id(),
                ],
            },
        };

        let witness_bytes = witness.psy_ser_to_bytes_vec()?;
        self.agg_state_part_1_witness = Some(witness);

        Ok((job_metadata, (self.agg_state_part_1_job_id.get_input_witness_id(), witness_bytes)))
    }

    pub fn get_checkpoint_state_transition_witness(
        &self,
        checkpoint_id: u64,
        next_checkpoint_id: u64,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
        reward_tree_root: N::QHash,
        genesis_checkpoint_state_transition_hash: N::QHash,
        block_time: u64,
    ) -> anyhow::Result<QCQEDCheckpointStateTransitionInput<N::F, N::QHash>> {
        //tracing::info!("last committed checkpoint leaf: {:?} ", last_committed.checkpoint_leaf);
        //tracing::info!("last committed checkpoint leaf hash: {:?} ({})", last_committed.checkpoint_leaf_hash, hex::encode(&last_committed.checkpoint_leaf_hash.into_owned_32bytes()));
        //tracing::info!("last committed checkpoint leaf hash (computed) : {:?} ({})", last_committed.checkpoint_leaf.qfhash::<N::HasherBase>(), hex::encode(&last_committed.checkpoint_leaf.qfhash::<N::HasherBase>().into_owned_32bytes()));
        //tracing::info!("last committed checkpoint leaf hash (computed) : {:?} ({})", last_committed.checkpoint_leaf.qfhash::<N::HasherBase>(), hex::encode(&last_committed.checkpoint_leaf.qfhash::<N::HasherBase>().into_owned_32bytes()));
        //tracing::info!("last committed global_chain_root: {:?} ({})", last_committed.checkpoint_leaf.global_chain_root, hex::encode(&last_committed.checkpoint_leaf.global_chain_root.into_owned_32bytes()));

        let checkpoint_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.final_contract_tree_root(),
            deposit_tree_root: last_committed.checkpoint_state_roots.deposit_tree_root,
            user_tree_root: self.guta_gatherer_result.end_global_user_tree_root,
            withdrawal_tree_root: last_committed.checkpoint_state_roots.withdrawal_tree_root,
            user_registration_tree_root: self.register_users_gatherer_result.end_user_registration_tree_hash,
        };
        let checkpoint_leaf_stats = PQEDCheckpointLeafStats {
            guta_fees_collected: self.guta_gatherer_result.guta_stats.guta_fees_collected,
            da_fees_collected: self.guta_gatherer_result.guta_stats.da_fees_collected,
            user_ops_processed: self.guta_gatherer_result.guta_stats.user_ops_processed,
            total_transactions: self.guta_gatherer_result.guta_stats.total_transactions,
            slots_modified: self.guta_gatherer_result.guta_stats.slots_modified,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: N::F::from_u64_value(self.total_deploy_contract_jobs as u64),
                register_users_completed: N::F::from_u64_value(self.total_register_user_jobs as u64),
                gutas_completed: N::F::from_u64_value(self.total_guta_jobs as u64),
            },
            block_time: N::F::from_u64_value(block_time),
            random_seed: self.guta_gatherer_result.random_seed_guta,
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: reward_tree_root,
                gutas_root: reward_tree_root,
                deploy_contracts_root: reward_tree_root,
            },
            da_challenges_claimed: [N::F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        };
        let new_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: checkpoint_state_roots.qfhash::<N::HasherBase>(),
            stats: checkpoint_leaf_stats.clone(),
        };
        let new_checkpoint_leaf_hash = new_checkpoint_leaf.qfhash::<N::HasherBase>();
        tracing::info!("New checkpoint leaf hash: {:?} ({})", new_checkpoint_leaf_hash, hex::encode(&new_checkpoint_leaf_hash.into_owned_32bytes()));
        let previous_checkpoint_proof = checkpoint_tree.get_leaf(checkpoint_id);
        let current_checkpoint_proof = checkpoint_tree.get_leaf(next_checkpoint_id);
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<N::QHash, N::HasherBase>(
            new_checkpoint_leaf_hash,
            next_checkpoint_id,
            &current_checkpoint_proof.siblings,
        );
        let append_checkpoint_tree_proof = DeltaMerkleProofCore {
            siblings: current_checkpoint_proof.siblings,
            old_root: current_checkpoint_proof.root,
            new_root: new_checkpoint_tree_root,
            old_value: N::QHash::get_zero_value(),
            new_value: new_checkpoint_leaf_hash,
            index: next_checkpoint_id,
        };
        let witness = QCQEDCheckpointStateTransitionInput::<N::F, N::QHash> {
            partial: QCQEDCheckpointStateTransitionInputPartial {
                pm_jobs_completed: PPMJobsCompletedStats {
                    deploy_contracts_completed: N::F::from_u64_value(self.total_deploy_contract_jobs as u64),
                    register_users_completed: N::F::from_u64_value(self.total_register_user_jobs as u64),
                    gutas_completed: N::F::from_u64_value(self.total_guta_jobs as u64),
                },
                part_1_header: self.get_part_1_header(last_committed, circuit_fingerprint_config),
                old_stats: last_committed.checkpoint_leaf_stats.clone(),
                block_time: N::F::from_u64_value(block_time),
                final_random_seed_contribution: self.guta_gatherer_result.random_seed_guta,
            },
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            last_old_checkpoint_tree_leaf_hash: last_committed.checkpoint_state_transition.old_checkpoint_leaf_hash,
            last_old_checkpoint_tree_root_hash: last_committed.checkpoint_state_transition.old_checkpoint_tree_root,
            genesis_checkpoint_state_transition_hash,
            previous_chain_hash: last_committed.last_chain_hash,
            checkpoint_state_transition_circuit_fingerprint:
                circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        };
        let computed_old_checkpoint_leaf = witness.partial.get_old_checkpoint_leaf::<N::HasherBase>();
        let computed_old_checkpoint_leaf_hash =
            computed_old_checkpoint_leaf.qfhash::<N::HasherBase>();
        if computed_old_checkpoint_leaf_hash != witness.previous_checkpoint_proof.value {
            let old_state_roots = witness.partial.get_old_state_roots::<N::HasherBase>();
            anyhow::bail!(
                "checkpoint witness old leaf mismatch for checkpoint {} -> {}: computed old checkpoint leaf hash {:?} ({}) does not match previous checkpoint proof value {:?} ({}); old_state_roots {:?}; last_committed_state_roots {:?}; guta_header {:?}; old_stats {:?}",
                checkpoint_id,
                next_checkpoint_id,
                computed_old_checkpoint_leaf_hash,
                hex::encode(&computed_old_checkpoint_leaf_hash.into_owned_32bytes()),
                witness.previous_checkpoint_proof.value,
                hex::encode(&witness.previous_checkpoint_proof.value.into_owned_32bytes()),
                old_state_roots,
                last_committed.checkpoint_state_roots,
                witness.partial.part_1_header.guta_proof_header,
                witness.partial.old_stats,
            );
        }
        Ok(witness)
    }

    pub fn get_checkpoint_state_transition_job(
        &mut self,
        checkpoint_id: u64,
        next_checkpoint_id: u64,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
        agg_part_1_reward_tree_value: N::QHash,
        genesis_checkpoint_state_transition_hash: N::QHash,
        block_time: u64,
    ) -> anyhow::Result<(PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>, (N::JobId, Vec<u8>))> {
        let witness = self.get_checkpoint_state_transition_witness(
            checkpoint_id,
            next_checkpoint_id,
            checkpoint_tree,
            last_committed,
            circuit_fingerprint_config,
            agg_part_1_reward_tree_value,
            genesis_checkpoint_state_transition_hash,
            block_time,
        )?;
        let witness_bytes = witness.psy_ser_to_bytes_vec()?;
        tracing::info!(
            "checkpoint_transition output_builder fingerprint(config)={} genesis_fp={} previous_chain_hash={}",
            hex::encode(circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint.into_owned_32bytes()),
            hex::encode(circuit_fingerprint_config.genesis_checkpoint_state_transition_fingerprint.into_owned_32bytes()),
            hex::encode(witness.previous_chain_hash.into_owned_32bytes()),
        );
        let expected_public_inputs = witness.get_chain_hash_with_fingerprint_from_previous::<N::HasherBase>(
            witness.previous_chain_hash,
            circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        );
        tracing::info!(
            "checkpoint_transition output_builder expected_public_inputs={}",
            hex::encode(expected_public_inputs.into_owned_32bytes()),
        );
        self.append_checkpoint_tree_siblings = witness.append_checkpoint_tree_proof.siblings;

        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id: self.checkpoint_state_transition_job_id.get_output_id(),
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_public_inputs,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD,
                reward_tree_node_children: 2,
                dependencies: vec![
                    self.agg_state_part_1_job_id.get_output_id(),
                    self.last_checkpoint_state_transition_job_id.get_output_id(),
                ],
            },
        };

        Ok((
            job_metadata,
            (self.checkpoint_state_transition_job_id.get_input_witness_id(), witness_bytes),
        ))
    }

    pub fn finalize(
        self,
        coordinator_ids: &CoordinatorProcessorIdState,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        reward_tree_root: N::QHash,
        block_time: u64,
    ) -> anyhow::Result<PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>> {
        let checkpoint_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.final_contract_tree_root(),
            deposit_tree_root: last_committed.checkpoint_state_roots.deposit_tree_root,
            user_tree_root: self.guta_gatherer_result.end_global_user_tree_root,
            withdrawal_tree_root: last_committed.checkpoint_state_roots.withdrawal_tree_root,
            user_registration_tree_root: self.register_users_gatherer_result.end_user_registration_tree_hash,
        };
        let checkpoint_leaf_stats = PQEDCheckpointLeafStats {
            guta_fees_collected: self.guta_gatherer_result.guta_stats.guta_fees_collected,
            da_fees_collected: self.guta_gatherer_result.guta_stats.da_fees_collected,
            user_ops_processed: self.guta_gatherer_result.guta_stats.user_ops_processed,
            total_transactions: self.guta_gatherer_result.guta_stats.total_transactions,
            slots_modified: self.guta_gatherer_result.guta_stats.slots_modified,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: N::F::from_u64_value(self.total_deploy_contract_jobs as u64),
                register_users_completed: N::F::from_u64_value(self.total_register_user_jobs as u64),
                gutas_completed: N::F::from_u64_value(self.total_guta_jobs as u64),
            },
            block_time: N::F::from_u64_value(block_time),
            random_seed: self.guta_gatherer_result.random_seed_guta,
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: reward_tree_root,
                gutas_root: reward_tree_root,
                deploy_contracts_root: reward_tree_root,
            },
            da_challenges_claimed: [N::F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        };
        let new_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: checkpoint_state_roots.qfhash::<N::HasherBase>(),
            stats: checkpoint_leaf_stats.clone(),
        };
        let new_checkpoint_leaf_hash = new_checkpoint_leaf.qfhash::<N::HasherBase>();
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<N::QHash, N::HasherBase>(
            new_checkpoint_leaf_hash,
            coordinator_ids.checkpoint_id + 1,
            &self.append_checkpoint_tree_siblings,
        );

        let output = PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: coordinator_ids.realm_id_u64,
            checkpoint_id: coordinator_ids.checkpoint_id + 1,
            unique_pending_id: coordinator_ids.unique_pending_id,
            proc_checkpoint_unique_id: coordinator_ids.proc_checkpoint_unique_id,
            old_base: PsyCoordinatorPendingCheckpointBase {
                block_state: last_committed.l2_state.clone(),
                checkpoint_leaf: PsyCheckpointLeafPopulated {
                    global_state_roots: last_committed.checkpoint_state_roots,
                    stats: last_committed.checkpoint_leaf_stats.clone(),
                },
                checkpoint_leaf_hash: last_committed.checkpoint_leaf.qfhash::<N::HasherBase>(),
                checkpoint_tree_root: last_committed.checkpoint_root,
            },
            new_base: PsyCoordinatorPendingCheckpointBase {
                block_state: QEDL2BlockState {
                    checkpoint_id: coordinator_ids.checkpoint_id + 1,
                    next_add_withdrawal_id: last_committed.l2_state.next_add_withdrawal_id,
                    next_process_withdrawal_id: last_committed.l2_state.next_process_withdrawal_id,
                    next_deposit_id: last_committed.l2_state.next_deposit_id,
                    total_deposits_claimed_epoch: last_committed.l2_state.total_deposits_claimed_epoch,

                    next_user_id: self.register_users_gatherer_result.next_user_id,
                    end_balance: last_committed.l2_state.end_balance,
                    next_contract_id: self.deploy_contract_gatherer_result.next_contract_id as u32,
                },
                checkpoint_leaf: PsyCheckpointLeafPopulated {
                    global_state_roots: checkpoint_state_roots,
                    stats: checkpoint_leaf_stats,
                },
                checkpoint_leaf_hash: new_checkpoint_leaf_hash,
                checkpoint_tree_root: new_checkpoint_tree_root,
            },

            // NOTE on the contract tree change sets: the update gatherer
            // finalizes on the same in-memory tree AFTER the deploy gatherer,
            // so when updates exist its `update_global_contract_tree_nodes_ffs`
            // is the union of the deploy and update changes (and must be used
            // instead of the deploy-only change set)
            update_global_contract_tree_nodes_ffs: if self.update_contract_gatherer_result.has_updates() {
                self.update_contract_gatherer_result.update_global_contract_tree_nodes_ffs
            } else {
                self.deploy_contract_gatherer_result.update_global_contract_tree_nodes_ffs
            },
            update_contract_function_tree_nodes_ffs: [
                self.deploy_contract_gatherer_result.update_contract_function_tree_nodes_ffs,
                self.update_contract_gatherer_result.update_contract_function_tree_nodes_ffs,
            ].concat(),
            new_contract_leaves_ffs: [
                self.deploy_contract_gatherer_result.new_contract_leaves_ffs,
                self.update_contract_gatherer_result.updated_contract_leaves_ffs,
            ].concat(),
            new_contract_code_definitions: [
                self.deploy_contract_gatherer_result.new_contract_code_definitions,
                self.update_contract_gatherer_result.updated_contract_code_definitions,
            ].concat(),

            update_global_user_tree_nodes_ffs: self.guta_gatherer_result.update_global_user_tree_nodes_ffs,
            new_realm_guta_reward_tree_node_keys_ffs: self.guta_gatherer_result.new_realm_guta_reward_tree_node_keys_ffs,

            update_user_registration_tree_nodes_ffs: self.register_users_gatherer_result.update_user_registration_tree_nodes_ffs,
            new_user_public_keys_ffs: self.register_users_gatherer_result.new_user_public_keys_ffs,
            new_public_key_hash_to_user_id_rows_ffs: self.register_users_gatherer_result.new_public_key_hash_to_user_id_rows_ffs,
            checkpoint_tree_update_proof: DeltaMerkleProofCore {
                old_root: last_committed.checkpoint_root,
                old_value: last_committed.checkpoint_leaf_hash,
                new_root: new_checkpoint_tree_root,
                new_value: new_checkpoint_leaf_hash,
                index: coordinator_ids.checkpoint_id + 1,
                siblings: self.append_checkpoint_tree_siblings,
            },
        };
        Ok(output)
    }
}

#[cfg(test)]
mod output_builder_tests {
    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher,
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{
            QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants,
            QNetworkTypesConfig, QNetworkZKTypes, QZKProofPublicInputsHasherReader, QZKProofVerifier,
        },
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_core::constants::protocol::{TODO_DEPOSIT_TREE_HEIGHT, TODO_WITHDRAWAL_TREE_HEIGHT};
    use psy_data::{
        guta::stats::GUTAStats,
        protocol::checkpoint_transition_hash::CheckpointStateHashTransition,
    };

    use crate::coordinator::processor::gatherers::{
        deploy_contract_gatherer::DeployContractGathererOutput, update_contract_gatherer::UpdateContractGathererOutput,
    };

    use super::*;

    // ---------------------------------------------------------------------
    // Test network config: satisfies QNetworkTypesConfig with a trivial ZK
    // verifier so the builder can be exercised without real proving backends.
    // ---------------------------------------------------------------------

    #[derive(Clone)]
    struct TestZKVerifier;
    impl QZKProofPublicInputsHasherReader<PHash, ()> for TestZKVerifier {
        fn get_proof_public_inputs_hash(_proof: &()) -> anyhow::Result<PHash> {
            Ok(PoseidonHasher::get_zero_hash(1))
        }
        fn try_proof_from_slice(_bytes: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }
    impl QZKProofVerifier<PHash, ()> for TestZKVerifier {
        fn verify_zk_proof(&self, _circuit_type: u32, _proof: &()) -> anyhow::Result<PHash> {
            Ok(PoseidonHasher::get_zero_hash(1))
        }
    }

    #[derive(Clone)]
    struct TestNetworkConfig;
    impl QNetworkTreeConstants for TestNetworkConfig {
        const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
        const CHECKPOINT_TREE_HEIGHT: u8 = 32;
        const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
        const GLOBAL_USER_TREE_HEIGHT: u8 = 32;
        const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
        const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = 24;
        const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
        const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = 16;
        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 12;
        const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
        const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 20;
        const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
        const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
        const GROUP_REALM_HEIGHT: u8 = 1;
        const MAX_USERS: u64 = 1 << 32;
        const MAX_REALMS: u32 = 1 << 12;
        const MAX_USERS_PER_REALM: u32 = 1 << 20;
    }
    impl QNetworkTreeCircuitSpecificConstants for TestNetworkConfig {
        const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
        const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
        const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
        const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
        const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
        const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;
        const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] = [
            3896366420105793420,
            17410332186442776169,
            7329967984378645716,
            6310665049578686403,
        ];
        const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] = [
            1412692327731855940,
            17963365021580141687,
            10532510199226356508,
            3943799806037696098,
        ];
    }
    impl QNetworkHashTypes for TestNetworkConfig {
        type QHash = PHash;
        type HasherBase = PoseidonHasher;
        type F = PF;
    }
    impl QNetworkZKTypes for TestNetworkConfig {
        type ZKProof = ();
        type ZKVerifier = TestZKVerifier;
    }
    impl QNetworkTypesConfig for TestNetworkConfig {
        type JobId = QProvingJobDataID;
    }

    type TestBuilder = CoordinatorOutputBuilder<TestNetworkConfig>;

    // deterministic, distinct roots: the poseidon zero hashes at distinct levels
    fn zh(level: usize) -> PHash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn sample_guta_db() -> CoordinatorGUTAUpdateGathererOutputDatabase<PF, PHash> {
        CoordinatorGUTAUpdateGathererOutputDatabase {
            update_global_user_tree_nodes_ffs: vec![1, 2, 3],
            new_realm_guta_reward_tree_node_keys_ffs: vec![4, 5],
            guta_stats: GUTAStats::<PF>::get_zero_value(),
            total_guta_proofs_generated: PF::from_u64_value(2),
            total_guta_inputs: 5,
            start_global_user_tree_root: zh(1),
            end_global_user_tree_root: zh(2),
            root_guta_header: None,
            random_seed_guta: zh(51),
        }
    }

    fn sample_register_db() -> RegisterUserGathererOutputDatabase<PHash> {
        RegisterUserGathererOutputDatabase {
            start_next_user_id: 10,
            start_user_registration_tree_hash: zh(3),
            new_user_public_keys_ffs: vec![10, 11],
            next_user_id: 12,
            end_user_registration_tree_hash: zh(4),
            user_registration_tree_update_pivot_siblings: vec![zh(9)],
            new_public_key_hash_to_user_id_rows_ffs: vec![12, 13],
            update_user_registration_tree_nodes_ffs: vec![14],
            total_jobs: 3,
            block_time: 1_000,
        }
    }

    fn sample_deploy_db() -> DeployContractGathererOutputDatabase<PHash> {
        DeployContractGathererOutputDatabase {
            start_next_contract_id: 20,
            start_global_contract_tree_root: zh(5),
            new_contract_leaves_ffs: vec![1, 2, 3],
            update_contract_function_tree_nodes_ffs: vec![4, 5],
            new_contract_code_definitions: Vec::new(),
            total_jobs: 2,
            next_contract_id: 22,
            end_global_contract_tree_root: zh(6),
            global_contract_tree_update_pivot_siblings: vec![zh(10)],
            update_global_contract_tree_nodes_ffs: vec![6, 7, 8],
        }
    }

    fn sample_update_db(has_updates: bool) -> UpdateContractGathererOutputDatabase<PHash> {
        UpdateContractGathererOutputDatabase {
            start_global_contract_tree_root: zh(7),
            updated_contract_ids: if has_updates { vec![77] } else { Vec::new() },
            updated_contract_leaves_ffs: vec![9, 10],
            update_contract_function_tree_nodes_ffs: vec![11, 12],
            updated_contract_code_definitions: Vec::new(),
            total_jobs: if has_updates { 1 } else { 0 },
            end_global_contract_tree_root: zh(8),
            global_contract_tree_update_pivot_siblings: Vec::new(),
            update_global_contract_tree_nodes_ffs: vec![13, 14],
        }
    }

    fn sample_ids(checkpoint_id: u64) -> CoordinatorProcessorIdState {
        CoordinatorProcessorIdState {
            realm_identifier: QRealmIdentifier { realm_id: 1, realm_sub_id: 2 },
            realm_id_u64: 1,
            realm_sub_id_u64: 2,
            checkpoint_id,
            next_checkpoint_id: checkpoint_id + 1,
            unique_pending_id: 100,
            proc_checkpoint_unique_id: 200,
            gathering_unique_pending_id: 300,
            gathering_proc_checkpoint_unique_id: 400,
        }
    }

    fn sample_last_committed(
        stats: PQEDCheckpointLeafStats<PF, PHash>,
    ) -> CoordinatorProcessorLastCommittedState<PF, PHash> {
        CoordinatorProcessorLastCommittedState {
            l2_state: QEDL2BlockState {
                checkpoint_id: 0,
                next_add_withdrawal_id: 3,
                next_process_withdrawal_id: 5,
                next_deposit_id: 7,
                total_deposits_claimed_epoch: 9,
                next_user_id: 11,
                end_balance: 13,
                next_contract_id: 15,
            },
            checkpoint_leaf_stats: stats,
            checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            checkpoint_state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
            checkpoint_state_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: PHash::qp_rand_gen(),
                new_checkpoint_tree_root: PHash::qp_rand_gen(),
                old_checkpoint_leaf_hash: PHash::qp_rand_gen(),
                new_checkpoint_leaf_hash: PHash::qp_rand_gen(),
            },
            checkpoint_root: PHash::qp_rand_gen(),
            checkpoint_leaf_hash: PHash::qp_rand_gen(),
            last_chain_hash: PHash::qp_rand_gen(),
        }
    }

    fn sample_fingerprint_config() -> PsyNodeCircuitFingerprintConfig<PHash> {
        PsyNodeCircuitFingerprintConfig {
            guta_circuit_whitelist_root: zh(21),
            register_users_circuit_whitelist_root: zh(22),
            deploy_contracts_circuit_whitelist_root: zh(23),
            update_contracts_circuit_whitelist_root: zh(24),
            checkpoint_state_transition_circuit_fingerprint: zh(25),
            genesis_checkpoint_state_transition_fingerprint: zh(26),
        }
    }

    fn make_builder(has_updates: bool) -> TestBuilder {
        CoordinatorOutputBuilder {
            guta_gatherer_result: sample_guta_db(),
            register_users_gatherer_result: sample_register_db(),
            deploy_contract_gatherer_result: sample_deploy_db(),
            update_contract_gatherer_result: sample_update_db(has_updates),
            total_guta_jobs: 2,
            total_register_user_jobs: 3,
            total_deploy_contract_jobs: 2,
            total_update_contract_jobs: if has_updates { 1 } else { 0 },
            root_guta_job_id: QProvingJobDataID::new_invalid_job_id(),
            root_register_user_job_id: QProvingJobDataID::new_invalid_job_id(),
            root_deploy_contract_job_id: QProvingJobDataID::new_invalid_job_id(),
            root_update_contract_job_id: QProvingJobDataID::new_invalid_job_id(),
            agg_state_part_1_job_id: QProvingJobDataID::block_agg_state_part_1_input_witness(100, 0).get_output_id(),
            checkpoint_state_transition_job_id: QProvingJobDataID::get_checkpoint_state_transition_job_id(5).get_output_id(),
            last_checkpoint_state_transition_job_id: QProvingJobDataID::get_checkpoint_state_transition_job_id(4).get_output_id().get_output_id(),
            append_checkpoint_tree_siblings: vec![zh(30), zh(31)],
            agg_state_part_1_witness: None,
        }
    }

    #[test]
    fn final_contract_tree_root_prefers_update_root_iff_updates_exist() {
        // with contract updates the update gatherer ran last, so its end root wins
        let with_updates = make_builder(true);
        assert_eq!(with_updates.final_contract_tree_root(), zh(8));

        // without updates the deploy gatherer's end root is the final one
        let without_updates = make_builder(false);
        assert_eq!(without_updates.final_contract_tree_root(), zh(6));
    }

    #[test]
    fn get_part_1_header_synthesizes_a_guta_header_from_the_block_when_missing() {
        let builder = make_builder(false);
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());
        let expected_checkpoint_root = last_committed.checkpoint_root;

        let witness = builder.get_part_1_header(&last_committed, &sample_fingerprint_config());

        // synthesized header: whitelist from the fingerprint config, checkpoint
        // root from the last committed state, zero-indexed root transition
        assert_eq!(witness.guta_proof_header.guta_circuit_whitelist, zh(21));
        assert_eq!(witness.guta_proof_header.checkpoint_tree_root, expected_checkpoint_root);
        assert_eq!(witness.guta_proof_header.total_aggregation_proofs_generated, PF::from_u64_value(2));
        assert_eq!(witness.guta_proof_header.state_transition.old_node_value, zh(1));
        assert_eq!(witness.guta_proof_header.state_transition.new_node_value, zh(2));
        assert_eq!(witness.guta_proof_header.state_transition.node_index, PF::ZERO_VALUE);
        assert_eq!(witness.guta_proof_header.state_transition.node_level, PF::ZERO_VALUE);
        assert_eq!(witness.guta_proof_header.stats.guta_fees_collected, PF::ZERO_VALUE);

        // the three aggregation transitions mirror the gatherer databases
        assert_eq!(witness.register_users_state_transition.state_transition_start, zh(3));
        assert_eq!(witness.register_users_state_transition.state_transition_end, zh(4));
        assert_eq!(witness.register_users_state_transition.total_proofs_generated, 3);
        assert_eq!(witness.deploy_contracts_state_transition.state_transition_start, zh(5));
        assert_eq!(witness.deploy_contracts_state_transition.state_transition_end, zh(6));
        assert_eq!(witness.deploy_contracts_state_transition.total_proofs_generated, 2);
        assert_eq!(witness.update_contracts_state_transition.state_transition_start, zh(7));
        assert_eq!(witness.update_contracts_state_transition.state_transition_end, zh(8));
        assert_eq!(witness.update_contracts_state_transition.total_proofs_generated, 0);
    }

    #[test]
    fn get_part_1_header_uses_the_recorded_guta_header_when_available() {
        fn recorded_header() -> GlobalUserTreeAggregatorHeader<PF, PHash> {
            GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: zh(41),
                checkpoint_tree_root: zh(42),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: zh(43),
                    new_node_value: zh(44),
                    node_index: PF::from_u64_value(7),
                    node_level: PF::from_u64_value(8),
                },
                stats: GUTAStats::<PF>::get_zero_value(),
                total_aggregation_proofs_generated: PF::from_u64_value(9),
            }
        }

        let mut builder = make_builder(false);
        builder.guta_gatherer_result.root_guta_header = Some(recorded_header());
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());

        let witness = builder.get_part_1_header(&last_committed, &sample_fingerprint_config());

        // the recorded header is used verbatim, ignoring the fallback inputs
        assert_eq!(witness.guta_proof_header.guta_circuit_whitelist, zh(41));
        assert_eq!(witness.guta_proof_header.checkpoint_tree_root, zh(42));
        assert_eq!(witness.guta_proof_header.state_transition.old_node_value, zh(43));
        assert_eq!(witness.guta_proof_header.state_transition.new_node_value, zh(44));
        assert_eq!(witness.guta_proof_header.state_transition.node_index, PF::from_u64_value(7));
        assert_eq!(witness.guta_proof_header.state_transition.node_level, PF::from_u64_value(8));
        assert_eq!(witness.guta_proof_header.total_aggregation_proofs_generated, PF::from_u64_value(9));
    }

    #[test]
    fn finalize_builds_the_expected_block_state_updates_with_contract_updates() {
        let ids = sample_ids(4);
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());
        let expected_old_leaf_hash = last_committed.checkpoint_leaf.qfhash::<PoseidonHasher>();
        let reward_root = zh(50);
        let block_time = 1_770_000_000u64;

        let output = make_builder(true).finalize(&ids, &last_committed, reward_root, block_time).unwrap();

        assert_eq!(output.coordinator_id, 1);
        assert_eq!(output.checkpoint_id, 5);
        assert_eq!(output.unique_pending_id, 100);
        assert_eq!(output.proc_checkpoint_unique_id, 200);

        // the old base mirrors the last committed state verbatim (the leaf
        // hash is recomputed from the leaf, not copied from the stored hash)
        assert_eq!(output.old_base.block_state.next_user_id, 11);
        assert_eq!(output.old_base.block_state.end_balance, 13);
        assert_eq!(output.old_base.checkpoint_leaf_hash, expected_old_leaf_hash);
        assert_eq!(output.old_base.checkpoint_tree_root, last_committed.checkpoint_root);
        assert_eq!(
            output.old_base.checkpoint_leaf.global_state_roots.contract_tree_root,
            last_committed.checkpoint_state_roots.contract_tree_root
        );

        // the new block state advances the counters owned by the gatherers and
        // copies the rest from the last committed L2 state
        assert_eq!(output.new_base.block_state.checkpoint_id, 5);
        assert_eq!(output.new_base.block_state.next_user_id, 12);
        assert_eq!(output.new_base.block_state.next_contract_id, 22);
        assert_eq!(output.new_base.block_state.next_deposit_id, 7);
        assert_eq!(output.new_base.block_state.end_balance, 13);

        // state roots: contract root from the update gatherer (updates exist),
        // user root from GUTA, registration root from the register gatherer
        assert_eq!(output.new_base.checkpoint_leaf.global_state_roots.contract_tree_root, zh(8));
        assert_eq!(output.new_base.checkpoint_leaf.global_state_roots.user_tree_root, zh(2));
        assert_eq!(output.new_base.checkpoint_leaf.global_state_roots.user_registration_tree_root, zh(4));
        assert_eq!(
            output.new_base.checkpoint_leaf.global_state_roots.deposit_tree_root,
            last_committed.checkpoint_state_roots.deposit_tree_root
        );
        assert_eq!(
            output.new_base.checkpoint_leaf.global_state_roots.withdrawal_tree_root,
            last_committed.checkpoint_state_roots.withdrawal_tree_root
        );

        // leaf stats: job counts, reward commitments, seed and block time
        assert_eq!(output.new_base.checkpoint_leaf.stats.block_time, PF::from_u64_value(block_time));
        assert_eq!(output.new_base.checkpoint_leaf.stats.random_seed, zh(51));
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_rewards_commitment.register_users_root, reward_root);
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_rewards_commitment.gutas_root, reward_root);
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_rewards_commitment.deploy_contracts_root, reward_root);
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_jobs_completed.gutas_completed, PF::from_u64_value(2));
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_jobs_completed.register_users_completed, PF::from_u64_value(3));
        assert_eq!(output.new_base.checkpoint_leaf.stats.pm_jobs_completed.deploy_contracts_completed, PF::from_u64_value(2));

        // the recorded leaf hash is the hash of the recorded leaf, and the new
        // tree root folds it in at index checkpoint_id + 1 over the siblings
        assert_eq!(output.new_base.checkpoint_leaf_hash, output.new_base.checkpoint_leaf.qfhash::<PoseidonHasher>());
        let expected_tree_root = compute_root_merkle_proof_generic::<PHash, PoseidonHasher>(
            output.new_base.checkpoint_leaf_hash,
            5,
            &[zh(30), zh(31)],
        );
        assert_eq!(output.new_base.checkpoint_tree_root, expected_tree_root);

        // with updates present the union change set comes from the update
        // gatherer; the remaining buffers are concatenations deploy || update
        assert_eq!(output.update_global_contract_tree_nodes_ffs, vec![13, 14]);
        assert_eq!(output.update_contract_function_tree_nodes_ffs, vec![4, 5, 11, 12]);
        assert_eq!(output.new_contract_leaves_ffs, vec![1, 2, 3, 9, 10]);
        assert_eq!(output.update_global_user_tree_nodes_ffs, vec![1, 2, 3]);
        assert_eq!(output.new_realm_guta_reward_tree_node_keys_ffs, vec![4, 5]);
        assert_eq!(output.update_user_registration_tree_nodes_ffs, vec![14]);
        assert_eq!(output.new_user_public_keys_ffs, vec![10, 11]);
        assert_eq!(output.new_public_key_hash_to_user_id_rows_ffs, vec![12, 13]);

        let proof = output.checkpoint_tree_update_proof;
        assert_eq!(proof.old_root, last_committed.checkpoint_root);
        assert_eq!(proof.old_value, last_committed.checkpoint_leaf_hash);
        assert_eq!(proof.new_root, expected_tree_root);
        assert_eq!(proof.new_value, output.new_base.checkpoint_leaf_hash);
        assert_eq!(proof.index, 5);
        assert_eq!(proof.siblings, vec![zh(30), zh(31)]);
    }

    #[test]
    fn finalize_without_updates_uses_the_deploy_change_set() {
        let ids = sample_ids(4);
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());

        let output = make_builder(false).finalize(&ids, &last_committed, zh(50), 999).unwrap();

        // no updates: the deploy gatherer's end root and change set win
        assert_eq!(output.new_base.checkpoint_leaf.global_state_roots.contract_tree_root, zh(6));
        assert_eq!(output.update_global_contract_tree_nodes_ffs, vec![6, 7, 8]);
        assert_eq!(output.update_contract_function_tree_nodes_ffs, vec![4, 5, 11, 12]);
        assert_eq!(output.new_contract_leaves_ffs, vec![1, 2, 3, 9, 10]);
        assert_eq!(output.new_base.block_state.next_contract_id, 22);
    }

    #[test]
    fn get_output_for_backup_covers_genesis_and_regular_checkpoints() {
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());

        // checkpoint_id 0 takes the genesis branch for the previous transition job id
        let output = TestBuilder::get_output_for_backup(
            &sample_ids(0),
            &last_committed,
            zh(50),
            sample_guta_db(),
            sample_register_db(),
            sample_deploy_db(),
            sample_update_db(false),
            vec![],
            12_345,
        )
        .unwrap();
        assert_eq!(output.checkpoint_id, 1);
        assert_eq!(output.new_base.block_state.next_user_id, 12);
        assert_eq!(output.old_base.checkpoint_tree_root, last_committed.checkpoint_root);

        // a regular checkpoint takes the checkpoint-id-based branch
        let output = TestBuilder::get_output_for_backup(
            &sample_ids(5),
            &last_committed,
            zh(50),
            sample_guta_db(),
            sample_register_db(),
            sample_deploy_db(),
            sample_update_db(true),
            vec![zh(30), zh(31)],
            12_346,
        )
        .unwrap();
        assert_eq!(output.checkpoint_id, 6);
        assert_eq!(output.new_base.checkpoint_leaf.global_state_roots.contract_tree_root, zh(8));
    }

    fn job_metadata(goal_id: u64, group_id: u32, task_index: u32) -> PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID> {
        PsyProvingJobMetadataWithJobId {
            job_id: QProvingJobDataID::new_proof_job_id(
                goal_id,
                group_id,
                ProvingJobCircuitType::GenesisBlockCheckpointStateTransition,
                0,
                task_index,
            ),
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: zh(1),
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: 0,
                reward_tree_node_children: 0,
                dependencies: vec![],
            },
        }
    }

    fn guta_output_with(
        job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>,
    ) -> CoordinatorGUTAUpdateGathererOutput<PF, PHash, QProvingJobDataID> {
        CoordinatorGUTAUpdateGathererOutput { db_output: sample_guta_db(), job_ids }
    }

    fn register_output_with(
        job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>,
    ) -> RegisterUserGathererOutput<PHash, QProvingJobDataID> {
        RegisterUserGathererOutput { db_output: sample_register_db(), job_ids }
    }

    fn contract_output_with(
        deploy_job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>,
        update_job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>,
    ) -> ContractGathererOutput<PHash, QProvingJobDataID> {
        ContractGathererOutput {
            deploy: DeployContractGathererOutput { db_output: sample_deploy_db(), job_ids: deploy_job_ids },
            update: UpdateContractGathererOutput { db_output: sample_update_db(true), job_ids: update_job_ids },
        }
    }

    #[test]
    fn new_extracts_roots_totals_and_proving_state() {
        let ids = sample_ids(4);
        let (proving_state, guta_jobs, register_jobs, deploy_jobs, update_jobs, builder) =
            TestBuilder::new(
                &ids,
                guta_output_with(vec![vec![job_metadata(1, 1, 1)], vec![job_metadata(2, 2, 2), job_metadata(2, 2, 3)]]),
                register_output_with(vec![vec![job_metadata(3, 3, 3)]]),
                contract_output_with(
                    vec![vec![job_metadata(4, 4, 4)]],
                    vec![vec![job_metadata(5, 5, 5), job_metadata(5, 5, 6)]],
                ),
            )
            .unwrap();

        assert_eq!(proving_state.realm_id, 1);
        // the job vecs are handed back to the caller for scheduling
        assert_eq!(guta_jobs.len(), 2);
        assert_eq!(guta_jobs[0].len(), 1);
        assert_eq!(guta_jobs[1].len(), 2);
        assert_eq!(register_jobs.len(), 1);
        assert_eq!(deploy_jobs.len(), 1);
        assert_eq!(update_jobs.len(), 1);
        assert_eq!(update_jobs[0].len(), 2);

        // root job ids come from the first job of the last (root) level
        assert_eq!(builder.root_guta_job_id, job_metadata(2, 2, 2).job_id.get_output_id().get_output_id());
        assert_eq!(builder.root_register_user_job_id, job_metadata(3, 3, 3).job_id.get_output_id().get_output_id());
        assert_eq!(builder.root_deploy_contract_job_id, job_metadata(4, 4, 4).job_id.get_output_id().get_output_id());
        assert_eq!(builder.root_update_contract_job_id, job_metadata(5, 5, 5).job_id.get_output_id().get_output_id());

        // totals are taken from the database outputs
        assert_eq!(builder.total_guta_jobs, 2);
        assert_eq!(builder.total_register_user_jobs, 3);
        assert_eq!(builder.total_deploy_contract_jobs, 2);
        assert_eq!(builder.total_update_contract_jobs, 1);

        assert_eq!(builder.agg_state_part_1_job_id, QProvingJobDataID::block_agg_state_part_1_input_witness(100, 0).get_output_id());
        assert_eq!(
            builder.checkpoint_state_transition_job_id,
            QProvingJobDataID::get_checkpoint_state_transition_job_id(5).get_output_id()
        );
        // checkpoint_id != 0: the previous transition job is checkpoint-id based
        assert_eq!(
            builder.last_checkpoint_state_transition_job_id,
            QProvingJobDataID::get_checkpoint_state_transition_job_id(4).get_output_id().get_output_id()
        );
        assert!(builder.agg_state_part_1_witness.is_none());
        assert!(builder.append_checkpoint_tree_siblings.is_empty());
    }

    #[test]
    fn new_uses_the_genesis_transition_job_for_checkpoint_zero() {
        let (.., builder) = TestBuilder::new(
            &sample_ids(0),
            guta_output_with(vec![vec![job_metadata(1, 1, 1)]]),
            register_output_with(vec![vec![job_metadata(3, 3, 3)]]),
            contract_output_with(vec![vec![job_metadata(4, 4, 4)]], vec![vec![job_metadata(5, 5, 5)]]),
        )
        .unwrap();

        assert_eq!(
            builder.last_checkpoint_state_transition_job_id,
            QProvingJobDataID::new_proof_job_id(
                0,
                0,
                ProvingJobCircuitType::GenesisBlockCheckpointStateTransition,
                0,
                0
            )
            .get_output_id()
            .get_output_id()
        );
    }

    #[test]
    fn new_rejects_missing_root_jobs() {
        let ids = sample_ids(4);

        // no GUTA levels at all
        let err = match TestBuilder::new(
            &ids,
            guta_output_with(vec![]),
            register_output_with(vec![vec![job_metadata(3, 3, 3)]]),
            contract_output_with(vec![vec![job_metadata(4, 4, 4)]], vec![vec![job_metadata(5, 5, 5)]]),
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected new() to fail for empty GUTA job list"),
        };
        assert!(err.to_string().contains("No GUTA jobs found"), "unexpected error: {err}");

        // a last GUTA level with no jobs
        let err = match TestBuilder::new(
            &ids,
            guta_output_with(vec![vec![job_metadata(1, 1, 1)], vec![]]),
            register_output_with(vec![vec![job_metadata(3, 3, 3)]]),
            contract_output_with(vec![vec![job_metadata(4, 4, 4)]], vec![vec![job_metadata(5, 5, 5)]]),
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected new() to fail for an empty root GUTA level"),
        };
        assert!(err.to_string().contains("No GUTA jobs found at last level"), "unexpected error: {err}");

        // no register user jobs
        let err = match TestBuilder::new(
            &ids,
            guta_output_with(vec![vec![job_metadata(1, 1, 1)]]),
            register_output_with(vec![]),
            contract_output_with(vec![vec![job_metadata(4, 4, 4)]], vec![vec![job_metadata(5, 5, 5)]]),
        ) {
            Err(err) => err,
            Ok(_) => panic!("expected new() to fail for an empty register job list"),
        };
        assert!(err.to_string().contains("No Register User jobs found"), "unexpected error: {err}");
    }

    #[test]
    fn agg_part_1_job_metadata_covers_the_four_root_jobs() {
        let mut builder = make_builder(false);
        let last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());

        let (job, (witness_id, witness_bytes)) = builder
            .get_agg_guta_register_users_deploy_contracts_job(&last_committed, &sample_fingerprint_config())
            .unwrap();

        let expected_root_output = QProvingJobDataID::new_invalid_job_id().get_output_id();
        assert_eq!(job.job_id, QProvingJobDataID::block_agg_state_part_1_input_witness(100, 0).get_output_id().get_output_id());
        assert_eq!(witness_id, QProvingJobDataID::block_agg_state_part_1_input_witness(100, 0).get_output_id().get_input_witness_id());
        assert_eq!(job.metadata.dependencies, vec![expected_root_output, expected_root_output, expected_root_output, expected_root_output]);
        assert_eq!(job.metadata.reward_tree_node_index, 0);
        assert_eq!(job.metadata.reward_tree_node_level, 1);
        assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN);
        assert_eq!(job.metadata.reward_tree_node_children, 4);
        assert!(!witness_bytes.is_empty());

        // the witness used for the job is retained on the builder
        let witness = builder.agg_state_part_1_witness.as_ref().unwrap();
        assert_eq!(witness.guta_proof_header.guta_circuit_whitelist, zh(21));
    }

    /// Builds a checkpoint tree whose leaf at index 0 matches the old leaf
    /// derived from `stats` and the gatherer start roots, exactly like the
    /// witness's own consistency check computes it.
    fn consistent_tree_and_stats() -> (PsyDashMemoryAppendOnlyMerkleStore<PoseidonHasher, PHash>, PQEDCheckpointLeafStats<PF, PHash>, PHash) {
        let stats = PQEDCheckpointLeafStats::<PF, PHash>::qp_rand_gen();
        let old_state_roots = PQEDCheckpointGlobalStateRoots::<PHash> {
            contract_tree_root: zh(5),
            deposit_tree_root: PoseidonHasher::get_zero_hash(TODO_DEPOSIT_TREE_HEIGHT as usize),
            user_tree_root: zh(1),
            withdrawal_tree_root: PoseidonHasher::get_zero_hash(TODO_WITHDRAWAL_TREE_HEIGHT as usize),
            user_registration_tree_root: zh(3),
        };
        let old_leaf = PQEDCheckpointLeaf::<PF, PHash> {
            global_chain_root: old_state_roots.qfhash::<PoseidonHasher>(),
            stats: stats.clone(),
        };
        let old_leaf_hash = old_leaf.qfhash::<PoseidonHasher>();

        let tree = PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(32);
        tree.append_leaf(0, old_leaf_hash).unwrap();
        (tree, stats, old_leaf_hash)
    }

    #[test]
    fn checkpoint_witness_accepts_a_consistent_tree_and_rejects_a_stale_one() {
        let (tree, stats, old_leaf_hash) = consistent_tree_and_stats();
        let last_committed = sample_last_committed(stats.clone());
        let fingerprint_config = sample_fingerprint_config();
        let builder = make_builder(false);

        let witness = builder
            .get_checkpoint_state_transition_witness(0, 1, &tree, &last_committed, &fingerprint_config, zh(50), zh(60), 999)
            .unwrap();

        assert_eq!(witness.previous_checkpoint_proof.value, old_leaf_hash);
        assert_eq!(witness.append_checkpoint_tree_proof.index, 1);
        assert_eq!(witness.append_checkpoint_tree_proof.old_value, PHash::get_zero_value());
        // the append proof is self-consistent: folding the new leaf hash over
        // the recorded siblings at the append index reproduces the new root
        assert_eq!(
            witness.append_checkpoint_tree_proof.new_root,
            compute_root_merkle_proof_generic::<PHash, PoseidonHasher>(
                witness.append_checkpoint_tree_proof.new_value,
                1,
                &witness.append_checkpoint_tree_proof.siblings,
            )
        );
        assert_eq!(witness.last_old_checkpoint_tree_leaf_hash, last_committed.checkpoint_state_transition.old_checkpoint_leaf_hash);
        assert_eq!(witness.last_old_checkpoint_tree_root_hash, last_committed.checkpoint_state_transition.old_checkpoint_tree_root);
        assert_eq!(witness.previous_chain_hash, last_committed.last_chain_hash);
        assert_eq!(witness.genesis_checkpoint_state_transition_hash, zh(60));
        assert_eq!(witness.checkpoint_state_transition_circuit_fingerprint, zh(25));
        assert_eq!(witness.partial.block_time, PF::from_u64_value(999));
        assert_eq!(witness.partial.final_random_seed_contribution, zh(51));
        assert_eq!(witness.partial.old_stats.random_seed, stats.random_seed);

        // a stale tree (leaf built from different stats) must be rejected
        let stale_last_committed = sample_last_committed(PQEDCheckpointLeafStats::qp_rand_gen());
        let err = builder
            .get_checkpoint_state_transition_witness(0, 1, &tree, &stale_last_committed, &fingerprint_config, zh(50), zh(60), 999)
            .unwrap_err();
        assert!(err.to_string().contains("old leaf mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn checkpoint_transition_job_metadata_and_sibling_capture() {
        let (tree, stats, _old_leaf_hash) = consistent_tree_and_stats();
        let last_committed = sample_last_committed(stats);
        let fingerprint_config = sample_fingerprint_config();
        let mut builder = make_builder(false);

        let reference = builder
            .get_checkpoint_state_transition_witness(0, 1, &tree, &last_committed, &fingerprint_config, zh(50), zh(60), 999)
            .unwrap();
        let expected_siblings = reference.append_checkpoint_tree_proof.siblings.clone();

        let (job, (witness_id, witness_bytes)) = builder
            .get_checkpoint_state_transition_job(0, 1, &tree, &last_committed, &fingerprint_config, zh(50), zh(60), 999)
            .unwrap();

        assert_eq!(
            job.job_id,
            QProvingJobDataID::get_checkpoint_state_transition_job_id(5).get_output_id().get_output_id()
        );
        assert_eq!(
            witness_id,
            QProvingJobDataID::get_checkpoint_state_transition_job_id(5).get_output_id().get_input_witness_id()
        );
        let expected_agg_dep = QProvingJobDataID::block_agg_state_part_1_input_witness(100, 0).get_output_id().get_output_id();
        let expected_last_dep = QProvingJobDataID::get_checkpoint_state_transition_job_id(4).get_output_id().get_output_id().get_output_id();
        assert_eq!(job.metadata.dependencies, vec![expected_agg_dep, expected_last_dep]);
        assert_eq!(job.metadata.reward_tree_node_index, 0);
        assert_eq!(job.metadata.reward_tree_node_level, 0);
        assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD);
        assert_eq!(job.metadata.reward_tree_node_children, 2);
        assert!(!witness_bytes.is_empty());

        // the siblings needed to append the new checkpoint leaf are captured
        assert_eq!(builder.append_checkpoint_tree_siblings, expected_siblings);
    }
}
