use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use psy_data::{
    agg::AggStateTransition,
    guta::header::GlobalUserTreeAggregatorHeader,
    v1::qdata::{checkpoint::PQEDCheckpointLeafStats, pm_rewards_commitment::PPMRewardCommitment},
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers,
};
use psy_plonky2_common_circuits::traits::CreatableTarget;

use crate::{
    coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,
    gadgets::qdata::{
        checkpoint::QEDCheckpointLeafGadget, checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget,
        checkpoint_stats::QEDCheckpointLeafStatsGadget, pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
        pm_reward_commitment::PMRewardCommitmentGadget,
    },
};

#[derive(Debug, Clone)]
pub struct QEDPart1StateDeltaResultGadget {
    pub part_1_header: VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,

    pub old_stats: QEDCheckpointLeafStatsGadget,
    pub block_time: Target,
    pub final_random_seed_contribution: HashOutTarget,
    pub pm_rewards_commitment: PMRewardCommitmentGadget,

    // computed
    pub old_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub new_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub new_stats: QEDCheckpointLeafStatsGadget,
    pub old_checkpoint_leaf: QEDCheckpointLeafGadget,
    pub new_checkpoint_leaf: QEDCheckpointLeafGadget,
}

impl QEDPart1StateDeltaResultGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let empty_pm_jobs = PMJobsCompletedStatsGadget::new_empty(builder);
        Self::add_virtual_to_with_pm_jobs::<H, F, D>(builder, empty_pm_jobs)
    }

    pub fn add_virtual_to_with_pm_jobs<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        pm_jobs_completed: PMJobsCompletedStatsGadget,
    ) -> Self {
        let part_1_header = VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget::add_virtual_to(builder);

        // TODO: add deposits and withdrawals, for now just leave with constant hashes
        let todo_add_deposits_root = builder.constant_qhash(QHashOut::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        ));
        let todo_add_withdrawals_root = builder.constant_qhash(QHashOut::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        ));
        let old_state_roots = QEDCheckpointGlobalStateRootsGadget {
            contract_tree_root: part_1_header.global_contract_tree_delta.state_transition_start,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: part_1_header.global_user_tree_delta.state_transition.old_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: part_1_header.user_registration_tree_delta.state_transition_start,
        };
        let new_state_roots = QEDCheckpointGlobalStateRootsGadget {
            contract_tree_root: part_1_header.global_contract_tree_delta.state_transition_end,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: part_1_header.global_user_tree_delta.state_transition.new_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: part_1_header.user_registration_tree_delta.state_transition_end,
        };

        let old_stats = QEDCheckpointLeafStatsGadget::create_virtual(builder);
        let block_time = builder.add_virtual_target();
        let final_random_seed_contribution = builder.add_virtual_hash();
        let pm_rewards_commitment = PMRewardCommitmentGadget::create_virtual(builder);

        let old_state_roots_hash = old_state_roots.to_hash::<H, F, D>(builder);
        let new_state_roots_hash = new_state_roots.to_hash::<H, F, D>(builder);

        let zero = builder.zero();

        let new_stats = QEDCheckpointLeafStatsGadget {
            fees_collected: part_1_header.global_user_tree_delta.stats.fees_collected,
            user_ops_processed: part_1_header.global_user_tree_delta.stats.user_ops_processed,
            total_transactions: part_1_header.global_user_tree_delta.stats.total_transactions,
            slots_modified: part_1_header.global_user_tree_delta.stats.slots_modified,
            pm_jobs_completed: pm_jobs_completed,
            block_time,
            random_seed: builder.hash_two_to_one::<H>(old_stats.random_seed, final_random_seed_contribution),
            pm_rewards_commitment,
            da_challenges_claimed: [zero; DA_CHALLENGE_WINDOW],
        };

        let old_checkpoint_leaf = QEDCheckpointLeafGadget {
            stats: old_stats,
            global_chain_root: old_state_roots_hash,
        };
        let new_checkpoint_leaf = QEDCheckpointLeafGadget {
            stats: new_stats,
            global_chain_root: new_state_roots_hash,
        };

        // ensure new block time is after old block
        builder.ensure_is_greater_than(60, block_time, old_stats.block_time);

        Self {
            part_1_header,
            old_state_roots,
            new_state_roots,
            old_stats,
            block_time,
            final_random_seed_contribution,
            pm_rewards_commitment,
            new_stats,
            old_checkpoint_leaf,
            new_checkpoint_leaf,
        }
    }

    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        user_registration_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_contract_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_user_tree_delta: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        old_stats: &PQEDCheckpointLeafStats<F, QHashOut<F>>,
        block_time: F,
        final_random_seed_contribution: QHashOut<F>,
        pm_rewards_commitment: &PPMRewardCommitment<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.part_1_header
            .set_witness_params(witness, user_registration_tree_delta, global_contract_tree_delta, global_user_tree_delta)?;
        self.old_stats.set_witness(witness, old_stats)?;
        witness.set_target(self.block_time, block_time)?;
        witness.set_hash_target(self.final_random_seed_contribution, final_random_seed_contribution.0)?;
        self.pm_rewards_commitment.set_witness(witness, pm_rewards_commitment)?;
        Ok(())
    }
}

// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct CheckpointStateTransitionChildProofsGadget<const D: usize> {
    pub part_1_verifier_data: VerifierCircuitTarget,
    pub part_1_proof_target: ProofWithPublicInputsTarget<D>,
    pub state_delta_gadget: QEDPart1StateDeltaResultGadget,
    pub combined_pm_jobs_completed: PMJobsCompletedStatsGadget,
}

impl<const D: usize> CheckpointStateTransitionChildProofsGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        part_1_common_data: &CommonCircuitData<F, D>,
        part_1_common_data_verifier_data_cap_height: usize,
        known_part_1_fingerprint: QHashOut<C::F>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let part_1_verifier_data = builder.add_virtual_verifier_data(part_1_common_data_verifier_data_cap_height);
        let part_1_proof_target = builder.add_virtual_proof_with_pis(part_1_common_data);

        builder.verify_proof::<C>(&part_1_proof_target, &part_1_verifier_data, part_1_common_data);

        let part_1_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&part_1_verifier_data);
        let expected_part_1_fingerprint = builder.constant_qhash(known_part_1_fingerprint);
        builder.connect_hashes(part_1_fingerprint, expected_part_1_fingerprint);

        let combined_pm_jobs_completed_from_proof = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: part_1_proof_target.public_inputs[16],
            register_users_completed: part_1_proof_target.public_inputs[17],
            gutas_completed: part_1_proof_target.public_inputs[18],
        };

        let state_delta_gadget =
            QEDPart1StateDeltaResultGadget::add_virtual_to_with_pm_jobs::<C::Hasher, C::F, D>(builder, combined_pm_jobs_completed_from_proof);

        let part_1_header_hash = state_delta_gadget.part_1_header.get_combined_hash::<C::Hasher, C::F, D>(builder);

        let expected_part_1_header_hash = HashOutTarget {
            elements: [
                part_1_proof_target.public_inputs[0],
                part_1_proof_target.public_inputs[1],
                part_1_proof_target.public_inputs[2],
                part_1_proof_target.public_inputs[3],
            ],
        };

        builder.connect_hashes(part_1_header_hash, expected_part_1_header_hash);

        let register_users_root_from_proof = HashOutTarget {
            elements: [
                part_1_proof_target.public_inputs[4],
                part_1_proof_target.public_inputs[5],
                part_1_proof_target.public_inputs[6],
                part_1_proof_target.public_inputs[7],
            ],
        };
        let deploy_contracts_root_from_proof = HashOutTarget {
            elements: [
                part_1_proof_target.public_inputs[8],
                part_1_proof_target.public_inputs[9],
                part_1_proof_target.public_inputs[10],
                part_1_proof_target.public_inputs[11],
            ],
        };
        let gutas_root_from_proof = HashOutTarget {
            elements: [
                part_1_proof_target.public_inputs[12],
                part_1_proof_target.public_inputs[13],
                part_1_proof_target.public_inputs[14],
                part_1_proof_target.public_inputs[15],
            ],
        };

        builder.connect_hashes(
            state_delta_gadget.pm_rewards_commitment.register_users_root,
            register_users_root_from_proof,
        );
        builder.connect_hashes(
            state_delta_gadget.pm_rewards_commitment.deploy_contracts_root,
            deploy_contracts_root_from_proof,
        );
        builder.connect_hashes(state_delta_gadget.pm_rewards_commitment.gutas_root, gutas_root_from_proof);

        Self {
            part_1_verifier_data,
            part_1_proof_target,
            state_delta_gadget,
            combined_pm_jobs_completed: combined_pm_jobs_completed_from_proof,
        }
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        user_registration_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_contract_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_user_tree_delta: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        old_stats: &PQEDCheckpointLeafStats<F, QHashOut<F>>,
        block_time: F,
        final_random_seed_contribution: QHashOut<F>,
        pm_rewards_commitment: &PPMRewardCommitment<QHashOut<F>>,
        part_1_proof: &ProofWithPublicInputs<F, C, D>,
        part_1_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        witness.set_verifier_data_target::<C, D>(&self.part_1_verifier_data, part_1_verifier_data)?;
        witness.set_proof_with_pis_target::<C, D>(&self.part_1_proof_target, part_1_proof)?;
        self.state_delta_gadget.set_witness_params(
            witness,
            user_registration_tree_delta,
            global_contract_tree_delta,
            global_user_tree_delta,
            old_stats,
            block_time,
            final_random_seed_contribution,
            pm_rewards_commitment,
        )?;

        Ok(())
    }
}
