use parth_core::{crypto::hash::traits::MerkleZeroHasher, pgoldilocks::QHashOut};
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
    guta::realm_finalize::VALIDATOR_TREE_HEIGHT,
    protocol::circuit_inputs::checkpoint_transition::CHECKPOINT_RANDOM_SEED_DOMAIN,
    v1::qdata::checkpoint::PQEDCheckpointLeafStats,
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers,
};
use psy_plonky2_common_circuits::traits::CreatableTarget;

use crate::{
    coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,
    gadgets::{qdata::{
        checkpoint::QEDCheckpointLeafGadget, checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget,
        checkpoint_stats::QEDCheckpointLeafStatsGadget, pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
        pm_reward_commitment::PMRewardCommitmentGadget,
    }, tag_tree::hash_tag_tree_node_single_circuit},
};

pub fn derive_checkpoint_random_seed_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, old_seed: HashOutTarget, new_state_roots_hash: HashOutTarget) -> HashOutTarget {
    let domain = builder.constant(F::from_canonical_u64(CHECKPOINT_RANDOM_SEED_DOMAIN));
    let old = old_seed.elements;
    let roots = new_state_roots_hash.elements;
    builder.hash_n_to_hash_no_pad::<H>(vec![domain, old[0], old[1], old[2], old[3], roots[0], roots[1], roots[2], roots[3]])
}

#[derive(Debug, Clone)]
pub struct QEDPart1StateDeltaResultGadget {
    pub part_1_header: VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,

    pub old_stats: QEDCheckpointLeafStatsGadget,
    pub block_time: Target,
    pub validator_tree_root: HashOutTarget,

    // computed
    pub old_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub new_state_roots: QEDCheckpointGlobalStateRootsGadget,
    pub new_stats: QEDCheckpointLeafStatsGadget,
    pub old_checkpoint_leaf: QEDCheckpointLeafGadget,
    pub new_checkpoint_leaf: QEDCheckpointLeafGadget,
}

impl QEDPart1StateDeltaResultGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<QHashOut<F>>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, part_1_worker_reward_tree_value: HashOutTarget, worker_rewards_tree_tag: HashOutTarget) -> Self {
       
        let part_1_header = VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget::add_virtual_to(builder);

        // TODO: add deposits and withdrawals, for now just leave with constant hashes
        let todo_add_deposits_root = builder.constant_qhash(QHashOut::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        ));
        let todo_add_withdrawals_root = builder.constant_qhash(QHashOut::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        ));
        let validator_tree_root = builder.add_virtual_hash();
        let old_state_roots = QEDCheckpointGlobalStateRootsGadget {
            contract_tree_root: part_1_header.global_contract_tree_delta.state_transition_start,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: part_1_header.global_user_tree_delta.state_transition.old_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: part_1_header.user_registration_tree_delta.state_transition_start,
            validator_tree_root,
        };
        let new_state_roots = QEDCheckpointGlobalStateRootsGadget {
            contract_tree_root: part_1_header.global_contract_tree_delta.state_transition_end,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: part_1_header.global_user_tree_delta.state_transition.new_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: part_1_header.user_registration_tree_delta.state_transition_end,
            validator_tree_root,
        };

        let old_stats = QEDCheckpointLeafStatsGadget::create_virtual(builder);
        let block_time = builder.add_virtual_target();

        let old_state_roots_hash = old_state_roots.to_hash::<H, F, D>(builder);
        let new_state_roots_hash = new_state_roots.to_hash::<H, F, D>(builder);
        let random_seed = derive_checkpoint_random_seed_target::<H, F, D>(builder, old_stats.random_seed, new_state_roots_hash);

        let zero = builder.zero();

        let rewards_tree_tag_tree_root = hash_tag_tree_node_single_circuit::<H, F, D>(builder, part_1_worker_reward_tree_value, worker_rewards_tree_tag);

        let new_stats = QEDCheckpointLeafStatsGadget {
            guta_fees_collected: part_1_header.global_user_tree_delta.stats.guta_fees_collected,
            da_fees_collected: part_1_header.global_user_tree_delta.stats.da_fees_collected,
            user_ops_processed: part_1_header.global_user_tree_delta.stats.user_ops_processed,
            total_transactions: part_1_header.global_user_tree_delta.stats.total_transactions,
            slots_modified: part_1_header.global_user_tree_delta.stats.slots_modified,
            pm_jobs_completed: part_1_header.combined_pm_jobs_completed,
            block_time,
            random_seed,
            pm_rewards_commitment: PMRewardCommitmentGadget {
                register_users_root: rewards_tree_tag_tree_root,
                gutas_root: rewards_tree_tag_tree_root,
                deploy_contracts_root: rewards_tree_tag_tree_root,
            },
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

        builder.ensure_is_greater_than(60, block_time, old_stats.block_time);

        Self {
            part_1_header,
            old_state_roots,
            new_state_roots,
            old_stats,
            block_time,
            validator_tree_root,
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
        deploy_contracts_completed: F,
        register_users_completed: F,
        old_stats: &PQEDCheckpointLeafStats<F, QHashOut<F>>,
        block_time: F,
        validator_tree_root: QHashOut<F>,
    ) -> anyhow::Result<()> {
        self.part_1_header
            .set_witness_params(witness, user_registration_tree_delta, global_contract_tree_delta, global_user_tree_delta, deploy_contracts_completed, register_users_completed)?;
        self.old_stats.set_witness(witness, old_stats)?;
        witness.set_target(self.block_time, block_time)?;
        witness.set_hash_target(self.validator_tree_root, validator_tree_root.0)?;
        Ok(())
    }
}

// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct CheckpointStateTransitionChildProofsGadget<const D: usize> {
    pub part_1_verifier_data: VerifierCircuitTarget,
    pub part_1_worker_reward_tree_value: HashOutTarget,
    pub part_1_proof_target: ProofWithPublicInputsTarget<D>,
    pub state_delta_gadget: QEDPart1StateDeltaResultGadget,
}

impl<const D: usize> CheckpointStateTransitionChildProofsGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        part_1_common_data: &CommonCircuitData<F, D>,
        part_1_common_data_verifier_data_cap_height: usize,
        known_part_1_fingerprint: QHashOut<C::F>,
        worker_rewards_tree_tag: HashOutTarget,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F> + MerkleZeroHasher<QHashOut<F>>,
    {
        let part_1_verifier_data = builder.add_virtual_verifier_data(part_1_common_data_verifier_data_cap_height);
        let part_1_proof_target = builder.add_virtual_proof_with_pis(part_1_common_data);

        builder.verify_proof::<C>(&part_1_proof_target, &part_1_verifier_data, part_1_common_data);

        let part_1_worker_reward_tree_value = builder.add_virtual_hash();

        let part_1_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&part_1_verifier_data);
        let expected_part_1_fingerprint = builder.constant_qhash(known_part_1_fingerprint);
        builder.connect_hashes(part_1_fingerprint, expected_part_1_fingerprint);

        let state_delta_gadget =
            QEDPart1StateDeltaResultGadget::add_virtual_to::<C::Hasher, C::F, D>(builder, part_1_worker_reward_tree_value, worker_rewards_tree_tag);

        
        let expected_part_1_public_inputs_hash = state_delta_gadget.part_1_header.get_expected_public_inputs_hash::<C::Hasher, C::F, D>(builder, part_1_worker_reward_tree_value);

        let actual_part_1_public_inputs_hash = HashOutTarget {
            elements: [
                part_1_proof_target.public_inputs[0],
                part_1_proof_target.public_inputs[1],
                part_1_proof_target.public_inputs[2],
                part_1_proof_target.public_inputs[3],
            ],
        };

        builder.connect_hashes(expected_part_1_public_inputs_hash, actual_part_1_public_inputs_hash);

        Self {
            part_1_worker_reward_tree_value,
            part_1_verifier_data,
            part_1_proof_target,
            state_delta_gadget,
        }
    }
    pub fn get_pm_jobs_completed(&self) -> PMJobsCompletedStatsGadget {
        self.state_delta_gadget.new_stats.pm_jobs_completed
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        user_registration_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_contract_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_user_tree_delta: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        deploy_contracts_completed: F,
        register_users_completed: F,
        old_stats: &PQEDCheckpointLeafStats<F, QHashOut<F>>,
        block_time: F,
        validator_tree_root: QHashOut<F>,
        part_1_worker_reward_tree_value: QHashOut<F>,
        part_1_proof: &ProofWithPublicInputs<F, C, D>,
        part_1_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        witness.set_hash_target(self.part_1_worker_reward_tree_value, part_1_worker_reward_tree_value.0)?;
        witness.set_verifier_data_target::<C, D>(&self.part_1_verifier_data, part_1_verifier_data)?;
        witness.set_proof_with_pis_target::<C, D>(&self.part_1_proof_target, part_1_proof)?;
        self.state_delta_gadget.set_witness_params(
            witness,
            user_registration_tree_delta,
            global_contract_tree_delta,
            global_user_tree_delta,
            deploy_contracts_completed,
            register_users_completed,
            old_stats,
            block_time,
            validator_tree_root,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod random_seed_tests {
    use super::*;
    use parth_core::{pgoldilocks::PoseidonHasher, PF};
    use parth_core::crypto::hash::traits::QFieldHashable as NodeQFieldHashable;
    use psy_crypto::hash::traits::qhashable::QFieldHashable as ClientQFieldHashable;
    use plonky2::field::extension::FieldExtension;
    use plonky2::{field::{extension::quadratic::QuadraticExtension, types::Field}, gates::{gate::Gate, poseidon::PoseidonGate}, hash::{hash_types::HashOut, poseidon::PoseidonHash}, iop::{generator::generate_partial_witness, witness::{PartialWitness, WitnessWrite}}, plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig, vars::EvaluationVars}};
    use psy_data::protocol::circuit_inputs::checkpoint_transition::derive_checkpoint_random_seed;

    #[test]
    fn random_seed_node_time_and_reward_independence() {
        use parth_core::utils::QPGenRandom;
        use psy_data::{protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInputPartial, v1::qdata::{pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment}};
        let mut input = QCQEDCheckpointStateTransitionInputPartial::<PF, QHashOut<PF>>::qp_rand_gen();
        let original = input.get_new_checkpoint_leaf::<PoseidonHasher>(QHashOut::qp_rand_gen());
        input.block_time = PF::qp_rand_gen();
        input.pm_jobs_completed = PPMJobsCompletedStats::qp_rand_gen();
        input.old_stats.pm_rewards_commitment = PPMRewardCommitment::qp_rand_gen();
        input.part_1_header.guta_proof_header.stats.guta_fees_collected = PF::qp_rand_gen();
        input.part_1_header.guta_proof_header.stats.da_fees_collected = PF::qp_rand_gen();
        let changed = input.get_new_checkpoint_leaf::<PoseidonHasher>(QHashOut::qp_rand_gen());
        assert_eq!(original.global_chain_root, changed.global_chain_root);
        assert_eq!(original.stats.random_seed, changed.stats.random_seed);
        let mut client = psy_client_data::protocol::circuit_inputs::checkpoint_transition::QCPsyCheckpointStateTransitionInputPartial::<PF>::default();
        let original = client.get_new_checkpoint_leaf::<PoseidonHash>();
        client.block_time = PF::from_canonical_u64(123);
        client.pm_jobs_completed.deploy_contracts_completed = PF::ONE;
        client.pm_rewards_commitment.register_users_root = psy_client_common::data::qhashout::QHashOut(HashOut { elements: [PF::ONE; 4] });
        client.part_1_header.guta_proof_header.stats.guta_fees_collected = PF::ONE;
        client.part_1_header.guta_proof_header.stats.da_fees_collected = PF::ONE;
        let changed = client.get_new_checkpoint_leaf::<PoseidonHash>();
        assert_eq!(original.global_chain_root, changed.global_chain_root);
        assert_eq!(original.stats.random_seed, changed.stats.random_seed);
    }

    #[test]
    fn random_seed_native_circuit_equality_and_replaced_seed_rejection() -> anyhow::Result<()> {
        let old = QHashOut(HashOut { elements: [1, 2, 3, 4].map(PF::from_canonical_u64) });
        let roots = QHashOut(HashOut { elements: [5, 6, 7, 8].map(PF::from_canonical_u64) });
        let expected = derive_checkpoint_random_seed::<PF, QHashOut<PF>, PoseidonHasher>(old, roots);
        assert_eq!(
            expected.0.elements,
            [0x3fa86564640496ebu64, 0x6dec7f0c86d49a9b, 0xa25eb3f99503eaeb, 0xcc2289274427ca26].map(PF::from_canonical_u64),
            "the pinned seed vector changed; regenerate it and resync the psy_data behavior test"
        );
        let mut builder = CircuitBuilder::<PF, 2>::new(CircuitConfig::standard_recursion_config());
        let old_target = builder.add_virtual_hash();
        let roots_target = builder.add_virtual_hash();
        let seed = derive_checkpoint_random_seed_target::<PoseidonHash, PF, 2>(&mut builder, old_target, roots_target);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let mut inputs = PartialWitness::new();
        inputs.set_hash_target(old_target, old.0)?;
        inputs.set_hash_target(roots_target, roots.0)?;
        let witness = generate_partial_witness(inputs, &data.prover_only, &data.common)?;
        assert_eq!(witness.get_hash_target(seed), expected.0);
        let Target::Wire(output_wire) = seed.elements[0] else { panic!("seed must be a Poseidon output wire") };
        let gate = PoseidonGate::<PF, 2>::new();
        let mut wires: Vec<QuadraticExtension<PF>> = (0..gate.num_wires()).map(|column| <QuadraticExtension<PF> as FieldExtension<2>>::from_basefield(witness.get_target(Target::wire(output_wire.row, column)))).collect();
        let public_inputs_hash = HashOut::ZERO;
        assert!(gate.eval_unfiltered(EvaluationVars { local_constants: &[], local_wires: &wires, public_inputs_hash: &public_inputs_hash }).iter().all(|value| value.is_zero()));
        wires[output_wire.column] += QuadraticExtension::ONE;
        assert!(gate.eval_unfiltered(EvaluationVars { local_constants: &[], local_wires: &wires, public_inputs_hash: &public_inputs_hash }).iter().any(|value| !value.is_zero()));
        Ok(())
    }

    #[test]
    fn random_seed_node_client_twins_match() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..128 {
            let old = HashOut { elements: std::array::from_fn(|_| PF::from_noncanonical_u64(rng.gen())) };
            let roots = HashOut { elements: std::array::from_fn(|_| PF::from_noncanonical_u64(rng.gen())) };
            let node = derive_checkpoint_random_seed::<PF, QHashOut<PF>, PoseidonHasher>(QHashOut(old), QHashOut(roots));
            let client = psy_client_data::protocol::circuit_inputs::checkpoint_transition::derive_checkpoint_random_seed::<PF, PoseidonHash>(psy_client_common::data::qhashout::QHashOut(old), psy_client_common::data::qhashout::QHashOut(roots));
            assert_eq!(node.0, client.0);
        }
    }

    #[test]
    fn checkpoint_leaf_twins_agree_in_empty_validator_tree_domain() {
        use parth_core::crypto::hash::traits::MerkleZeroHasher;
        use parth_core::utils::QPGenRandom;
        use psy_client_data::qdata::pm_jobs_completed_stats::PMJobsCompletedStats as ClientPMJobs;
        use psy_client_data::qdata::pm_reward_commitment::PMRewardCommitment as ClientRewards;
        use psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT;
        use psy_data::protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInputPartial;

        type H = QHashOut<PF>;
        let contract_root = H::qp_rand_gen();
        let reward_root = H::qp_rand_gen();
        let mut node = QCQEDCheckpointStateTransitionInputPartial::<PF, H>::qp_rand_gen();
        node.validator_tree_root = PoseidonHasher::get_zero_hash(VALIDATOR_TREE_HEIGHT);
        node.part_1_header.deploy_contracts_state_transition.state_transition_end = contract_root;
        node.part_1_header.update_contracts_state_transition.state_transition_end = contract_root;
        let node_leaf = node.get_new_checkpoint_leaf::<PoseidonHasher>(reward_root);

        let mut client = psy_client_data::protocol::circuit_inputs::checkpoint_transition::QCPsyCheckpointStateTransitionInputPartial::<PF>::default();
        client.part_1_header.deploy_contracts_state_transition.state_transition_end = psy_client_common::data::qhashout::QHashOut(contract_root.0);
        client.part_1_header.register_users_state_transition.state_transition_end = psy_client_common::data::qhashout::QHashOut(node.part_1_header.register_users_state_transition.state_transition_end.0);
        client.part_1_header.guta_proof_header.state_transition.new_node_value = psy_client_common::data::qhashout::QHashOut(node.part_1_header.guta_proof_header.state_transition.new_node_value.0);
        client.part_1_header.guta_proof_header.stats.guta_fees_collected = node.part_1_header.guta_proof_header.stats.guta_fees_collected;
        client.part_1_header.guta_proof_header.stats.da_fees_collected = node.part_1_header.guta_proof_header.stats.da_fees_collected;
        client.part_1_header.guta_proof_header.stats.user_ops_processed = node.part_1_header.guta_proof_header.stats.user_ops_processed;
        client.part_1_header.guta_proof_header.stats.total_transactions = node.part_1_header.guta_proof_header.stats.total_transactions;
        client.part_1_header.guta_proof_header.stats.slots_modified = node.part_1_header.guta_proof_header.stats.slots_modified;
        client.old_stats.random_seed = psy_client_common::data::qhashout::QHashOut(node.old_stats.random_seed.0);
        client.pm_jobs_completed = ClientPMJobs {
            deploy_contracts_completed: node.pm_jobs_completed.deploy_contracts_completed,
            register_users_completed: node.pm_jobs_completed.register_users_completed,
            gutas_completed: node.pm_jobs_completed.gutas_completed,
        };
        client.block_time = node.block_time;
        client.pm_rewards_commitment = ClientRewards {
            register_users_root: psy_client_common::data::qhashout::QHashOut(reward_root.0),
            gutas_root: psy_client_common::data::qhashout::QHashOut(reward_root.0),
            deploy_contracts_root: psy_client_common::data::qhashout::QHashOut(reward_root.0),
        };
        let client_leaf = client.get_new_checkpoint_leaf::<PoseidonHash>();
        assert_eq!(node_leaf.qfhash::<PoseidonHasher>().0, client_leaf.qfhash::<PoseidonHash>().0);
    }
}
