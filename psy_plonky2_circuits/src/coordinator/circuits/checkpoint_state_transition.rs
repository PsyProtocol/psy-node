use async_trait::async_trait;
use parth_core::{crypto::hash::{tag_tree::hash_tag_tree_node_single, traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable}}, data::proof_input::CircuitInputWithDependencies, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::{Q256BitHash, QFHashBase}};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{self, PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{protocol::{checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs}, circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput}, v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,

};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{coordinator::gadgets::{checkpoint_state_transition::CheckpointStateTransitionPublicInputsGadget, recursive_checkpoint_state_transition_verify::VerifyRecursiveCheckpointStateTransitionProofGadget}, proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic}, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithRawProofsAndRefLibrary, proof_store::QProofStoreReaderAsync}, utils::proof_serialization::deserialize_plonky2_proof};

use crate::coordinator::gadgets::{
    checkpoint_state_transition::CheckpointStateTransitionCoreGadget,
    checkpoint_state_transition_proofs::CheckpointStateTransitionChildProofsGadget,
};

#[derive(Debug)]
pub struct QEDCheckpointStateTransitionCircuit<C: GenericConfig<D>, const D: usize> {
    pub child_proofs_gadget: CheckpointStateTransitionChildProofsGadget<D>,
    pub verify_previous_checkpoint_proof_gadget: VerifyRecursiveCheckpointStateTransitionProofGadget<D>,
    pub core_checkpoint_gadget: CheckpointStateTransitionCoreGadget,
    pub worker_rewards_tree_tag_target: HashOutTarget,
    pub genesis_checkpoint_state_transition_hash: HashOutTarget,
    pub checkpoint_state_transition_circuit_fingerprint: HashOutTarget,

    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,

    pub minifier_chain: Option<QEDProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for QEDCheckpointStateTransitionCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GenerateRollupStateTransitionProof
    }
}
impl<C: GenericConfig<D>, const D: usize> QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        part_1_common_data: &CommonCircuitData<C::F, D>,
        part_1_verifier_data_cap_height: usize,
        known_part_1_fingerprint: QHashOut<C::F>,
        checkpoint_state_transition_genesis_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_state_transition_genesis_verifier_data_cap_height: usize,
        known_checkpoint_state_transition_genesis_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
    ) -> Self {
        Self::new_with_config(part_1_common_data, part_1_verifier_data_cap_height, known_part_1_fingerprint, checkpoint_state_transition_genesis_common_data, checkpoint_state_transition_genesis_verifier_data_cap_height, known_checkpoint_state_transition_genesis_fingerprint, checkpoint_tree_height, true)
    }
    pub fn new_with_config(
        part_1_common_data: &CommonCircuitData<C::F, D>,
        part_1_verifier_data_cap_height: usize,
        known_part_1_fingerprint: QHashOut<C::F>,
        checkpoint_state_transition_genesis_common_data: &CommonCircuitData<C::F, D>,
        checkpoint_state_transition_genesis_verifier_data_cap_height: usize,
        known_checkpoint_state_transition_genesis_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,

        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let child_proofs_gadget =
            CheckpointStateTransitionChildProofsGadget::<D>::add_virtual_to::<C, C::F>(
                &mut builder,
                part_1_common_data,
                part_1_verifier_data_cap_height,
                known_part_1_fingerprint,
                worker_rewards_tree_tag_target,
            );
        let core_checkpoint_gadget = CheckpointStateTransitionCoreGadget::add_virtual_to::<
            C::Hasher,
            C::F,
            D,
        >(&mut builder, checkpoint_tree_height);

        let expected_old_leaf_hash = child_proofs_gadget.state_delta_gadget.old_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let expected_new_leaf_hash = child_proofs_gadget.state_delta_gadget.new_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let expected_old_checkpoint_root = child_proofs_gadget.state_delta_gadget.part_1_header.global_user_tree_delta.checkpoint_tree_root;

        let core_gadget_old_leaf_hash = core_checkpoint_gadget.checkpoint_hash_transition.old_checkpoint_leaf_hash;
        let core_gadget_new_leaf_hash = core_checkpoint_gadget.checkpoint_hash_transition.new_checkpoint_leaf_hash;
        let core_gadget_old_checkpoint_root = core_checkpoint_gadget.checkpoint_hash_transition.old_checkpoint_tree_root;
        builder.connect_hashes(
            expected_old_leaf_hash,
            core_gadget_old_leaf_hash,
        );
        builder.connect_hashes(
            expected_new_leaf_hash,
            core_gadget_new_leaf_hash,
        );

        builder.connect_hashes(
            expected_old_checkpoint_root,
            core_gadget_old_checkpoint_root,
        );

        let new_checkpoint_root = core_checkpoint_gadget.checkpoint_hash_transition.new_checkpoint_tree_root;

        tracing::debug!("🏛️ Checkpoint State Transition - new_checkpoint_root: {:?}", new_checkpoint_root);
        //let combo_hash = builder.hash_two_to_one::<C::Hasher>(expected_old_checkpoint_root, new_checkpoint_root);

        let checkpoint_state_transition_circuit_fingerprint = builder.add_virtual_hash();
        let genesis_checkpoint_state_transition_hash = builder.add_virtual_hash();
        let public_inputs_gadget = CheckpointStateTransitionPublicInputsGadget {
            checkpoint_transition: core_checkpoint_gadget.checkpoint_hash_transition,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        };

        let checkpoint_id = core_checkpoint_gadget.append_checkpoint_tree_proof.index;

        let verify_previous_checkpoint_proof_gadget = VerifyRecursiveCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            checkpoint_state_transition_genesis_common_data,
            checkpoint_state_transition_genesis_verifier_data_cap_height,
            known_checkpoint_state_transition_genesis_fingerprint,
            public_inputs_gadget,
            checkpoint_id
        );
        let public_inputs_hash = public_inputs_gadget.get_public_inputs_hash_no_rewards_tag::<C::Hasher, C::F, D>(&mut builder);


        builder.register_public_inputs(&public_inputs_hash.elements);
        //builder.register_public_inputs(&public_inputs_gadget.genesis_checkpoint_state_transition_hash.elements);
        //builder.register_public_inputs(&public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint.elements);

        builder.add_qed_type_d_common_gates();
        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(&base_circuit_data.verifier_only));

        let minifier_chain = if has_minifier {
            Some(QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &base_circuit_data.verifier_only,
                &base_circuit_data.common,
                &[false, false],
            ))
        } else {
            None
        };
        Self {
            base_circuit_data,
            child_proofs_gadget,
            verify_previous_checkpoint_proof_gadget,
            core_checkpoint_gadget,
            worker_rewards_tree_tag_target,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &QCQEDCheckpointStateTransitionInput<C::F, QHashOut<C::F>>,
        part_1_worker_reward_tree_value: QHashOut<C::F>,
        part_1_proof: &ProofWithPublicInputs<C::F, C, D>,
        part_1_verifier_data: &VerifierOnlyCircuitData<C, D>,
        previous_checkpoint_state_transition_proof: &ProofWithPublicInputs<C::F, C, D>,
        previous_checkpoint_state_transition_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;
        pw.set_hash_target(self.genesis_checkpoint_state_transition_hash, input.genesis_checkpoint_state_transition_hash.0)?;
        pw.set_hash_target(self.checkpoint_state_transition_circuit_fingerprint, self.get_fingerprint().0)?;
        tracing::debug!("🏛️ Checkpoint State Transition prove_base - worker_rewards_tree_tag: {:?}, append_checkpoint_proof (index: {}, siblings_len: {}), previous_checkpoint_proof (index: {}, siblings_len: {})",
            worker_rewards_tree_tag,
            input.append_checkpoint_tree_proof.index, input.append_checkpoint_tree_proof.siblings.len(),
            input.previous_checkpoint_proof.index, input.previous_checkpoint_proof.siblings.len());

        self.child_proofs_gadget.set_witness_params(
            &mut pw,
            &input.partial.part_1_header.register_users_state_transition.get_agg_state_transition(),
            &input.partial.part_1_header.deploy_contracts_state_transition.get_agg_state_transition(),
            &input.partial.part_1_header.guta_proof_header,
            input.partial.pm_jobs_completed.deploy_contracts_completed,
            input.partial.pm_jobs_completed.register_users_completed,
            &input.partial.old_stats,
            input.partial.block_time,
            input.partial.final_random_seed_contribution,
            part_1_worker_reward_tree_value,
            part_1_proof,
            part_1_verifier_data,
        )?;

        self.core_checkpoint_gadget.set_witness_params(
            &mut pw,
            &input.append_checkpoint_tree_proof,
            &input.previous_checkpoint_proof,
        )?;
        self.verify_previous_checkpoint_proof_gadget.set_witness_params(
            &mut pw,
            input.last_old_checkpoint_tree_leaf_hash,
            input.last_old_checkpoint_tree_root_hash,
            previous_checkpoint_state_transition_proof,
            previous_checkpoint_state_transition_verifier_data,
        )?;
        let base_proof = self.base_circuit_data.prove(pw)?;

        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().prove(&base_proof)
        } else {
            Ok(base_proof)
        }
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.enable_minifier {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        } else {
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        } else {
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        } else {
            &self.base_circuit_data.common
        }
    }
}

#[async_trait]
impl<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash +QFHashBase<C::F>,
    C::F: QFelt64,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        input.ensure_expected_child_proof_count_with_tags(2)?;
        let mut witness = QCQEDCheckpointStateTransitionInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        //println!("witness: {:#?}", witness);
        //println!("genesis state transition hash: {:?} ({})", witness.genesis_checkpoint_state_transition_hash.0.elements, hex::encode(&witness.genesis_checkpoint_state_transition_hash.into_owned_32bytes()));
        //let expected_public_inputs_no_tag = witness.get_public_inputs_hash_with_fingerprint::<C::Hasher>(self.get_fingerprint());

        //println!("expected_public_inputs_no_tag: {:?} ({})", expected_public_inputs_no_tag.0.elements, hex::encode(&expected_public_inputs_no_tag.into_owned_32bytes()));
        //println!("expected_public_inputs_metadata: {:?} ({})", input.base.job.metadata.expected_public_inputs_hash.0.elements, hex::encode(&input.base.job.metadata.expected_public_inputs_hash.into_owned_32bytes()));

        let part_1_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[0])?;
        let part_1_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(0)?)?;
        let part_1_worker_reward_tree_value = input.base.child_proof_tag_values[0];
        //println!("part_1_proof_public_inputs: {:?} ({})", part_1_proof.public_inputs, hex::encode(&QHashOut::<C::F>::from_felt_slice(&part_1_proof.public_inputs).into_owned_32bytes()));
        //println!("part_1_worker_reward_tree_value: {:?} ({})", part_1_worker_reward_tree_value.0.elements, hex::encode(&part_1_worker_reward_tree_value.into_owned_32bytes()));

        let previous_checkpoint_state_transition_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[1])?;
        let previous_checkpoint_state_transition_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(1)?)?;

        /*
        let transition_circuit_fingerprint =self.get_fingerprint();

        let last_checkpoint_hash_transition = CheckpointStateHashTransition{
            old_checkpoint_tree_root: witness.last_old_checkpoint_tree_root_hash,
            new_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
            old_checkpoint_leaf_hash: witness.last_old_checkpoint_tree_leaf_hash,
            new_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value,
        };

        let last_checkpoint_hash_transition_hash = last_checkpoint_hash_transition.qfhash::<C::Hasher>();
        //println!("last_checkpoint_hash_transition: {:#?}", last_checkpoint_hash_transition);
        //println!("last_checkpoint_hash_transition_hash: {:?} ({})", last_checkpoint_hash_transition_hash.0.elements, hex::encode(&last_checkpoint_hash_transition_hash.into_owned_32bytes()));

        let last_checkpoint_transition_hash_publics = CheckpointStateTransitionPublicInputs { checkpoint_transition: last_checkpoint_hash_transition, genesis_checkpoint_state_transition_hash: witness.genesis_checkpoint_state_transition_hash, checkpoint_state_transition_circuit_fingerprint: transition_circuit_fingerprint };

        let last_checkpoint_transition_publics_hash = last_checkpoint_transition_hash_publics.qfhash::<C::Hasher>();

        //println!("last_checkpoint_transition_publics_hash: {:?} ({})", last_checkpoint_transition_publics_hash.0.elements, hex::encode(&last_checkpoint_transition_publics_hash.into_owned_32bytes()));
        let checkpoint_hash_transition = CheckpointStateHashTransition{
            old_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
            new_checkpoint_tree_root: witness.append_checkpoint_tree_proof.new_root,
            old_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value,
            new_checkpoint_leaf_hash: witness.append_checkpoint_tree_proof.new_value,
        };
        let checkpoint_hash_transition_hash = checkpoint_hash_transition.qfhash::<C::Hasher>();
        let checkpoint_hash_transition_publics_hash = checkpoint_hash_transition.get_public_inputs_hash_no_rewards_tag::<C::Hasher>(
            &witness.genesis_checkpoint_state_transition_hash,
            &transition_circuit_fingerprint,
        );
        //println!("checkpoint_hash_transition: {:#?}", checkpoint_hash_transition);
        //println!("checkpoint_hash_transition_hash: {:?} ({})", checkpoint_hash_transition_hash.0.elements, hex::encode(&checkpoint_hash_transition_hash.into_owned_32bytes()));
        //println!("checkpoint_hash_transition_publics_hash: {:?} ({})", checkpoint_hash_transition_publics_hash.0.elements, hex::encode(&checkpoint_hash_transition_publics_hash.into_owned_32bytes()));
        //println!("genesis_checkpoint_state_transition_hash: {:?} ({})", witness.genesis_checkpoint_state_transition_hash.0.elements, hex::encode(&witness.genesis_checkpoint_state_transition_hash.into_owned_32bytes()));
        let expected_prev_pubs = witness.get_previous_proof_expected_public_inputs_hash_with_fingerprint::<C::Hasher>(transition_circuit_fingerprint);
        //println!("transition_circuit_fingerprint: {:?} ({})", transition_circuit_fingerprint.0.elements, hex::encode(&transition_circuit_fingerprint.into_owned_32bytes()));
        //println!("expected_previous_checkpoint_state_transition_proof_public_inputs: {:?} ({})", expected_prev_pubs.0.elements, hex::encode(&expected_prev_pubs.into_owned_32bytes()));
        //println!("previous_checkpoint_state_transition_proof_public_inputs: {:?} ({})", previous_checkpoint_state_transition_proof.public_inputs, hex::encode(&QHashOut::<C::F>::from_felt_slice(&previous_checkpoint_state_transition_proof.public_inputs).into_owned_32bytes()));

        */
        //println!("[updadting reward root]...");
        let reward_tree_root = hash_tag_tree_node_single::<QHashOut<C::F>, C::Hasher>(&part_1_worker_reward_tree_value, &worker_reward_tag);
        witness.update_for_prover::<C::Hasher>(reward_tree_root);

        //println!("dmp: {:?}", witness.append_checkpoint_tree_proof);



        // TODO: add deposits and withdrawals, for now just leave with constant hashes
        let todo_add_deposits_root = QHashOut::<C::F>::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        );
        let todo_add_withdrawals_root = QHashOut::<C::F>::from_string_or_panic(
            "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
        );
        let old_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: witness.partial.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: witness.partial.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: witness.partial.part_1_header.register_users_state_transition.state_transition_start,
        };
        let new_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: witness.partial.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: todo_add_deposits_root,
            user_tree_root: witness.partial.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root: todo_add_withdrawals_root,
            user_registration_tree_root: witness.partial.part_1_header.register_users_state_transition.state_transition_end,
        };

        //println!("old_state_roots: {:#?}", old_state_roots);

        //println!("new_state_roots: {:#?}", new_state_roots);

        let old_global_chain_root = old_state_roots.qfhash::<C::Hasher>();
        let new_global_chain_root = new_state_roots.qfhash::<C::Hasher>();
        //println!("old_global_chain_root: {:?} ({})", old_global_chain_root.0.elements, hex::encode(&old_global_chain_root.into_owned_32bytes()));
        //println!("new_global_chain_root: {:?} ({})", new_global_chain_root.0.elements, hex::encode(&new_global_chain_root.into_owned_32bytes()));
        let old_stats = witness.partial.old_stats.clone();
        let old_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: old_global_chain_root,
            stats: old_stats,
        };

        let old_checkpoint_leaf_hash = old_checkpoint_leaf.qfhash::<C::Hasher>();

        if old_checkpoint_leaf_hash != witness.previous_checkpoint_proof.value {
            tracing::error!("Error: old_checkpoint_leaf_hash does not match previous_checkpoint_proof value:\n old_checkpoint_leaf_hash: {:?} ({})\n  previous_checkpoint_proof.value: {:?} ({})\nExpected Old Checkpoint Leaf: {:#?}",
                old_checkpoint_leaf_hash.0.elements, hex::encode(&old_checkpoint_leaf_hash.into_owned_32bytes()),
                witness.previous_checkpoint_proof.value.0.elements, hex::encode(&witness.previous_checkpoint_proof.value.into_owned_32bytes()),
                old_checkpoint_leaf,
            );
        }

        let expected_old_public_inputs = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: witness.last_old_checkpoint_tree_root_hash,
                new_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
                old_checkpoint_leaf_hash: witness.last_old_checkpoint_tree_leaf_hash,
                new_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value
            },

            genesis_checkpoint_state_transition_hash: witness.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.get_fingerprint()
        };

        let expected_new_public_inputs = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: witness.previous_checkpoint_proof.root,
                new_checkpoint_tree_root: witness.append_checkpoint_tree_proof.new_root,
                old_checkpoint_leaf_hash: witness.previous_checkpoint_proof.value,
                new_checkpoint_leaf_hash: witness.append_checkpoint_tree_proof.new_value
            },

            genesis_checkpoint_state_transition_hash: witness.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.get_fingerprint()
        };
        println!("expected_old_public_inputs_preimage: {:#?}", expected_old_public_inputs);
        println!("expected_new_public_inputs_preimage: {:#?}", expected_new_public_inputs);
        let expected_old_public_inputs_hash = expected_old_public_inputs.qfhash::<C::Hasher>();
        let expected_new_public_inputs_hash = expected_new_public_inputs.qfhash::<C::Hasher>();
        let actual_old_public_inputs_hash = QHashOut::<C::F>::from_felt_slice(&previous_checkpoint_state_transition_proof.public_inputs);
        //println!("old_checkpoint_leaf: {:#?}", old_checkpoint_leaf);
        println!("expected public inputs for the last checkpoint transition proof:\n{:?} ({})", expected_old_public_inputs_hash.0.elements, hex::encode(&expected_old_public_inputs_hash.into_owned_32bytes()));
        if expected_old_public_inputs_hash != actual_old_public_inputs_hash {
            tracing::error!("Error: expected_old_public_inputs does not match previous_checkpoint_state_transition_proof public inputs:\n expected_old_public_inputs: {:?} ({})\n  previous_checkpoint_state_transition_proof.public_inputs: {:?} ({})\nExpected Old Checkpoint Leaf: {:#?}",
                expected_old_public_inputs_hash.0.elements, hex::encode(&expected_old_public_inputs_hash.into_owned_32bytes()),
                actual_old_public_inputs_hash.0.elements, hex::encode(&actual_old_public_inputs_hash.into_owned_32bytes()),
                old_checkpoint_leaf,
            );
        }

        //println!("last_merkle_proof_checkpoint_leaf_hash: {:?} ({})", witness.previous_checkpoint_proof.value.0.elements, hex::encode(&witness.previous_checkpoint_proof.value.into_owned_32bytes()));


        let expected_public_inputs_after = witness.get_public_inputs_hash_with_fingerprint_and_reward_root::<C::Hasher>(
            self.get_fingerprint(),
            reward_tree_root,
        );
        //println!("expected new state transition proof public inputs after updating reward root:\n{:?} ({})", expected_public_inputs_after.0.elements, hex::encode(&expected_public_inputs_after.into_owned_32bytes()));

        //println!("expected_new_pubs: {:?} ({})", expected_new_pubs.0.elements, hex::encode(&expected_new_pubs.into_owned_32bytes()));
        //println!("upd_expected_public_inputs_metadata: {:?} ({})", input.base.job.metadata.expected_public_inputs_hash.0.elements, hex::encode(&input.base.job.metadata.expected_public_inputs_hash.into_owned_32bytes()));

        //println!("pub_test_hash: {:?} ({})", pub_test_hash.0.elements, hex::encode(&pub_test_hash.into_owned_32bytes()));

        let proof = self.prove_base(
            worker_reward_tag,
            &witness,
            part_1_worker_reward_tree_value,
            &part_1_proof,
            &part_1_verifier_data,
            &previous_checkpoint_state_transition_proof,
            &previous_checkpoint_state_transition_verifier_data,
        )?;

        let got_public_inputs = QHashOut::<C::F>::from_felt_slice(&proof.public_inputs);

        println!("🏛️ Checkpoint State Transition - got_public_inputs: {:?} ({})", got_public_inputs.0.elements, hex::encode(&got_public_inputs.into_owned_32bytes()));
        Ok(proof)
    }
}
