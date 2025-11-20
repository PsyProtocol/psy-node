use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::proof_input::CircuitInputWithDependencies, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{coordinator::gadgets::{checkpoint_state_transition::CheckpointStateTransitionPublicInputsGadget, recursive_checkpoint_state_transition_verify::VerifyRecursiveCheckpointStateTransitionProofGadget}, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithRawProofsAndRefLibrary, proof_store::QProofStoreReaderAsync}, utils::proof_serialization::deserialize_plonky2_proof};

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

    

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
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
        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            circuit_data,
            child_proofs_gadget,
            verify_previous_checkpoint_proof_gadget,
            core_checkpoint_gadget,
            worker_rewards_tree_tag_target,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            fingerprint,
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
        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

#[async_trait]
impl<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash,
    C::F: QFelt64,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        input.ensure_expected_child_proof_count_with_tags(2)?;
        let witness = QCQEDCheckpointStateTransitionInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        let part_1_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[0])?;
        let part_1_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(0)?)?;
        let part_1_worker_reward_tree_value = input.base.child_proof_tag_values[0];
        
        let previous_checkpoint_state_transition_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[1])?;
        let previous_checkpoint_state_transition_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(1)?)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            part_1_worker_reward_tree_value,
            &part_1_proof,
            &part_1_verifier_data,
            &previous_checkpoint_state_transition_proof,
            &previous_checkpoint_state_transition_verifier_data,
        )
    }
}
