use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::proof_input::CircuitInputWithDependencies, pgoldilocks::QHashOut};
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
use psy_data::protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput;
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType}};

use crate::coordinator::gadgets::{
    checkpoint_state_transition::CheckpointStateTransitionCoreGadget,
    checkpoint_state_transition_proofs::CheckpointStateTransitionChildProofsGadget,
};

#[derive(Debug)]
pub struct QEDCheckpointStateTransitionCircuit<C: GenericConfig<D>, const D: usize> {
    pub child_proofs_gadget: CheckpointStateTransitionChildProofsGadget<D>,
    pub core_checkpoint_gadget: CheckpointStateTransitionCoreGadget,
    pub worker_public_key: HashOutTarget,

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

        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let child_proofs_gadget =
            CheckpointStateTransitionChildProofsGadget::<D>::add_virtual_to::<C, C::F>(
                &mut builder,
                part_1_common_data,
                part_1_verifier_data_cap_height,
                known_part_1_fingerprint,
            );
        let core_checkpoint_gadget = CheckpointStateTransitionCoreGadget::add_virtual_to::<
            C::Hasher,
            C::F,
            D,
        >(&mut builder, checkpoint_tree_height);
        let expected_old_leaf_hash = child_proofs_gadget.state_delta_gadget.old_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let expected_new_leaf_hash = child_proofs_gadget.state_delta_gadget.new_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let expected_old_checkpoint_root = child_proofs_gadget.state_delta_gadget.part_1_header.global_user_tree_delta.checkpoint_tree_root;

        tracing::debug!("🏛️ Checkpoint State Transition - expected_old_leaf_hash: {:?}, expected_new_leaf_hash: {:?}, expected_old_checkpoint_root: {:?}, core_checkpoint_gadget: {:?}",
            expected_old_leaf_hash, expected_new_leaf_hash, expected_old_checkpoint_root, core_checkpoint_gadget);


        builder.connect_hashes(
            expected_old_leaf_hash,
            core_checkpoint_gadget.old_checkpoint_leaf_hash,
        );
        builder.connect_hashes(
            expected_new_leaf_hash,
            core_checkpoint_gadget.new_checkpoint_leaf_hash,
        );

        builder.connect_hashes(
            expected_old_checkpoint_root,
            core_checkpoint_gadget.old_checkpoint_tree_root,
        );

        let new_checkpoint_root = core_checkpoint_gadget.new_checkpoint_tree_root;

        tracing::debug!("🏛️ Checkpoint State Transition - new_checkpoint_root: {:?}", new_checkpoint_root);
        //let combo_hash = builder.hash_two_to_one::<C::Hasher>(expected_old_checkpoint_root, new_checkpoint_root);

        let worker_public_key = builder.add_virtual_hash();
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        let pm_stats_targets = [
            child_proofs_gadget.state_delta_gadget.new_stats.pm_jobs_completed.deploy_contracts_completed,
            child_proofs_gadget.state_delta_gadget.new_stats.pm_jobs_completed.register_users_completed,
            child_proofs_gadget.state_delta_gadget.new_stats.pm_jobs_completed.gutas_completed,
        ];

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_stats_targets);
        builder.register_public_inputs(&core_checkpoint_gadget.old_checkpoint_tree_root.elements);
        builder.register_public_inputs(&new_checkpoint_root.elements);
        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            circuit_data,
            child_proofs_gadget,
            core_checkpoint_gadget,
            worker_public_key,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        input: &QCQEDCheckpointStateTransitionInput<C::F, QHashOut<C::F>>,
        part_1_proof: &ProofWithPublicInputs<C::F, C, D>,
        part_1_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        tracing::debug!("🏛️ Checkpoint State Transition prove_base - worker_public_key: {:?}, append_checkpoint_proof (index: {}, siblings_len: {}), previous_checkpoint_proof (index: {}, siblings_len: {})",
            worker_public_key, 
            input.append_checkpoint_tree_proof.index, input.append_checkpoint_tree_proof.siblings.len(),
            input.previous_checkpoint_proof.index, input.previous_checkpoint_proof.siblings.len());

        self.child_proofs_gadget.set_witness_params(
            &mut pw,
            &input.partial.part_1_header.register_users_state_transition,
            &input.partial.part_1_header.deploy_contracts_state_transition,
            &input.partial.part_1_header.guta_proof_header,
            &input.partial.old_stats,
            input.partial.block_time,
            input.partial.final_random_seed_contribution,
            &input.partial.pm_rewards_commitment,
            part_1_proof,
            part_1_verifier_data,
        )?;

        self.core_checkpoint_gadget.set_witness_params(
            &mut pw,
            &input.append_checkpoint_tree_proof,
            &input.previous_checkpoint_proof,
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
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for QEDCheckpointStateTransitionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<QCQEDCheckpointStateTransitionInput<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;

        if r.dependencies.len() != 1 {
            anyhow::bail!("expected 1 dependency");
        }



        let part_1_proof = store.get_proof_by_id(r.dependencies[0]).await?;

        let part_1_proof_type = r.dependencies[0].circuit_type;

        let part_1_verifier_data = library.get_verifier_data(part_1_proof_type)?;

        let result = self.prove_base(
            worker_public_key,
            &r.input,
            &part_1_proof,
            &part_1_verifier_data,
        )?;
        Ok(result)
    }
}
