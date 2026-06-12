use async_trait::async_trait;
use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleZeroHasher}, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::{Q256BitHash, QFHashBase}};
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
use psy_data::{proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{CircuitBuilderQEDCommonGates, pad_circuit_degree}}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary}};


#[derive(Debug)]
pub struct QEDCheckpointStateTransitionGenesisCircuit<C: GenericConfig<D>, const D: usize> {
    pub checkpoint_tree_root: HashOutTarget,
    pub checkpoint_leaf_hash: HashOutTarget,
    pub genesis_fingerprint: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for QEDCheckpointStateTransitionGenesisCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
    }
}
impl<C: GenericConfig<D>, const D: usize> QEDCheckpointStateTransitionGenesisCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        
        let checkpoint_tree_root = builder.add_virtual_hash();
        let checkpoint_leaf_hash = builder.add_virtual_hash();
        let genesis_fingerprint = builder.add_virtual_hash();
        // chain_0 = H(H(checkpoint_tree_root_0, checkpoint_leaf_hash_0), genesis_fingerprint)
        let root_leaf = builder.hash_two_to_one::<C::Hasher>(
            checkpoint_tree_root,
            checkpoint_leaf_hash,
        );
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(
            root_leaf,
            genesis_fingerprint,
        );
        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_qed_type_e_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            checkpoint_tree_root,
            checkpoint_leaf_hash,
            genesis_fingerprint,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        checkpoint_tree_root: QHashOut<C::F>,
        checkpoint_leaf_hash: QHashOut<C::F>,
        genesis_fingerprint: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.checkpoint_tree_root, checkpoint_tree_root.0)?;
        pw.set_hash_target(self.checkpoint_leaf_hash, checkpoint_leaf_hash.0)?;
        pw.set_hash_target(self.genesis_fingerprint, genesis_fingerprint.0)?;
        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for QEDCheckpointStateTransitionGenesisCircuit<C, D>
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
    for QEDCheckpointStateTransitionGenesisCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>,
    C::F: QFelt64,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        _worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        println!("metadata expected public_inputs: {}", hex::encode(&input.base.job.metadata.expected_public_inputs_hash.into_owned_32bytes()));
        let input: PsyCheckpointStateTransitionGenesisCircuitInput::<QHashOut<C::F>> = PsyCheckpointStateTransitionGenesisCircuitInput::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        let expected_public_inputs = input.get_public_inputs_hash_no_rewards_tag::<C::Hasher>();
        println!("🏛️ Genesis Checkpoint State Transition - expected_public_inputs: {:?}", hex::encode(&expected_public_inputs.into_owned_32bytes()));
        println!("🏛️ Genesis Checkpoint State Transition - checkpoint_tree_root: {:?} ({})", input.checkpoint_tree_root, hex::encode(&input.checkpoint_tree_root.into_owned_32bytes()));
        println!("🏛️ Genesis Checkpoint State Transition - checkpoint_leaf_hash: {:?} ({})", input.checkpoint_leaf_hash, hex::encode(&input.checkpoint_leaf_hash.into_owned_32bytes()));
        let proof = self.prove_base(
            input.checkpoint_tree_root,
            input.checkpoint_leaf_hash,
            input.genesis_fingerprint,
        )?;
        let got_public_inputs = QHashOut::<C::F>::from_felt_slice(&proof.public_inputs);
        println!("🏛️ Genesis Checkpoint State Transition - got_public_inputs: {:?}", hex::encode(&got_public_inputs.into_owned_32bytes()));

        Ok(proof)
    }
}
