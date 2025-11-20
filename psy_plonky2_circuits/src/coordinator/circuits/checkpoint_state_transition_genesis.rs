use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
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
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibraryAsync}};


#[derive(Debug)]
pub struct QEDCheckpointStateTransitionGenesisCircuit<C: GenericConfig<D>, const D: usize> {
    pub genesis_checkpoint_state_transition_hash: HashOutTarget,
    pub checkpoint_state_transition_circuit_fingerprint: HashOutTarget,
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
        
        let genesis_checkpoint_state_transition_hash = builder.add_virtual_hash();
        let checkpoint_state_transition_circuit_fingerprint = builder.add_virtual_hash();
        /*
        public inputs are:
        hash(genesis_checkpoint_state_transition_hash, hash(genesis_checkpoint_state_transition_hash, checkpoint_state_transition_circuit_fingerprint))
         */
        let config_hash = builder.hash_two_to_one::<C::Hasher>(
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        );
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(
            genesis_checkpoint_state_transition_hash,
            config_hash,
        );
        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_qed_type_d_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        genesis_checkpoint_state_transition_hash: QHashOut<C::F>,
        checkpoint_state_transition_circuit_fingerprint: QHashOut<C::F>,

    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.genesis_checkpoint_state_transition_hash, genesis_checkpoint_state_transition_hash.0)?;
        pw.set_hash_target(self.checkpoint_state_transition_circuit_fingerprint, checkpoint_state_transition_circuit_fingerprint.0)?;
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
impl<L: CircuitInfoLibrary<C, D> + Send + Sync, C: GenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibraryAsync<L, C, D>
    for QEDCheckpointStateTransitionGenesisCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash,
    C::F: QFelt64,
{
    async fn prove_with_raw_proofs_and_ref_library_async(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        _worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input: PsyCheckpointStateTransitionGenesisCircuitInput::<QHashOut<C::F>> = PsyCheckpointStateTransitionGenesisCircuitInput::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            input.genesis_checkpoint_state_transition_hash,
            input.checkpoint_state_transition_circuit_fingerprint,
        )
    }
}
