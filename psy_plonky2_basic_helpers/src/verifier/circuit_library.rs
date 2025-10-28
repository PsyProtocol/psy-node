use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{hash::hash_types::RichField, plonk::{circuit_data::{CommonCircuitData, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs}};
use psy_core::job::job_id::ProvingJobCircuitType;

use crate::verifier::alt::AltVerifierOnlyCircuitData;




pub trait CircuitInfoLibraryBuilder<F: RichField> {
    fn register_circuit(&mut self, circuit_type: ProvingJobCircuitType, fingerprint: QHashOut<F>, verifier_data: AltVerifierOnlyCircuitData<F>);
    fn add_inclusion_proof(&mut self, parent_types: &[ProvingJobCircuitType], child_type: ProvingJobCircuitType, proof: MerkleProofCore<QHashOut<F>>);
}

pub trait CircuitInfoLibraryCore<F: RichField> {
    fn get_verifier_data_cap_height(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<usize>;
    fn get_fingerprint(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<QHashOut<F>>;
    fn get_group_inclusion_proof(&self, parent_circuit: ProvingJobCircuitType, proof_circuit_type: ProvingJobCircuitType) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    fn get_agg_whitelist<H: AlgebraicHasher<F>>(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<QHashOut<F>>;
      
}
pub trait CircuitInfoLibrary<C: GenericConfig<D>, const D: usize>: CircuitInfoLibraryCore<C::F> {
    fn get_verifier_data(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;     
    fn verify_proof_of_type(
        &self,
        circuit_type: ProvingJobCircuitType,
        common_data: &CommonCircuitData<C::F, D>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;
}