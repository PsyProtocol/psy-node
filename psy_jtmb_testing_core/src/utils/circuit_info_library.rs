use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, protocol::core_types::QZKProofPublicInputsHasherReader};
use psy_core::job::job_id::ProvingJobCircuitType;

use crate::proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData};




pub trait PsyJTMBCircuitInfoLibraryBuilder<Hash> {
    fn register_circuit(&mut self, circuit_type: ProvingJobCircuitType, fingerprint: Hash, verifier_data: PsyTestJTMBProofVerifierData);
    fn add_inclusion_proof(&mut self, parent_types: &[ProvingJobCircuitType], child_type: ProvingJobCircuitType, proof: MerkleProofCore<Hash>);
}

pub trait PsyJTMBCircuitInfoLibraryCore<Hash> {
    fn get_verifier_data_cap_height(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<usize>;
    fn get_fingerprint(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<Hash>;
    fn get_group_inclusion_proof(&self, parent_circuit: ProvingJobCircuitType, proof_circuit_type: ProvingJobCircuitType) -> anyhow::Result<MerkleProofCore<Hash>>;
    fn get_agg_whitelist<H: MerkleZeroHasher<Hash>>(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<Hash>;
      
}
pub trait PsyJTMBCircuitInfoLibrary<Hash>: PsyJTMBCircuitInfoLibraryCore<Hash> + QZKProofPublicInputsHasherReader<Hash, PsyTestJTMBProof<Hash>> {
    fn get_verifier_data(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<PsyTestJTMBProofVerifierData>;     
    fn verify_proof_of_type(
        &self,
        circuit_type: ProvingJobCircuitType,
        proof: &PsyTestJTMBProof<Hash>,
    ) -> anyhow::Result<()>;
}