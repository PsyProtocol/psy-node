use parth_core::{pgoldilocks::QHashOut, protocol::core_types::{QZKProofPublicInputsHasherReader, QZKProofVerifier}};
use plonky2::{hash::hash_types::HashOut, plonk::{config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs}};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_plonky2_basic_helpers::verifier::generic_circuit_library::GenericCircuitVerifier;

#[derive(Clone, Debug)]
pub struct PsyPlonky2ZKVerifier<C: GenericConfig<D>, const D: usize> {
    pub gcv: GenericCircuitVerifier<C, D>,
}
impl<C: GenericConfig<D>, const D: usize> PsyPlonky2ZKVerifier<C, D> {
    pub fn new(gcv: GenericCircuitVerifier<C, D>,) -> Self {
        Self {
            gcv,
        }
    }
}
impl<C: GenericConfig<D>, const D: usize> QZKProofPublicInputsHasherReader<QHashOut<C::F>, ProofWithPublicInputs<C::F, C, D>> for PsyPlonky2ZKVerifier<C, D> 
where
    C::Hasher: AlgebraicHasher<C::F> {
    fn get_proof_public_inputs_hash(proof: &ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<QHashOut<C::F>> {
        if proof.public_inputs.len() != 4 {
            return Err(anyhow::anyhow!("Invalid number of public inputs in proof, expected 4, got {}", proof.public_inputs.len()));
        }
        Ok(QHashOut(HashOut{
            elements: [
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ],
        }))
    }
    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let proof: ProofWithPublicInputs<C::F, C, D> = bincode::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize proof: {}", e))?;
        Ok(proof)
    }
}
impl<C: GenericConfig<D>, const D: usize> QZKProofVerifier<QHashOut<C::F>, ProofWithPublicInputs<C::F, C, D>> for PsyPlonky2ZKVerifier<C, D> 
where
    C::Hasher: AlgebraicHasher<C::F>,{
    fn verify_zk_proof(&self, circuit_type: u32, proof: &ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<QHashOut<C::F>> {
        let proving_job_circuit_type = ProvingJobCircuitType::try_from_u32(circuit_type)?;
        self.gcv.verify_proof_of_type(proving_job_circuit_type, proof)?;
        Self::get_proof_public_inputs_hash(proof)
    }
}
