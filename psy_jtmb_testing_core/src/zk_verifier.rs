use parth_core::protocol::core_types::{QZKProofPublicInputsHasherReader, QZKProofVerifier};
use psy_core::job::job_id::ProvingJobCircuitType;

use crate::{proof::PsyTestJTMBProof, utils::{generic_circuit_library::JTMBGenericCircuitVerifier, jtmb_standard_circuit::JTMBCircuitConfig, proof_serialization::deserialize_jtmb_proof}};


#[derive(Clone, Debug)]
pub struct PsyJTMBZKVerifier<C: JTMBCircuitConfig> {
    pub gcv: JTMBGenericCircuitVerifier<C>,
}
impl<C: JTMBCircuitConfig> PsyJTMBZKVerifier<C> {
    pub fn new(gcv: JTMBGenericCircuitVerifier<C>,) -> Self {
        Self {
            gcv,
        }
    }
}
impl<C: JTMBCircuitConfig> QZKProofPublicInputsHasherReader<C::Hash, PsyTestJTMBProof<C::Hash>> for PsyJTMBZKVerifier<C> 
{
    fn get_proof_public_inputs_hash(proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<C::Hash> {
        Ok(proof.public_inputs_hash)
    }
    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        deserialize_jtmb_proof(bytes)
    }
}
impl<C: JTMBCircuitConfig> QZKProofVerifier<C::Hash, PsyTestJTMBProof<C::Hash>> for PsyJTMBZKVerifier<C> {
    fn verify_zk_proof(&self, circuit_type: u32, proof: &PsyTestJTMBProof<C::Hash>) -> anyhow::Result<C::Hash> {
        let proving_job_circuit_type = ProvingJobCircuitType::try_from_u32(circuit_type)?;
        self.gcv.verify_proof_of_type(proving_job_circuit_type, proof)?;
        Self::get_proof_public_inputs_hash(proof)
    }
}