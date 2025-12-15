
use psy_core::job::job_id::ProvingJobCircuitType;

use crate::{proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData}, utils::{circuit_info_library::{PsyJTMBCircuitInfoLibrary, PsyJTMBCircuitInfoLibraryBuilder}, jtmb_standard_circuit::JTMBCircuitConfig, simple_circuit_info_library::{JTMBSerializableSimpleCircuitLibrary, JTMBSimpleCircuitLibrary}}};



#[derive(Debug, Clone)]
pub struct JTMBSerializedGenericCircuitVerifier<Hash> {
    pub library: JTMBSerializableSimpleCircuitLibrary<Hash>,
}

#[derive(Debug, Clone)]
pub struct JTMBGenericCircuitVerifier<C: JTMBCircuitConfig> {
    pub library: JTMBSimpleCircuitLibrary<C>,
}

impl<C: JTMBCircuitConfig> JTMBGenericCircuitVerifier<C> {
    pub fn new() -> Self {
        Self {
            library: JTMBSimpleCircuitLibrary::new(),
        }
    }
    pub fn from_serialized(
        ser: JTMBSerializedGenericCircuitVerifier<C::Hash>,
    ) -> anyhow::Result<Self> {
        let library = JTMBSimpleCircuitLibrary::<C>::from_serialized(ser.library);
        
        Ok(Self { library })
    }
    pub fn to_serialized(&self) -> JTMBSerializedGenericCircuitVerifier<C::Hash> {
        let library = self.library.to_serialized();

        JTMBSerializedGenericCircuitVerifier { library }
    }
    pub fn verify_proof_of_type(
        &self,
        circuit_type: ProvingJobCircuitType,
        proof: &PsyTestJTMBProof<C::Hash>
    ) -> anyhow::Result<()>
    {
        self.library
            .verify_proof_of_type(circuit_type, proof)?;
        Ok(())
    }

    pub fn register_circuit_triplet(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        triplet: (
            &PsyTestJTMBProofVerifierData,
            C::Hash,
        ),
    ) {
        let (v_ref, fingerprint) = triplet;

        self.library
            .register_circuit(circuit_type, fingerprint, *v_ref);
    }
}