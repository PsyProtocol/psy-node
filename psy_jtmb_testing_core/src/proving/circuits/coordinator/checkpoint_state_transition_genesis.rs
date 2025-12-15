use parth_core::
    crypto::hash::traits::MerkleHasher
;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct QEDCheckpointStateTransitionGenesisCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for QEDCheckpointStateTransitionGenesisCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> QEDCheckpointStateTransitionGenesisCircuit<C> {
    pub fn new(private_key: &MemorySecp256K1SinglePrivateKeyWallet) -> Self {
        let circuit_type = ProvingJobCircuitType::GenesisBlockCheckpointStateTransition;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            circuit_type as u32,
            [0u8; 32],
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        genesis_checkpoint_state_transition_hash: C::Hash,
        checkpoint_state_transition_circuit_fingerprint: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let config_hash = C::Hasher::two_to_one(&genesis_checkpoint_state_transition_hash, &checkpoint_state_transition_circuit_fingerprint);
        let public_inputs_hash = C::Hasher::two_to_one(&genesis_checkpoint_state_transition_hash, &config_hash);

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for QEDCheckpointStateTransitionGenesisCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        _worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let witness = PsyCheckpointStateTransitionGenesisCircuitInput::<C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            witness.genesis_checkpoint_state_transition_hash,
            witness.checkpoint_state_transition_circuit_fingerprint,
        )
    }
}