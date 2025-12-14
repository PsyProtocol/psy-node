use parth_core::crypto::hash::traits::ZeroableHash;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::VerifySingleEndCapInputV2, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::
        gadgets::guta::{
            guta_header::compute_guta_public_inputs_hash_two_children, single_variable_height_state_transition::verify_single_variable_height_state_transition, verify_end_cap::verify_end_cap_proof
        }
    ,
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_single_child_proof_for_api_response_with_inclusion_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTAVerifySingleEndCapCircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,

    pub global_user_tree_height: usize,
    pub global_user_tree_realm_height: usize,
    pub checkpoint_tree_height: usize,
    pub known_end_cap_fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifySingleEndCapCircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTASingleEndCap
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifySingleEndCapCircuitV2<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        global_user_tree_realm_height: usize,
        checkpoint_tree_height: usize,
        known_end_cap_fingerprint: C::Hash,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTASingleEndCap;
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
            global_user_tree_height,
            global_user_tree_realm_height,
            checkpoint_tree_height,
            known_end_cap_fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &VerifySingleEndCapInputV2<C::F, C::Hash>,
        child_proof: &PsyTestJTMBProof<C::Hash>,
        child_verifier_data: &PsyTestJTMBProofVerifierData,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        let mut a_header = verify_end_cap_proof::<C>(
            &input.get_end_result_a(),
            &input.core.guta_stats,
            &input.core.checkpoint_historical_merkle_proof,
            child_proof,
            child_verifier_data,
            self.checkpoint_tree_height,
            self.global_user_tree_height as u8,
            self.known_end_cap_fingerprint,
        )?;
        
        a_header.guta_circuit_whitelist = input.guta_circuit_whitelist;

        let new_header = verify_single_variable_height_state_transition::<C>(
            &a_header,
            &input.global_user_tree_sub_root_transition,
            self.global_user_tree_realm_height,
        )?;

        let zero = C::Hash::get_zero_value();
        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            zero,
            zero,
            worker_reward_tag,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTAVerifySingleEndCapCircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let child = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        let witness = VerifySingleEndCapInputV2::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            &child.zk_proof,
            &child.verifier_data,
        )
    }
}