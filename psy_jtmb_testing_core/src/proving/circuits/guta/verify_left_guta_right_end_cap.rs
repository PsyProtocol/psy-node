use parth_core::crypto::hash::{merkle_proof::MerkleProofCore, traits::ZeroableHash};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::GUTAVerifyLeftGUTARightEndCapCircuitInputV2, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::
        gadgets::guta::{
            guta_header::compute_guta_public_inputs_hash_two_children, left_linear_right_variable_height_state_transition::verify_left_linear_right_variable_state_transition, verify_end_cap::verify_end_cap_proof, verify_guta_proof::verify_guta_proof
        }
    ,
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTAVerifyLeftGUTARightEndCapCircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,

    pub global_user_tree_height: usize,
    pub max_guta_nca_merkle_proof_height: usize,
    pub guta_circuit_whitelist_tree_height: u8,
    pub checkpoint_tree_height: usize,
    pub known_end_cap_fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifyLeftGUTARightEndCapCircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTALeftGUTARightEndCap
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifyLeftGUTARightEndCapCircuitV2<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        known_end_cap_fingerprint: C::Hash,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTALeftGUTARightEndCap;
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
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            known_end_cap_fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &GUTAVerifyLeftGUTARightEndCapCircuitInputV2<C::F, C::Hash>,
        guta_inclusion_proof_a: &MerkleProofCore<C::Hash>,
        child_a_proof: &PsyTestJTMBProof<C::Hash>,
        child_a_verifier_data: &PsyTestJTMBProofVerifierData,
        child_b_proof: &PsyTestJTMBProof<C::Hash>,
        child_b_verifier_data: &PsyTestJTMBProofVerifierData,
        left_child_rewards: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        let a_header = input.get_guta_header_a();
        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof_a,
            &a_header,
            child_a_proof,
            child_a_verifier_data,
            left_child_rewards,
        )?;

        let mut b_header = verify_end_cap_proof::<C>(
            &input.get_end_cap_result_b(),
            &input.right_end_cap.guta_stats,
            &input.right_end_cap.checkpoint_historical_merkle_proof,
            child_b_proof,
            child_b_verifier_data,
            self.checkpoint_tree_height,
            self.global_user_tree_height as u8,
            self.known_end_cap_fingerprint,
        )?;
        // Inherit whitelist from A
        b_header.guta_circuit_whitelist = a_header.guta_circuit_whitelist;

        let new_header = verify_left_linear_right_variable_state_transition::<C>(
            &a_header,
            &b_header,
            &input.right_global_user_tree_delta_merkle_proof,
            self.max_guta_nca_merkle_proof_height,
            self.global_user_tree_height,

        )?;

        let zero = C::Hash::get_zero_value();
        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            left_child_rewards,
            zero,
            worker_reward_tag,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTAVerifyLeftGUTARightEndCapCircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let (left, right) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        let witness = GUTAVerifyLeftGUTARightEndCapCircuitInputV2::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            &left.whitelist_inclusion_proof,
            &left.zk_proof,
            &left.verifier_data,
            &right.zk_proof,
            &right.verifier_data,
            left.reward_tag_tree_value,
        )
    }
}