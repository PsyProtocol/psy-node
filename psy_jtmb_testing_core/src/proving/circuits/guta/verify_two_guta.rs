use parth_core::
    crypto::hash::merkle_proof::{MerkleProofCore}
;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    proof_input::guta::GUTAVerifyTwoGUTACircuitInputV2,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::
        gadgets::guta::{
            dual_variable_height_state_transition::verify_dual_variable_height_state_transition,
            guta_header::compute_guta_public_inputs_hash_two_children,
            verify_guta_proof::verify_guta_proof,
        }
    ,
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTAVerifyTwoGUTACircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    
    pub global_user_tree_height: usize,
    pub max_guta_nca_merkle_proof_height: usize,
    pub guta_circuit_whitelist_tree_height: u8,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifyTwoGUTACircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoGUTA
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifyTwoGUTACircuitV2<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTATwoGUTA;
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
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        guta_inclusion_proof_a: &MerkleProofCore<C::Hash>,
        guta_inclusion_proof_b: &MerkleProofCore<C::Hash>,
        input: &GUTAVerifyTwoGUTACircuitInputV2<C::F, C::Hash>,
        child_a_proof: &PsyTestJTMBProof<C::Hash>,
        child_a_verifier_data: &PsyTestJTMBProofVerifierData,
        child_b_proof: &PsyTestJTMBProof<C::Hash>,
        child_b_verifier_data: &PsyTestJTMBProofVerifierData,
        left_child_rewards: C::Hash,
        right_child_rewards: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        let a_header = input.get_guta_header_a();
        let b_header = input.get_guta_header_b();

        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof_a,
            &a_header,
            child_a_proof,
            child_a_verifier_data,
            left_child_rewards,
        )?;

        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof_b,
            &b_header,
            child_b_proof,
            child_b_verifier_data,
            right_child_rewards,
        )?;

        let new_header = verify_dual_variable_height_state_transition::<C>(
            &a_header,
            &b_header,
            &input.left_global_user_tree_delta_merkle_proof,
            &input.right_global_user_tree_delta_merkle_proof,
            self.max_guta_nca_merkle_proof_height,
            self.global_user_tree_height,
        )?;

        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            left_child_rewards,
            right_child_rewards,
            worker_reward_tag,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTAVerifyTwoGUTACircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let (left_child, right_child) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        
        let witness = GUTAVerifyTwoGUTACircuitInputV2::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &left_child.whitelist_inclusion_proof,
            &right_child.whitelist_inclusion_proof,
            &witness,
            &left_child.zk_proof,
            &left_child.verifier_data,
            &right_child.zk_proof,
            &right_child.verifier_data,
            left_child.reward_tag_tree_value,
            right_child.reward_tag_tree_value,
        )
    }
}