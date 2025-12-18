use parth_core::crypto::hash::traits::ZeroableHash;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    proof_input::guta::GUTAVerifyTwoEndCapCircuitInputV2,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::
        gadgets::guta::{
            dual_variable_height_state_transition::verify_dual_variable_height_state_transition, guta_header::compute_guta_public_inputs_hash_two_children, verify_end_cap::verify_end_cap_proof
        }
    ,
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTAVerifyTwoEndCapCircuitV2<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,

    pub global_user_tree_height: usize,
    pub max_guta_nca_merkle_proof_height: usize,
    pub checkpoint_tree_height: usize,
    pub known_end_cap_fingerprint: C::Hash,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifyTwoEndCapCircuitV2<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoEndCap
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifyTwoEndCapCircuitV2<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
        checkpoint_tree_height: usize,
        known_end_cap_fingerprint: C::Hash,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTATwoEndCap;
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
            checkpoint_tree_height,
            known_end_cap_fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &GUTAVerifyTwoEndCapCircuitInputV2<C::F, C::Hash>,
        guta_circuit_whitelist: C::Hash,
        child_a_proof: &PsyTestJTMBProof<C::Hash>,
        child_a_verifier_data: &PsyTestJTMBProofVerifierData,
        child_b_proof: &PsyTestJTMBProof<C::Hash>,
        child_b_verifier_data: &PsyTestJTMBProofVerifierData,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        let mut a_header = verify_end_cap_proof::<C>(
            &input.get_end_cap_result_a(),
            &input.left_end_cap.guta_stats,
            &input.left_end_cap.checkpoint_historical_merkle_proof,
            child_a_proof,
            child_a_verifier_data,
            self.checkpoint_tree_height,
            self.global_user_tree_height as u8,
            self.known_end_cap_fingerprint,
        )?;
        // Inject the whitelist (End caps generate headers with zero whitelist by default in some contexts, but here input carries the expected whitelist)
        a_header.guta_circuit_whitelist = guta_circuit_whitelist;

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
        b_header.guta_circuit_whitelist = guta_circuit_whitelist;

        let new_header = verify_dual_variable_height_state_transition::<C>(
            &a_header,
            &b_header,
            &input.left_global_user_tree_delta_merkle_proof,
            &input.right_global_user_tree_delta_merkle_proof,
            self.max_guta_nca_merkle_proof_height,
            self.global_user_tree_height,
        )?;
        println!("new_header computed: {:#?}", new_header);

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

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTAVerifyTwoEndCapCircuitV2<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let (left_child, right_child) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;

        let whitelist_root = library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?.root;

        let witness = GUTAVerifyTwoEndCapCircuitInputV2::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

/*         println!("got witness: {:?}", witness);
        let expected_public_inputs_hash_no_tag = witness.get_public_inputs_hash_no_rewards_tag::<C::Hasher>(32, whitelist_root);
        let expected_public_inputs_hash = C::Hasher::two_to_one(&expected_public_inputs_hash_no_tag, &worker_reward_tag);
*/
        let proof = self.prove_base(
            worker_reward_tag,
            &witness,
            whitelist_root,
            &left_child.zk_proof,
            &left_child.verifier_data,
            &right_child.zk_proof,
            &right_child.verifier_data,
        )?;
        /* 
        println!("metadata: {:?}", input.base.job.metadata);
        println!("input_pubs: {:?}", input.base.job.metadata.expected_public_inputs_hash);
        println!("get_new_guta_header: witness: {:#?}", witness.get_new_guta_header(32, whitelist_root));
        println!("expected_public_inputs_hash: {:?}", expected_public_inputs_hash);
        println!("expected_public_inputs_hash_no_tag: {:?}", expected_public_inputs_hash_no_tag);
        let metadata_final_tag = input.base.job.metadata.compute_reward_tagged_expected_public_inputs::<C::Hasher>(worker_reward_tag, &[]);
        println!("metadata_final_tag: {:?}", metadata_final_tag);
        println!("generated proof public inputs hash: {:?}", proof.public_inputs_hash);
        */
        Ok(proof)
    }
}