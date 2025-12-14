use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    proof_input::guta::GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::guta::{
            guta_header::compute_guta_public_inputs_hash_two_children, guta_linear_transition::verify_guta_linear_transition,
            verify_guta_proof::verify_guta_proof, verify_historical_root::verify_historical_root_proof_gt,
        },
        utils::connect::jtmb_connect_ref,
    },
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof
    },
};

#[derive(Debug, Clone)]
pub struct GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    pub guta_circuit_whitelist_tree_height: u8,
    pub checkpoint_tree_height: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C> {
    pub fn new(private_key: &MemorySecp256K1SinglePrivateKeyWallet, guta_circuit_whitelist_tree_height: u8, checkpoint_tree_height: usize) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint;
        let verifier_data =
            PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<C::F, C::Hash>,
        guta_inclusion_proof_a: &MerkleProofCore<C::Hash>,
        guta_inclusion_proof_b: &MerkleProofCore<C::Hash>,
        child_a_proof: &PsyTestJTMBProof<C::Hash>,
        child_a_verifier_data: &PsyTestJTMBProofVerifierData,
        child_b_proof: &PsyTestJTMBProof<C::Hash>,
        child_b_verifier_data: &PsyTestJTMBProofVerifierData,
        left_child_rewards: C::Hash,
        right_child_rewards: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof_a,
            &input.left_header,
            child_a_proof,
            child_a_verifier_data,
            left_child_rewards,
        )?;

        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof_b,
            &input.right_header,
            child_b_proof,
            child_b_verifier_data,
            right_child_rewards,
        )?;

        // Upgrade Checkpoints
        let (hist_a, current_a) = verify_historical_root_proof_gt::<C>(&input.left_historical_checkpoint_proof)?;
        jtmb_connect_ref(&hist_a, &input.left_header.checkpoint_tree_root, "left checkpoint root mismatch")?;
        let mut a_header = input.left_header.clone();
        a_header.checkpoint_tree_root = current_a;

        let (hist_b, current_b) = verify_historical_root_proof_gt::<C>(&input.right_historical_checkpoint_proof)?;
        jtmb_connect_ref(&hist_b, &input.right_header.checkpoint_tree_root, "right checkpoint root mismatch")?;
        let mut b_header = input.right_header.clone();
        b_header.checkpoint_tree_root = current_b;

        jtmb_connect_ref(&current_a, &current_b, "upgraded checkpoint roots mismatch")?;

        // Linear Transition
        let new_header = verify_guta_linear_transition::<C>(&a_header, &b_header)?;

        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            left_child_rewards,
            right_child_rewards,
            worker_reward_tag,
        );

        self.verifier_data
            .generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(public_inputs_hash, &self.private_key)
    }
}

impl<
        L: PsyJTMBCircuitInfoLibrary<C::Hash>,
        C: JTMBCircuitConfig,
    > QJTMBProofCircuit<C, L> for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C>
{
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let (left, right) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        let witness = GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            &left.whitelist_inclusion_proof,
            &right.whitelist_inclusion_proof,
            &left.zk_proof,
            &left.verifier_data,
            &right.zk_proof,
            &right.verifier_data,
            left.reward_tag_tree_value,
            right.reward_tag_tree_value,
        )
    }
}
