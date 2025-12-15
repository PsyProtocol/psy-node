use parth_core::crypto::hash::{merkle_proof::MerkleProofCore, traits::ZeroableHash};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::guta::{
            guta_header::compute_guta_public_inputs_hash_two_children, verify_guta_proof::verify_guta_proof, verify_historical_root::verify_historical_root_proof_gt, verify_to_cap::verify_guta_to_cap
        },
        utils::connect::jtmb_connect_ref,
    },
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_single_child_proof_for_api_response_with_inclusion_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,
    pub guta_circuit_whitelist_tree_height: u8,
    pub checkpoint_tree_height: usize,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(circuit_type as u32, [0u8; 32], &private_key.get_public_key());
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
        input: &VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<C::F, C::Hash>,
        guta_inclusion_proof: &MerkleProofCore<C::Hash>,
        child_proof: &PsyTestJTMBProof<C::Hash>,
        child_verifier_data: &PsyTestJTMBProofVerifierData,
        child_rewards: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        
        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_inclusion_proof,
            &input.guta_proof_header,
            child_proof,
            child_verifier_data,
            child_rewards,
        )?;

        // Upgrade Checkpoint
        let (hist, current) = verify_historical_root_proof_gt::<C>(&input.historical_checkpoint_proof)?;
        jtmb_connect_ref(&hist, &input.guta_proof_header.checkpoint_tree_root, "historical checkpoint root mismatch")?;
        
        let mut header_upgraded = input.guta_proof_header.clone();
        header_upgraded.checkpoint_tree_root = current;

        let new_header = verify_guta_to_cap::<C>(
            &header_upgraded,
            &input.top_line_siblings,
        )?;

        let zero = C::Hash::get_zero_value();
        let public_inputs_hash = compute_guta_public_inputs_hash_two_children::<C::F, C::Hash, C::Hasher>(
            &new_header,
            child_rewards,
            zero,
            worker_reward_tag,
        );

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            public_inputs_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let child = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        let witness = VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            &child.whitelist_inclusion_proof,
            &child.zk_proof,
            &child.verifier_data,
            child.reward_tag_tree_value,
        )
    }
}