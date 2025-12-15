use parth_common::{memory_stores::simple_merkle_tree::SimpleMerkleTree, secp256k1::MemorySecp256K1SinglePrivateKeyWallet};
use parth_core::
    crypto::hash::merkle_proof::MerkleProofCore
;
use psy_core::{
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
    worker::traits::QNextGenWorkerGenericInfo,
};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use psy_worker_core::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerGenericLibraryProverInfoProvider};

use crate::{
    proving::circuits::{
        dummy_end_cap::DummyUPSStandardEndCapCircuit,
        guta::{
            guta_no_change::GUTANoChangeCircuit, verify_guta_left_linear_right_leaf_upgrade_checkpoint::GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit, verify_guta_linear_transition::GUTAVerifyTwoGUTALinearCircuit, verify_guta_to_cap::GUTAVerifyGUTAToCapCircuit, verify_guta_to_cap_upgrade_checkpoint::GUTAVerifyGUTAToCapUpgradeCheckpointCircuit, verify_left_guta_right_end_cap::GUTAVerifyLeftGUTARightEndCapCircuitV2, verify_single_end_cap::GUTAVerifySingleEndCapCircuitV2, verify_two_end_cap::GUTAVerifyTwoEndCapCircuitV2, verify_two_guta::GUTAVerifyTwoGUTACircuitV2, verify_two_guta_linear_transition_upgrade_checkpoint::GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit, verify_two_guta_upgrade_checkpoint::GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2
        },
    },
    utils::{
        circuit_info_library::{PsyJTMBCircuitInfoLibrary, PsyJTMBCircuitInfoLibraryBuilder},
        jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase},
        proof_serialization::serialize_jtmb_proof,
    },
};

pub struct QEDGUTACircuitManager<C: JTMBCircuitConfig> {
    // Circuits
    pub verify_single_end_cap: GUTAVerifySingleEndCapCircuitV2<C>,
    pub verify_two_end_cap: GUTAVerifyTwoEndCapCircuitV2<C>,
    pub verify_two_guta: GUTAVerifyTwoGUTACircuitV2<C>,
    pub verify_left_guta_right_end_cap: GUTAVerifyLeftGUTARightEndCapCircuitV2<C>,
    pub verify_two_guta_linear_transition: GUTAVerifyTwoGUTALinearCircuit<C>,
    pub verify_two_guta_linear_transition_upgrade_checkpoint: GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C>,
    pub verify_guta_to_cap: GUTAVerifyGUTAToCapCircuit<C>,
    pub verify_two_guta_upgrade_checkpoint: GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2<C>,
    pub verify_guta_to_cap_upgrade_checkpoint: GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C>,
    pub verify_guta_left_linear_right_leaf_upgrade_checkpoint: GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C>,
    pub no_change: GUTANoChangeCircuit<C>,

    // Whitelist Config
    pub guta_circuit_whitelist_root: C::Hash,

    // Inclusion Proofs
    pub verify_single_end_cap_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_two_end_cap_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_two_guta_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_left_guta_right_end_cap_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_two_guta_linear_transition_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_guta_to_cap_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_two_guta_upgrade_checkpoint_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_guta_to_cap_upgrade_checkpoint_whitelist_proof: MerkleProofCore<C::Hash>,
    pub verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof: MerkleProofCore<C::Hash>,
    pub no_change_whitelist_proof: MerkleProofCore<C::Hash>,
}

impl<C: JTMBCircuitConfig> QEDGUTACircuitManager<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        global_user_tree_realm_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
    ) -> Self {
        // Instantiate a dummy end cap to get its fingerprint
        let end_cap_circuit = DummyUPSStandardEndCapCircuit::<C>::new(private_key);
        let end_cap_fingerprint = end_cap_circuit.get_fingerprint();

        // 1. Instantiate all circuits
        let verify_single_end_cap = GUTAVerifySingleEndCapCircuitV2::new(
            private_key,
            global_user_tree_height,
            global_user_tree_realm_height,
            checkpoint_tree_height,
            end_cap_fingerprint,
        );
        let verify_two_end_cap = GUTAVerifyTwoEndCapCircuitV2::new(
            private_key,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            checkpoint_tree_height,
            end_cap_fingerprint,
        );
        let verify_two_guta = GUTAVerifyTwoGUTACircuitV2::new(
            private_key,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
        );
        let verify_left_guta_right_end_cap = GUTAVerifyLeftGUTARightEndCapCircuitV2::new(
            private_key,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            end_cap_fingerprint,
        );
        let verify_two_guta_linear_transition = GUTAVerifyTwoGUTALinearCircuit::new(private_key, guta_circuit_whitelist_tree_height);
        let verify_two_guta_linear_transition_upgrade_checkpoint =
            GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit::new(private_key, guta_circuit_whitelist_tree_height, checkpoint_tree_height);
        let verify_guta_to_cap = GUTAVerifyGUTAToCapCircuit::new(private_key, guta_circuit_whitelist_tree_height);
        let verify_two_guta_upgrade_checkpoint = GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2::new(
            private_key,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        );
        let verify_guta_to_cap_upgrade_checkpoint =
            GUTAVerifyGUTAToCapUpgradeCheckpointCircuit::new(private_key, guta_circuit_whitelist_tree_height, checkpoint_tree_height);
        let verify_guta_left_linear_right_leaf_upgrade_checkpoint = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit::new(
                private_key,
                guta_circuit_whitelist_tree_height,
                checkpoint_tree_height,
                global_user_tree_height,
                max_guta_nca_merkle_proof_height,
        );
        let no_change = GUTANoChangeCircuit::new(private_key, checkpoint_tree_height);

        // 2. Generate Whitelist Merkle Tree
        let mut guta_circuit_whitelist_proofs = SimpleMerkleTree::<C::Hasher, C::Hash>::gen_fast_tree_inclusion_proofs(
            guta_circuit_whitelist_tree_height,
            &[
                verify_single_end_cap.get_fingerprint(),
                verify_two_end_cap.get_fingerprint(),
                verify_two_guta.get_fingerprint(),
                verify_left_guta_right_end_cap.get_fingerprint(),
                verify_two_guta_linear_transition.get_fingerprint(),
                verify_two_guta_linear_transition_upgrade_checkpoint.get_fingerprint(),
                verify_guta_to_cap.get_fingerprint(),
                verify_two_guta_upgrade_checkpoint.get_fingerprint(),
                verify_guta_to_cap_upgrade_checkpoint.get_fingerprint(),
                verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_fingerprint(),
                no_change.get_fingerprint(),
            ],
        )
        .expect("Failed to generate GUTA whitelist");

        let guta_circuit_whitelist_root = guta_circuit_whitelist_proofs[0].root;
        guta_circuit_whitelist_proofs.reverse(); // Pop order

        let verify_single_end_cap_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_two_end_cap_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_two_guta_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_left_guta_right_end_cap_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_two_guta_linear_transition_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_guta_to_cap_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_two_guta_upgrade_checkpoint_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_guta_to_cap_upgrade_checkpoint_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();
        let no_change_whitelist_proof = guta_circuit_whitelist_proofs.pop().unwrap();

        Self {
            verify_single_end_cap,
            verify_two_end_cap,
            verify_two_guta,
            verify_left_guta_right_end_cap,
            verify_two_guta_linear_transition,
            verify_two_guta_linear_transition_upgrade_checkpoint,
            verify_guta_to_cap,
            verify_two_guta_upgrade_checkpoint,
            verify_guta_to_cap_upgrade_checkpoint,
            verify_guta_left_linear_right_leaf_upgrade_checkpoint,
            no_change,

            guta_circuit_whitelist_root,

            verify_single_end_cap_whitelist_proof,
            verify_two_end_cap_whitelist_proof,
            verify_two_guta_whitelist_proof,
            verify_left_guta_right_end_cap_whitelist_proof,
            verify_two_guta_linear_transition_whitelist_proof,
            verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof,
            verify_guta_to_cap_whitelist_proof,
            verify_two_guta_upgrade_checkpoint_whitelist_proof,
            verify_guta_to_cap_upgrade_checkpoint_whitelist_proof,
            verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof,
            no_change_whitelist_proof,
        }
    }

    pub fn register_library<L: PsyJTMBCircuitInfoLibraryBuilder<C::Hash>>(&self, library: &mut L) {
        let circuits: Vec<&dyn QJTMBProofCircuitBase<C::Hash>> = vec![
            &self.verify_single_end_cap,
            &self.verify_two_end_cap,
            &self.verify_two_guta,
            &self.verify_left_guta_right_end_cap,
            &self.verify_two_guta_linear_transition,
            &self.verify_two_guta_linear_transition_upgrade_checkpoint,
            &self.verify_guta_to_cap,
            &self.verify_two_guta_upgrade_checkpoint,
            &self.verify_guta_to_cap_upgrade_checkpoint,
            &self.verify_guta_left_linear_right_leaf_upgrade_checkpoint,
            &self.no_change,
        ];

        for c in circuits {
            library.register_circuit(c.get_circuit_type(), c.get_fingerprint(), c.get_verifier_data().clone());
        }

        let all_group = [
            ProvingJobCircuitType::GUTASingleEndCap,
            ProvingJobCircuitType::GUTATwoEndCap,
            ProvingJobCircuitType::GUTATwoGUTA,
            ProvingJobCircuitType::GUTALeftGUTARightEndCap,
            ProvingJobCircuitType::GUTATwoGUTALinear,
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint,
            ProvingJobCircuitType::GUTAVerifyToCap,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
            ProvingJobCircuitType::GUTANoChange,
        ];

        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTASingleEndCap,
            self.verify_single_end_cap_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTATwoEndCap,
            self.verify_two_end_cap_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTATwoGUTA,
            self.verify_two_guta_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTALeftGUTARightEndCap,
            self.verify_left_guta_right_end_cap_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTATwoGUTALinear,
            self.verify_two_guta_linear_transition_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint,
            self.verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTAVerifyToCap,
            self.verify_guta_to_cap_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
            self.verify_two_guta_upgrade_checkpoint_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
            self.verify_guta_to_cap_upgrade_checkpoint_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(
            &all_group,
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
            self.verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof.clone(),
        );
        library.add_inclusion_proof(&all_group, ProvingJobCircuitType::GUTANoChange, self.no_change_whitelist_proof.clone());
    }
}

impl<C: JTMBCircuitConfig> QNextGenWorkerGenericInfo<QProvingJobDataID> for QEDGUTACircuitManager<C> {
    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        match job_id.circuit_type {
            ProvingJobCircuitType::GUTASingleEndCap
            | ProvingJobCircuitType::GUTATwoEndCap
            | ProvingJobCircuitType::GUTATwoGUTA
            | ProvingJobCircuitType::GUTALeftGUTARightEndCap
            | ProvingJobCircuitType::GUTATwoGUTALinear
            | ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint
            | ProvingJobCircuitType::GUTAVerifyToCap
            | ProvingJobCircuitType::GUTANoChange
            | ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
            | ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
            | ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint => true,
            _ => false,
        }
    }
}

impl<C: JTMBCircuitConfig> PsyWorkerGenericLibraryProverInfoProvider<QProvingJobDataID> for QEDGUTACircuitManager<C> {
    fn prover_can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        self.can_process_job(job_id)
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> PsyWorkerGenericLibraryProver<C::Hash, QProvingJobDataID, L>
    for QEDGUTACircuitManager<C>
{
    fn prove_job_from_api(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<Vec<u8>> {
        let proof = match input.base.job.job_id.circuit_type {
            ProvingJobCircuitType::GUTASingleEndCap => {
                self.verify_single_end_cap
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTATwoEndCap => {
                self.verify_two_end_cap
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTATwoGUTA => {
                self.verify_two_guta
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
                self.verify_left_guta_right_end_cap
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTATwoGUTALinear => {
                self.verify_two_guta_linear_transition
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint => self
                .verify_two_guta_linear_transition_upgrade_checkpoint
                .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GUTAVerifyToCap => {
                self.verify_guta_to_cap
                    .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?
            }
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => self
                .verify_two_guta_upgrade_checkpoint
                .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => self
                .verify_guta_to_cap_upgrade_checkpoint
                .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint => self
                .verify_guta_left_linear_right_leaf_upgrade_checkpoint
                .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            ProvingJobCircuitType::GUTANoChange => self
                .no_change
                .jtmb_prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)?,
            _ => anyhow::bail!("Unsupported GUTA circuit type: {:?}", input.base.job.job_id.circuit_type),
        };
        serialize_jtmb_proof(&proof)
    }
}