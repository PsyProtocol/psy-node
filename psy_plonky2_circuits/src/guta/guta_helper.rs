use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::{FieldQHasher, MerkleZeroHasher}}, felt::QFelt64, pgoldilocks::{QGenericConfig, QHashOut, QRichField}, protocol::core_types::{Q256BitHash, QFHashBase}};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use psy_core::{job::job_id::{ProvingJobCircuitType, QProvingJobDataID}, worker::traits::QNextGenWorkerGenericInfo};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use psy_plonky2_basic_helpers::{lookalike::standard::get_end_cap_type_e_common_data, verifier::circuit_library::{CircuitInfoLibrary, CircuitInfoLibraryBuilder}};
use psy_worker_core::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerGenericLibraryProverInfoProvider};

use super::circuits::{
    guta_no_change::GUTANoChangeCircuit, verify_guta_to_cap::GUTAVerifyGUTAToCapCircuit,
};
use crate::{guta::circuits::
    verify_guta_to_cap_upgrade_checkpoint::GUTAVerifyGUTAToCapUpgradeCheckpointCircuit
, guta_v2::circuits::{verify_guta_left_linear_right_leaf_upgrade_checkpoint::GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit, verify_guta_linear_transition::GUTAVerifyTwoGUTALinearCircuit, verify_guta_linear_transition_upgrade_checkpoint::GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit, verify_left_guta_right_end_cap::GUTAVerifyLeftGUTARightEndCapCircuitV2, verify_single_end_cap::GUTAVerifySingleEndCapCircuitV2, verify_two_end_cap::GUTAVerifyTwoEndCapCircuitV2, verify_two_guta::GUTAVerifyTwoGUTACircuitV2, verify_two_guta_upgrade_checkpoint::GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2}, qstandard::{QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary}, utils::proof_serialization::serialize_plonky2_proof};

#[derive(Debug)]
pub struct QEDGUTACircuitManager<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    pub end_cap_fingerprint: QHashOut<C::F>,

    pub verify_single_end_cap: GUTAVerifySingleEndCapCircuitV2<C, D>,
    pub verify_two_end_cap: GUTAVerifyTwoEndCapCircuitV2<C, D>,
    pub verify_two_guta: GUTAVerifyTwoGUTACircuitV2<C, D>,
    pub verify_left_guta_right_end_cap: GUTAVerifyLeftGUTARightEndCapCircuitV2<C, D>,

    pub verify_two_guta_linear_transition_upgrade_checkpoint: GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit<C, D>,
    pub verify_two_guta_linear_transition: GUTAVerifyTwoGUTALinearCircuit<C, D>,
    pub verify_guta_to_cap: GUTAVerifyGUTAToCapCircuit<C, D>,
    pub verify_guta_left_linear_right_leaf_upgrade_checkpoint: GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C, D>,
    pub no_change: GUTANoChangeCircuit<C, D>,

    pub verify_two_guta_upgrade_checkpoint: GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2<C, D>,
    pub verify_guta_to_cap_upgrade_checkpoint: GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C, D>,

    pub guta_circuit_whitelist_root: QHashOut<C::F>,
    pub worker_reward_tag: QHashOut<C::F>,
    pub verify_single_end_cap_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_two_end_cap_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_two_guta_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_left_guta_right_end_cap_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_two_guta_linear_transition_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_guta_to_cap_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_two_guta_upgrade_checkpoint_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_guta_to_cap_upgrade_checkpoint_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub no_change_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
}

impl<C: QGenericConfig<D> + 'static, const D: usize> QEDGUTACircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    pub fn new_with_library<T: CircuitInfoLibrary<C, D>>(
        library: &T, 
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        group_realm_height: usize,
        max_users_to_register_per_proof: usize,
                only_register_max_users_per_proof: usize,

        default_user_state_tree_root: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> Self {
        let end_cap_common = get_end_cap_type_e_common_data::<C, D>();
        let known_end_cap_fingerprint = library.get_fingerprint(ProvingJobCircuitType::UserEndCap).unwrap();
        let end_can_proof_verifier_data_cap_height = library.get_verifier_data_cap_height(ProvingJobCircuitType::UserEndCap).unwrap();
        Self::new_with_config(
            &end_cap_common,
            end_can_proof_verifier_data_cap_height,
            global_user_tree_realm_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            group_realm_height,
            max_users_to_register_per_proof,
            only_register_max_users_per_proof,
            known_end_cap_fingerprint,
            default_user_state_tree_root,
            worker_reward_tag,

        )
    }
    pub fn new_with_config(
        end_cap_proof_common_data: &CommonCircuitData<C::F, D>,
        end_cap_proof_verifier_data_cap_height: usize,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        _group_realm_height: usize,
        _max_users_to_register_per_proof: usize,
        _only_register_max_users_per_proof: usize,
        known_end_cap_fingerprint: QHashOut<C::F>,
        _default_user_state_tree_root: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> Self {

        assert!(global_user_tree_height >= global_user_tree_realm_height, "global_user_tree_height must be >= global_user_tree_realm_height");
        let coordinator_global_user_tree_height = global_user_tree_height - global_user_tree_realm_height;
        let max_guta_nca_merkle_proof_height = if global_user_tree_realm_height > coordinator_global_user_tree_height {
            global_user_tree_realm_height
        } else {
            coordinator_global_user_tree_height
        };
        let verify_single_end_cap = GUTAVerifySingleEndCapCircuitV2::<C, D>::new(
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            known_end_cap_fingerprint,
            global_user_tree_height,
            global_user_tree_realm_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        );

        let verify_two_end_cap = GUTAVerifyTwoEndCapCircuitV2::<C, D>::new(
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            known_end_cap_fingerprint,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        );

        let guta_proof_common_data: &CommonCircuitData<C::F, D> = verify_two_end_cap.get_common_circuit_data_ref();
        let guta_proof_verifier_data_cap_height: usize = verify_single_end_cap.get_verifier_config_ref().constants_sigmas_cap.height();

        let verify_two_guta = GUTAVerifyTwoGUTACircuitV2::<C, D>::new(guta_proof_common_data, guta_proof_verifier_data_cap_height, global_user_tree_height, max_guta_nca_merkle_proof_height, guta_circuit_whitelist_tree_height);

        let verify_left_guta_right_end_cap = GUTAVerifyLeftGUTARightEndCapCircuitV2::<C, D>::new(
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            known_end_cap_fingerprint,
            global_user_tree_height, 
            max_guta_nca_merkle_proof_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        );

        let verify_guta_left_linear_right_leaf_upgrade_checkpoint = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit::<C, D>::new(
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
        );

        let verify_two_guta_linear_transition = GUTAVerifyTwoGUTALinearCircuit::<C, D>::new(
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        let verify_two_guta_linear_transition_upgrade_checkpoint = GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuit::<C, D>::new(
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
        );

        let verify_guta_to_cap = GUTAVerifyGUTAToCapCircuit::<C, D>::new(guta_proof_common_data, guta_proof_verifier_data_cap_height, coordinator_global_user_tree_height, global_user_tree_height, guta_circuit_whitelist_tree_height);

        let verify_two_guta_upgrade_checkpoint =
            GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2::<C, D>::new(guta_proof_common_data, guta_proof_verifier_data_cap_height, global_user_tree_height, max_guta_nca_merkle_proof_height, guta_circuit_whitelist_tree_height, checkpoint_tree_height);

        let verify_guta_to_cap_upgrade_checkpoint =
            GUTAVerifyGUTAToCapUpgradeCheckpointCircuit::<C, D>::new(guta_proof_common_data, guta_proof_verifier_data_cap_height, coordinator_global_user_tree_height, global_user_tree_height, guta_circuit_whitelist_tree_height, checkpoint_tree_height);

        let no_change = GUTANoChangeCircuit::<C, D>::new(checkpoint_tree_height);

        let mut guta_circuit_whitelist_proofs = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::gen_fast_tree_inclusion_proofs(
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
        .unwrap();
        guta_circuit_whitelist_proofs.reverse();

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
            end_cap_fingerprint: known_end_cap_fingerprint,

            verify_single_end_cap,
            verify_two_end_cap,
            verify_two_guta,
            verify_left_guta_right_end_cap,
            verify_two_guta_linear_transition_upgrade_checkpoint,
            verify_two_guta_linear_transition,

            verify_guta_to_cap,
            no_change,
            verify_two_guta_upgrade_checkpoint,
            verify_guta_to_cap_upgrade_checkpoint,

            guta_circuit_whitelist_root: verify_two_guta_whitelist_proof.root,
            worker_reward_tag,
            verify_single_end_cap_whitelist_proof,
            verify_two_end_cap_whitelist_proof,
            verify_two_guta_whitelist_proof,
            verify_left_guta_right_end_cap_whitelist_proof,
            verify_two_guta_linear_transition_whitelist_proof,
            verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof,
            verify_guta_to_cap_whitelist_proof,
            verify_two_guta_upgrade_checkpoint_whitelist_proof,
            verify_guta_to_cap_upgrade_checkpoint_whitelist_proof,
            no_change_whitelist_proof,
            verify_guta_left_linear_right_leaf_upgrade_checkpoint,
            verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof,
        }
    }

    pub fn print_common_config(&self) {
        println!(
            "\n\n\n\n================================\n[verify_single_end_cap.common]:\n{:?}",
            self.verify_single_end_cap.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_two_end_cap.common]:\n{:?}",
            self.verify_two_end_cap.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_two_guta.common]:\n{:?}",
            self.verify_two_guta.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_left_guta_right_end_cap.common]:\n{:?}",
            self.verify_left_guta_right_end_cap.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_two_guta_linear_transition.common]:\n{:?}",
            self.verify_two_guta_linear_transition.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_two_guta_linear_transition_upgrade_checkpoint.common]:\n{:?}",
            self.verify_two_guta_linear_transition_upgrade_checkpoint.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_guta_to_cap.common]:\n{:?}",
            self.verify_guta_to_cap.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_two_guta_upgrade_checkpoint.common]:\n{:?}",
            self.verify_two_guta_upgrade_checkpoint.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_guta_to_cap_upgrade_checkpoint.common]:\n{:?}",
            self.verify_guta_to_cap_upgrade_checkpoint.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[verify_guta_left_linear_right_leaf_upgrade_checkpoint.common]:\n{:?}",
            self.verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[no_change.common]:\n{:?}",
            self.no_change.get_common_circuit_data_ref()
        );
        println!("===============================\n\n\n\n");
    }
    pub fn register_library<T: CircuitInfoLibraryBuilder<C::F>>(&self, library: &mut T) {
        library.register_circuit(
            ProvingJobCircuitType::GUTASingleEndCap.into(),
            self.verify_single_end_cap.get_fingerprint(),
            self.verify_single_end_cap.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTATwoEndCap.into(),
            self.verify_two_end_cap.get_fingerprint(),
            self.verify_two_end_cap.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTATwoGUTA.into(),
            self.verify_two_guta.get_fingerprint(),
            self.verify_two_guta.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTALeftGUTARightEndCap.into(),
            self.verify_left_guta_right_end_cap.get_fingerprint(),
            self.verify_left_guta_right_end_cap.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTATwoGUTALinear.into(),
            self.verify_two_guta_linear_transition.get_fingerprint(),
            self.verify_two_guta_linear_transition.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint.into(),
            self.verify_two_guta_linear_transition_upgrade_checkpoint.get_fingerprint(),
            self.verify_two_guta_linear_transition_upgrade_checkpoint.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTAVerifyToCap.into(),
            self.verify_guta_to_cap.get_fingerprint(),
            self.verify_guta_to_cap.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade.into(),
            self.verify_two_guta_upgrade_checkpoint.get_fingerprint(),
            self.verify_two_guta_upgrade_checkpoint.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade.into(),
            self.verify_guta_to_cap_upgrade_checkpoint.get_fingerprint(),
            self.verify_guta_to_cap_upgrade_checkpoint.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint.into(),
            self.verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_fingerprint(),
            self.verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_verifier_config_ref().into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::GUTANoChange.into(),
            self.no_change.get_fingerprint(),
            self.no_change.get_verifier_config_ref().into(),
        );

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
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
            self.verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof.clone(),
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

        library.add_inclusion_proof(&all_group, ProvingJobCircuitType::GUTANoChange, self.no_change_whitelist_proof.clone());
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QNextGenWorkerGenericInfo<QProvingJobDataID> for QEDGUTACircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        match job_id.circuit_type {
            ProvingJobCircuitType::GUTASingleEndCap => true,
            ProvingJobCircuitType::GUTATwoEndCap => true,
            ProvingJobCircuitType::GUTATwoGUTA => true,
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => true,
            ProvingJobCircuitType::GUTATwoGUTALinear => true,
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint => true,
            ProvingJobCircuitType::GUTAVerifyToCap => true,
            ProvingJobCircuitType::GUTANoChange => true,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => true,
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => true,
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint => true,
            _ => false,
        }
    }
}


impl<C: GenericConfig<D> + 'static, const D: usize> PsyWorkerGenericLibraryProverInfoProvider<QProvingJobDataID> for QEDGUTACircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    fn prover_can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        self.can_process_job(job_id)
    }
}



impl<Library: CircuitInfoLibrary<C, D>, C: QGenericConfig<D> + 'static, const D: usize> PsyWorkerGenericLibraryProver<QHashOut<C::F>,QProvingJobDataID, Library> for QEDGUTACircuitManager<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>, QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>, C::F: QFelt64 + QRichField,
{
    fn prove_job_from_api(
        &self,
        library: &Library,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<Vec<u8>>{
        let proof = match input.base.job.job_id.circuit_type {
            ProvingJobCircuitType::GUTASingleEndCap => {
                self.verify_single_end_cap
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTATwoEndCap => {
                self.verify_two_end_cap
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTATwoGUTA => {
                self.verify_two_guta
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
                self.verify_left_guta_right_end_cap
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint => {
                self.verify_two_guta_linear_transition_upgrade_checkpoint
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTATwoGUTALinear => {
                self.verify_two_guta_linear_transition
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint => {
                self.verify_guta_left_linear_right_leaf_upgrade_checkpoint
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTAVerifyToCap => {
                self.verify_guta_to_cap
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTANoChange => self.no_change.prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag),
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => {
                self.verify_two_guta_upgrade_checkpoint
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => {
                self.verify_guta_to_cap_upgrade_checkpoint
                    .prove_with_raw_proofs_and_ref_library(library, input, worker_reward_tag)
            }
            _ => anyhow::bail!("unsupported circuit: {:?}", input.base.job.job_id.circuit_type),
        }?;
        serialize_plonky2_proof::<C, D>(&proof)
    }
}


/* 
#[async_trait]
impl<S: QProofStoreReaderAsync + Send + Sync, L: CircuitInfoLibrary<C, D> + Send + Sync, C: GenericConfig<D> + 'static, const D: usize>
    QNextGenWorkerGenericProverAsyncMut<S, L, C, D> for QEDGUTACircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    async fn worker_prove_mut_async(&self, store: &S, library: &L, job_id: QProvingJobDataID) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        match job_id.circuit_type {
            ProvingJobCircuitType::GUTASingleEndCap => {
                self.verify_single_end_cap
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTATwoEndCap => {
                self.verify_two_end_cap
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTATwoGUTA => {
                self.verify_two_guta
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
                self.verify_left_guta_right_end_cap
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTALeftEndCapRightGUTA => {
                self.verify_left_end_cap_right_guta
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTARegisterUsers => {
                self.verify_guta_register_users
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTAOnlyRegisterUsers => {
                self.only_register_users
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTAVerifyToCap => {
                self.verify_guta_to_cap
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTANoChange => self.no_change.prove_with_proof_store_async(store, library, job_id, self.public_key).await,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade => {
                self.verify_two_guta_upgrade_checkpoint
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => {
                self.verify_guta_to_cap_upgrade_checkpoint
                    .prove_with_proof_store_async(store, library, job_id, self.public_key)
                    .await
            }
            _ => anyhow::bail!("unsupported circuit: {:?}", job_id.circuit_type),
        }
    }
}
    */
#[cfg(test)]
mod tests {
    use parth_core::pgoldilocks::QHashOut;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_plonky2_basic_helpers::lookalike::{custom::get_lookalike_custom, types::QCircuitCommonGatesType};
    use crate::qstandard::QStandardCircuit;

    use super::QEDGUTACircuitManager;

    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    #[test]
    fn check_fingerprints() {
        let end_cap_info = get_lookalike_custom::<C, D>(QCircuitCommonGatesType::E, 12, 4);
        let global_user_tree_realm_height = 14;
        let global_user_tree_height = 24;
        let guta_circuit_whitelist_tree_height = 4;
        let checkpoint_tree_height = 32;
        let group_realm_height = 1;
        let max_users_to_register_per_proof = 32;
        let only_register_max_users_per_proof = 64;

        let known_end_cap_fingerprint = QHashOut::rand();
        let default_user_state_tree_root = QHashOut::rand();

        let mgr = QEDGUTACircuitManager::<C, D>::new_with_config(
            &end_cap_info.common,
            end_cap_info.verifier_only.constants_sigmas_cap.height(),
            global_user_tree_realm_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            group_realm_height,
            max_users_to_register_per_proof,
            only_register_max_users_per_proof,
            known_end_cap_fingerprint,
            default_user_state_tree_root,
            QHashOut::rand(), // public_key for testing
        );

        assert_eq!(mgr.verify_single_end_cap.fingerprint, mgr.verify_single_end_cap_whitelist_proof.value,);
        assert_eq!(mgr.verify_two_end_cap.fingerprint, mgr.verify_two_end_cap_whitelist_proof.value,);
        assert_eq!(mgr.verify_two_guta.fingerprint, mgr.verify_two_guta_whitelist_proof.value,);
        assert_eq!(
            mgr.verify_left_guta_right_end_cap.fingerprint,
            mgr.verify_left_guta_right_end_cap_whitelist_proof.value,
        );

        assert_eq!(
            mgr.verify_two_guta_linear_transition.fingerprint,
            mgr.verify_two_guta_linear_transition_whitelist_proof.value,
        );
        assert_eq!(
            mgr.verify_two_guta_linear_transition_upgrade_checkpoint.get_fingerprint(),
            mgr.verify_two_guta_linear_transition_upgrade_checkpoint_whitelist_proof.value,
        );
        assert_eq!(mgr.verify_guta_to_cap.fingerprint, mgr.verify_guta_to_cap_whitelist_proof.value,);
        assert_eq!(mgr.verify_guta_left_linear_right_leaf_upgrade_checkpoint.get_fingerprint(), mgr.verify_guta_left_linear_right_leaf_upgrade_checkpoint_whitelist_proof.value,);
        assert_eq!(mgr.no_change.fingerprint, mgr.no_change_whitelist_proof.value,);
    }
}
