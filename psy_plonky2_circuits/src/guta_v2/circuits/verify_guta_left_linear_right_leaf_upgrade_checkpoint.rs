use async_trait::async_trait;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    felt::QFelt64,
    pgoldilocks::{QGenericConfig, QHashOut, QRichField},
    protocol::core_types::Q256BitHash,
};
use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::PsyCircuitBuilderGateCountPrinter},
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::{
        helpers::ToGUTAHeader,
        left_linear_right_variable_height_state_transition::LeftLinearRightVariableHeightStateTransitionGadget,
        verify_guta_proof::VerifyGUTAProofGadget,
    },
    proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
    qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary},
    utils::proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof,
};

#[derive(Debug)]
pub struct GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub a_guta_gadget: VerifyGUTAProofGadget<D>,
    pub b_guta_gadget: VerifyGUTAProofGadget<D>,
    pub historical_checkpoint_proof_b: HistoricalRootMerkleProofGadget,
    pub llrv_state_transition_gadget: LeftLinearRightVariableHeightStateTransitionGadget,
    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,

    pub minifier_chain: Option<QEDProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    C::F: QRichField,
{
    pub fn new(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
    ) -> Self {
        Self::new_with_config(
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
            checkpoint_tree_height,
            global_user_tree_height,
            max_guta_nca_merkle_proof_height,
            false,
        )
    }
    pub fn new_with_config(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade start");
        let a_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after a_guta_gadget");

        let b_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after b_guta_gadget");

        let historical_checkpoint_proof_b =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after historical_checkpoint_proof_b");

        // ensure we are syncing both proofs to the same checkpoint root
        builder.connect_hashes(
            a_guta_gadget.guta_proof_header_gadget.checkpoint_tree_root,
            historical_checkpoint_proof_b.current_root,
        );

        // sanity check: ensure we are not referencing a checkpoint proof with a zero
        // checkpoint leaf
        builder.ensure_hash_is_non_zero(a_guta_gadget.guta_proof_header_gadget.checkpoint_tree_root);
        builder.ensure_hash_is_non_zero(historical_checkpoint_proof_b.current_value);

        let a_guta_header = a_guta_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
            //a_guta_gadget.guta_whitelist_merkle_proof.root,
        );

        let mut b_guta_header =
            b_guta_gadget.get_guta_header::<C::Hasher, C::F>(&mut builder, b_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist);
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after get_guta_headers");

        // ensure that the guta proof headers match our historical checkpoint tree
        // proofs historical roots
        builder.connect_hashes(a_guta_header.checkpoint_tree_root, historical_checkpoint_proof_b.current_root);
        builder.connect_hashes(b_guta_header.checkpoint_tree_root, historical_checkpoint_proof_b.historical_root);

        // AFTER we have connected the historical roots, we can now override the
        // checkpoint tree roots in the guta headers to be the current roots from the
        // historical proofs
        b_guta_header.checkpoint_tree_root = historical_checkpoint_proof_b.current_root;
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade before guta_linear_state_transition_gadget");

        let llrv_state_transition_gadget = LeftLinearRightVariableHeightStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            a_guta_header,
            b_guta_header,
            max_guta_nca_merkle_proof_height,
            global_user_tree_height,
        );
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after guta_linear_state_transition_gadget");

        // compute public inputs hash from worker rewards tree tag and child rewards
        // tree value: left child rewards tree value => The rewards tree value
        // from the left hand proof verified in a_guta_gadget right child
        // rewards tree value => The rewards tree value from the right hand proof
        // verified in b_guta_gadget
        let left_child_proof_rewards_tree_value = a_guta_gadget.rewards_tree_value;
        let right_child_proof_rewards_tree_value = b_guta_gadget.rewards_tree_value;
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let public_inputs_hash = llrv_state_transition_gadget
            .new_guta_header
            .get_public_inputs_hash_two_children::<C::Hasher, C::F, D>(
                &mut builder,
                left_child_proof_rewards_tree_value,
                right_child_proof_rewards_tree_value,
                worker_rewards_tree_tag_target,
            );
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after public_inputs_hash");

        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade after register_public_inputs");

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        builder.print_gate_counts_with_message("GLeftLinearRightLeafUpgrade before build");
        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(&base_circuit_data.verifier_only));

        let minifier_chain = if has_minifier {
            Some(QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &base_circuit_data.verifier_only,
                &base_circuit_data.common,
                &[true],
            ))
        } else {
            None
        };
        Self {
            a_guta_gadget,
            b_guta_gadget,
            historical_checkpoint_proof_b,
            llrv_state_transition_gadget,
            worker_rewards_tree_tag_target,
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_a_verifier_data: &VerifierOnlyCircuitData<C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_b_verifier_data: &VerifierOnlyCircuitData<C, D>,
        guta_inclusion_proof_a: &MerkleProofCore<QHashOut<C::F>>,
        guta_inclusion_proof_b: &MerkleProofCore<QHashOut<C::F>>,
        left_child_proof_rewards_tree_value: QHashOut<C::F>,
        right_child_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;

        
        self.historical_checkpoint_proof_b
            .set_witness_proof_core(&mut pw, &input.right_historical_checkpoint_proof)?;

        self.a_guta_gadget.set_witness(
            &mut pw,
            &guta_inclusion_proof_a,
            &input.left_header,
            child_a_proof,
            child_a_verifier_data,
            left_child_proof_rewards_tree_value,
        )?;
        self.b_guta_gadget.set_witness(
            &mut pw,
            &guta_inclusion_proof_b,
            &input.right_header,
            child_b_proof,
            child_b_verifier_data,
            right_child_proof_rewards_tree_value,
        )?;
        self.llrv_state_transition_gadget.set_witness_params(&mut pw, &input.right_global_user_tree_delta_merkle_proof)?;

        let base_proof = self.base_circuit_data.prove(pw)?;

        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().prove(&base_proof)
        } else {
            Ok(base_proof)
        }
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.enable_minifier {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        } else {
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        } else {
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        } else {
            &self.base_circuit_data.common
        }
    }
}

#[async_trait]
impl<L: CircuitInfoLibrary<C, D>, C: QGenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash,
    C::F: QFelt64 + QRichField,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let (left_child_guta_proof_result, right_child_guta_proof_result) =
            get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C, D>(library, &input)?;

        let witness = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &witness,
            &left_child_guta_proof_result.zk_proof,
            &left_child_guta_proof_result.verifier_data,
            &right_child_guta_proof_result.zk_proof,
            &right_child_guta_proof_result.verifier_data,
            &left_child_guta_proof_result.whitelist_inclusion_proof,
            &right_child_guta_proof_result.whitelist_inclusion_proof,
            left_child_guta_proof_result.reward_tag_tree_value,
            right_child_guta_proof_result.reward_tag_tree_value,
        )
    }
}
