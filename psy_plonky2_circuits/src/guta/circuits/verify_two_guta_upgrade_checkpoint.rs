use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    felt::QFelt64,
    pgoldilocks::{QHashOut, QRichField},
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
use psy_data::{
    proof_input::guta::{VerifyTwoGUTAProofUpgradeCheckpointStandardInput, VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple},
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_plonky2_basic_helpers::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{PsyCircuitBuilderGateCountPrinter, pad_circuit_degree}}, verifier::circuit_library::CircuitInfoLibrary};
use psy_plonky2_common_circuits::hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::{helpers::ToGUTAHeader, two_nca_state_transition::TwoNCAStateTransitionGadget, verify_guta_proof::VerifyGUTAProofGadget},
    proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
    qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary},
    utils::proof_llbrary::get_two_child_proofs_for_api_response_with_inclusion_proof,
};

#[derive(Debug)]
pub struct GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub a_guta_gadget: VerifyGUTAProofGadget<D>,
    pub b_guta_gadget: VerifyGUTAProofGadget<D>,
    pub historical_checkpoint_proof_a: HistoricalRootMerkleProofGadget,
    pub historical_checkpoint_proof_b: HistoricalRootMerkleProofGadget,
    pub nca_state_transition_gadget: TwoNCAStateTransitionGadget,
    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,

    pub minifier_chain: QEDProofMinifierDynamicChain<D, C::F, C>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    C::F: QRichField,
{
    pub fn new(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,

        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        builder.print_gate_counts_with_message("G2GUpgrade start");
        let a_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        builder.print_gate_counts_with_message("G2GUpgrade after a_guta_gadget");


        let b_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        builder.print_gate_counts_with_message("G2GUpgrade after b_guta_gadget");

        let historical_checkpoint_proof_a =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);
        builder.print_gate_counts_with_message("G2GUpgrade after historical_checkpoint_proof_a");

        let historical_checkpoint_proof_b =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);
        builder.print_gate_counts_with_message("G2GUpgrade after historical_checkpoint_proof_b");

        // ensure we are syncing both proofs to the same checkpoint root
        builder.connect_hashes(historical_checkpoint_proof_a.current_root, historical_checkpoint_proof_b.current_root);

        // sanity check: ensure we are not referencing a checkpoint proof with a zero
        // checkpoint leaf
        builder.ensure_hash_is_non_zero(historical_checkpoint_proof_a.current_value);
        builder.ensure_hash_is_non_zero(historical_checkpoint_proof_b.current_value);

        let mut a_guta_header = a_guta_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
            //a_guta_gadget.guta_whitelist_merkle_proof.root,
        );

        let mut b_guta_header =
            b_guta_gadget.get_guta_header::<C::Hasher, C::F>(&mut builder, b_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist);
        builder.print_gate_counts_with_message("G2GUpgrade after get_guta_headers");

        // ensure that the guta proof headers match our historical checkpoint tree
        // proofs historical roots
        builder.connect_hashes(a_guta_header.checkpoint_tree_root, historical_checkpoint_proof_a.historical_root);
        builder.connect_hashes(b_guta_header.checkpoint_tree_root, historical_checkpoint_proof_b.historical_root);

        // AFTER we have connected the historical roots, we can now override the
        // checkpoint tree roots in the guta headers to be the current roots from the
        // historical proofs
        a_guta_header.checkpoint_tree_root = historical_checkpoint_proof_a.current_root;
        b_guta_header.checkpoint_tree_root = historical_checkpoint_proof_b.current_root;
        builder.print_gate_counts_with_message("G2GUpgrade before nca_state_transition_gadget");

        let nca_state_transition_gadget = TwoNCAStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            a_guta_header,
            b_guta_header,
            max_guta_nca_merkle_proof_height,
            global_user_tree_height,
        );
        builder.print_gate_counts_with_message("G2GUpgrade after nca_state_transition_gadget");


        // compute public inputs hash from worker rewards tree tag and child rewards tree value:
        // left child rewards tree value => The rewards tree value from the left hand proof verified in a_guta_gadget 
        // right child rewards tree value => The rewards tree value from the right hand proof verified in b_guta_gadget
        let left_child_proof_rewards_tree_value = a_guta_gadget.rewards_tree_value;
        let right_child_proof_rewards_tree_value = b_guta_gadget.rewards_tree_value;
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let public_inputs_hash = nca_state_transition_gadget
            .new_guta_header
            .get_public_inputs_hash_two_children::<C::Hasher, C::F, D>(
                &mut builder,
                left_child_proof_rewards_tree_value,
                right_child_proof_rewards_tree_value,
                worker_rewards_tree_tag_target,
            );
        builder.print_gate_counts_with_message("G2GUpgrade after public_inputs_hash");

        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.print_gate_counts_with_message("G2GUpgrade after register_public_inputs");

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        builder.print_gate_counts_with_message("G2GUpgrade before build");
        let circuit_data = builder.build::<C>();
        println!("common_data_verify_two_guta_upgrade_checkpoint: {:?}", circuit_data.common);

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let minifier_chain = QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[true],
        );

        Self {
            a_guta_gadget,
            b_guta_gadget,
            historical_checkpoint_proof_a,
            historical_checkpoint_proof_b,
            nca_state_transition_gadget,
            worker_rewards_tree_tag_target,
            circuit_data,
            fingerprint,
            minifier_chain,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &VerifyTwoGUTAProofUpgradeCheckpointStandardInput<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_a_verifier_data: &VerifierOnlyCircuitData<C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_b_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_child_proof_rewards_tree_value: QHashOut<C::F>,
        right_child_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;

        tracing::debug!(
            "🔄 Two GUTA Upgrade Checkpoint set_witness - worker_rewards_tree_tag: {}, checkpoint_proof_a: {}, checkpoint_proof_b: {}",
            serde_json::to_string_pretty(&worker_rewards_tree_tag).unwrap(),
            serde_json::to_string_pretty(&input.historical_checkpoint_proof_a).unwrap(),
            serde_json::to_string_pretty(&input.historical_checkpoint_proof_b).unwrap()
        );

        self.historical_checkpoint_proof_a
            .set_witness_proof_core(&mut pw, &input.historical_checkpoint_proof_a)?;
        self.historical_checkpoint_proof_b
            .set_witness_proof_core(&mut pw, &input.historical_checkpoint_proof_b)?;

        self.a_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_a,
            &input.get_guta_header_a::<C::Hasher>(),
            child_a_proof,
            child_a_verifier_data,
            left_child_proof_rewards_tree_value,
        )?;
        self.b_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_b,
            &input.get_guta_header_b::<C::Hasher>(),
            child_b_proof,
            child_b_verifier_data,
            right_child_proof_rewards_tree_value,
        )?;

        self.nca_state_transition_gadget.set_witness_partial(&mut pw, &input.nca_proof)?;

        let base_proof = self.circuit_data.prove(pw)?;
        self.minifier_chain.prove(&base_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.minifier_chain.get_common_data()
    }
}

#[async_trait]
impl<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
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

        let witness = VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        self.prove_base(
            worker_reward_tag,
            &VerifyTwoGUTAProofUpgradeCheckpointStandardInput {
                historical_checkpoint_proof_a: witness.historical_checkpoint_proof_a,
                historical_checkpoint_proof_b: witness.historical_checkpoint_proof_b,
                stats_a: witness.stats_a,
                stats_b: witness.stats_b,
                nca_proof: witness.nca_proof,
                guta_inclusion_proof_a: left_child_guta_proof_result.whitelist_inclusion_proof,
                guta_inclusion_proof_b: right_child_guta_proof_result.whitelist_inclusion_proof,
                total_aggregation_proofs_generated_a: witness.total_aggregation_proofs_generated_a,
                total_aggregation_proofs_generated_b: witness.total_aggregation_proofs_generated_b,
            },
            &left_child_guta_proof_result.zk_proof,
            &left_child_guta_proof_result.verifier_data,
            &right_child_guta_proof_result.zk_proof,
            &right_child_guta_proof_result.verifier_data,
            left_child_guta_proof_result.reward_tag_tree_value,
            right_child_guta_proof_result.reward_tag_tree_value,
        )
    }
}
