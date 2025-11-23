use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher, felt::QFelt64, pgoldilocks::{QHashOut, QRichField}, protocol::core_types::Q256BitHash
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
use psy_data::{proof_input::guta::{VerifyLeftGUTARightEndCapInput, VerifyLeftGUTARightEndCapInputSimple}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::pad_circuit_degree},
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::{
        helpers::ToGUTAHeader, two_nca_state_transition::TwoNCAStateTransitionGadget, verify_end_cap::VerifyEndCapProofGadget,
        verify_guta_proof::VerifyGUTAProofGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{
        QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary
    }, utils::proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof,
};

#[derive(Debug)]
pub struct GUTAVerifyLeftGUTARightEndCapCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub a_guta_gadget: VerifyGUTAProofGadget<D>,
    pub b_end_cap_gadget: VerifyEndCapProofGadget<D>,
    pub nca_state_transition_gadget: TwoNCAStateTransitionGadget,
    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTALeftGUTARightEndCap
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
    C::F: QRichField,
{
    pub fn new(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        end_cap_proof_common_data: &CommonCircuitData<C::F, D>,
        end_cap_proof_verifier_data_cap_height: usize,
        known_end_cap_fingerprint: QHashOut<C::F>,
        global_user_tree_height: usize,
        max_guta_nca_merkle_proof_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let known_end_cap_fingerprint_hash = builder.constant_qhash(known_end_cap_fingerprint);

        let a_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        let b_end_cap_gadget = VerifyEndCapProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            checkpoint_tree_height,
            global_user_tree_height,
            known_end_cap_fingerprint_hash,
        );

        let a_guta_header =
            a_guta_gadget.get_guta_header::<C::Hasher, C::F>(&mut builder, a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist);
        tracing::debug!("📊 a_guta_header: {:?}", a_guta_header);

        let b_guta_header = b_end_cap_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
            global_user_tree_height as u8,
        );
        tracing::debug!("📊 b_guta_header: {:?}", b_guta_header);

        let nca_state_transition_gadget = TwoNCAStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            a_guta_header,
            b_guta_header,
            max_guta_nca_merkle_proof_height,
            global_user_tree_height,
        );

        // generate public inputs hash from worker rewards tree tag and child rewards tree value
        // left child rewards tree value => The rewards tree value from the right hand proof verified in a_guta_gadget
        // right child rewards tree value => Zero Hash, because it is an end cap
        let left_child_rewards_tree_value = a_guta_gadget.rewards_tree_value;
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let public_inputs_hash = nca_state_transition_gadget.new_guta_header.get_public_inputs_hash_right_end_cap::<C::Hasher, C::F, D>(
            &mut builder, 
            left_child_rewards_tree_value, 
            worker_rewards_tree_tag_target
        );

        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            a_guta_gadget,
            b_end_cap_gadget,
            nca_state_transition_gadget,
            worker_rewards_tree_tag_target,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &VerifyLeftGUTARightEndCapInput<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_a_verifier_data: &VerifierOnlyCircuitData<C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        end_cap_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_child_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;

        self.a_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_a,
            &input.get_guta_header_a(),
            child_a_proof,
            child_a_verifier_data,
            left_child_proof_rewards_tree_value,
        )?;
        self.b_end_cap_gadget.set_witness(
            &mut pw,
            &input.get_end_result_b(),
            &input.b_end_cap.guta_stats,
            &input.b_end_cap.checkpoint_historical_merkle_proof,
            child_b_proof,
            end_cap_verifier_data,
        )?;

        self.nca_state_transition_gadget.set_witness_partial(&mut pw, &input.nca_proof)?;

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

impl<
        L: CircuitInfoLibrary<C, D>,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, QHashOut<C::F>: Q256BitHash, C::F: QFelt64 + QRichField,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let (left_child_guta_proof_result, right_child_end_cap_proof_result) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C, D>(
            library,
            &input,
        )?;


        let witness = VerifyLeftGUTARightEndCapInputSimple::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        
        self.prove_base(
            worker_reward_tag,
            &VerifyLeftGUTARightEndCapInput {
                checkpoint_tree_root: witness.checkpoint_tree_root,
                stats_a: witness.stats_a,
                b_end_cap: witness.b_end_cap,
                nca_proof: witness.nca_proof,
                guta_inclusion_proof_a: left_child_guta_proof_result.whitelist_inclusion_proof,
                total_aggregation_proofs_generated_a: witness.total_aggregation_proofs_generated_a,
            },
            &left_child_guta_proof_result.zk_proof,
            &left_child_guta_proof_result.verifier_data,
            &right_child_end_cap_proof_result.zk_proof,
            &right_child_end_cap_proof_result.verifier_data,
            left_child_guta_proof_result.reward_tag_tree_value,
        )
    }
}
