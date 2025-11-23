use cf_utils::timer::DebugTimer;
use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher, felt::QFelt64, pgoldilocks::{QHashOut, QRichField}, protocol::core_types::Q256BitHash
};
use psy_core::
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID}
;
use psy_data::{
    proof_input::guta::GUTAVerifyTwoEndCapCircuitInputV2, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{PsyCircuitBuilderGateCountPrinter, pad_circuit_degree},
    },
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::dual_variable_height_state_transition::DualVariableHeightStateTransitionGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary}, utils::proof_library::get_two_child_proofs_for_api_response_with_inclusion_proof
};

use crate::guta::gadgets::verify_end_cap::VerifyEndCapProofGadget;

#[derive(Debug)]
pub struct GUTAVerifyTwoEndCapCircuitV2<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub guta_circuit_whitelist_root_hash: HashOutTarget,
    pub a_end_cap_gadget: VerifyEndCapProofGadget<D>,
    pub b_end_cap_gadget: VerifyEndCapProofGadget<D>,
    pub dvh_state_transition_gadget: DualVariableHeightStateTransitionGadget,
    pub worker_rewards_tree_tag: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}


impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyTwoEndCapCircuitV2<C, D> where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoEndCap
    }
}
impl<C: GenericConfig<D>+ 'static, const D: usize> GUTAVerifyTwoEndCapCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, C::F: QRichField {
        pub fn new(
            end_cap_proof_common_data: &CommonCircuitData<C::F, D>,
            end_cap_proof_verifier_data_cap_height: usize,
            known_end_cap_fingerprint: QHashOut<C::F>,
            global_user_tree_height: usize,
            max_guta_nca_merkle_proof_height: usize,
            _guta_circuit_whitelist_tree_height: u8,
            checkpoint_tree_height: usize,
        ) -> Self {

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let known_end_cap_fingerprint_hash = builder.constant_qhash(known_end_cap_fingerprint);

        let guta_circuit_whitelist_root_hash = builder.add_virtual_hash();

        let a_end_cap_gadget = VerifyEndCapProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            checkpoint_tree_height,
            global_user_tree_height,
            known_end_cap_fingerprint_hash,
        );

        let b_end_cap_gadget = VerifyEndCapProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            checkpoint_tree_height,
            global_user_tree_height,
            known_end_cap_fingerprint_hash,
        );


        let a_end_cap_guta_header = a_end_cap_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            guta_circuit_whitelist_root_hash,
            global_user_tree_height as u8,
        );
        tracing::debug!("📊 a_end_cap_guta_header: {:?}", a_end_cap_guta_header);

        let b_end_cap_guta_header = b_end_cap_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            guta_circuit_whitelist_root_hash,

            global_user_tree_height as u8,
        );
        tracing::debug!("📊 b_end_cap_guta_header: {:?}", b_end_cap_guta_header);

        let dvh_state_transition_gadget = DualVariableHeightStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            a_end_cap_guta_header,
            b_end_cap_guta_header,
            max_guta_nca_merkle_proof_height,
            global_user_tree_height,
        );

        let worker_rewards_tree_tag = builder.add_virtual_hash();
        let public_inputs_hash = dvh_state_transition_gadget.new_guta_header.get_public_inputs_hash_two_end_cap::<C::Hasher, C::F, D>(&mut builder, worker_rewards_tree_tag);

        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        builder.print_gate_counts_with_message("G2EC before pad");
        pad_circuit_degree(&mut builder, 12);
        builder.print_gate_counts_with_message("G2EC after pad");

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            guta_circuit_whitelist_root_hash,
            a_end_cap_gadget,
            b_end_cap_gadget,
            dvh_state_transition_gadget,
            worker_rewards_tree_tag,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &GUTAVerifyTwoEndCapCircuitInputV2<C::F, QHashOut<C::F>>,
        guta_circuit_whitelist: QHashOut<C::F>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        end_cap_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_hash_target(self.guta_circuit_whitelist_root_hash, guta_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_rewards_tree_tag, worker_rewards_tree_tag.0)?;

        self.a_end_cap_gadget.set_witness(
            &mut pw,
            &input.get_end_cap_result_a(),
            &input.left_end_cap.guta_stats,
            &input.left_end_cap.checkpoint_historical_merkle_proof,
            child_a_proof,
            end_cap_verifier_data
        )?;
        self.b_end_cap_gadget.set_witness(
            &mut pw,
            &input.get_end_cap_result_b(),
            &input.right_end_cap.guta_stats,
            &input.right_end_cap.checkpoint_historical_merkle_proof,
            child_b_proof,
            end_cap_verifier_data
        )?;

        self.dvh_state_transition_gadget.set_witness_params(
            &mut pw,
            &input.left_global_user_tree_delta_merkle_proof,
            &input.right_global_user_tree_delta_merkle_proof,
        )?;

        // Set witness for pm_jobs_completed stats (leaf circuit adds 1 GUTA completion)
        
        let mut dbgt = DebugTimer::new("prove end cap two");
        dbgt.lap("start");

        let result = self.circuit_data.prove(pw);

        dbgt.lap("finished");
        result
    }
}


impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for GUTAVerifyTwoEndCapCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
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
    for GUTAVerifyTwoEndCapCircuitV2<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, QHashOut<C::F>: Q256BitHash, C::F: QFelt64 + QRichField,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let (left_child_end_cap_proof_result, right_child_end_cap_proof_result) = get_two_child_proofs_for_api_response_with_inclusion_proof::<L, C, D>(
            library,
            &input,
        )?;


        let witness = GUTAVerifyTwoEndCapCircuitInputV2::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        
        self.prove_base(
            worker_reward_tag,
            &witness,
            left_child_end_cap_proof_result.whitelist_inclusion_proof.root,
            &left_child_end_cap_proof_result.zk_proof,
            &right_child_end_cap_proof_result.zk_proof,
            &left_child_end_cap_proof_result.verifier_data,
        )
    }
}
