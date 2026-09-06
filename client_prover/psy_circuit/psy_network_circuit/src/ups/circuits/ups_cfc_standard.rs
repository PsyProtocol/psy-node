use plonky2::{
    hash::hash_types::HashOut,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::traits::QProofStoreReaderSync};
use psy_client_data::ups::ups_cfc_standard_step::UPSCFCStandardTransactionCircuitInput;
use psy_common_circuit::{
    builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::compute_tree_aware_proof_public_inputs,
};
use psy_config::network_constants::{UPS_CIRCUIT_WHITELIST_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use crate::ups::gadgets::{ups_cfc_standard::UPSVerifyCFCStandardStepGadget, verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeGadget};

#[derive(Debug)]
pub struct UPSCFCStandardTransactionCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub verify_previous_ups_step_gadget: VerifyPreviousUPSStepProofInProofTreeGadget,
    pub standard_cfc_step_gadget: UPSVerifyCFCStandardStepGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        Self::new_with_config(UPS_SESSION_PROOF_TREE_HEIGHT as usize, UPS_CIRCUIT_WHITELIST_TREE_HEIGHT as usize)
    }
    pub fn new_with_config(ups_session_proof_tree_height: usize, ups_circuit_whitelist_tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verify_previous_ups_step_gadget = VerifyPreviousUPSStepProofInProofTreeGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            ups_session_proof_tree_height,
            ups_circuit_whitelist_tree_height,
        );

        let current_proof_tree_root = verify_previous_ups_step_gadget.current_proof_tree_root;

        let standard_cfc_step_gadget = UPSVerifyCFCStandardStepGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            &verify_previous_ups_step_gadget.previous_step_header_gadget,
            current_proof_tree_root,
            ups_session_proof_tree_height,
        );

        let inner_public_inputs_hash = standard_cfc_step_gadget.new_header_gadget.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let public_inputs_hash =
            compute_tree_aware_proof_public_inputs::<C::Hasher, C::F, D>(&mut builder, current_proof_tree_root, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            verify_previous_ups_step_gadget,
            standard_cfc_step_gadget,
            circuit_data,
            fingerprint,
        }
    }

    fn prove_base_inner(&self, target: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        /*
                println!("\n\n\nUPSCFCStandardTransactionCircuitInput:\n{:?}\n\n",&target);
                println!("\n\n\nUPSCFCStandardTransactionCircuitInput:\n{}\n\n",serde_json::to_string_pretty(&target).unwrap());
        */
        self.verify_previous_ups_step_gadget
            .set_witness(&mut pw, &target.verify_previous_ups_step)?;
        self.standard_cfc_step_gadget.set_witness(&mut pw, &target.standard_cfc_step)?;

        self.circuit_data.prove(pw)
    }
    pub fn prove_base(&self, target: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base_inner(target)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for UPSCFCStandardTransactionCircuit<C, D>
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

impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<UPSCFCStandardTransactionCircuitInput<C::F>, C, D>
    for UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, UPSCFCStandardTransactionCircuitInput<C::F>, C, D> for UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

#[cfg(test)]
mod vt626_index_map {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::config::PoseidonGoldilocksConfig,
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn idx(t: plonky2::iop::target::Target) -> String {
        match t {
            plonky2::iop::target::Target::VirtualTarget { index } => format!("VT{}", index),
            other => format!("{:?}", other),
        }
    }
    fn hs(h: plonky2::hash::hash_types::HashOutTarget) -> String {
        format!("[{}]", h.elements.iter().map(|e| idx(*e)).collect::<Vec<_>>().join(","))
    }

    #[test]
    fn print_standard_tx_target_map() {
        let circuit = super::UPSCFCStandardTransactionCircuit::<C, D>::new();
        let vp = &circuit.verify_previous_ups_step_gadget;
        let st = &circuit.standard_cfc_step_gadget;
        let hdr = &vp.previous_step_header_gadget;
        println!("== verify_previous ==)");
        println!("current_proof_tree_root = {}", hs(vp.current_proof_tree_root));
        println!("whitelist_root = {}", hs(vp.ups_step_circuit_whitelist_root));
        println!("attest.fingerprint = {} inner_pi = {} pi_hash = {} attested = {}", hs(vp.proof_attestation_gadget.fingerprint), hs(vp.proof_attestation_gadget.inner_public_inputs_hash), hs(vp.proof_attestation_gadget.public_inputs_hash), hs(vp.proof_attestation_gadget.attested_proof_tree_root));
        println!("attest.historical_root_proof.current_root = {} historical = {} value = {}", hs(vp.proof_attestation_gadget.historical_root_proof.current_root), hs(vp.proof_attestation_gadget.historical_root_proof.historical_root), hs(vp.proof_attestation_gadget.historical_root_proof.current_value));
        println!("prev_header.whitelist_root = {}", hs(hdr.ups_step_circuit_whitelist_root));
        println!("prev_header.start_ctx.checkpoint_id = {} tree_root = {} leaf_hash = {} user_leaf_hash = {}", idx(hdr.session_start_context.checkpoint_id), hs(hdr.session_start_context.checkpoint_tree_root), hs(hdr.session_start_context.checkpoint_leaf_hash), hs(hdr.session_start_context.start_session_user_leaf_hash));
        println!("prev_header.start_leaf.user_state_tree_root = {}", hs(hdr.session_start_context.start_session_user_leaf.user_state_tree_root));
        println!("prev_header.current.user_state_tree_root = {}", hs(hdr.current_state.user_leaf.user_state_tree_root));
        println!("prev_header.current.deferred = {} inline = {} tx_stack = {}", hs(hdr.current_state.deferred_tx_debt_tree_root), hs(hdr.current_state.inline_tx_debt_tree_root), hs(hdr.current_state.tx_hash_stack));
        println!("prev_header.current_state_hash = {} start_ctx_hash = {}", hs(hdr.current_state_hash), hs(hdr.session_start_context_hash));
        println!("prev_header.whitelist_mp.value = {} root = {} index = {}", hs(vp.ups_circuit_whitelist_merkle_proof.value), hs(vp.ups_circuit_whitelist_merkle_proof.root), idx(vp.ups_circuit_whitelist_merkle_proof.index));
        println!("== standard step ==)");
        let delta = &st.process_cfc_state_delta_gadget;
        let cs = &delta.cfc_transaction_input_context.transaction_call_start_ctx;
        let ce = &delta.cfc_transaction_input_context.transaction_end_ctx;
        println!("tx_in.start_user_contract_tree_root = {} start_contract_state_tree_root = {}", hs(cs.start_user_contract_tree_root), hs(cs.start_contract_state_tree_root));
        println!("tx_in.call_data.contract_id = {} method_id = {} inputs_len = {}", idx(cs.call_data.contract_id), idx(cs.call_data.method_id), idx(cs.call_data.inputs_length));
        println!("tx_in.start_deferred = {} balance = {} event_index = {}", hs(cs.start_deferred_tx_debt_tree_root), idx(cs.start_user_balance), idx(cs.start_user_event_index));
        println!("tx_in.end_contract_state_tree_root = {} end_deferred = {}", hs(ce.end_contract_state_tree_root), hs(ce.end_deferred_tx_debt_tree_root));
        println!("tx_in.outputs_hash = {} outputs_len = {} total_events = {} total_spent = {}", hs(ce.outputs_hash), idx(ce.outputs_length), idx(ce.total_events_emitted), idx(ce.total_balance_spent));
        let u = &delta.user_contract_tree_update_proof;
        println!("uct.old_root = {} old_value = {} new_root = {} new_value = {} index = {}", hs(u.old_root), hs(u.old_value), hs(u.new_root), hs(u.new_value), idx(u.index));
        println!("uct.sib0 = {} sib_last = {}", hs(u.siblings[0]), hs(u.siblings[u.siblings.len()-1]));
        println!("pivot_deferred.historical = {} current = {} value = {}", hs(delta.deferred_tx_debt_pivot_proof.historical_root), hs(delta.deferred_tx_debt_pivot_proof.current_root), hs(delta.deferred_tx_debt_pivot_proof.current_value));
        println!("pivot_inline.historical = {} current = {}", hs(delta.inline_tx_debt_pivot_proof.historical_root), hs(delta.inline_tx_debt_pivot_proof.current_root));
        println!("delta.cfc_inner_pi_hash = {} cfc_contract_id = {} method = {} num_in = {} num_out = {}", hs(delta.cfc_inner_public_inputs_hash), idx(delta.cfc_contract_id), idx(delta.cfc_method_id), idx(delta.cfc_num_inputs), idx(delta.cfc_num_outputs));
        let v = &st.verify_cfc_exists_and_valid_gadget;
        println!("verify.ckpt_leaf_hash = {} attested = {} fp = {} inner_pi = {}", hs(v.checkpoint_leaf_hash), hs(v.attested_proof_tree_root), hs(v.cfc_fingerprint), hs(v.cfc_inner_public_inputs_hash));
        println!("verify.cfc_contract_id = {} method = {} num_in = {} num_out = {}", idx(v.cfc_contract_id), idx(v.cfc_method_id), idx(v.cfc_num_inputs), idx(v.cfc_num_outputs));
        println!("verify.ckpt_state.global_state_roots.user_tree_root = {} contract_tree_root = {}", hs(v.checkpoint_state_gadget.global_state_roots.user_tree_root), hs(v.checkpoint_state_gadget.global_state_roots.contract_tree_root));
        println!("new_header.current.user_state_tree_root = {}", hs(st.new_header_gadget.current_state.user_leaf.user_state_tree_root));
        println!("new_header.current.deferred = {}", hs(st.new_header_gadget.current_state.deferred_tx_debt_tree_root));
        let incl = &v.cfc_inclusion_proof_gadget;
        let cip = &incl.contract_inclusion_proof;
        let fn_mp = &incl.contract_function_merkle_proof;
        println!("incl.method_id = {} num_in = {} num_out = {} fn_fp = {}", idx(incl.method_id), idx(incl.num_inputs), idx(incl.num_outputs), hs(incl.function_verifier_fingerprint));
        println!("incl.fn_mp.root = {} value = {} index = {}", hs(fn_mp.root), hs(fn_mp.value), idx(fn_mp.index));
        println!("incl.fn_mp.sib0 = {}", hs(fn_mp.siblings[0]));
        println!("incl.contract_leaf.state_tree_height = {} code_root = {} fn_tree_root = {}", idx(cip.contract_leaf.state_tree_height), hs(cip.contract_leaf.code_root), hs(cip.contract_leaf.function_tree_root));
        println!("incl.contract_mp.root = {} value = {} index = {}", hs(cip.contract_tree_merkle_proof.root), hs(cip.contract_tree_merkle_proof.value), idx(cip.contract_tree_merkle_proof.index));
        for (i, s) in fn_mp.siblings.iter().enumerate() {
            let s = hs(*s);
            if (620..=640).any(|n| s.contains(&format!("VT{n}"))) {
                println!("fn_sib[{i}] = {}", s);
            }
        }
        for (i, s) in cip.contract_tree_merkle_proof.siblings.iter().enumerate() {
            let s = hs(*s);
            if (620..=640).any(|n| s.contains(&format!("VT{n}"))) {
                println!("contract_sib[{i}] = {}", s);
            }
        }
        // Also check default_zero_hashes / select path in delta for VT626
        println!("contract_state_tree_height target = {}", idx(cip.contract_leaf.state_tree_height));
    }
}
