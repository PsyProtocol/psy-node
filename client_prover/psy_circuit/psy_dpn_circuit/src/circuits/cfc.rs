use plonky2::{
    field::types::Field,
    gates::gate::GateRef,
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::traits::QProofStoreReaderSync};
use psy_client_data::dpn::sd_key::{SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS};
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, vm::cfc_input::DapenContractFunctionCircuitInput};

use crate::vm::compile::PsyContractFunctionBuilderGadget;

#[derive(Debug)]
pub struct DapenContractFunctionCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inputs: Vec<Target>,
    pub fn_builder_gadget: PsyContractFunctionBuilderGadget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    // pub fingerprint: QHashOut<C::F>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,

    // end circuit data
    pub fn_def: DPNFunctionCircuitDefinition,
}

impl<C: GenericConfig<D>, const D: usize> Clone for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new(
            &self.fn_def,
            self.fn_builder_gadget.state_reader.contract_state_tree_height,
            self.fn_builder_gadget.state_reader.session_proof_tree_height,
            self.fn_builder_gadget.state_reader.force_four_align,
        )
    }
}

impl<C: GenericConfig<D>, const D: usize> DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        //coset_gate: &GateRef<C::F, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        contract_state_tree_height: usize,
        session_proof_tree_height: usize,
        force_four_align: bool,
    ) -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let inputs = builder.add_virtual_targets(fn_def.circuit_inputs.len());
        let fn_builder_gadget = PsyContractFunctionBuilderGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            fn_def,
            contract_state_tree_height,
            session_proof_tree_height,
            inputs.clone(),
            force_four_align,
        );

        let inner_public_inputs_hash = fn_builder_gadget.tx_ctx_header.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(fn_builder_gadget.session_proof_tree_root, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);
        //builder.add_psy_type_a_common_gates(Some(coset_gate.clone()));
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();

        // let fingerprint =
        // QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        Self {
            inputs,
            fn_builder_gadget,
            circuit_data,
            // fingerprint,
            fn_def: fn_def.clone(),
            minifier_chain,
        }
    }
    pub fn prove_base(&self, cfc_input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_target_arr(&self.inputs, &cfc_input.inputs)?;

        pw.set_hash_target(self.fn_builder_gadget.session_proof_tree_root, cfc_input.session_proof_tree_root.0)?;

        self.fn_builder_gadget.tx_ctx_header.set_witness(&mut pw, &cfc_input.tx_input_ctx)?;
        self.fn_builder_gadget.state_reader.set_witness(&mut pw, cfc_input, &self.fn_def)?;
        if let Some(context) = &self.fn_builder_gadget.transaction_context {
            anyhow::ensure!(
                cfc_input.transaction_infos.len() <= MAX_INTROSPECTABLE_TRANSACTIONS as usize,
                "transaction log exceeds MAX_TX_COUNT"
            );
            pw.set_target(context.tx_count, C::F::from_canonical_u64(cfc_input.transaction_infos.len() as u64))?;
            pw.set_hash_target(context.tx_stack_hash, cfc_input.transaction_stack_hash.0)?;
            for (index, entry_targets) in context.entries.iter().enumerate() {
                if let Some(entry) = cfc_input.transaction_infos.get(index) {
                    let inputs = cfc_input.transaction_inputs.get(index).map(Vec::as_slice).unwrap_or(&[]);
                    anyhow::ensure!(
                        inputs.len() <= SDKEY_MAX_CALLDATA_WORDS as usize,
                        "transaction calldata exceeds MAX_CALLDATA_WORDS"
                    );
                    pw.set_target(entry_targets.contract_id, entry.contract_id)?;
                    pw.set_target(entry_targets.caller_contract_id, entry.caller_contract_id)?;
                    pw.set_target(entry_targets.method_id, entry.method_id)?;
                    pw.set_target(entry_targets.inputs_length, entry.inputs_length)?;
                    pw.set_hash_target(entry_targets.inputs_hash, entry.inputs_hash.0)?;
                    for (word, target) in entry_targets.inputs.iter().enumerate() {
                        pw.set_target(*target, inputs.get(word).copied().unwrap_or(C::F::ZERO))?;
                    }
                } else {
                    pw.set_target(entry_targets.contract_id, C::F::ZERO)?;
                    pw.set_target(entry_targets.caller_contract_id, C::F::ZERO)?;
                    pw.set_target(entry_targets.method_id, C::F::ZERO)?;
                    pw.set_target(entry_targets.inputs_length, C::F::ZERO)?;
                    pw.set_hash_target(entry_targets.inputs_hash, HashOut::ZERO)?;
                    for target in &entry_targets.inputs {
                        pw.set_target(*target, C::F::ZERO)?;
                    }
                }
            }
        }

        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<DapenContractFunctionCircuitInput<C::F>, C, D>
    for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, DapenContractFunctionCircuitInput<C::F>, C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::dpn::{proving_session::DPNProvingSessionCompactMethodCall, sd_key::SDKeyTransactionInfo};
    use psy_config::network_constants::{
        CHECKPOINT_TREE_HEIGHT, DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT,
    };
    use psy_crypto::hash::{
        traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
        utils::safe_hash_fixed_length,
    };
    use psy_vm::{
        dpn::{
            ops::op_types::{encode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
            vm::def::DPNFunctionCircuitDefinition,
        },
        vm::cfc_input::DapenContractFunctionCircuitInput,
    };

    use super::*;

    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    const D: usize = 2;
    type H = <C as GenericConfig<D>>::Hasher;

    fn introspection_definition_at(word_index: u64) -> DPNFunctionCircuitDefinition {
        let target = DPNBuiltInDataType::Target;
        let target_id = |index| encode_indexed_op_id(target, index);

        DPNFunctionCircuitDefinition {
            name: "read_previous_calldata".to_owned(),
            method_id: 1,
            circuit_inputs: vec![],
            circuit_outputs: vec![target_id(2)],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![
                DPNIndexedVarDef {
                    data_type: target,
                    index: 0,
                    op_type: DPNOpType::Constant,
                    inputs: vec![0],
                },
                DPNIndexedVarDef {
                    data_type: target,
                    index: 1,
                    op_type: DPNOpType::Constant,
                    inputs: vec![word_index],
                },
                DPNIndexedVarDef {
                    data_type: target,
                    index: 2,
                    op_type: DPNOpType::GetTransactionInputWord,
                    inputs: vec![target_id(0), target_id(1)],
                },
            ],
            events: vec![],
        }
    }

    fn introspection_definition() -> DPNFunctionCircuitDefinition {
        introspection_definition_at(1)
    }

    fn input_with_calldata(calldata: Vec<F>) -> DapenContractFunctionCircuitInput<F> {
        let current_inputs = vec![];
        let call_data =
            DPNProvingSessionCompactMethodCall::new_from_inputs::<H>(F::ZERO, F::from_canonical_u64(100), F::from_canonical_u64(1), &current_inputs);
        let previous = DPNProvingSessionCompactMethodCall::new_from_inputs::<H>(
            F::from_canonical_u64(7),
            F::from_canonical_u64(8),
            F::from_canonical_u64(3),
            &calldata,
        );
        let previous_info = SDKeyTransactionInfo::from(previous);
        let transaction_infos = vec![previous_info];
        let transaction_inputs = vec![calldata];
        let transaction_stack_hash = H::q_two_to_one(QHashOut::default(), previous.qfhash::<H>());

        let mut tx_input_ctx = psy_client_data::dpn::cfc_context_input::DapenCFCUserTransactionInputContext::<F>::default();
        let zero_root = |height: u8| QHashOut(H::get_zero_hash(height as usize));
        let state_root = zero_root(4);
        let deferred_root = zero_root(DEFERRED_TRANSACTION_TREE_HEIGHT);
        let user_contract_root = zero_root(GLOBAL_CONTRACT_TREE_HEIGHT);
        let checkpoint_root = zero_root(CHECKPOINT_TREE_HEIGHT);
        let session_root = zero_root(UPS_SESSION_PROOF_TREE_HEIGHT);
        let deposit_root = zero_root(32);
        let user_root = zero_root(GLOBAL_USER_TREE_HEIGHT);
        let withdrawal_root = zero_root(32);
        let user_registration_root = zero_root(GLOBAL_USER_TREE_HEIGHT);
        let contract_and_deposit = QHashOut(H::two_to_one(user_contract_root.0, deposit_root.0));
        let user_and_withdrawal = QHashOut(H::two_to_one(user_root.0, withdrawal_root.0));
        let base_chain_root = QHashOut(H::two_to_one(contract_and_deposit.0, user_and_withdrawal.0));
        let global_chain_root = QHashOut(H::two_to_one(base_chain_root.0, user_registration_root.0));
        tx_input_ctx.proving_session_start_ctx.checkpoint_tree_root = checkpoint_root;
        tx_input_ctx.proving_session_start_ctx.checkpoint_leaf.global_chain_root = global_chain_root;
        tx_input_ctx.proving_session_start_ctx.state_roots.contract_tree_root = user_contract_root;
        tx_input_ctx.proving_session_start_ctx.state_roots.deposit_tree_root = deposit_root;
        tx_input_ctx.proving_session_start_ctx.state_roots.user_tree_root = user_root;
        tx_input_ctx.proving_session_start_ctx.state_roots.withdrawal_tree_root = withdrawal_root;
        tx_input_ctx.proving_session_start_ctx.state_roots.user_registration_tree_root = user_registration_root;
        tx_input_ctx.proving_session_start_ctx.start_session_user_leaf.user_state_tree_root = state_root;
        tx_input_ctx.transaction_call_start_ctx.start_user_contract_tree_root = user_contract_root;
        tx_input_ctx.transaction_call_start_ctx.start_contract_state_tree_root = state_root;
        tx_input_ctx.transaction_call_start_ctx.start_deferred_tx_debt_tree_root = deferred_root;
        tx_input_ctx.transaction_call_start_ctx.call_data = call_data;
        tx_input_ctx.transaction_call_start_ctx.previous_tx_stack_hash = transaction_stack_hash;
        tx_input_ctx.transaction_call_start_ctx.previous_tx_count = F::ONE;
        let outputs = vec![F::from_canonical_u64(22)];
        tx_input_ctx.transaction_end_ctx.outputs_length = F::ONE;
        tx_input_ctx.transaction_end_ctx.outputs_hash = safe_hash_fixed_length::<H, F>(&outputs);
        tx_input_ctx.transaction_end_ctx.end_contract_state_tree_root = state_root;
        tx_input_ctx.transaction_end_ctx.end_deferred_tx_debt_tree_root = deferred_root;
        DapenContractFunctionCircuitInput {
            inputs: current_inputs,
            outputs,
            events: vec![],
            cmd_witnesses: vec![],
            session_proof_tree_root: session_root,
            tx_input_ctx,
            transaction_infos,
            transaction_inputs,
            transaction_stack_hash,
        }
    }

    #[test]
    #[ignore = "full CFC proving fixture is intentionally expensive"]
    fn cfc_non_full_transaction_context_padding_is_constrained() {
        let definition = introspection_definition();
        let circuit = DapenContractFunctionCircuit::<C, D>::new(&definition, 4, 4, false);
        let input = input_with_calldata(vec![F::from_canonical_u64(11), F::from_canonical_u64(22)]);
        let proof = circuit.prove_base(&input).expect("introspection CFC should prove");
        circuit.minifier_chain.verify(proof).expect("introspection CFC proof should verify");
    }

    #[test]
    #[ignore = "full CFC proving fixture is intentionally expensive"]
    fn cfc_proof_rejects_tampered_previous_calldata() {
        let definition = introspection_definition();
        let circuit = DapenContractFunctionCircuit::<C, D>::new(&definition, 4, 4, false);
        let mut input = input_with_calldata(vec![F::from_canonical_u64(11), F::from_canonical_u64(22)]);
        input.transaction_inputs[0][1] = F::from_canonical_u64(23);
        assert!(
            circuit.prove_base(&input).is_err(),
            "tampered calldata must fail the calldata hash binding"
        );
    }

    #[test]
    #[ignore = "full CFC proving fixture is intentionally expensive"]
    fn cfc_proof_rejects_read_from_calldata_padding() {
        let definition = introspection_definition_at(1);
        let circuit = DapenContractFunctionCircuit::<C, D>::new(&definition, 4, 4, false);
        let mut input = input_with_calldata(vec![F::from_canonical_u64(11)]);
        input.outputs = vec![F::ZERO];
        input.tx_input_ctx.transaction_end_ctx.outputs_hash = safe_hash_fixed_length::<H, F>(&input.outputs);
        assert!(
            circuit.prove_base(&input).is_err(),
            "a CFC must not read the zero-filled tail after calldata inputs_length"
        );
    }
}
