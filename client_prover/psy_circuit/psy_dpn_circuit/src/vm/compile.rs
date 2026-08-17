use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::dpn::sd_key::{SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS};
use psy_common_circuit::builder::{
    comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers,
};
use psy_network_circuit::gadgets::qdata::cfc_context_input::DapenCFCUserTransactionInputContextGadget;
use psy_vm::dpn::{
    ops::{op_types::DPNOpType, state_cmd::data::DPNStateCmd},
    vm::def::DPNFunctionCircuitDefinition,
};

use super::{
    gadgets::state_readers::StateReaderGadget,
    ops::{DPNTransactionContextTargets, DPNTransactionEntryTargets, SimpleDPNBuilder},
};

fn add_transaction_context<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> DPNTransactionContextTargets {
    let tx_count = builder.add_virtual_target();
    let tx_stack_hash = builder.add_virtual_hash();
    let max_count = builder.constant(F::from_canonical_u64(MAX_INTROSPECTABLE_TRANSACTIONS as u64 + 1));
    let count_in_range = builder.is_less_than(6, tx_count, max_count);
    builder.assert_one(count_in_range.target);
    let magic = builder.constant(F::from_noncanonical_u64(psy_config::network_constants::DEFERRED_CALL_MAGIC));
    let mut running_hash = builder.constant_hash(plonky2::hash::hash_types::HashOut::ZERO);
    let mut entries = Vec::with_capacity(MAX_INTROSPECTABLE_TRANSACTIONS as usize);

    for entry_index in 0..MAX_INTROSPECTABLE_TRANSACTIONS as usize {
        let caller_contract_id = builder.add_virtual_target();
        let contract_id = builder.add_virtual_target();
        let method_id = builder.add_virtual_target();
        let inputs_length = builder.add_virtual_target();
        let inputs_hash = builder.add_virtual_hash();
        let inputs = builder.add_virtual_targets(SDKEY_MAX_CALLDATA_WORDS as usize);
        let entry_index_target = builder.constant(F::from_canonical_u64(entry_index as u64));
        let active = builder.is_less_than(6, entry_index_target, tx_count);
        let zero = builder.zero();
        for target in [caller_contract_id, contract_id, method_id, inputs_length] {
            let constrained = builder.select(active, target, zero);
            builder.connect(constrained, target);
        }
        for target in inputs_hash.elements {
            let constrained = builder.select(active, target, zero);
            builder.connect(constrained, target);
        }
        for target in &inputs {
            let constrained = builder.select(active, *target, zero);
            builder.connect(constrained, *target);
        }

        let mut hashes = Vec::with_capacity(SDKEY_MAX_CALLDATA_WORDS as usize + 1);
        for length in 0..=SDKEY_MAX_CALLDATA_WORDS as usize {
            let len = builder.constant(F::from_canonical_u64(length as u64));
            let mut preimage = Vec::with_capacity(length + 2);
            preimage.push(len);
            preimage.extend_from_slice(&inputs[..length]);
            preimage.push(len);
            hashes.push(builder.hash_n_to_hash_no_pad::<H>(preimage));
        }
        let mut selected_hash = hashes[0];
        let mut any_length = builder._false();
        for (length, candidate) in hashes.into_iter().enumerate() {
            let length_target = builder.constant(F::from_canonical_u64(length as u64));
            let matches = builder.is_equal(inputs_length, length_target);
            selected_hash = builder.select_hash(matches, candidate, selected_hash);
            any_length = builder.or(any_length, matches);
        }
        builder.assert_one(any_length.target);
        // Padding entries are represented by zeroes in the witness.  Do not
        // force their zero hash to equal the hash of an empty calldata list;
        // only active transaction entries carry an authenticated calldata
        // commitment.
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let authenticated_inputs_hash = builder.select_hash(active, selected_hash, zero_hash);
        builder.connect_hashes(authenticated_inputs_hash, inputs_hash);
        let tx_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            magic,
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length,
            inputs_hash.elements[0],
            inputs_hash.elements[1],
            inputs_hash.elements[2],
            inputs_hash.elements[3],
        ]);
        // The native transaction log chains only the preceding transactions,
        // not the fixed-capacity padding entries.
        let next_running_hash = builder.hash_two_to_one::<H>(running_hash, tx_hash);
        running_hash = builder.select_hash(active, next_running_hash, running_hash);
        entries.push(DPNTransactionEntryTargets {
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length,
            inputs_hash,
            inputs,
        });
    }
    builder.connect_hashes(running_hash, tx_stack_hash);
    DPNTransactionContextTargets {
        tx_count,
        tx_stack_hash,
        entries,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PsyCmdWithInputAndResultTargets {
    pub state_cmd: DPNStateCmd<u64>,
    pub result: Vec<Target>,
}

/// Execute a compiled DPN function against a caller-provided execution
/// context and state reader.  CFC and SDKey both use the same DPN definition
/// format, so the ordering of definitions, state-command resolution, and
/// assertion handling must live in one place.
pub fn execute_dpn_function<
    H: AlgebraicHasher<F> + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<F>>,
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    fn_def: &DPNFunctionCircuitDefinition,
    dpn: &mut SimpleDPNBuilder<F, D>,
    mut state_reader: Option<&mut StateReaderGadget>,
) -> anyhow::Result<(Vec<PsyCmdWithInputAndResultTargets>, Vec<Target>)> {
    fn_def.validate_state_command_resolution_semantics()?;
    let mut cmd_results: Vec<PsyCmdWithInputAndResultTargets> = Vec::new();
    let state_cmd_len = fn_def.state_command_resolution_indices.len();
    let mut next_state_cmd_id = 0;
    let mut next_state_cmd_index = if state_cmd_len == 0 {
        fn_def.definitions.len() + 1
    } else {
        fn_def.state_command_resolution_indices[0]
    };

    for (i, def) in fn_def.definitions.iter().enumerate() {
        while next_state_cmd_id < state_cmd_len && i >= next_state_cmd_index {
            let state_cmd = &fn_def.state_commands[next_state_cmd_id];
            let reader = state_reader
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("DPN state command requires a state reader"))?;
            let result = reader.injest_symbolic_state_command::<H, F, D>(builder, dpn, state_cmd);
            cmd_results.push(PsyCmdWithInputAndResultTargets {
                state_cmd: state_cmd.clone(),
                result,
            });
            next_state_cmd_id += 1;
            next_state_cmd_index = if next_state_cmd_id >= state_cmd_len {
                fn_def.definitions.len()
            } else {
                fn_def.state_command_resolution_indices[next_state_cmd_id]
            };
        }

        match def.op_type {
            DPNOpType::GetStateCommandResultSingle => {
                let cmd_index = *def.inputs.first().ok_or_else(|| anyhow::anyhow!("missing state command index"))? as usize;
                let result = cmd_results
                    .get(cmd_index)
                    .ok_or_else(|| anyhow::anyhow!("state command result {} is not available", cmd_index))?
                    .result
                    .first()
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("state command {} has no scalar result", cmd_index))?;
                dpn.push_external_target(def.index as usize, result);
            }
            DPNOpType::GetStateCommandResultArray => {
                let cmd_index = *def.inputs.first().ok_or_else(|| anyhow::anyhow!("missing state command index"))? as usize;
                let result = cmd_results
                    .get(cmd_index)
                    .ok_or_else(|| anyhow::anyhow!("state command result {} is not available", cmd_index))?
                    .result
                    .clone();
                dpn.push_external_target_array(def.index as usize, result);
            }
            DPNOpType::GetStateCommandResultHash => {
                let cmd_index = *def.inputs.first().ok_or_else(|| anyhow::anyhow!("missing state command index"))? as usize;
                let result = &cmd_results
                    .get(cmd_index)
                    .ok_or_else(|| anyhow::anyhow!("state command result {} is not available", cmd_index))?
                    .result;
                if result.len() != 4 {
                    anyhow::bail!("state command {} hash result has {} elements", cmd_index, result.len());
                }
                dpn.set_hash_at(
                    def.index as usize,
                    HashOutTarget {
                        elements: [result[0], result[1], result[2], result[3]],
                    },
                    "GetStateCommandResultHash",
                );
            }
            _ => dpn.process_var_def(builder, def),
        }
    }

    while next_state_cmd_id < state_cmd_len {
        let state_cmd = &fn_def.state_commands[next_state_cmd_id];
        let reader = state_reader
            .as_deref_mut()
            .ok_or_else(|| anyhow::anyhow!("DPN state command requires a state reader"))?;
        let result = reader.injest_symbolic_state_command::<H, F, D>(builder, dpn, state_cmd);
        cmd_results.push(PsyCmdWithInputAndResultTargets {
            state_cmd: state_cmd.clone(),
            result,
        });
        next_state_cmd_id += 1;
    }

    for assertion in &fn_def.assertions {
        let left = dpn.resolve_target(assertion.left);
        let right = dpn.resolve_target(assertion.right);
        builder.connect(left, right);
    }

    let outputs = fn_def.circuit_outputs.iter().map(|id| dpn.resolve_target(*id)).collect::<Vec<_>>();
    Ok((cmd_results, outputs))
}

#[derive(Clone, Debug)]
pub struct PsyContractFunctionBuilderGadget {
    pub cmd_results: Vec<PsyCmdWithInputAndResultTargets>,
    pub state_reader: StateReaderGadget,
    pub session_proof_tree_root: HashOutTarget,
    pub tx_ctx_header: DapenCFCUserTransactionInputContextGadget,
    pub outputs: Vec<Target>,
    pub transaction_context: Option<DPNTransactionContextTargets>,
}
impl PsyContractFunctionBuilderGadget {
    pub fn add_virtual_to<
        H: AlgebraicHasher<F> + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        contract_state_tree_height: usize,
        session_proof_tree_height: usize,
        inputs: Vec<Target>,
        force_four_align: bool,
    ) -> Self {
        let tx_ctx_header = DapenCFCUserTransactionInputContextGadget::add_virtual_to::<H, F, D>(builder);
        let session_proof_tree_root = builder.add_virtual_hash();

        let state_reader = StateReaderGadget::new(
            tx_ctx_header.proving_session_start_ctx.state_roots.clone(),
            tx_ctx_header.transaction_call_start_ctx.start_user_contract_tree_root,
            tx_ctx_header.transaction_call_start_ctx.start_deferred_tx_debt_tree_root,
            tx_ctx_header.transaction_call_start_ctx.start_contract_state_tree_root,
            contract_state_tree_height,
            session_proof_tree_root,
            session_proof_tree_height,
            force_four_align,
            tx_ctx_header.proving_session_start_ctx.checkpoint_leaf.stats.clone(),
            tx_ctx_header.proving_session_start_ctx.checkpoint_tree_root,
        );
        let transaction_context = if fn_def.definitions.iter().any(|def| {
            matches!(
                def.op_type,
                DPNOpType::GetTransactionCount
                    | DPNOpType::GetTransactionStackHash
                    | DPNOpType::GetTransactionContractId
                    | DPNOpType::GetTransactionCallerContractId
                    | DPNOpType::GetTransactionMethodId
                    | DPNOpType::GetTransactionInputsHash
                    | DPNOpType::GetTransactionInputLength
                    | DPNOpType::GetTransactionInputWord
            )
        }) {
            let context = add_transaction_context::<H, F, D>(builder);
            builder.connect_hashes(
                context.tx_stack_hash,
                tx_ctx_header.transaction_call_start_ctx.previous_tx_stack_hash,
            );
            builder.connect(
                context.tx_count,
                tx_ctx_header.transaction_call_start_ctx.previous_tx_count,
            );
            Some(context)
        } else {
            None
        };

        let mut g = Self {
            cmd_results: Vec::new(),
            state_reader,
            session_proof_tree_root,
            tx_ctx_header,
            outputs: Vec::new(),
            transaction_context,
        };

        let new_outputs = g.eval_session::<H, F, D>(builder, fn_def, inputs);
        g.outputs = new_outputs;
        g
    }
    fn eval_session<
        H: AlgebraicHasher<F> + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<Target>,
    ) -> Vec<Target> {
        let inputs_length_target = builder.constant_u64(inputs.len() as u64);
        let inputs_hash = builder.safe_hash_fixed_length::<H>(&inputs);

        let mut executor = SimpleDPNBuilder::<F, D>::new_with_contract_ctx(
            inputs,
            self.tx_ctx_header.proving_session_start_ctx.start_session_user_leaf.user_id,
            self.tx_ctx_header.transaction_call_start_ctx.call_data.contract_id,
            self.tx_ctx_header.transaction_call_start_ctx.call_data.caller_contract_id,
            self.tx_ctx_header.proving_session_start_ctx.checkpoint_id,
            self.tx_ctx_header.proving_session_start_ctx.start_session_user_leaf.nonce,
            self.tx_ctx_header.proving_session_start_ctx.start_session_user_leaf.public_key,
            self.session_proof_tree_root,
        );
        if let Some(context) = self.transaction_context.clone() {
            executor.set_transaction_context(context);
        }
        let (_cmd_results, outputs) = execute_dpn_function::<H, F, D>(builder, fn_def, &mut executor, Some(&mut self.state_reader))
            .expect("compiled DPN function must be internally consistent");
        self.cmd_results = _cmd_results;

        let outputs_length_target = builder.constant_u64(outputs.len() as u64);
        let outputs_hash = builder.safe_hash_fixed_length::<H>(&outputs);

        // ensure the result of our evaluation reflects the data in the tx_ctx_header
        // gadget

        // ensure the inputs are correct
        builder.connect(
            inputs_length_target,
            self.tx_ctx_header.transaction_call_start_ctx.call_data.inputs_length,
        );
        builder.connect_hashes(inputs_hash, self.tx_ctx_header.transaction_call_start_ctx.call_data.inputs_hash);

        // ensure the outputs are correct
        builder.connect(outputs_length_target, self.tx_ctx_header.transaction_end_ctx.outputs_length);
        builder.connect_hashes(outputs_hash, self.tx_ctx_header.transaction_end_ctx.outputs_hash);

        builder.connect_hashes(
            self.state_reader.end_contract_state_root,
            self.tx_ctx_header.transaction_end_ctx.end_contract_state_tree_root,
        );

        // ensure the end deferred tx root is correct
        builder.connect_hashes(
            self.state_reader.end_deferred_tx_tree_root,
            self.tx_ctx_header.transaction_end_ctx.end_deferred_tx_debt_tree_root,
        );

        outputs
    }
}
