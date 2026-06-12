use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_common_circuit::builder::{core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore};
use psy_network_circuit::gadgets::qdata::cfc_context_input::DapenCFCUserTransactionInputContextGadget;
use psy_vm::dpn::{
    ops::{op_types::DPNOpType, state_cmd::data::DPNStateCmd},
    vm::def::DPNFunctionCircuitDefinition,
};

use super::{gadgets::state_readers::StateReaderGadget, ops::SimpleDPNBuilder};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PsyCmdWithInputAndResultTargets {
    pub state_cmd: DPNStateCmd<u64>,
    pub result: Vec<Target>,
}

#[derive(Clone, Debug)]
pub struct PsyContractFunctionBuilderGadget {
    pub cmd_results: Vec<PsyCmdWithInputAndResultTargets>,
    pub state_reader: StateReaderGadget,
    pub session_proof_tree_root: HashOutTarget,
    pub tx_ctx_header: DapenCFCUserTransactionInputContextGadget,
    pub outputs: Vec<Target>,
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

        let mut g = Self {
            cmd_results: Vec::new(),
            state_reader,
            session_proof_tree_root,
            tx_ctx_header,
            outputs: Vec::new(),
        };

        let new_outputs = g.eval_session::<H, F, D>(builder, fn_def, inputs);
        g.outputs = new_outputs;
        g
    }
    fn process_state_cmd<
        H: AlgebraicHasher<F> + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        cmd: &DPNStateCmd<u64>,
    ) {
        let result = self.state_reader.injest_symbolic_state_command::<H, F, D>(builder, dpn, cmd);
        self.cmd_results.push(PsyCmdWithInputAndResultTargets {
            state_cmd: cmd.clone(),
            result,
        });
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
        let state_cmd_len = fn_def.state_command_resolution_indices.len();
        let mut next_state_cmd_id = 0;
        let mut next_state_cmd_index = if state_cmd_len == 0 {
            fn_def.definitions.len() + 10
        } else {
            fn_def.state_command_resolution_indices[0]
        };
        for (i, def) in fn_def.definitions.iter().enumerate() {
            if def.op_type.eq(&DPNOpType::GetStateCommandResultSingle) {
                let ind = def.inputs[0] as usize;
                executor.push_external_target(def.index, self.cmd_results[ind].result[0]);
            } else if def.op_type.eq(&DPNOpType::GetStateCommandResultArray) {
                let ind = def.inputs[0] as usize;
                executor.push_external_target_array(def.index, self.cmd_results[ind].result.clone());
            } else if def.op_type.eq(&DPNOpType::GetStateCommandResultHash) {
                let ind = def.inputs[0] as usize;
                executor.set_hash_at(
                    def.index,
                    HashOutTarget {
                        elements: [
                            self.cmd_results[ind].result[0],
                            self.cmd_results[ind].result[1],
                            self.cmd_results[ind].result[2],
                            self.cmd_results[ind].result[3],
                        ],
                    },
                    "GetStateCommandResultHash",
                );
            } else {
                executor.process_var_def(builder, &def);
            }
            while (i + 1) >= next_state_cmd_index {
                self.process_state_cmd::<H, F, D>(builder, &executor, &fn_def.state_commands[next_state_cmd_id]);
                next_state_cmd_id += 1;
                if next_state_cmd_id >= state_cmd_len {
                    next_state_cmd_index = fn_def.definitions.len() + 10;
                } else {
                    next_state_cmd_index = fn_def.state_command_resolution_indices[next_state_cmd_id];
                }
            }
        }
        for assertion in fn_def.assertions.iter() {
            let left = executor.resolve_target(assertion.left);
            let right = executor.resolve_target(assertion.right);
            if assertion.message == "proof tree root mismatch" {
                tracing::info!("proof tree root constraint: left_target={:?} right_target={:?}", left, right);
            }
            builder.connect(left, right);
        }
        let outputs = fn_def
            .circuit_outputs
            .iter()
            .map(|x| executor.resolve_target(*x))
            .collect::<Vec<Target>>();

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
