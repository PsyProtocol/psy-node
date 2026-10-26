use psy_config::network_constants::MAX_EVENT_RECORDS_PER_CALL;

use super::def::DPNFunctionCircuitDefinition;
use crate::dpn::ops::{
    exec_context::QExecContext,
    op_types::{encode_indexed_op_id, DPNAssertEqInfoIndexed, DPNBuiltInDataType, DPNEventRecord, DPNIndexedVarDef},
    state_cmd::{data::DPNStateCmd, types::DPNStateCmdCore},
    sym_felt::SymFeltRef,
    sym_felt_store::SymFeltStore,
};

pub struct PsyCompileResult {
    pub circuit_inputs: Vec<u64>,
    pub circuit_outputs: Vec<u64>,
    pub state_commands: Vec<DPNStateCmd<u64>>,
    pub state_command_resolution_indices: Vec<usize>,
    pub assertions: Vec<DPNAssertEqInfoIndexed>,
    pub definitions: Vec<DPNIndexedVarDef>,
    pub events: Vec<DPNEventRecord>,

    /*


    Target = 0,
    Bool = 1,
    U32Target = 2,
    HashOut = 3,
    HashOut160 = 4,
    TargetArray = 5,
    BoolArray = 6,
    U32TargetArray = 7, */
    pub total_targets: usize,
    pub total_bools: usize,
    pub total_u32s: usize,
    pub total_hashes: usize,
    pub total_hash160s: usize,
    pub total_target_arrays: usize,
    pub total_bool_arrays: usize,
    pub total_u32_arrays: usize,

    pub indexed_map: hashbrown::HashMap<SymFeltRef, u64>,
}

impl PsyCompileResult {
    pub fn compile_exec(
        name: String,
        method_id: u32,
        sym_store: &SymFeltStore,
        ctx: &QExecContext,
        outputs: &[SymFeltRef],
    ) -> DPNFunctionCircuitDefinition {
        let mut result = PsyCompileResult::new();
        result.compile(sym_store, ctx, outputs);
        result.finalize(name, method_id)
    }
    pub fn new() -> Self {
        PsyCompileResult {
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![],
            total_targets: 0,
            total_target_arrays: 0,
            total_hashes: 0,
            total_u32_arrays: 0,
            total_bools: 0,
            total_bool_arrays: 0,
            total_u32s: 0,
            total_hash160s: 0,
            indexed_map: hashbrown::HashMap::new(),
            events: vec![],
        }
    }

    pub fn injest_sfr(&mut self, sym_store: &SymFeltStore, value: SymFeltRef) -> u64 {
        if self.indexed_map.contains_key(&value) {
            return *self.indexed_map.get(&value).unwrap();
        }

        let mut children_inds = sym_store
            .get_direct_children(value)
            .into_iter()
            .map(|c| self.injest_sfr(sym_store, c))
            .collect::<Vec<_>>();

        let new_base_index = match value.get_op_type().get_data_type() {
            DPNBuiltInDataType::Target => {
                let v = self.total_targets;
                self.total_targets += 1;
                v
            }
            DPNBuiltInDataType::Bool => {
                let v = self.total_bools;
                self.total_bools += 1;
                v
            }
            DPNBuiltInDataType::U32Target => {
                let v = self.total_u32s;
                self.total_u32s += 1;
                v
            }
            DPNBuiltInDataType::HashOut => {
                let v = self.total_hashes;
                self.total_hashes += 1;
                v
            }
            DPNBuiltInDataType::HashOut160 => {
                let v = self.total_hash160s;
                self.total_hash160s += 1;
                v
            }
            DPNBuiltInDataType::TargetArray => {
                let v = self.total_target_arrays;
                self.total_target_arrays += 1;
                v
            }
            DPNBuiltInDataType::BoolArray => {
                let v = self.total_bool_arrays;
                self.total_bool_arrays += 1;
                v
            }
            DPNBuiltInDataType::U32TargetArray => {
                let v = self.total_u32_arrays;
                self.total_u32_arrays += 1;
                v
            }
            DPNBuiltInDataType::Unknown => panic!("unsupported data type"),
        };
        if !value.needs_store() {
            let idef = value.get_inline_def();
            self.definitions.push(DPNIndexedVarDef {
                data_type: idef.op_type.get_data_type(),
                index: new_base_index,
                op_type: idef.op_type,
                inputs: vec![idef.const_param],
            });
        } else {
            let vdef = sym_store.get(value);
            let mut inputs = if value.get_op_type().has_constant_param() {
                vec![vdef.const_param]
            } else {
                vec![]
            };
            inputs.append(&mut children_inds);
            self.definitions.push(DPNIndexedVarDef {
                data_type: vdef.op_type.get_data_type(),
                index: new_base_index,
                op_type: vdef.op_type,
                inputs,
            });
        }

        let new_op_id = encode_indexed_op_id(value.get_op_type().get_data_type(), new_base_index);
        self.indexed_map.insert(value, new_op_id);
        new_op_id
    }

    pub fn injest_state_cmd(&mut self, sym_store: &SymFeltStore, cmd: DPNStateCmd<SymFeltRef>) {
        let inputs = cmd.get_inputs();
        let inputs_resolved = inputs.iter().map(|c| self.injest_sfr(sym_store, *c)).collect::<Vec<_>>();
        let def_count = self.definitions.len();
        self.state_command_resolution_indices.push(def_count);
        let converted = cmd.convert_to_u64(&inputs_resolved);
        self.state_commands.push(converted);
    }

    pub fn compile(&mut self, sym_store: &SymFeltStore, ctx: &QExecContext, outputs: &[SymFeltRef]) {
        if ctx.events.len() > MAX_EVENT_RECORDS_PER_CALL {
            panic!("too many events, only {} events are supported", MAX_EVENT_RECORDS_PER_CALL);
        }
        for i in 0..ctx.input_count {
            let inp = self.injest_sfr(sym_store, SymFeltRef::new_input(i, ctx.input_types[i as usize]));
            self.circuit_inputs.push(inp);
        }
        for cmd in ctx.state_cmd_store.commands.iter() {
            self.injest_state_cmd(sym_store, cmd.clone());
        }
        for assertion in ctx.assertions.iter() {
            let left = self.injest_sfr(sym_store, assertion.left);
            let right = self.injest_sfr(sym_store, assertion.right);
            self.assertions.push(DPNAssertEqInfoIndexed {
                message: assertion.message.to_string(),
                left,
                right,
            });
        }
        for event in ctx.events.iter() {
            let condition = self.injest_sfr(sym_store, event.condition);
            let checkpoint_id = self.injest_sfr(sym_store, event.checkpoint_id);
            let user_id = self.injest_sfr(sym_store, event.user_id);
            let contract_id = self.injest_sfr(sym_store, event.contract_id);
            let data = event.data.iter().map(|c| self.injest_sfr(sym_store, *c)).collect::<Vec<_>>();
            self.events.push(DPNEventRecord {
                condition,
                checkpoint_id,
                user_id,
                contract_id,
                data,
            });
        }
        for output in outputs.iter() {
            let o = self.injest_sfr(sym_store, *output);
            self.circuit_outputs.push(o);
        }
    }
    pub fn finalize(self, name: String, method_id: u32) -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name,
            method_id: method_id,
            circuit_inputs: self.circuit_inputs,
            circuit_outputs: self.circuit_outputs,
            state_commands: self.state_commands,
            state_command_resolution_indices: self.state_command_resolution_indices,
            assertions: self.assertions,
            definitions: self.definitions,
            events: self.events,
        }
    }
}

/*

QExecContext*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::ops::context_trait::DPNContext;
    use crate::dpn::ops::op_types::DPNOpType;
    use crate::dpn::ops::sym_felt::SymFeltRefValue;

    #[test]
    fn compiles_inputs_outputs_assertions_state_commands_and_events() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_input();
        let one = ctx.op_const(1);
        let output = ctx.op_add(input, one);
        ctx.assert_eq(output, output, "output is stable");

        let slot = ctx.op_const(3);
        ctx.op_set_state_felt(slot, output);
        ctx.emit_event(vec![output]);

        let definition = PsyCompileResult::compile_exec("increment".to_string(), 9, &ctx.store, &ctx, &[output]);

        assert_eq!(definition.name, "increment");
        assert_eq!(definition.method_id, 9);
        assert_eq!(definition.circuit_inputs.len(), 1);
        assert_eq!(definition.circuit_outputs.len(), 1);
        assert_eq!(definition.assertions.len(), 1);
        assert_eq!(definition.assertions[0].message, "output is stable");
        // A state write also materializes the read of its previous value.
        assert_eq!(definition.state_commands.len(), 2);
        assert_eq!(definition.state_command_resolution_indices.len(), 2);
        assert_eq!(definition.events.len(), 1);
        assert_eq!(definition.events[0].data.len(), 1);
        assert!(!definition.definitions.is_empty());
        assert!(!definition.is_view_function());
    }

    #[test]
    #[should_panic(expected = "too many events")]
    fn rejects_more_events_than_circuit_limit() {
        let mut ctx = QExecContext::new();
        let data = ctx.op_const(1);
        for _ in 0..=MAX_EVENT_RECORDS_PER_CALL {
            ctx.emit_event(vec![data]);
        }

        PsyCompileResult::compile_exec("events".to_string(), 1, &ctx.store, &ctx, &[]);
    }

    #[test]
    fn ingestion_allocates_each_representable_register_family_and_reuses_duplicates() {
        let mut store = SymFeltStore::new();
        let constant = SymFeltRef::new_constant(3);
        let values = [
            SymFeltRef::new_input(0, DPNBuiltInDataType::Target),
            SymFeltRef::new_input(1, DPNBuiltInDataType::Bool),
            SymFeltRef::new_input(2, DPNBuiltInDataType::U32Target),
            store.insert(SymFeltRefValue { op_type: DPNOpType::HashNoPad, const_param: 0, inputs: vec![constant] }),
            store.insert(SymFeltRefValue { op_type: DPNOpType::GetStateCommandResultArray, const_param: 7, inputs: vec![] }),
            store.insert(SymFeltRefValue { op_type: DPNOpType::SplitBits, const_param: 4, inputs: vec![constant] }),
            store.insert(SymFeltRefValue { op_type: DPNOpType::Keccak256, const_param: 0, inputs: vec![constant] }),
        ];
        let mut result = PsyCompileResult::new();
        let encoded = values.map(|value| result.injest_sfr(&store, value));
        assert_eq!(result.injest_sfr(&store, values[0]), encoded[0]);
        assert_eq!(result.total_targets, 2);
        assert_eq!(result.total_bools, 1);
        assert_eq!(result.total_u32s, 1);
        assert_eq!(result.total_hashes, 1);
        assert_eq!(result.total_target_arrays, 1);
        assert_eq!(result.total_bool_arrays, 1);
        assert_eq!(result.total_u32_arrays, 1);
        assert_eq!(result.total_hash160s, 0);
        assert_eq!(result.definitions.len(), 8);
    }
}
