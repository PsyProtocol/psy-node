use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use super::{op_types::DPNOpType, sym_felt::SymFeltRef, sym_felt_store::SymFeltStore};

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct StatePhaseKey {
    pub before_set_state_index: u32,
    pub before_external_call_index: u16,
}

#[derive(Debug, Clone)]
pub struct StatePhaseBuilder {
    pub state_phase_cache: HashMap<SymFeltRef, StatePhaseKey>,
    //pub first_group: Vec<SymFeltRef>,
    pub state_phases: HashMap<StatePhaseKey, Vec<SymFeltRef>>,
    /*
    pub ref_points: Vec<Vec<SymFeltRef>>,
    pub current_phase_ref_points: Vec<SymFeltRef>,*/
}

impl StatePhaseBuilder {
    pub fn new() -> Self {
        Self {
            state_phase_cache: HashMap::new(),
            //first_group: Vec::new(),
            state_phases: HashMap::new(),
            /*
            ref_points: Vec::new(),
            current_phase_ref_points: Vec::new(),*/
        }
    }
    pub fn compute_phase(&mut self, store: &SymFeltStore, sfr: SymFeltRef) -> StatePhaseKey {
        if self.state_phase_cache.contains_key(&sfr) {
            self.state_phase_cache[&sfr]
        } else if !sfr.needs_store() {
            StatePhaseKey {
                before_set_state_index: 0,
                before_external_call_index: 0,
            }
        } else {
            let key = if sfr.get_op_type().eq(&DPNOpType::GetStateQueryResultSingle) || sfr.get_op_type().eq(&DPNOpType::GetStateQueryResult) {
                //const_param: ((contract_state_tree_height as u64)<<48) |
                // (self.external_function_call_count as u64)<<32 |
                // (self.set_state_command_count as u64),
                let const_param = store.get_def(sfr).const_param;
                let tk = StatePhaseKey {
                    before_set_state_index: (const_param & 0xFFFFFFFFu64) as u32,
                    before_external_call_index: ((const_param >> 32) & 0xFFFFu64) as u16,
                };
                if self.state_phases.contains_key(&tk) {
                    self.state_phases.get_mut(&tk).unwrap().push(sfr);
                } else {
                    self.state_phases.insert(tk, vec![sfr]);
                }

                tk
            } else {
                let children = store.get_direct_children(sfr);
                if children.len() == 0 {
                    StatePhaseKey {
                        before_set_state_index: 0,
                        before_external_call_index: 0,
                    }
                } else {
                    let mut before_set_state_index = 0;
                    let mut before_external_call_index = 0;
                    for child in children {
                        let child_phase = self.compute_phase(store, child);
                        if child_phase.before_external_call_index > before_external_call_index
                            || (child_phase.before_external_call_index == before_external_call_index
                                && child_phase.before_set_state_index > before_set_state_index)
                        {
                            before_external_call_index = child_phase.before_external_call_index;
                            before_set_state_index = child_phase.before_set_state_index;
                        }
                    }
                    StatePhaseKey {
                        before_set_state_index: before_set_state_index,
                        before_external_call_index: before_external_call_index,
                    }
                }
            };
            self.state_phase_cache.insert(sfr, key);

            key
        }
    }
}
