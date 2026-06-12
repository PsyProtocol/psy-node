use super::{data::DPNStateCmd, types::DPNStateCmdCore};
use crate::dpn::ops::sym_felt::SymFeltRef;

#[derive(Debug, Clone)]
pub struct DPNStateCommandStore {
    pub any_order_cmd_map: hashbrown::HashMap<DPNStateCmd<SymFeltRef>, usize>,
    pub external_sensitive_cmd_map: hashbrown::HashMap<DPNStateCmd<SymFeltRef>, usize>,
    pub external_and_state_sensitive_cmd_map: hashbrown::HashMap<DPNStateCmd<SymFeltRef>, usize>,
    pub commands: Vec<DPNStateCmd<SymFeltRef>>,
}

impl DPNStateCommandStore {
    pub fn new() -> Self {
        Self {
            any_order_cmd_map: hashbrown::HashMap::new(),
            external_sensitive_cmd_map: hashbrown::HashMap::new(),
            external_and_state_sensitive_cmd_map: hashbrown::HashMap::new(),
            commands: Vec::new(),
        }
    }
    pub fn injest_command(&mut self, cmd: DPNStateCmd<SymFeltRef>) -> usize {
        if !cmd.is_read_only() {
            // todo: de-dup write commands intelligently
            if cmd.is_inline_external_call_cmd() {
                self.external_sensitive_cmd_map.clear();
                self.external_and_state_sensitive_cmd_map.clear();
            } else if cmd.is_set_state_cmd() {
                self.external_and_state_sensitive_cmd_map.clear();
            }
            let index = self.commands.len();
            self.commands.push(cmd);
            index
        } else if cmd.is_set_state_order_sensitive() {
            if self.external_and_state_sensitive_cmd_map.contains_key(&cmd) {
                *self.external_and_state_sensitive_cmd_map.get(&cmd).unwrap()
            } else {
                let index = self.commands.len();
                self.external_and_state_sensitive_cmd_map.insert(cmd.clone(), index);
                self.commands.push(cmd);
                index
            }
        } else if cmd.is_external_call_order_sensitive() {
            if self.external_sensitive_cmd_map.contains_key(&cmd) {
                *self.external_sensitive_cmd_map.get(&cmd).unwrap()
            } else {
                let index = self.commands.len();
                self.external_sensitive_cmd_map.insert(cmd.clone(), index);
                self.commands.push(cmd);
                index
            }
        } else {
            if self.any_order_cmd_map.contains_key(&cmd) {
                *self.any_order_cmd_map.get(&cmd).unwrap()
            } else {
                let index = self.commands.len();
                self.any_order_cmd_map.insert(cmd.clone(), index);
                self.commands.push(cmd);
                index
            }
        }
    }
    pub fn finalize(self) -> Vec<DPNStateCmd<SymFeltRef>> {
        self.commands
    }
}
