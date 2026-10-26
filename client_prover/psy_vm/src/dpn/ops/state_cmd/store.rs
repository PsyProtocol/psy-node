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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplicates_read_commands_but_keeps_writes_and_resets_sensitive_caches() {
        let mut store = DPNStateCommandStore::new();
        let slot = SymFeltRef::new_constant(2);
        let read = DPNStateCmd::get_other_user_contract_state_slot_single(
            SymFeltRef::new_constant(1), SymFeltRef::new_constant(2), SymFeltRef::new_constant(4), slot,
        );
        assert_eq!(store.injest_command(read.clone()), 0);
        assert_eq!(store.injest_command(read), 0);

        let sensitive = DPNStateCmd::get_self_user_current_contract_state_slot_single(slot);
        assert_eq!(store.injest_command(sensitive.clone()), 1);
        assert_eq!(store.injest_command(sensitive), 1);

        let write = DPNStateCmd::set_contract_state_slot_single(
            SymFeltRef::constant_true(), slot, SymFeltRef::new_constant(9),
        );
        assert_eq!(store.injest_command(write.clone()), 2);
        assert_eq!(store.injest_command(write), 3);
        assert_eq!(store.commands.len(), 4);
        assert!(store.external_and_state_sensitive_cmd_map.is_empty());
        assert_eq!(store.finalize().len(), 4);
    }
}
