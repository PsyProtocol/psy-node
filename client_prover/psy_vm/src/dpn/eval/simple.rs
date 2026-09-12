use hashbrown::HashMap;
use psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;

use super::traits::ContextInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractHashRef {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_id: u64,
}
pub struct DummyContextEvalInput {
    pub input: Vec<u64>,
    pub checkpoint_id: u64,
    pub contract_id: u64,
    pub caller_contract_id: u64,
    pub user_id: u64,
    pub global_contract_slots: HashMap<ContractHashRef, [u64; 4]>,
    pub contract_deployers: HashMap<u64, [u64; 4]>,
    pub user_public_key_hash: [u64; 4],
    pub session_proof_tree_root: [u64; 4],
    pub last_nonce: u64,
}

impl DummyContextEvalInput {
    pub fn new(input: Vec<u64>) -> DummyContextEvalInput {
        DummyContextEvalInput {
            input: input,
            contract_id: 0,
            caller_contract_id: DEFAULT_CALLER_CONTRACT_ID_U64,
            checkpoint_id: 1,
            user_id: 0,
            last_nonce: 1,
            global_contract_slots: HashMap::new(),
            contract_deployers: HashMap::new(),
            user_public_key_hash: [1337; 4],
            session_proof_tree_root: [0; 4],
        }
    }
    fn get_global_contract_hash_or_default(&self, user_id: u64, contract_id: u64, index: u64) -> [u64; 4] {
        let key = ContractHashRef {
            user_id: user_id,
            contract_id: contract_id,
            slot_id: index,
        };
        let value = self.global_contract_slots.get(&key);

        match value {
            Some(v) => v.to_owned(),
            None => [0; 4],
        }
    }
    fn get_global_contract_slot_or_default(&self, user_id: u64, contract_id: u64, index: u64) -> u64 {
        self.get_global_contract_hash_or_default(user_id, contract_id, index / 4)[(index & 3) as usize]
    }
}
impl ContextInput for DummyContextEvalInput {
    fn get_input(&self, index: u64) -> u64 {
        self.input[index as usize]
    }
    fn get_contract_id(&self) -> u64 {
        self.contract_id
    }
    fn get_contract_deployer(&self, contract_id: u64) -> [u64; 4] {
        self.contract_deployers.get(&contract_id).copied().unwrap_or([0; 4])
    }
    fn get_caller_contract_id(&self) -> u64 {
        self.caller_contract_id
    }
    fn get_user_id(&self) -> u64 {
        self.user_id
    }
    fn get_self_current_contract_slot(&self, index: u64) -> u64 {
        self.get_global_contract_slot_or_default(self.user_id, self.contract_id, index)
    }
    fn get_self_contract_slot(&self, contract_id: u64, index: u64) -> u64 {
        self.get_global_contract_slot_or_default(self.user_id, contract_id, index)
    }
    fn get_global_contract_slot(&self, user_id: u64, contract_id: u64, index: u64) -> u64 {
        self.get_global_contract_slot_or_default(user_id, contract_id, index)
    }

    fn get_user_nonce(&self) -> u64 {
        self.last_nonce
    }

    fn get_checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }

    fn get_user_public_key_hash(&self) -> [u64; 4] {
        self.user_public_key_hash
    }

    fn get_session_proof_tree_root(&self) -> [u64; 4] {
        self.session_proof_tree_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_expose_the_documented_context_values() {
        let input = DummyContextEvalInput::new(vec![11, 22]);

        assert_eq!(input.get_input(0), 11);
        assert_eq!(input.get_input(1), 22);
        assert_eq!(input.get_contract_id(), 0);
        assert_eq!(input.get_caller_contract_id(), DEFAULT_CALLER_CONTRACT_ID_U64);
        assert_eq!(input.get_user_id(), 0);
        assert_eq!(input.get_user_nonce(), 1);
        assert_eq!(input.get_checkpoint_id(), 1);
        assert_eq!(input.get_contract_deployer(123), [0; 4]);
        assert_eq!(input.get_self_current_contract_slot(0), 0);
        assert_eq!(input.get_user_public_key_hash(), [1337; 4]);
        assert_eq!(input.get_session_proof_tree_root(), [0; 4]);
    }

    #[test]
    fn configured_state_is_visible_through_each_lookup_scope() {
        let mut input = DummyContextEvalInput::new(vec![]);
        input.user_id = 3;
        input.contract_id = 4;
        input.contract_deployers.insert(4, [9, 8, 7, 6]);
        input.global_contract_slots.insert(
            ContractHashRef {
                user_id: 3,
                contract_id: 4,
                slot_id: 2,
            },
            [10, 11, 12, 13],
        );
        input.global_contract_slots.insert(
            ContractHashRef {
                user_id: 5,
                contract_id: 6,
                slot_id: 0,
            },
            [20, 21, 22, 23],
        );

        assert_eq!(input.get_contract_deployer(4), [9, 8, 7, 6]);
        assert_eq!(input.get_self_current_contract_slot(9), 11);
        assert_eq!(input.get_self_contract_slot(4, 11), 13);
        assert_eq!(input.get_global_contract_slot(5, 6, 2), 22);
        assert_eq!(input.get_global_contract_slot(5, 6, 9), 0);
    }
}
