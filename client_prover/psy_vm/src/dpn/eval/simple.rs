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
