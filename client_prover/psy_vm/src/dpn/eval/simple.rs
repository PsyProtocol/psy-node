use hashbrown::HashMap;
use psy_client_data::dpn::sd_key::{SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS};
use psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;

use super::traits::ContextInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractHashRef {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEvalEntry {
    pub contract_id: u64,
    pub caller_contract_id: u64,
    pub method_id: u64,
    pub inputs_hash: [u64; 4],
    pub inputs: Vec<u64>,
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
    pub transaction_log: Vec<TransactionEvalEntry>,
    pub transaction_stack_hash: [u64; 4],
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
            transaction_log: Vec::new(),
            transaction_stack_hash: [0; 4],
        }
    }

    pub fn set_transaction_context(&mut self, transaction_log: Vec<TransactionEvalEntry>, transaction_stack_hash: [u64; 4]) {
        assert!(
            transaction_log.len() <= MAX_INTROSPECTABLE_TRANSACTIONS as usize,
            "transaction introspection exceeds MAX_TX_COUNT"
        );
        assert!(
            transaction_log
                .iter()
                .all(|entry| entry.inputs.len() <= SDKEY_MAX_CALLDATA_WORDS as usize),
            "transaction calldata length exceeds MAX_CALLDATA_WORDS"
        );
        self.transaction_log = transaction_log;
        self.transaction_stack_hash = transaction_stack_hash;
    }

    fn transaction(&self, index: u64) -> &TransactionEvalEntry {
        self.transaction_log
            .get(index as usize)
            .unwrap_or_else(|| panic!("transaction index {index} out of bounds"))
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

    fn get_transaction_count(&self) -> u64 {
        self.transaction_log.len() as u64
    }

    fn get_transaction_stack_hash(&self) -> [u64; 4] {
        self.transaction_stack_hash
    }

    fn get_transaction_contract_id(&self, index: u64) -> u64 {
        self.transaction(index).contract_id
    }

    fn get_transaction_caller_contract_id(&self, index: u64) -> u64 {
        self.transaction(index).caller_contract_id
    }

    fn get_transaction_method_id(&self, index: u64) -> u64 {
        self.transaction(index).method_id
    }

    fn get_transaction_inputs_hash(&self, index: u64) -> [u64; 4] {
        self.transaction(index).inputs_hash
    }

    fn get_transaction_input_length(&self, index: u64) -> u64 {
        self.transaction(index).inputs.len() as u64
    }

    fn get_transaction_input_word(&self, tx_index: u64, word_index: u64) -> u64 {
        assert!(word_index < SDKEY_MAX_CALLDATA_WORDS as u64, "calldata word index out of bounds");
        self.transaction(tx_index).inputs.get(word_index as usize).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_introspection_reads_real_context() {
        let mut input = DummyContextEvalInput::new(vec![]);
        input.set_transaction_context(
            vec![TransactionEvalEntry {
                contract_id: 7,
                caller_contract_id: 8,
                method_id: 9,
                inputs_hash: [11, 12, 13, 14],
                inputs: vec![21, 22],
            }],
            [31, 32, 33, 34],
        );

        assert_eq!(input.get_transaction_count(), 1);
        assert_eq!(input.get_transaction_stack_hash(), [31, 32, 33, 34]);
        assert_eq!(input.get_transaction_contract_id(0), 7);
        assert_eq!(input.get_transaction_caller_contract_id(0), 8);
        assert_eq!(input.get_transaction_method_id(0), 9);
        assert_eq!(input.get_transaction_inputs_hash(0), [11, 12, 13, 14]);
        assert_eq!(input.get_transaction_input_length(0), 2);
        assert_eq!(input.get_transaction_input_word(0, 1), 22);
        assert_eq!(input.get_transaction_input_word(0, 2), 0);
    }

    #[test]
    #[should_panic(expected = "transaction index 1 out of bounds")]
    fn transaction_introspection_rejects_missing_transaction() {
        let input = DummyContextEvalInput::new(vec![]);
        input.get_transaction_contract_id(1);
    }
}
