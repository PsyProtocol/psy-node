use crate::dpn::ops::sym_felt::SymFeltRef;

pub trait EvalCache {
    fn contains(&self, key: SymFeltRef) -> bool;
    fn get(&self, key: SymFeltRef) -> u64;
    fn insert(&mut self, key: SymFeltRef, value: u64);
    fn contains_arr(&self, key: SymFeltRef) -> bool;
    fn get_arr_ref(&self, key: SymFeltRef) -> Box<Vec<u64>>;
    fn insert_arr(&mut self, key: SymFeltRef, value: Vec<u64>);
}
pub trait ContextInput {
    fn get_input(&self, index: u64) -> u64;
    fn get_contract_id(&self) -> u64;
    fn get_contract_deployer(&self, contract_id: u64) -> [u64; 4];
    fn get_caller_contract_id(&self) -> u64;
    fn get_user_id(&self) -> u64;
    fn get_user_nonce(&self) -> u64;
    fn get_checkpoint_id(&self) -> u64;
    fn get_user_public_key_hash(&self) -> [u64; 4];
    fn get_session_proof_tree_root(&self) -> [u64; 4];
    fn get_self_current_contract_slot(&self, index: u64) -> u64;
    fn get_self_contract_slot(&self, contract_id: u64, index: u64) -> u64;
    fn get_global_contract_slot(&self, user_id: u64, contract_id: u64, index: u64) -> u64;
}
pub trait ContextEval {
    fn resolve_felt_ref_cached<I: ContextInput, C: EvalCache>(&self, felt_ref: SymFeltRef, input: &I, cache: &mut C) -> u64;
    fn resolve_array_ref_cached<I: ContextInput, C: EvalCache>(&self, felt_ref: SymFeltRef, input: &I, cache: &mut C) -> Box<Vec<u64>>;
}
