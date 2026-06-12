use plonky2::hash::hash_types::HashOutTarget;

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct DPNContractFunctionExecutionGadget {
    pub contract_tree_root: HashOutTarget,
    pub deposit_tree_root: HashOutTarget,
    pub user_tree_root: HashOutTarget,
    pub withdrawal_tree_root: HashOutTarget,
}
