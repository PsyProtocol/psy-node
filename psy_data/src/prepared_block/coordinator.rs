use parth_core::{QCoreProcCheckpointUniqueId, crypto::hash::merkle_proof::DeltaMerkleProofCore};

use crate::{prepared_block::common::PsyCoordinatorPendingCheckpointBase, v1::qdata::contract::ContractCodeDefinitionWithContractId};


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyPreparedCoordinatorBlockStateUpdates<F, Hash> {
    pub coordinator_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,
    pub new_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,
    
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
    
    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    
    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub registered_users_start_pivot_siblings: Vec<Hash>,
}




