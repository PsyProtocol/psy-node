#[pderive::serialize_copy]
pub struct QBlobWriterContextMetadataHeader {
    // the chain ID this batch is for
    pub chain_id: u32, 
    
    // a unique ID for the node that created this batch 
    pub created_by_node_id: u32, 
     // seconds since the unix epoch 
    pub created_at_seconds: u32,

    // This is who created the node
    // For coordinators, this is the coordinator ID.
    // For realms, this is the realm ID.
    pub realm_id: u64, 

    // The sub ID of the realm/coordinator that created these nodes.
    pub realm_sub_id: u64, 
    

    // The current unique_pending_id of the realm/coordinator as of when these nodes were created.
    pub unique_pending_id: u64, 

    // The last checkpoint ID applied as of when these nodes were created.
    pub checkpoint_id: u64, 
    
    // If the nodes are associated with a specific target (e.g. user, contract, etc.), this is the ID of that target.
    // If not associated with a specific target, this will be zero.
    // For QBlobMerkleNodeTreeType::UserContractTree, this is the user ID.
    // For QBlobMerkleNodeTreeType::ContractFunctionTree, this is the contract ID.
    // For QBlobMerkleNodeTreeType::UserContractStateTree, this is the user ID.
    // For QBlobMerkleNodeTreeType::GlobalUserTree, GlobalContractTree, or GlobalUserRegistrationTree, this will be zero.
    pub for_target_id: u64, 
}



impl QBlobWriterContextMetadataHeader {
    pub fn new(chain_id: u32, created_by_node_id: u32, created_at_seconds: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64, checkpoint_id: u64, for_target_id: u64) -> Self {
        Self {
            chain_id,
            created_by_node_id,
            created_at_seconds,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id,
            for_target_id,
        }
    }
    pub fn new_at_now(chain_id: u32, created_by_node_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64, checkpoint_id: u64, for_target_id: u64) -> Self {
        Self {
            chain_id,
            created_by_node_id,
            created_at_seconds: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id,
            for_target_id,
        }
    }
}