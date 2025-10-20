use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{
    crypto::hash::merkle_proof::MerkleProofCore,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_data::{
    proof_input::guta::SubmitGUTARealmResultAPINoProofInput,
    v1::{
        common_api::APILatestCheckpointResponse,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{ContractCodeDefinition, PQBCDeployContract, PQEDContractLeaf},
            public_key::PZKPublicKeyInfo,
            user::PQEDUserLeaf,
        },
    },
};


#[rpc(server, client, namespace = "psy")]
pub trait CoordinatorEdgeRpc<N: QNetworkTypesConfig> {
    // Basic methods
    #[method(name = "register_user")]
    async fn register_user(&self, public_key: PZKPublicKeyInfo<N::QHash>) -> RpcResult<String>;

    #[method(name = "get_user_id")]
    async fn get_user_id(&self, public_key: N::QHash) -> RpcResult<u64>;

    #[method(name = "deploy_contract")]
    async fn deploy_contract(&self, deploy_contract: PQBCDeployContract<N::QHash>) -> RpcResult<String>;

    #[method(name = "build_block")]
    async fn build_block(&self) -> RpcResult<String>;

    #[method(name = "submit_guta")]
    async fn submit_guta(&self, input: SubmitGUTARealmResultAPINoProofInput<N::F, N::QHash>, proof: N::ZKProof, realm_id: u64) -> RpcResult<String>;

    #[method(name = "get_latest_checkpoint")]
    async fn get_latest_checkpoint(&self) -> RpcResult<APILatestCheckpointResponse>;

    #[method(name = "latest_checkpoint")]
    async fn latest_checkpoint(&self) -> RpcResult<u64>;

    #[method(name = "get_latest_checkpoint_id")]
    async fn get_latest_checkpoint_id(&self) -> RpcResult<u64>;

    /*
    // Checkpoint sync info
    #[method(name = "get_checkpoint_sync_info")]
    async fn get_checkpoint_sync_info(&self, realm_id: u32, checkpoint_id: u64) -> RpcResult<CheckpointSyncInfo<N::F>>;

    #[method(name = "get_checkpoint_sync_info_compact")]
    async fn get_checkpoint_sync_info_compact(&self, checkpoint_id: u64) -> RpcResult<QCheckpointSyncInfoCompact>;*/

    // Contract methods
    #[method(name = "get_contract_leaf_data")]
    async fn get_contract_leaf_data(&self, contract_id: u64) -> RpcResult<PQEDContractLeaf<N::F, N::QHash>>;

    #[method(name = "get_contract_code_definition")]
    async fn get_contract_code_definition(&self, contract_id: u64) -> RpcResult<ContractCodeDefinition>;

    #[method(name = "get_contract_code_definition_f")]
    async fn get_contract_code_definition_f(&self, contract_id: N::F) -> RpcResult<ContractCodeDefinition>;

    // Checkpoint methods
    #[method(name = "get_checkpoint_leaf_data")]
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> RpcResult<PQEDCheckpointLeaf<N::F, N::QHash>>;

    #[method(name = "get_checkpoint_leaf_data_f")]
    async fn get_checkpoint_leaf_data_f(&self, checkpoint_id: N::F) -> RpcResult<PQEDCheckpointLeaf<N::F, N::QHash>>;

    #[method(name = "get_checkpoint_global_state_roots")]
    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> RpcResult<PQEDCheckpointGlobalStateRoots<N::QHash>>;

    // L2 block state
    #[method(name = "get_latest_l2_block_state")]
    async fn get_latest_l2_block_state(&self) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state")]
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state_f")]
    async fn get_l2_block_state_f(&self, checkpoint_id: N::F) -> RpcResult<QEDL2BlockState>;

    // User registration tree
    #[method(name = "get_user_registration_tree_root")]
    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_registration_tree_root_f")]
    async fn get_user_registration_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_user_registration_tree_leaf_hash")]
    async fn get_user_registration_tree_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_registration_tree_leaf_hash_f")]
    async fn get_user_registration_tree_leaf_hash_f(&self, checkpoint_id: N::F, leaf_index: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_user_registration_tree_merkle_proof")]
    async fn get_user_registration_tree_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_registration_tree_merkle_proof_f")]
    async fn get_user_registration_tree_merkle_proof_f(&self, checkpoint_id: N::F, leaf_index: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    // User tree
    #[method(name = "get_user_tree_root")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_tree_root_f")]
    async fn get_user_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_user_sub_tree_merkle_proof")]
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_top_tree_merkle_proof")]
    async fn get_user_top_tree_merkle_proof(&self, checkpoint_id: u64, leaf_level: u8, leaf_index: u64) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_top_tree_cap_root")]
    async fn get_user_top_tree_cap_root(&self, checkpoint_id: u64, cap_level: u8, cap_index: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_latest_top_tree_cap_root")]
    async fn get_user_latest_top_tree_cap_root(&self, cap_level: u8, cap_index: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_leaf_data")]
    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> RpcResult<PQEDUserLeaf<N::F, N::QHash>>;

    #[method(name = "get_user_tree_merkle_proof")]
    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_tree_merkle_proof_f")]
    async fn get_user_tree_merkle_proof_f(&self, checkpoint_id: N::F, user_id: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    // Contract function tree
    #[method(name = "get_contract_function_tree_root")]
    async fn get_contract_function_tree_root(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_function_tree_root_f")]
    async fn get_contract_function_tree_root_f(&self, checkpoint_id: N::F, contract_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_function_tree_leaf_hash")]
    async fn get_contract_function_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_function_tree_leaf_hash_f")]
    async fn get_contract_function_tree_leaf_hash_f(&self, checkpoint_id: N::F, contract_id: N::F, function_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_function_tree_merkle_proof")]
    async fn get_contract_function_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_contract_function_tree_merkle_proof_f")]
    async fn get_contract_function_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        contract_id: N::F,
        function_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    // Contract tree
    #[method(name = "get_contract_tree_root")]
    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_tree_root_f")]
    async fn get_contract_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_tree_leaf_hash")]
    async fn get_contract_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_tree_leaf_hash_f")]
    async fn get_contract_tree_leaf_hash_f(&self, checkpoint_id: N::F, contract_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_contract_tree_merkle_proof")]
    async fn get_contract_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_contract_tree_merkle_proof_f")]
    async fn get_contract_tree_merkle_proof_f(&self, checkpoint_id: N::F, contract_id: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    // Deposit tree
    #[method(name = "get_deposit_tree_root")]
    async fn get_deposit_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_deposit_tree_root_f")]
    async fn get_deposit_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_deposit_tree_leaf_hash")]
    async fn get_deposit_tree_leaf_hash(&self, checkpoint_id: u64, deposit_id: u32) -> RpcResult<N::QHash>;

    #[method(name = "get_deposit_tree_leaf_hash_f")]
    async fn get_deposit_tree_leaf_hash_f(&self, checkpoint_id: N::F, deposit_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_deposit_tree_merkle_proof")]
    async fn get_deposit_tree_merkle_proof(&self, checkpoint_id: u64, deposit_id: u32) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_deposit_tree_merkle_proof_f")]
    async fn get_deposit_tree_merkle_proof_f(&self, checkpoint_id: N::F, deposit_id: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    // Withdrawal tree
    #[method(name = "get_withdrawal_tree_root")]
    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_withdrawal_tree_root_f")]
    async fn get_withdrawal_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_withdrawal_tree_leaf_hash")]
    async fn get_withdrawal_tree_leaf_hash(&self, checkpoint_id: u64, withdrawal_id: u32) -> RpcResult<N::QHash>;

    #[method(name = "get_withdrawal_tree_leaf_hash_f")]
    async fn get_withdrawal_tree_leaf_hash_f(&self, checkpoint_id: N::F, withdrawal_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_withdrawal_tree_merkle_proof")]
    async fn get_withdrawal_tree_merkle_proof(&self, checkpoint_id: u64, withdrawal_id: u32) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_withdrawal_tree_merkle_proof_f")]
    async fn get_withdrawal_tree_merkle_proof_f(&self, checkpoint_id: N::F, withdrawal_id: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    // Checkpoint tree
    #[method(name = "get_latest_checkpoint_tree_root")]
    async fn get_latest_checkpoint_tree_root(&self) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_root")]
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_root_f")]
    async fn get_checkpoint_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_leaf_hash")]
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_leaf_hash_f")]
    async fn get_checkpoint_tree_leaf_hash_f(&self, checkpoint_id: N::F, leaf_checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_merkle_proof")]
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_checkpoint_tree_merkle_proof_f")]
    async fn get_checkpoint_tree_merkle_proof_f(&self, checkpoint_id: N::F, leaf_checkpoint_id: N::F) -> RpcResult<MerkleProofCore<N::QHash>>;

    //#[method(name = "generate_batch_variable_height_reward_proofs")]
    //async fn generate_batch_variable_height_reward_proofs(&self, checkpoint_id:
    // u64, job_ids: Vec<QProvingJobDataID>) ->
    // RpcResult<Vec<(VariableHeightRewardMerkleProof, QProvingJobDataID)>>;

    #[method(name = "get_graphviz")]
    async fn get_graphviz(&self, checkpoint_id: u64) -> RpcResult<String>;
}
