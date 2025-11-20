use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{
    crypto::hash::merkle_proof::MerkleProofCore,
    QProvingJobDataIDWithRewardPath,
};

use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, proof_input::guta::SubmitGUTARealmResultAPINoProofInput, v1::{
        common_api::{APILatestCheckpointResponse, PsyProoffMinerRewardProof},
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{ContractCodeDefinition, PQBCDeployContract, PQEDContractLeaf},
            public_key::PZKPublicKeyInfo,
            user::PQEDUserLeaf,
        },
    }
};


#[rpc(server, client, namespace = "psy")]
pub trait CoordinatorEdgeRpc<F, Hash, JobId, ZKProof> {
    // Basic methods
    #[method(name = "register_user")]
    async fn register_user(&self, public_key: PZKPublicKeyInfo<Hash>) -> RpcResult<String>;


    #[method(name = "get_user_ids_for_public_key")]
    async fn get_user_ids_for_public_key(&self, public_key: Hash, start_user_id: u64, count: u32) -> RpcResult<Vec<u64>>;

    #[method(name = "deploy_contract")]
    async fn deploy_contract(&self, deploy_contract: PQBCDeployContract<Hash>) -> RpcResult<String>;

    //#[method(name = "build_block")]
    //async fn build_block(&self) -> RpcResult<String>;

    #[method(name = "submit_guta")]
    async fn submit_guta(&self, input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>, proof: Vec<u8>, realm_id: u64) -> RpcResult<String>;


    #[method(name = "get_latest_checkpoint_id")]
    async fn get_latest_checkpoint_id(&self) -> RpcResult<u64>;

    /*
    // Checkpoint sync info
    #[method(name = "get_checkpoint_sync_info")]
    async fn get_checkpoint_sync_info(&self, realm_id: u32, checkpoint_id: u64) -> RpcResult<CheckpointSyncInfo<F>>;

    #[method(name = "get_checkpoint_sync_info_compact")]
    async fn get_checkpoint_sync_info_compact(&self, checkpoint_id: u64) -> RpcResult<QCheckpointSyncInfoCompact>;*/

    // Contract methods
    #[method(name = "get_contract_leaf_data")]
    async fn get_contract_leaf_data(&self, contract_id: u64) -> RpcResult<PQEDContractLeaf<F, Hash>>;

    #[method(name = "get_contract_code_definition")]
    async fn get_contract_code_definition(&self, contract_id: u64) -> RpcResult<ContractCodeDefinition>;

    // Checkpoint methods
    #[method(name = "get_checkpoint_leaf_data")]
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> RpcResult<PQEDCheckpointLeaf<F, Hash>>;

    #[method(name = "get_checkpoint_global_state_roots")]
    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> RpcResult<PQEDCheckpointGlobalStateRoots<Hash>>;

    // L2 block state
    #[method(name = "get_latest_l2_block_state")]
    async fn get_latest_l2_block_state(&self) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state")]
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> RpcResult<QEDL2BlockState>;

    // User registration tree
    #[method(name = "get_user_registration_tree_root")]
    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_user_registration_tree_leaf_hash")]
    async fn get_user_registration_tree_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> RpcResult<Hash>;

    #[method(name = "get_user_registration_tree_merkle_proof")]
    async fn get_user_registration_tree_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> RpcResult<MerkleProofCore<Hash>>;

    // User tree
    #[method(name = "get_user_tree_root")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_user_sub_tree_merkle_proof")]
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_top_tree_merkle_proof")]
    async fn get_user_top_tree_merkle_proof(&self, checkpoint_id: u64, leaf_level: u8, leaf_index: u64) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_top_tree_cap_root")]
    async fn get_user_top_tree_cap_root(&self, checkpoint_id: u64, cap_level: u8, cap_index: u64) -> RpcResult<Hash>;

    #[method(name = "get_user_latest_top_tree_cap_root")]
    async fn get_user_latest_top_tree_cap_root(&self, cap_level: u8, cap_index: u64) -> RpcResult<Hash>;

    #[method(name = "get_user_leaf_data")]
    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> RpcResult<PQEDUserLeaf<F, Hash>>;

    #[method(name = "get_user_tree_merkle_proof")]
    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> RpcResult<MerkleProofCore<Hash>>;

    // Contract function tree
    #[method(name = "get_contract_function_tree_root")]
    async fn get_contract_function_tree_root(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<Hash>;

    #[method(name = "get_contract_function_tree_leaf_hash")]
    async fn get_contract_function_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> RpcResult<Hash>;

    #[method(name = "get_contract_function_tree_merkle_proof")]
    async fn get_contract_function_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    // Contract tree
    #[method(name = "get_contract_tree_root")]
    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_contract_tree_leaf_hash")]
    async fn get_contract_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<Hash>;

    #[method(name = "get_contract_tree_merkle_proof")]
    async fn get_contract_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32) -> RpcResult<MerkleProofCore<Hash>>;

    // Checkpoint tree
    #[method(name = "get_latest_checkpoint_tree_root")]
    async fn get_latest_checkpoint_tree_root(&self) -> RpcResult<Hash>;

    #[method(name = "get_checkpoint_tree_root")]
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_checkpoint_tree_leaf_hash")]
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_checkpoint_tree_merkle_proof")]
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "generate_batch_proof_miner_reward_proofs")]
    async fn generate_batch_proof_miner_reward_proofs(&self, unique_pending_id: u64, job_ids: Vec<QProvingJobDataIDWithRewardPath<JobId>>) -> RpcResult<Vec<PsyProoffMinerRewardProof<Hash, JobId>>>;
    
}





