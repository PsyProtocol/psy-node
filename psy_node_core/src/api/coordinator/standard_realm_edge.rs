use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{
    felt::ToU64Value,
    crypto::hash::merkle_proof::MerkleProofCore,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    v1::
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            user::PQEDUserLeaf,
        }
    ,
};


#[rpc(server, client, namespace = "qed")]
pub trait RealmEdgeRpc<N: QNetworkTypesConfig> {
    /// Check if a user id belongs to this realm
    #[method(name = "check_user_id_in_realm")]
    async fn check_user_id_in_realm(&self, user_id: u64) -> RpcResult<bool>;

    /// Submit user end cap proof
    #[method(name = "submit_user_end_cap")]
    async fn submit_user_end_cap(
        &self,
        user_ec_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof: N::ZKProof,
    ) -> RpcResult<String>;

    #[method(name = "get_checkpoint_leaf_data")]
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64)
        -> RpcResult<PQEDCheckpointLeaf<N::F, N::QHash>>;

    #[method(name = "get_checkpoint_leaf_data_f")]
    async fn get_checkpoint_leaf_data_f(&self, checkpoint_id: N::F)
        -> RpcResult<PQEDCheckpointLeaf<N::F, N::QHash>>;
    #[method(name = "get_latest_l2_block_state")]
    async fn get_latest_l2_block_state(&self) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state")]
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state_f")]
    async fn get_l2_block_state_f(&self, checkpoint_id: N::F) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_user_registration_tree_root")]
    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_latest_checkpoint_tree_root")]
    async fn get_latest_checkpoint_tree_root(&self) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_root")]
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_root_f")]
    async fn get_checkpoint_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_leaf_hash")]
    async fn get_checkpoint_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_leaf_hash_f")]
    async fn get_checkpoint_tree_leaf_hash_f(
        &self,
        checkpoint_id: N::F,
        leaf_checkpoint_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_checkpoint_tree_merkle_proof")]
    async fn get_checkpoint_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_checkpoint_tree_merkle_proof_f")]
    async fn get_checkpoint_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        leaf_checkpoint_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_checkpoint_global_state_roots")]
    async fn get_checkpoint_global_state_roots(
        &self,
        checkpoint_id: u64,
    ) -> RpcResult<PQEDCheckpointGlobalStateRoots<N::QHash>>;

    #[method(name = "get_user_leaf_data")]
    async fn get_user_leaf_data(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<PQEDUserLeaf<N::F, N::QHash>>;

    #[method(name = "get_user_leaf_data_f")]
    async fn get_user_leaf_data_f(&self, checkpoint_id: N::F, user_id: N::F)
        -> RpcResult<PQEDUserLeaf<N::F, N::QHash>>;
    #[method(name = "get_user_contract_state_tree_root")]
    async fn get_user_contract_state_tree_root(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_state_tree_root_f")]
    async fn get_user_contract_state_tree_root_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
        contract_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_state_tree_leaf_hash")]
    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_state_tree_leaf_hash_f")]
    async fn get_user_contract_state_tree_leaf_hash_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
        contract_id: N::F,
        height: u8,
        leaf_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_state_tree_merkle_proof")]
    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_contract_state_tree_merkle_proof_f")]
    async fn get_user_contract_state_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
        contract_id: N::F,
        height: u8,
        leaf_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_contract_tree_root")]
    async fn get_user_contract_tree_root(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_tree_root_f")]
    async fn get_user_contract_tree_root_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_tree_leaf_hash")]
    async fn get_user_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_tree_leaf_hash_f")]
    async fn get_user_contract_tree_leaf_hash_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
        contract_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_contract_tree_merkle_proof")]
    async fn get_user_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_contract_tree_merkle_proof_f")]
    async fn get_user_contract_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
        contract_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_tree_root")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> RpcResult<N::QHash>;

    #[method(name = "get_user_tree_root_f")]
    async fn get_user_tree_root_f(&self, checkpoint_id: N::F) -> RpcResult<N::QHash>;

    #[method(name = "get_user_tree_leaf_hash")]
    async fn get_user_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_tree_leaf_hash_f")]
    async fn get_user_tree_leaf_hash_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
    ) -> RpcResult<N::QHash>;

    #[method(name = "get_user_bottom_tree_merkle_proof")]
    async fn get_user_bottom_tree_merkle_proof(
        &self,
        root_level: u8,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_bottom_tree_merkle_proof_f")]
    async fn get_user_bottom_tree_merkle_proof_f(
        &self,
        root_level: u8,
        checkpoint_id: N::F,
        user_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_sub_tree_merkle_proof")]
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_sub_tree_merkle_proof_f")]
    async fn get_user_sub_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        root_level: u8,
        leaf_level: u8,
        leaf_index: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_tree_merkle_proof")]
    async fn get_user_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<MerkleProofCore<N::QHash>>;

    #[method(name = "get_user_tree_merkle_proof_f")]
    async fn get_user_tree_merkle_proof_f(
        &self,
        checkpoint_id: N::F,
        user_id: N::F,
    ) -> RpcResult<MerkleProofCore<N::QHash>> {
        self.get_user_tree_merkle_proof(
            checkpoint_id.to_u64_value(),
            user_id.to_u64_value(),
        )
        .await
    }
/*
    #[method(name = "generate_batch_variable_height_reward_proofs")]
    async fn generate_batch_variable_height_reward_proofs(
        &self,
        checkpoint_id: u64,
        job_ids: Vec<QProvingJobDataID>,
    ) -> RpcResult<Vec<(VariableHeightRewardMerkleProof, QProvingJobDataID)>>;
*/
    #[method(name = "get_graphviz")]
    async fn get_graphviz(&self, checkpoint_id: u64) -> RpcResult<String>;
}
