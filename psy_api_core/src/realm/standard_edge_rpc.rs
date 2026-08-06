use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{
    QProvingJobDataIDWithRewardPath, crypto::hash::{tag_tree::TagTreeMerkleProof, merkle_proof::MerkleProofCore}, data::hash::merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey}
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    protocol::chain_context::AuthorityObservation,
    v1::{common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{IMTContractStateLeaf, IMTMembershipProof, IMTNonMembershipProof, IMTPredecessorResult},
            user::PQEDUserLeaf,
        }}
    ,
};
use crate::CheckpointJobStats;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RealmSlotUpdate {
    pub slot: u64,
    pub old_value: u64,
    pub new_value: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RealmContractSlotUpdates {
    pub contract_id: u32,
    pub slot_updates: Vec<RealmSlotUpdate>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RealmEndCapSlotUpdates {
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub user_id: u64,
    pub contracts: Vec<RealmContractSlotUpdates>,
}

#[rpc(server, client, namespace = "psy")]
pub trait RealmEdgeRpcTest {
    #[method(name = "get_sum")]
    async fn get_sum(
        &self,
        a: u64,
        b: u64,
    ) -> RpcResult<u64>;
}

#[rpc(server, client, namespace = "psy")]
pub trait RealmEdgeRpc<F, Hash, JobId, ZKProof> {
    /// Return the exact durable branch and local-state marker last published
    /// by the Realm Processor. Missing state is an explicit RPC error; callers
    /// must never synthesize epoch zero or combine this with legacy latest
    /// reads as if the pair were atomic.
    #[method(name = "get_realm_authority_observation")]
    async fn get_realm_authority_observation(&self) -> RpcResult<AuthorityObservation<Hash>>;

    /// Check if a user id belongs to this realm
    #[method(name = "check_user_id_in_realm")]
    async fn check_user_id_in_realm(&self, user_id: u64) -> RpcResult<bool>;

    /// Submit user end cap proof
    #[method(name = "submit_user_end_cap")]
    async fn submit_user_end_cap(
        &self,
        user_ec_input: SubmitUserEndCapNonProofInput<F, Hash>,
        proof: Vec<u8>,
    ) -> RpcResult<String>;
    /// Submit user end cap proofs in batch
    #[method(name = "submit_user_end_cap_batch")]
    async fn submit_user_end_cap_batch(
        &self,
        requests: Vec<(SubmitUserEndCapNonProofInput<F, Hash>, Vec<u8>)>,
    ) -> RpcResult<(Vec<u64>,Vec<u64>)>;

    #[method(name = "get_checkpoint_leaf_data")]
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64)
        -> RpcResult<PQEDCheckpointLeaf<F, Hash>>;

    /// Return proof job statistics for a committed checkpoint.
    #[method(name = "get_job_stats")]
    async fn get_job_stats(&self, checkpoint_id: u64) -> RpcResult<CheckpointJobStats>;


    #[method(name = "get_latest_checkpoint_id")]
    async fn get_latest_checkpoint_id(&self) -> RpcResult<u64>;

    #[method(name = "get_checkpoint_id_for_unique_pending_id")]
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> RpcResult<Option<u64>>;

    #[method(name = "get_unique_pending_id_for_checkpoint_id")]
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<Option<(u64, u128)>>;

    #[method(name = "get_user_end_cap_slot_updates")]
    async fn get_user_end_cap_slot_updates(
        &self,
        unique_pending_id: u64,
        user_id: u64,
    ) -> RpcResult<Option<RealmEndCapSlotUpdates>>;

    #[method(name = "get_latest_l2_block_state")]
    async fn get_latest_l2_block_state(&self) -> RpcResult<QEDL2BlockState>;

    #[method(name = "get_l2_block_state")]
    async fn get_l2_block_state(&self, checkpoint_id: u64) -> RpcResult<QEDL2BlockState>;

    // not sure why this is here in isolation, removing for now...
    //#[method(name = "get_user_registration_tree_root")]
    //async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_latest_checkpoint_tree_root")]
    async fn get_latest_checkpoint_tree_root(&self) -> RpcResult<Hash>;

    #[method(name = "get_checkpoint_tree_root")]
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;

    #[method(name = "get_contract_tree_state_heights")]
    async fn get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> RpcResult<Vec<u8>>;


    #[method(name = "get_checkpoint_tree_leaf_hash")]
    async fn get_checkpoint_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> RpcResult<Hash>;

    #[method(name = "get_checkpoint_tree_merkle_proof")]
    async fn get_checkpoint_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_checkpoint_global_state_roots")]
    async fn get_checkpoint_global_state_roots(
        &self,
        checkpoint_id: u64,
    ) -> RpcResult<PQEDCheckpointGlobalStateRoots<Hash>>;

    #[method(name = "get_user_leaf_data")]
    async fn get_user_leaf_data(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<PQEDUserLeaf<F, Hash>>;

    #[method(name = "get_user_leaves_batch")]
    async fn get_user_leaves_batch(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<PQEDUserLeaf<F, Hash>>>;

    #[method(name = "get_user_contract_state_tree_root")]
    async fn get_user_contract_state_tree_root(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<Hash>;

    #[method(name = "get_user_contract_state_tree_leaf_hash")]
    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> RpcResult<Hash>;

    #[method(name = "get_user_contract_state_tree_nodes")]
    async fn get_user_contract_state_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreDoubleIdKeyWithHeight>,
    ) -> RpcResult<Vec<Hash>>;

    #[method(name = "get_user_contract_tree_nodes")]
    async fn get_user_contract_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreSingleIdKey>,
    ) -> RpcResult<Vec<Hash>>;

    #[method(name = "get_user_contract_state_tree_merkle_proof")]
    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_contract_tree_root")]
    async fn get_user_contract_tree_root(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<Hash>;

    #[method(name = "get_user_contract_tree_leaf_hash")]
    async fn get_user_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<Hash>;

    #[method(name = "get_user_contract_tree_merkle_proof")]
    async fn get_user_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_tree_root")]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> RpcResult<Hash>;


    #[method(name = "get_user_tree_leaf_hash")]
    async fn get_user_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<Hash>;


    #[method(name = "get_user_tree_leaf_hashes")]
    async fn get_user_tree_leaf_hashes(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<Hash>>;

    #[method(name = "get_user_bottom_tree_merkle_proof")]
    async fn get_user_bottom_tree_merkle_proof(
        &self,
        root_level: u8,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_sub_tree_merkle_proof")]
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "get_user_tree_merkle_proof")]
    async fn get_user_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> RpcResult<MerkleProofCore<Hash>>;

    #[method(name = "generate_batch_proof_miner_reward_proofs")]
    async fn generate_batch_proof_miner_reward_proofs(&self, unique_pending_id: u64, job_ids: Vec<QProvingJobDataIDWithRewardPath<JobId>>) -> RpcResult<Vec<PsyProoffMinerRewardProof<Hash, JobId>>>;

    #[method(name = "get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id")]
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<TagTreeMerkleProof<Hash>>;

    // Indexed Merkle Tree (IMT) endpoints for contract state trees with 256-bit key storage

    /// Get an IMT leaf preimage by its position index.
    #[method(name = "get_imt_leaf_preimage")]
    async fn get_imt_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_index: u64,
    ) -> RpcResult<IMTContractStateLeaf<F, Hash>>;

    /// Get the leaf index for a given key in a contract's IMT, or None if the key doesn't exist.
    #[method(name = "get_imt_leaf_index_for_key")]
    async fn get_imt_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: Hash,
    ) -> RpcResult<u64>;

    #[method(name = "find_imt_predecessor")]
    async fn find_imt_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: Hash,
    ) -> RpcResult<(u64, IMTContractStateLeaf<F, Hash>)>;

    #[method(name = "get_imt_next_append_index")]
    async fn get_imt_next_append_index(&self, user_id: u64, contract_id: u64) -> RpcResult<u64>;

    /// Get an IMT membership proof: proves key K exists with value V.
    #[method(name = "get_imt_membership_proof")]
    async fn get_imt_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: Hash,
    ) -> RpcResult<IMTMembershipProof<F, Hash>>;

    /// Get an IMT non-membership proof: proves key K does NOT exist.
    #[method(name = "get_imt_non_membership_proof")]
    async fn get_imt_non_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: Hash,
    ) -> RpcResult<IMTNonMembershipProof<F, Hash>>;

    /// Get predecessor info for a key: used by clients to construct IMT insertion deltas.
    #[method(name = "get_imt_predecessor_info")]
    async fn get_imt_predecessor_info(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: Hash,
    ) -> RpcResult<IMTPredecessorResult<F, Hash>>;
}
