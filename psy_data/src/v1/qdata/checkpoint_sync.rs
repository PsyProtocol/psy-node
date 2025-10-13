use std::hash::Hash;

use parth_common::memory_stores::simple_memory_merkle_store::get_merkle_proofs_for_compact;
use parth_core::crypto::hash::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore};
use parth_core::crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable};
use parth_core::felt::QFelt64;
use parth_core::protocol::core_types::QFHashBase;
use parth_core::{felt::QFelt, protocol::core_types::QHashBase};

use crate::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState};
use crate::v1::qdata::public_key::PZKPublicKeyInfo;

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointSyncInfoCompact")]
pub struct PQEDCheckpointSyncInfoCompact<F, Hash> {
    pub l2_block_state: QEDL2BlockState,
    pub stats: PQEDCheckpointLeafStats<F, Hash>,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_tree_update_siblings: Vec<Hash>,
    pub regsitered_users_start_pivot_siblings: Vec<Hash>,
    pub registered_users: Vec<PZKPublicKeyInfo<Hash>>,
    pub old_checkpoint_leaf_hash: Hash,
    pub slot: u64,
}

impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointSyncInfoCompact<F, Hash> {

    pub fn get_registered_user_merkle_proofs<H: MerkleZeroHasher<Hash>+ FieldQHasher<F, Hash>>(&self) -> Vec<MerkleProofCore<Hash>> {
        get_merkle_proofs_for_compact::<H, Hash>(
            self.l2_block_state.next_user_id - (self.registered_users.len() as u64),
            &self.regsitered_users_start_pivot_siblings,
            &self.registered_users.iter().map(|x|x.qfhash::<H>()).collect::<Vec<_>>(),
        )
    }

}
impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointSyncInfoCompact<F, Hash> {

    pub fn to_sync_info<H: FieldQHasher<F, Hash>>(self) -> PQEDCheckpointSyncInfo<F, Hash> {
        let global_chain_root = self.state_roots.qfhash::<H>();
        let checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root,
            stats: self.stats,
        };
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<H>();

        let checkpoint_tree_update_proof = DeltaMerkleProofCore::from_params::<H>(
            self.l2_block_state.checkpoint_id, 
            self.old_checkpoint_leaf_hash,
            checkpoint_leaf_hash,
            self.checkpoint_tree_update_siblings
        );
        let core = PQEDCheckpointCoreSyncInfo{
            checkpoint_tree_root: checkpoint_tree_update_proof.new_root,
            checkpoint_leaf_hash,
            l2_block_state: self.l2_block_state,
            checkpoint_leaf,
            state_roots: self.state_roots,
        };
        PQEDCheckpointSyncInfo {
            core,
            checkpoint_tree_update_proof,
            regsitered_users_start_pivot_siblings: self.regsitered_users_start_pivot_siblings,
            registered_users: self.registered_users,
            slot: self.slot,
        }


    }
}

impl<F: QFelt, Hash: QHashBase> From<PQEDCheckpointSyncInfo<F, Hash>> for PQEDCheckpointSyncInfoCompact<F, Hash> {
    fn from(value: PQEDCheckpointSyncInfo<F, Hash>) -> Self {
        Self {
            l2_block_state: value.core.l2_block_state,
            stats: value.core.checkpoint_leaf.stats,
            state_roots: value.core.state_roots,
            checkpoint_tree_update_siblings: value.checkpoint_tree_update_proof.siblings,
            regsitered_users_start_pivot_siblings: value.regsitered_users_start_pivot_siblings,
            registered_users: value.registered_users,
            old_checkpoint_leaf_hash: value.checkpoint_tree_update_proof.old_value,
            slot: value.slot,
        }
        
    }
}
impl<F: QFelt, Hash: QHashBase> From<&PQEDCheckpointSyncInfo<F, Hash>> for PQEDCheckpointSyncInfoCompact<F, Hash> {
    fn from(value: &PQEDCheckpointSyncInfo<F, Hash>) -> Self {
        Self {
            l2_block_state: value.core.l2_block_state,
            stats: value.core.checkpoint_leaf.stats,
            state_roots: value.core.state_roots,
            checkpoint_tree_update_siblings: value.checkpoint_tree_update_proof.siblings.clone(),
            regsitered_users_start_pivot_siblings: value.regsitered_users_start_pivot_siblings.clone(),
            registered_users: value.registered_users.clone(),
            old_checkpoint_leaf_hash: value.checkpoint_tree_update_proof.old_value,
            slot: value.slot,
        }
        
    }
}



#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointCoreSyncInfo")]
pub struct PQEDCheckpointCoreSyncInfo<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub checkpoint_leaf_hash: Hash,
    pub l2_block_state: QEDL2BlockState,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointSyncInfo")]
pub struct PQEDCheckpointSyncInfo<F, Hash> {
    pub core: PQEDCheckpointCoreSyncInfo<F, Hash>,
    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub regsitered_users_start_pivot_siblings: Vec<Hash>,
    pub registered_users: Vec<PZKPublicKeyInfo<Hash>>,
    pub slot: u64,
}
impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointSyncInfo<F, Hash> {

    pub fn get_registered_user_merkle_proofs<H: MerkleZeroHasher<Hash>+ FieldQHasher<F, Hash>>(&self) -> Vec<MerkleProofCore<Hash>> {
        get_merkle_proofs_for_compact::<H, Hash>(
            self.core.l2_block_state.next_user_id - (self.registered_users.len() as u64),
            &self.regsitered_users_start_pivot_siblings,
            &self.registered_users.iter().map(|x|x.qfhash::<H>()).collect::<Vec<_>>(),
        )
    }

}