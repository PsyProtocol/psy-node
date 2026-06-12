use kvq::traits::{KVQPair, KVQSerializable, KVQStoreAdapter, KVQStoreAdapterReader};
use psy_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    traits::hasher::MerkleZeroHasherWithMarkedLeaf,
};

use super::{KVQMerkleTreeModelCore, KVQMerkleTreeModelReaderCore};
use crate::models::kvq_merkle::key::KVQMerkleNodeKey;

pub trait KVQSemiFixedConfigMerkleTreeModelReaderCore<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapterReader<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>: KVQMerkleTreeModelReaderCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn new_node_key_sfc(checkpoint_id: u64, primary_id: u64, level: u8, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: primary_id,
            secondary_id: SECONDARY_ID,
            level,
            index,
            checkpoint_id,
        }
    }
    fn new_leaf_key_sfc(checkpoint_id: u64, primary_id: u64, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: primary_id,
            secondary_id: SECONDARY_ID,
            level: TREE_HEIGHT,
            index,
            checkpoint_id,
        }
    }
    fn get_leaf_sfc(store: &S, checkpoint_id: u64, primary_id: u64, index: u64) -> anyhow::Result<MerkleProofCore<Hash>> {
        Self::get_leaf(store, &Self::new_leaf_key_sfc(checkpoint_id, primary_id, index))
    }
    fn get_leaf_value_fc(store: &S, checkpoint_id: u64, primary_id: u64, index: u64) -> anyhow::Result<Hash> {
        Self::get_node(store, TREE_HEIGHT as usize, &Self::new_leaf_key_sfc(checkpoint_id, primary_id, index))
    }
    fn get_leaf_values_fc(store: &S, checkpoint_id: u64, primary_id: u64, indexes: &[u64]) -> anyhow::Result<Vec<Hash>> {
        let leaf_keys = indexes
            .iter()
            .map(|index| Self::new_leaf_key_sfc(checkpoint_id, primary_id, *index))
            .collect::<Vec<_>>();
        Self::get_nodes(store, TREE_HEIGHT as usize, &leaf_keys)
    }
    fn get_node_value_fc(store: &S, checkpoint_id: u64, primary_id: u64, level: u8, index: u64) -> anyhow::Result<Hash> {
        Self::get_node(
            store,
            TREE_HEIGHT as usize,
            &Self::new_node_key_sfc(checkpoint_id, primary_id, level, index),
        )
    }
    fn get_root_fc(store: &S, checkpoint_id: u64, primary_id: u64) -> anyhow::Result<Hash> {
        Self::get_node(store, TREE_HEIGHT as usize, &Self::new_node_key_sfc(checkpoint_id, primary_id, 0, 0))
    }
}
pub trait KVQSemiFixedConfigMerkleTreeModelCore<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>:
    KVQMerkleTreeModelCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
    + KVQSemiFixedConfigMerkleTreeModelReaderCore<TREE_ID, TREE_HEIGHT, SECONDARY_ID, TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn set_leaf_sfc(store: &S, checkpoint_id: u64, primary_id: u64, index: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::set_leaf(store, &Self::new_leaf_key_sfc(checkpoint_id, primary_id, index), value)
    }

    fn injest_merkle_proof_sfc(store: &S, primary_id: u64, checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash>) -> anyhow::Result<()> {
        Self::injest_merkle_proof(store, TREE_ID, primary_id, SECONDARY_ID, checkpoint_id, merkle_proof)
    }
    fn injest_merkle_proof_set_leaf_sfc(
        store: &S,
        primary_id: u64,
        old_checkpoint_id: u64,
        merkle_proof: &MerkleProofCore<Hash>,
        new_checkpoint_id: u64,
        new_value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::injest_merkle_proof_sfc(store, primary_id, old_checkpoint_id, merkle_proof)?;
        Self::set_leaf(
            store,
            &Self::new_leaf_key_sfc(new_checkpoint_id, primary_id, merkle_proof.index),
            new_value,
        )
    }

    fn injest_merkle_proof_sfc_imm(store: &S, primary_id: u64, checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash>) -> anyhow::Result<()> {
        Self::injest_merkle_proof(store, TREE_ID, primary_id, SECONDARY_ID, checkpoint_id, merkle_proof)
    }
    fn injest_merkle_proof_set_leaf_sfc_imm(
        store: &S,
        primary_id: u64,
        old_checkpoint_id: u64,
        merkle_proof: &MerkleProofCore<Hash>,
        new_checkpoint_id: u64,
        new_value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::injest_merkle_proof_sfc_imm(store, primary_id, old_checkpoint_id, merkle_proof)?;
        Self::set_leaf(
            store,
            &Self::new_leaf_key_sfc(new_checkpoint_id, primary_id, merkle_proof.index),
            new_value,
        )
    }
    fn set_leaf_sfc_imm(store: &S, checkpoint_id: u64, primary_id: u64, index: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::set_leaf(store, &Self::new_leaf_key_sfc(checkpoint_id, primary_id, index), value)
    }

    /// Batch set leaves from index 0, optimized for bulk updates
    /// Returns the new root hash after all leaves are updated
    fn batch_set_leaves_from_zero_sfc(store: &S, checkpoint_id: u64, primary_id: u64, leaves: &[Hash]) -> anyhow::Result<Hash> {
        if leaves.is_empty() {
            return Self::get_root_fc(store, checkpoint_id, primary_id);
        }

        // Batch write all leaf nodes at once
        let mut leaf_updates = Vec::with_capacity(leaves.len());
        for (i, leaf_value) in leaves.iter().enumerate() {
            leaf_updates.push(KVQPair {
                key: Self::new_leaf_key_sfc(checkpoint_id, primary_id, i as u64),
                value: *leaf_value,
            });
        }
        Self::set_nodes(store, &leaf_updates)?;

        // Find the smallest subtree that covers all updated leaves (0 to
        // leaves.len()-1) This is the parent of the last leaf at the
        // appropriate level
        let last_leaf_index = (leaves.len() - 1) as u64;
        let first_leaf_key = Self::new_leaf_key_sfc(checkpoint_id, primary_id, 0);
        let last_leaf_key = Self::new_leaf_key_sfc(checkpoint_id, primary_id, last_leaf_index);

        // Find the nearest common ancestor of first and last leaf
        let affected_subtree_root = first_leaf_key.find_nearest_common_ancestor(&last_leaf_key);

        // Rehash only the affected subtree
        Self::rehash_sub_tree(store, TREE_HEIGHT as usize, &affected_subtree_root)?;

        // If the affected subtree is not the root, rehash from subtree root to tree
        // root
        if affected_subtree_root.level > 0 {
            Self::rehash_from_node_to_level(store, TREE_HEIGHT as usize, affected_subtree_root, 0)?;
        }

        // Return the new root
        Self::get_root_fc(store, checkpoint_id, primary_id)
    }
}
