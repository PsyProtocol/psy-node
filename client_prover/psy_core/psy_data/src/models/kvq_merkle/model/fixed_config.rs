use kvq::traits::{KVQPair, KVQSerializable, KVQStoreAdapter, KVQStoreAdapterReader};
use psy_crypto::hash::{
    merkle::{
        core::{DeltaMerkleProofCore, MerkleProofCore},
        utils::{common::SimpleMerkleNode, sub_tree_nca::UpdateNCAProofsWithDependencies},
    },
    traits::hasher::MerkleZeroHasherWithMarkedLeaf,
};

use super::{KVQMerkleTreeModelCore, KVQMerkleTreeModelReaderCore};
use crate::models::kvq_merkle::key::KVQMerkleNodeKey;

pub trait KVQFixedConfigMerkleTreeModelReaderCore<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const PRIMARY_ID: u64,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapterReader<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>: KVQMerkleTreeModelReaderCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn new_node_key_fc(checkpoint_id: u64, level: u8, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: PRIMARY_ID,
            secondary_id: SECONDARY_ID,
            level,
            index,
            checkpoint_id,
        }
    }
    fn new_leaf_key_fc(checkpoint_id: u64, index: u64) -> KVQMerkleNodeKey<TABLE_TYPE> {
        KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id: TREE_ID,
            primary_id: PRIMARY_ID,
            secondary_id: SECONDARY_ID,
            level: TREE_HEIGHT,
            index,
            checkpoint_id,
        }
    }
    fn get_sub_tree_proof_fc(
        store: &S,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        Self::get_sub_tree_proof(
            store,
            TREE_HEIGHT as usize,
            root_level,
            &Self::new_node_key_fc(checkpoint_id, leaf_level, leaf_index),
        )
    }
    fn get_leaf_fc(store: &S, checkpoint_id: u64, index: u64) -> anyhow::Result<MerkleProofCore<Hash>> {
        Self::get_leaf(store, &Self::new_leaf_key_fc(checkpoint_id, index))
    }
    fn get_leaf_value_fc(store: &S, checkpoint_id: u64, index: u64) -> anyhow::Result<Hash> {
        Self::get_node(store, TREE_HEIGHT as usize, &Self::new_leaf_key_fc(checkpoint_id, index))
    }
    fn get_leaf_values_fc(store: &S, checkpoint_id: u64, indexes: &[u64]) -> anyhow::Result<Vec<Hash>> {
        let leaf_keys = indexes
            .iter()
            .map(|index| Self::new_leaf_key_fc(checkpoint_id, *index))
            .collect::<Vec<_>>();
        Self::get_nodes(store, TREE_HEIGHT as usize, &leaf_keys)
    }
    fn get_node_value_fc(store: &S, checkpoint_id: u64, level: u8, index: u64) -> anyhow::Result<Hash> {
        Self::get_node(store, TREE_HEIGHT as usize, &Self::new_node_key_fc(checkpoint_id, level, index))
    }
    fn get_root_fc(store: &S, checkpoint_id: u64) -> anyhow::Result<Hash> {
        Self::get_node(store, TREE_HEIGHT as usize, &Self::new_node_key_fc(checkpoint_id, 0, 0))
    }
}

pub trait KVQFixedConfigMerkleTreeModelCore<
    const TREE_ID: u8,
    const TREE_HEIGHT: u8,
    const PRIMARY_ID: u64,
    const SECONDARY_ID: u32,
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>:
    KVQMerkleTreeModelCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
    + KVQFixedConfigMerkleTreeModelReaderCore<TREE_ID, TREE_HEIGHT, PRIMARY_ID, SECONDARY_ID, TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn injest_merkle_proof_fc(store: &S, checkpoint_id: u64, merkle_proof: &MerkleProofCore<Hash>) -> anyhow::Result<()> {
        Self::injest_merkle_proof(store, TREE_ID, PRIMARY_ID, SECONDARY_ID, checkpoint_id, merkle_proof)
    }
    fn injest_merkle_proof_set_leaf_fc(
        store: &S,
        old_checkpoint_id: u64,
        merkle_proof: &MerkleProofCore<Hash>,
        new_checkpoint_id: u64,
        new_value: Hash,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::injest_merkle_proof_fc(store, old_checkpoint_id, merkle_proof)?;
        Self::set_leaf(store, &Self::new_leaf_key_fc(new_checkpoint_id, merkle_proof.index), new_value)
    }
    fn set_leaf_fc(store: &S, checkpoint_id: u64, index: u64, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        Self::set_leaf(store, &Self::new_leaf_key_fc(checkpoint_id, index), value)
    }

    fn smart_injest_nca_fc(
        store: &S,
        root_level: u8,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<UpdateNCAProofsWithDependencies<Hash>> {
        let kvq_nodes: Vec<_> = nodes
            .iter()
            .map(|n| KVQPair {
                key: Self::new_node_key_fc(checkpoint_id, n.key.level, n.key.index),
                value: n.value,
            })
            .collect();
        Self::smart_injest_nca(store, TREE_HEIGHT as usize, root_level, kvq_nodes)
    }

    fn smart_injest_nca_at_height_dmp_fc(
        store: &S,
        root_level: u8,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
        let kvq_nodes: Vec<_> = nodes
            .iter()
            .map(|n| KVQPair {
                key: Self::new_node_key_fc(checkpoint_id, n.key.level, n.key.index),
                value: n.value,
            })
            .collect();
        Self::smart_injest_nca_at_height_dmp(store, TREE_HEIGHT as usize, root_level, &kvq_nodes)
    }
}
