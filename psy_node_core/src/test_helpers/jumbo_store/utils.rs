use std::collections::HashSet;

use parth_core::{
    crypto::hash::
        traits::MerkleZeroHasher
    , data::
        hash::
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}
        
    , protocol::core_types::QDBHashBase, utils::QPGenRandom
};

use psy_serialize::PsySerializeCanonicalAsyncSafe;
pub trait PsyDBSer:  PsySerializeCanonicalAsyncSafe + PartialEq + Clone {

}
impl<T: PsySerializeCanonicalAsyncSafe + PartialEq + Clone> PsyDBSer for T {}

pub const MAX_REAL_U64_ID_VALUE: u64 = 0x0000_FFFF_FFFF_FFFF;
pub const DEFINITELY_MISSING_U64_VALUE: u64 = MAX_REAL_U64_ID_VALUE + 1;

pub const MAX_REAL_CHECKPOINT_ID: u64 = 0x0000_FFFF_FFFF_FFFF;
//const DEFINITELY_MISSING_CHECKPOINT_ID: u64 = MAX_REAL_CHECKPOINT_ID + 1;

pub const MAX_REAL_U128_ID_VALUE: u128 = 0x0000_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;
pub const DEFINITELY_MISSING_U128_ID_VALUE: u128 = MAX_REAL_U128_ID_VALUE + 1;


pub const MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS: usize = 64;

pub fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
    let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
    hset.into_iter().collect::<Vec<_>>()
}

pub fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey>{

    let max_node_id = 1u64 << (height as u64);

    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(SimpleMerkleNodeKey {
            level: height,
            index: rand::random::<u64>()%max_node_id,
        });
    }

    get_unique_node_set(result)
    
}

pub fn rand_real_u64_id() -> u64 {
    rand::random::<u64>() % MAX_REAL_U64_ID_VALUE
}
/* 
fn rand_real_checkpoint_id() -> u64 {
    // add some padding for addon checks
    (rand::random::<u64>() % MAX_REAL_CHECKPOINT_ID) - 0xFFFF
}
    */
pub fn rand_real_u128_id() -> u128 {
    rand::random::<u128>() % MAX_REAL_U128_ID_VALUE
}

pub fn rand_child(key: &SimpleMerkleNodeKey) -> SimpleMerkleNodeKey {
    let bit: bool = rand::random::<bool>();
    if bit {
        key.left_child()
    } else {
        key.right_child()
    }
}
pub fn rand_children_to_height(sub_root_key: &SimpleMerkleNodeKey, height: u8) -> Vec<SimpleMerkleNodeKey> {
    assert!(height > sub_root_key.level, "Height must be greater than sub root level");

    let mut keys = Vec::with_capacity(height as usize - sub_root_key.level as usize);
    let mut key = sub_root_key.clone();
    while key.level < height {
        key = rand_child(&key);
        keys.push(key.clone());
    }
    keys
}
pub fn fisher_yates_shuffle_array<T: Copy>(arr: &mut [T]) {
    let len = arr.len();
    for i in (1..len).rev() {
        let j = rand::random::<usize>() % (i + 1);
        arr.swap(i, j);
    }
}
pub fn unique_u64s_in_range(count: usize, min_inclusive: u64, max_exclusive: u64) -> Vec<u64> {
    assert!(max_exclusive > min_inclusive, "Max must be greater than min");
    let span = max_exclusive - min_inclusive;
    assert!(span >= (count as u64), "Range must be at least as large as count");
    let span_usize = span as usize;
    
    if count == span_usize {
        let mut arr: Vec<u64> = (min_inclusive..max_exclusive).collect();
        fisher_yates_shuffle_array(&mut arr);
        return arr;
    }

    // The heuristic for choosing the algorithm.
    // A threshold of 25% or even 10% is often a good trade-off.
    // We only create the full vector if the number of items we need is a significant
    // fraction of the total range.
    if count > span_usize / 4 { // Using 25% as a reasonable threshold
        let mut all: Vec<u64> = (min_inclusive..max_exclusive).collect();
        fisher_yates_shuffle_array(&mut all);
        return all.into_iter().take(count).collect();
    }

    // This is the correct path for your case: low count, large span.
    let mut set = std::collections::HashSet::with_capacity(count);
    while set.len() < count {
        let value = min_inclusive + (rand::random::<u64>() % span);
        set.insert(value);
    }
    set.into_iter().collect()
}
pub fn rand_leaves_for_subtree<Hash: PartialEq + Copy + QPGenRandom>(sub_root_key: &SimpleMerkleNodeKey, tree_height: u8, count: usize) -> Vec<SimpleMerkleNode<Hash>> {
    assert!(tree_height > sub_root_key.level, "Tree height must be greater than sub root level");
    let num_leaves_in_span_u64: u64 = 1u64 << (tree_height - sub_root_key.level - 1);
    let num_leaves_in_span: usize = num_leaves_in_span_u64 as usize;
    let start_leaf_offset = sub_root_key.index * num_leaves_in_span_u64;
    assert!(count <= num_leaves_in_span, "Count must be less than or equal to number of leaves in span");

    let leaf_indexes = unique_u64s_in_range(count, start_leaf_offset, start_leaf_offset + num_leaves_in_span_u64);

    leaf_indexes.into_iter()
        .map(|index| {
            SimpleMerkleNode {
                value: Hash::qp_rand_gen(),
                key: SimpleMerkleNodeKey::new(tree_height, index),
            }
        })
        .collect::<Vec<SimpleMerkleNode<Hash>>>()


}

pub trait THStandardTableIdentifier: Clone + Send + Sync {}
impl<T: Clone + Send + Sync> THStandardTableIdentifier for T {}

pub trait THHasher<Hash: QDBHashBase>: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static {}
impl<T: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static, Hash: QDBHashBase> THHasher<Hash> for T {}


