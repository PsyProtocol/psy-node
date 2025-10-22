use std::cmp::Ordering;

use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};
use rand::Rng;

use crate::{
    data::serializable::{QPDSerializable, QPDSerializableFixed},
    protocol::core_types::Q256BitHash,
    utils::QPGenRandom,
};
pub const JOB_ID_EMPTY_REWARD_PATH_INFO: u64 = 0xFFFF_FFFF_FFFF_FFFFu64;

pub const PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY: usize = 9;
pub const PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE: usize = 41;
#[pderive::serialize_copy_default_no_ord]
#[repr(C)]
pub struct SimpleMerkleNodeKey {
    pub level: u8,
    pub index: u64,
}
impl SimpleMerkleNodeKey {
    pub fn random_simple_merkle_node_in_tree(tree_height: u8) -> Self {
        let mut rng = rand::thread_rng();
        let level = rng.gen_range(0..=tree_height);
        let max_index = 1u64 << (tree_height - level);
        let index = rng.gen_range(0..max_index);
        Self { level, index }
    }
}
impl PartialOrd for SimpleMerkleNodeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.level != other.level {
            self.level.partial_cmp(&other.level)
        } else {
            self.index.partial_cmp(&other.index)
        }
    }
}
impl Ord for SimpleMerkleNodeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.level != other.level {
            self.level.cmp(&other.level)
        } else {
            self.index.cmp(&other.index)
        }
    }
}
impl SimpleMerkleNodeKey {
    pub fn new_root() -> Self {
        Self { level: 0, index: 0 }
    }
    pub fn new(level: u8, index: u64) -> Self {
        Self { level, index }
    }
    pub fn first_leaf_for_height(&self, height: u8) -> Self {
        if height <= self.level {
            self.clone()
        } else {
            let diff = (height - self.level) as u64;
            Self {
                level: height,
                index: (1u64 << diff) * self.index,
            }
        }
    }
    pub fn to_reward_path_info(&self) -> u64 {
        ((self.level as u64) << 56) | (self.index & 0x00FFFFFFFFFFFFFF)
    }
    pub fn from_reward_path_info(reward_path_info: u64) -> Self {
        let level = (reward_path_info >> 56) as u8;
        let index = reward_path_info & 0x00FFFFFFFFFFFFFF;
        Self { level, index }
    }
    pub fn is_empty_reward_path(&self) -> bool {
        self.to_reward_path_info() == JOB_ID_EMPTY_REWARD_PATH_INFO
    }
    pub fn sibling(&self) -> Self {
        Self {
            level: self.level,
            index: self.index ^ 1,
        }
    }

    pub fn siblings(&self) -> Vec<Self> {
        let mut result = Vec::with_capacity(self.level as usize);
        let mut current = *self;
        for _ in 0..self.level {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }
    pub fn siblings_to_level(&self, to_level: u8) -> Vec<Self> {
        if to_level >= self.level {
            return vec![];
        }
        let mut result = Vec::with_capacity((self.level - to_level) as usize);
        let mut current = *self;
        for _ in 0..(self.level - to_level) {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }

    // if self or other are on the same merkle path
    pub fn is_direct_path_related(&self, other: &SimpleMerkleNodeKey) -> bool {
        if other.level == self.level {
            self.index == other.index
        } else if other.level < self.level {
            // opt?: (self.index>>(self.level-other.level)) == other.index
            self.parent_at_level(other.level).index == other.index
        } else {
            other.parent_at_level(self.level).index == self.index
        }
    }
    pub fn parent(&self) -> Self {
        if self.level == 0 {
            return *self;
        }
        Self {
            level: self.level - 1,
            index: self.index >> 1,
        }
    }
    pub fn first_leaf_child(&self, tree_height: u8) -> Self {
        if self.level >= tree_height {
            return self.clone();
        }
        Self {
            level: tree_height,
            index: self.index << (tree_height - self.level),
        }
    }
    pub fn left_child(&self) -> Self {
        Self {
            level: self.level + 1,
            index: self.index << 1,
        }
    }
    pub fn right_child(&self) -> Self {
        Self {
            level: self.level + 1,
            index: (self.index << 1) + 1,
        }
    }
    pub fn is_on_the_right_of(&self, other: &SimpleMerkleNodeKey) -> bool {
        if other.level == self.level {
            self.index > other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index > other.index
        } else {
            self.index > other.parent_at_level(self.level).index
        }
    }
    pub fn is_to_the_left_of(&self, other: &SimpleMerkleNodeKey) -> bool {
        if other.level == self.level {
            self.index < other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index < other.index
        } else {
            self.index < other.parent_at_level(self.level).index
        }
    }

    pub fn parent_at_level(&self, level: u8) -> Self {
        if level > self.level {
            panic!("given level is not above this node")
        }
        self.n_th_ancestor(self.level - level)
    }
    pub fn n_th_ancestor(&self, levels_above: u8) -> Self {
        if levels_above >= self.level {
            Self::new_root()
        } else {
            Self {
                level: self.level - levels_above,
                index: self.index >> levels_above,
            }
        }
    }
    pub fn is_left_sibling(&self) -> bool {
        self.index % 2 == 0
    }
    pub fn is_right_sibling(&self) -> bool {
        self.index % 2 == 1
    }
    pub fn find_nearest_common_ancestor(&self, other: &SimpleMerkleNodeKey) -> SimpleMerkleNodeKey {
        let start_level = u8::min(other.level, self.level);
        let mut self_current = self.parent_at_level(start_level);
        let mut other_current = other.parent_at_level(start_level);
        while !other_current.eq(&self_current) {
            self_current = self_current.parent();
            other_current = other_current.parent();
        }
        self_current
    }
    pub fn get_siblings_keys_to_height(&self, to_level: u8) -> Vec<SimpleMerkleNodeKey> {
        if to_level > self.level {
            vec![]
        } else {
            let mut my_node = self.clone();
            let mut siblings = Vec::with_capacity((self.level - to_level) as usize);
            while my_node.level != to_level {
                siblings.push(my_node.sibling());
                my_node = my_node.parent();
            }

            siblings
        }
    }
    pub fn get_above_path_to_height(&self, to_level: u8, include_root: bool) -> Vec<SimpleMerkleNodeKey> {
        if to_level >= self.level {
            vec![]
        } else {
            let mut my_node = self.parent();
            let mut path_node_keys = Vec::with_capacity((self.level - to_level - if include_root {
                0
            } else {
                1
            }) as usize);
            while my_node.level != to_level {
                path_node_keys.push(my_node.clone());
                my_node = my_node.parent();
            }
            if include_root {
                path_node_keys.push(my_node);
            }

            path_node_keys
        }
    }
    pub fn get_above_path_without_root(&self) -> Vec<SimpleMerkleNodeKey> {
        self.get_above_path_to_height(0, false)
    }
    pub fn get_above_path_including_root(&self) -> Vec<SimpleMerkleNodeKey> {
        self.get_above_path_to_height(0, true)
    }

    pub fn get_path_above_self_to_level(&self, sub_root_level: u8, include_sub_root: bool) -> Vec<SimpleMerkleNodeKey> {
        if sub_root_level >= self.level {
            return vec![];
        }

        // Determine the level at which we should stop.
        // If we don't include the sub-root, we stop at the level *above* it.
        let stop_level = if include_sub_root {
            sub_root_level
        } else {
            // Use saturating_add to prevent overflow if sub_root_level is 255.
            sub_root_level.saturating_add(1)
        };

        // If the stop level is already at or above our current level, there's no path.
        if stop_level > self.level {
            return vec![];
        }

        let mut path_node_keys = Vec::with_capacity((self.level - sub_root_level) as usize);
        let mut my_node = *self;
        while my_node.level > stop_level {
            my_node = my_node.parent();
            path_node_keys.push(my_node);
        }

        path_node_keys
    }
}
impl QPGenRandom for SimpleMerkleNodeKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            level: rand::random::<u8>() % 64,
            index: rand::random::<u64>(),
        }
    }
}

impl QPDSerializable for SimpleMerkleNodeKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let index_bytes = u64::to_be_bytes(self.index);
        Ok(vec![
            self.level,
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
            index_bytes[4],
            index_bytes[5],
            index_bytes[6],
            index_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() == 9 {
            Ok(Self {
                level: bytes[0],
                index: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            })
        } else {
            anyhow::bail!("error deserializing SimpleMerkleNodeKey, expected 9 bytes, got {}", bytes.len());
        }
    }
}
impl QPDSerializableFixed for SimpleMerkleNodeKey {
    fn get_fixed_size() -> usize {
        9
    }
}

impl FastFixedSerializable<9> for SimpleMerkleNodeKey {
    fn ffs_from_owned_bytes(data: [u8; 9]) -> Self {
        Self {
            level: data[0],
            index: u64::from_le_bytes(data[1..9].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            level: data[0],
            index: u64::from_le_bytes(data[1..9].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 9 {
            anyhow::bail!("invalid length for SimpleMerkleNodeKey, expected 9 bytes, got {}", data.len());
        }
        Ok(Self {
            level: data[0],
            index: u64::from_le_bytes(data[1..9].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 9] {
        let mut data: [u8; 9] = [0u8; 9];
        data[0] = self.level;

        data[1..9].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 9] {
        let mut data: [u8; 9] = [0u8; 9];
        data[0] = self.level;

        data[1..9].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}

impl PsyCanonicalSerializeMetadata for SimpleMerkleNodeKey {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 9;
}
impl AutoDatabaseSerializationUseFastFixedSerialize<9> for SimpleMerkleNodeKey {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(SimpleMerkleNodeKey, 9);

pser::impl_bytemuck_pod_and_zeroable!(SimpleMerkleNodeKey);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match_key() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY] = SimpleMerkleNodeKey::qp_rand_gen().ffs_into_bytes();
}

#[pderive::serialize_copy_no_ord]
#[repr(C)]
pub struct SimpleMerkleNode<Hash> {
    pub key: SimpleMerkleNodeKey,
    pub value: Hash,
}

impl<Hash> SimpleMerkleNode<Hash> {
    pub fn new_root(value: Hash) -> Self {
        Self {
            key: SimpleMerkleNodeKey::new_root(),
            value,
        }
    }
    pub fn new(level: u8, index: u64, value: Hash) -> Self {
        Self {
            key: SimpleMerkleNodeKey { level, index },
            value,
        }
    }
}
impl<Hash: PartialOrd> PartialOrd for SimpleMerkleNode<Hash> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.key.level != other.key.level {
            self.key.level.partial_cmp(&other.key.level)
        } else if self.key.index != other.key.index {
            self.key.index.partial_cmp(&other.key.index)
        } else {
            self.value.partial_cmp(&other.value)
        }
    }
}
impl<Hash: Ord> Ord for SimpleMerkleNode<Hash> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key.level != other.key.level {
            self.key.level.cmp(&other.key.level)
        } else if self.key.index != other.key.index {
            self.key.index.cmp(&other.key.index)
        } else {
            self.value.cmp(&other.value)
        }
    }
}

impl<Hash: Q256BitHash> FastFixedSerializable<41> for SimpleMerkleNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 41]) -> Self {
        Self {
            key: SimpleMerkleNodeKey::ffs_from_owned_bytes(data[0..9].try_into().unwrap()),
            value: Hash::from_ref_32bytes(data[9..41].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: SimpleMerkleNodeKey::ffs_from_slice_or_panic(&data[0..9]),
            value: Hash::from_ref_32bytes(data[9..41].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 41 {
            anyhow::bail!("invalid length for SimpleMerkleNode, expected 41 bytes, got {}", data.len());
        }
        Ok(Self {
            key: SimpleMerkleNodeKey::ffs_try_from_slice(&data[0..9])?,
            value: Hash::from_slice_32bytes(&data[9..41])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 41] {
        let mut data: [u8; 41] = [0u8; 41];
        data[0..9].copy_from_slice(&self.key.ffs_to_bytes());
        data[9..41].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 41] {
        let mut data: [u8; 41] = [0u8; 41];
        data[0..9].copy_from_slice(&self.key.ffs_into_bytes());
        data[9..41].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }
}

pser::impl_bytemuck_pod_and_zeroable!(SimpleMerkleNode, Hash);

pser::impl_bytemuck_ffs_tests!(SimpleMerkleNode, { crate::PHash }, 41, true);

// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match_node() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE] =
        SimpleMerkleNode::<crate::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE] = SimpleMerkleNode::<crate::PHash>::qp_rand_gen().ffs_into_bytes();
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for SimpleMerkleNode<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 41;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<41> for SimpleMerkleNode<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    SimpleMerkleNode,
    {Hash: Q256BitHash} => {Hash},
    41
);

impl<Hash: QPGenRandom> QPGenRandom for SimpleMerkleNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            key: SimpleMerkleNodeKey::qp_rand_gen(),
            value: Hash::qp_rand_gen(),
        }
    }
}

#[pderive::serialize_copy]
pub struct SimpleMerkleNodeNCAAggregation {
    pub nca: SimpleMerkleNodeKey,
    pub left: SimpleMerkleNodeKey,
    pub right: SimpleMerkleNodeKey,
}

// --- Add this new helper function ---

/// A truly v1 recursive helper that avoids HashMap lookups in the hot
/// path.
///
/// It returns a tuple `(SimpleMerkleNodeKey, usize)` representing the NCA key
/// and its calculated dependency level. This avoids the need for a shared map
/// to store levels, passing the state up the call stack instead.
fn build_recursive_truly_v1(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
    // We still collect the aggregations with their levels as we go.
    aggregations: &mut Vec<SimpleMerkleNodeNCAAggregation>,
) -> Option<SimpleMerkleNodeKey> {
    // Return type changed!
    if nodes.is_empty() {
        return None;
    }
    // Base case: A single node is a leaf in the NCA tree. Its level is 0.
    if nodes.len() == 1 {
        return Some(nodes[0]); // Return key and level 0.
    }

    // --- Divide Phase ---
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    // --- Conquer Phase ---
    let left_result = build_recursive_truly_v1(left_nodes, subtree_root.left_child(), tree_height, aggregations);
    let right_result = build_recursive_truly_v1(right_nodes, right_child, tree_height, aggregations);

    // --- Combine Phase ---
    match (left_result, right_result) {
        (Some(l_key), Some(r_key)) => {
            let combined_nca_key = l_key.find_nearest_common_ancestor(&r_key);

            let agg = SimpleMerkleNodeNCAAggregation {
                nca: combined_nca_key,
                left: l_key,
                right: r_key,
            };
            aggregations.push(agg);

            // Pass the new key and its calculated level up the call stack.
            Some(combined_nca_key)
        }
        // If only one side has a result, pass it up directly.
        (Some(l_res), None) => Some(l_res),
        (None, Some(r_res)) => Some(r_res),
        (None, None) => None,
    }
}

// --- New top-level function. Can replace the old `v1` one ---

pub fn generate_nca_tree_groups_v1(leaves: &[SimpleMerkleNodeKey], _leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    if leaves.len() < 2 {
        return vec![];
    }

    let tree_height = leaves[0].level;

    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    // This single call builds the tree and determines the level for each
    // aggregation.
    build_recursive_truly_v1(&sorted_leaves, root_node, tree_height, &mut aggregations);

    if aggregations.is_empty() {
        return vec![];
    }

    let mut nca_map: std::collections::HashMap<SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation> = std::collections::HashMap::new();
    aggregations.iter().for_each(|x| {
        nca_map.insert(x.nca.clone(), x.clone());
    });
    let mut levels = Vec::with_capacity(tree_height as usize + 1);

    let root = aggregations.last().unwrap().clone();
    if root.left.level == tree_height && root.right.level == tree_height {
        return vec![vec![root]];
    }

    let mut has_non_leaf_children = true;
    let mut current_level = vec![root];

    while has_non_leaf_children {
        levels.push(current_level.clone());
        let mut next_level = Vec::new();
        has_non_leaf_children = false;
        for agg in current_level.iter() {
            if agg.left.level != tree_height {
                if let Some(left_agg) = nca_map.get(&agg.left) {
                    next_level.push(left_agg.clone());
                    has_non_leaf_children = true;
                }
            }
            if agg.right.level != tree_height {
                if let Some(right_agg) = nca_map.get(&agg.right) {
                    next_level.push(right_agg.clone());
                    has_non_leaf_children = true;
                }
            }
        }
        current_level = next_level;
    }
    if current_level.len() > 0 {
        levels.push(current_level);
    }
    levels.reverse();
    levels
}
// --- Function Implementation ---

/// Recursively builds the aggregation path for a given set of nodes within a
/// specific sub-tree.
///
/// This is the helper function that implements the core divide-and-conquer
/// logic.
fn build_recursive(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
    aggregations: &mut Vec<SimpleMerkleNodeNCAAggregation>,
) -> Option<SimpleMerkleNodeKey> {
    // Base case: If there are no nodes in this partition, there's no root.
    if nodes.is_empty() {
        return None;
    }
    // Base case: If there is only one node, it is the de-facto root of this
    // sub-tree.
    if nodes.len() == 1 {
        return Some(nodes[0]);
    }

    // --- Divide Phase ---
    // Find the split point to partition the nodes into the left and right
    // children's domains. The first leaf index belonging to the right child of
    // our current sub-tree root serves as the partition boundary.
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;

    // Since `nodes` is sorted, we can v1ly find the partition point.
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    // --- Conquer Phase ---
    // Recurse on the left and right partitions.
    let left_nca = build_recursive(left_nodes, subtree_root.left_child(), tree_height, aggregations);
    let right_nca = build_recursive(right_nodes, right_child, tree_height, aggregations);

    // --- Combine Phase ---
    // Combine the results from the recursive calls.
    match (left_nca, right_nca) {
        // If both left and right sub-trees produced a root, we have an aggregation step.
        (Some(l), Some(r)) => {
            let combined_nca = l.find_nearest_common_ancestor(&r);
            aggregations.push(SimpleMerkleNodeNCAAggregation {
                nca: combined_nca,
                left: l,
                right: r,
            });
            Some(combined_nca)
        }
        // If only one sub-tree had nodes, its root is passed up.
        (Some(l), None) => Some(l),
        (None, Some(r)) => Some(r),
        // This case should not be reachable if nodes.len() > 1
        (None, None) => None,
    }
}

/// Generates the PARTH tree aggregation path for a set of leaf nodes using a
/// recursive, divide-and-conquer strategy that respects the Merkle tree's
/// binary structure.
///
/// This method avoids path conflicts by building up sub-proofs for distinct
/// sub-trees before combining them, correctly handling sparse distributions of
/// leaves.
///
/// # Arguments
///
/// * `leaves` - A slice of `SimpleMerkleNodeKey` representing the initial
///   nodes. It's assumed all leaves are at the same level (tree height).
///
/// # Returns
///
/// A `Vec<SimpleMerkleNodeNCAAggregation>` detailing the correct aggregation
/// path. The vector is ordered such that independent sub-tree aggregations
/// appear before the steps that combine them.
pub fn generate_nca_tree(leaves: &[SimpleMerkleNodeKey]) -> Vec<SimpleMerkleNodeNCAAggregation> {
    if leaves.len() < 2 {
        return vec![];
    }

    // Assume all leaves are at the same level and use the first to determine tree
    // height.
    let tree_height = leaves[0].level;

    // Sorting is crucial for the partitioning logic to work correctly.
    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    build_recursive(&sorted_leaves, root_node, tree_height, &mut aggregations);

    aggregations
}

pub fn generate_nca_tree_groups_naive(leaves: &[SimpleMerkleNodeKey], leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    let mut ncas = generate_nca_tree(leaves);
    let mut nca_map: std::collections::HashMap<SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation> = std::collections::HashMap::new();
    ncas.iter().for_each(|x| {
        nca_map.insert(x.nca.clone(), x.clone());
    });
    let mut levels = Vec::with_capacity(leaf_level as usize + 1);

    let root = ncas.last().unwrap();
    if root.left.level == leaf_level && root.right.level == leaf_level {
        return vec![vec![root.clone()]];
    }

    let mut has_non_leaf_children = true;
    let mut current_level = vec![ncas.pop().unwrap()];

    while has_non_leaf_children {
        levels.push(current_level.clone());
        let mut next_level = Vec::new();
        has_non_leaf_children = false;
        for agg in current_level.iter() {
            if agg.left.level != leaf_level {
                if let Some(left_agg) = nca_map.get(&agg.left) {
                    next_level.push(left_agg.clone());
                    has_non_leaf_children = true;
                }
            }
            if agg.right.level != leaf_level {
                if let Some(right_agg) = nca_map.get(&agg.right) {
                    next_level.push(right_agg.clone());
                    has_non_leaf_children = true;
                }
            }
        }
        current_level = next_level;
    }
    if current_level.len() > 0 {
        levels.push(current_level);
    }
    levels.reverse();
    levels
}
// for a given NCA node, its left and right children must be in the group
// directly below
pub fn check_nca_tree_groups(groups: &[Vec<SimpleMerkleNodeNCAAggregation>], leaf_level: u8) -> bool {
    //let mut nca_set = std::collections::HashSet::new();
    for i in 1..groups.len() {
        let group = &groups[i];
        for node in group.iter() {
            // Check if the NCA is unique in this group
            if group.iter().filter(|x| x.nca == node.nca).count() > 1 {
                println!("Duplicate NCA found in group {}: {:?}", i, node.nca);
                return false;
            }
            // Check if the left and right children are unique in this group
            if group.iter().filter(|x| x.left == node.left).count() > 1 {
                println!("Duplicate left child found in group {}: {:?}", i, node.left);
                return false;
            }
            if group.iter().filter(|x| x.right == node.right).count() > 1 {
                println!("Duplicate right child found in group {}: {:?}", i, node.right);
                return false;
            }
            if node.left.level != leaf_level && !groups[i - 1].iter().any(|x| x.nca == node.left) {
                println!("The dependencies of a group MUST be in the group directly below");
                return false;
            }
            if node.right.level != leaf_level && !groups[i - 1].iter().any(|x| x.nca == node.right) {
                println!("The dependencies of a group MUST be in the group directly below");
                return false;
            }
        }
    }
    true
}

/*
remember:

        let x0 = SimpleMerkleNodeKey::new(24, 10);

        let x1 = SimpleMerkleNodeKey::new(24, 26);

        let x2 = SimpleMerkleNodeKey::new(24, 76);

        let x3 = SimpleMerkleNodeKey::new(24, 140);


Good:
        let x01 = x0.find_nearest_common_ancestor(&x1);
        let x012 = x01.find_nearest_common_ancestor(&x2);
        let x0123 = x012.find_nearest_common_ancestor(&x3);

nca(SimpleMerkleNodeKey { level: 24, index: 10 }, SimpleMerkleNodeKey { level: 24, index: 26 }) = SimpleMerkleNodeKey { level: 19, index: 0 }
nca(SimpleMerkleNodeKey { level: 19, index: 0 }, SimpleMerkleNodeKey { level: 24, index: 76 }) = SimpleMerkleNodeKey { level: 17, index: 0 }
nca(SimpleMerkleNodeKey { level: 17, index: 0 }, SimpleMerkleNodeKey { level: 24, index: 140 }) = SimpleMerkleNodeKey { level: 16, index: 0 }



Bad:



        let x01 = x0.find_nearest_common_ancestor(&x1);
        let x23 = x2.find_nearest_common_ancestor(&x3);

        let x0123 = x01.find_nearest_common_ancestor(&x23);

        println!("nca({:?}, {:?}) = {:?}", x0, x1, x01);
        println!("nca({:?}, {:?}) = {:?}", x2, x3, x23);
        println!("nca({:?}, {:?}) = {:?}", x01, x23, x0123);

---- data::hash::merkle_node_key::tests::it_test_bad stdout ----
bad nca(SimpleMerkleNodeKey { level: 24, index: 10 }, SimpleMerkleNodeKey { level: 24, index: 26 }) = SimpleMerkleNodeKey { level: 19, index: 0 }
bad nca(SimpleMerkleNodeKey { level: 24, index: 76 }, SimpleMerkleNodeKey { level: 24, index: 140 }) = SimpleMerkleNodeKey { level: 16, index: 0 }
bad nca(SimpleMerkleNodeKey { level: 19, index: 0 }, SimpleMerkleNodeKey { level: 16, index: 0 }) = SimpleMerkleNodeKey { level: 16, index: 0 }

*/



/// A truly v1 recursive helper that avoids HashMap lookups in the hot path.
///
/// It returns a tuple `(SimpleMerkleNodeKey, usize)` representing the NCA key and its
/// calculated dependency level. This avoids the need for a shared map to store levels,
/// passing the state up the call stack instead.
fn build_recursive_v2(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
    // We still collect the aggregations with their levels as we go.
    aggregations_with_levels: &mut Vec<(SimpleMerkleNodeNCAAggregation, usize)>,
) -> Option<(SimpleMerkleNodeKey, usize)> { // Return type changed!
    if nodes.is_empty() {
        return None;
    }
    // Base case: A single node is a leaf in the NCA tree. Its level is 0.
    if nodes.len() == 1 {
        return Some((nodes[0], 0)); // Return key and level 0.
    }

    // --- Divide Phase ---
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    // --- Conquer Phase ---
    let left_result = build_recursive_v2(
        left_nodes,
        subtree_root.left_child(),
        tree_height,
        aggregations_with_levels,
    );
    let right_result = build_recursive_v2(
        right_nodes,
        right_child,
        tree_height,
        aggregations_with_levels,
    );

    // --- Combine Phase ---
    match (left_result, right_result) {
        (Some((l_key, l_level)), Some((r_key, r_level))) => {
            let combined_nca_key = l_key.find_nearest_common_ancestor(&r_key);
            
            // The new level is 1 greater than the maximum level of its children.
            let new_level = 1 + std::cmp::max(l_level, r_level);

            let agg = SimpleMerkleNodeNCAAggregation {
                nca: combined_nca_key,
                left: l_key,
                right: r_key,
            };
            aggregations_with_levels.push((agg, new_level));
            
            // Pass the new key and its calculated level up the call stack.
            Some((combined_nca_key, new_level))
        }
        // If only one side has a result, pass it up directly.
        (Some(l_res), None) => Some(l_res),
        (None, Some(r_res)) => Some(r_res),
        (None, None) => None,
    }
}


// --- New top-level function. Can replace the old `v1` one ---

pub fn generate_nca_tree_groups_v2(leaves: &[SimpleMerkleNodeKey], _leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    if leaves.len() < 2 {
        return vec![];
    }
    
    let tree_height = leaves[0].level;

    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations_with_levels = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    // This single call builds the tree and determines the level for each aggregation.
    build_recursive_v2(
        &sorted_leaves, 
        root_node, 
        tree_height, 
        &mut aggregations_with_levels,
    );

    if aggregations_with_levels.is_empty() {
        return vec![];
    }

    // This bucketing logic remains the same.
    let max_level = match aggregations_with_levels.iter().map(|(_, level)| *level).max() {
        Some(level) => level,
        None => return vec![],
    };
    
    let mut groups: Vec<Vec<SimpleMerkleNodeNCAAggregation>> = vec![Vec::new(); max_level];

    for (agg, level) in aggregations_with_levels {
        // Levels are 1-based, but vector indices are 0-based.
        if level > 0 {
            let group_idx = level - 1;
            groups[group_idx].push(agg);
        }
    }
    // Filter out potential empty groups if max_level calculation has gaps, though unlikely.
     groups.into_iter().filter(|g| !g.is_empty()).collect()


}

// how to keep v2's speed but make the output match the example correct output:

/*



For a tree of height 24 with leaves of index:
238671, 5244926, 13271444, 13990092, 14444179

The correct aggregation strategy is to:
1. Aggregate 13990092 and 14444179 first to form their NCA at level 4, index 13.
2. aggregate 238671 and 5244926 to form their NCA at level 1, index 0, aggregate 13271444 with the NCA from step 1 to form a new NCA at level 3, index 6.
3. Finally, aggregate the two NCAs from step 2 to form the root NCA at level 0, index 0.

Remember unless a child (left or right) is a leaf node, then it must appear in the group directly before the current group.

example correct output: [
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 4,
                index: 13,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 13990092,
            },
            right: SimpleMerkleNodeKey {
                level: 24,
                index: 14444179,
            },
        },
    ],
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 1,
                index: 0,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 238671,
            },
            right: SimpleMerkleNodeKey {
                level: 24,
                index: 5244926,
            },
        },
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 3,
                index: 6,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 13271444,
            },
            right: SimpleMerkleNodeKey {
                level: 4,
                index: 13,
            },
        },
    ],
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 0,
                index: 0,
            },
            left: SimpleMerkleNodeKey {
                level: 1,
                index: 0,
            },
            right: SimpleMerkleNodeKey {
                level: 3,
                index: 6,
            },
        },
    ],
]
example wrong output: [
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 1,
                index: 0,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 238671,
            },
            right: SimpleMerkleNodeKey {
                level: 24,
                index: 5244926,
            },
        },
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 4,
                index: 13,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 13990092,
            },
            right: SimpleMerkleNodeKey {
                level: 24,
                index: 14444179,
            },
        },
    ],
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 3,
                index: 6,
            },
            left: SimpleMerkleNodeKey {
                level: 24,
                index: 13271444,
            },
            right: SimpleMerkleNodeKey {
                level: 4,
                index: 13,
            },
        },
    ],
    [
        SimpleMerkleNodeNCAAggregation {
            nca: SimpleMerkleNodeKey {
                level: 0,
                index: 0,
            },
            left: SimpleMerkleNodeKey {
                level: 1,
                index: 0,
            },
            right: SimpleMerkleNodeKey {
                level: 3,
                index: 6,
            },
        },
    ],
]

*/

#[cfg(test)]
mod tests_old {

    struct NCAGroupCheckerHelper {
        pub node_to_group_id_map: std::collections::HashMap<SimpleMerkleNodeKey, usize>,
        pub tree_height: u8,
    }

    impl NCAGroupCheckerHelper {
        pub fn new(tree_height: u8) -> Self {
            Self {
                node_to_group_id_map: std::collections::HashMap::new(),
                tree_height,
            }
        }
        pub fn insert(&mut self, key: SimpleMerkleNodeKey, group_id: usize) {
            self.node_to_group_id_map.insert(key, group_id);
        }
        pub fn validate_nca_children(&self, nca: &SimpleMerkleNodeNCAAggregation) -> bool {
            let left_group_id = self.get_group_id(&nca.left);
            let right_group_id = self.get_group_id(&nca.right);
            let nca_group_id = self.get_group_id(&nca.nca);
            if left_group_id.is_none() && right_group_id.is_none() {
                return true;
            } else if left_group_id.is_none() {
                return right_group_id.unwrap() + 1 == nca_group_id.unwrap();
            } else if right_group_id.is_none() {
                return left_group_id.unwrap() + 1 == nca_group_id.unwrap();
            } else {
                return left_group_id.unwrap() + 1 == nca_group_id.unwrap() && right_group_id.unwrap() + 1 == nca_group_id.unwrap();
            }
        }
        pub fn get_group_id(&self, key: &SimpleMerkleNodeKey) -> Option<usize> {
            if key.level == self.tree_height {
                None
            } else {
                self.node_to_group_id_map.get(key).cloned()
            }
        }
        pub fn check_groups(groups: Vec<Vec<SimpleMerkleNodeNCAAggregation>>, tree_height: u8) -> bool {
            let mut helper = NCAGroupCheckerHelper::new(tree_height);
            for (group_id, group) in groups.iter().enumerate() {
                for nca in group.iter() {
                    helper.insert(nca.nca.clone(), group_id);
                }
            }
            for group in groups.iter() {
                for nca in group.iter() {
                    if !helper.validate_nca_children(nca) {
                        println!("NCA {:?} has invalid children", nca.nca);
                        return false;
                    }
                }
            }
            true
        }
    }

    use std::collections::HashSet;

    use crate::data::hash::merkle_node_key::{
        check_nca_tree_groups, generate_nca_tree, generate_nca_tree_groups_v1, generate_nca_tree_groups_naive, generate_nca_tree_groups_v2, SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation
    };

    fn is_unique_node_set(node_set: &[SimpleMerkleNodeKey]) -> bool {
        let unique_len = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.to_vec().into_iter()).len();

        node_set.len() == unique_len
    }

    fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
        let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
        hset.into_iter().collect::<Vec<_>>()
    }

    fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey> {
        let max_node_id = 1u64 << (height as u64);

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(SimpleMerkleNodeKey {
                level: height,
                index: rand::random::<u64>() % max_node_id,
            });
        }

        get_unique_node_set(result)
    }

    fn random_nodes_test_gen(count: usize, height: u8) {
        let leaves = random_nodes_in_tree(height, count);
        let ncas = generate_nca_tree(&leaves);
        let ncp = ncas.iter().map(|x| x.nca).collect::<Vec<_>>();

        assert!(is_unique_node_set(&ncp), "is not unique node set");
    }

    #[test]
    fn t_random_nodes() {
        random_nodes_test_gen(3, 3);
        random_nodes_test_gen(4, 3);
        random_nodes_test_gen(5, 3);
        random_nodes_test_gen(6, 3);
        random_nodes_test_gen(7, 3);

        random_nodes_test_gen(3, 24);
        random_nodes_test_gen(4, 24);
        random_nodes_test_gen(5, 24);
        random_nodes_test_gen(6, 24);
        random_nodes_test_gen(7, 24);

        random_nodes_test_gen(1000, 24);
        random_nodes_test_gen(1001, 24);
        random_nodes_test_gen(1002, 24);
        random_nodes_test_gen(1003, 24);
        random_nodes_test_gen(1004, 24);

        random_nodes_test_gen(5000, 24);
        random_nodes_test_gen(5001, 24);
        random_nodes_test_gen(5002, 24);
        random_nodes_test_gen(5003, 24);
        random_nodes_test_gen(5004, 24);
    }
    #[test]
    fn check_tree_groups() {
        let height: u8 = 24;
        let leaves = random_nodes_in_tree(height, 1337);
        let groups = generate_nca_tree_groups_naive(&leaves, height);

        let groups_alt = generate_nca_tree_groups_v1(&leaves, height);

        assert!(check_nca_tree_groups(&groups, height), "NCA tree groups are not valid");
        assert_eq!(groups.len(), groups_alt.len(), "group lengths differ");
        //        assert_eq!(groups.len(), groups_alt_2.len(), "group lengths differ");
        for i in 0..groups.len() {
            assert_eq!(groups[i], groups_alt[i], "group {} differs between naive and v1", i);
        }

        println!("NCA tree groups are valid");
    }
    #[test]
    fn check_tree_groups_v2() {
        let height: u8 = 24;
        let leaves = random_nodes_in_tree(height, 5);
        let groups = generate_nca_tree_groups_naive(&leaves, height);

        let groups_alt = generate_nca_tree_groups_v1(&leaves, height);
        let groups_v2 = generate_nca_tree_groups_v2(&leaves, height);

        println!("naive groups: {:#?}", groups);
        println!("v1 groups: {:#?}", groups_alt);
        assert!(check_nca_tree_groups(&groups, height), "NCA tree groups are not valid");
        assert!(check_nca_tree_groups(&groups_v2, height), "NCA tree groups are not valid");
        assert!(check_nca_tree_groups(&groups_alt, height), "NCA tree groups are not valid");
        assert_eq!(groups.len(), groups_alt.len(), "group lengths differ");
        //assert_eq!(groups.len(), groups_alt_2.len(), "group lengths differ");
        for i in 0..groups.len() {
            assert_eq!(groups[i], groups_alt[i], "group {} differs between naive and v1", i);
            //    assert_eq!(groups[i], groups_alt_2[i], "group {} differs
            // between naive and v1 2", i);
        }

        println!("NCA tree groups are valid");
    }
    #[test]
    fn check_tree_groups_2() {
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let e_group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        println!("v1 groups: {:#?}", e_group_levels);
        let n_group_levels = generate_nca_tree_groups_naive(&leaves, guta_height);
        println!("naive groups: {:#?}", n_group_levels);

        assert!(
            NCAGroupCheckerHelper::check_groups(n_group_levels.clone(), guta_height),
            "naive groups are not valid"
        );
        assert!(
            NCAGroupCheckerHelper::check_groups(e_group_levels.clone(), guta_height),
            "v1 groups are not valid"
        );
        assert_eq!(n_group_levels, e_group_levels, "group levels differ");
    }
    #[test]
    fn check_tree_groups_3() {
        let guta_height = 32u8;
        let leaves = random_nodes_in_tree(guta_height, 133713);
        let e_group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        let n_group_levels = generate_nca_tree_groups_naive(&leaves, guta_height);

        assert!(
            NCAGroupCheckerHelper::check_groups(n_group_levels.clone(), guta_height),
            "naive groups are not valid"
        );
        assert!(
            NCAGroupCheckerHelper::check_groups(e_group_levels.clone(), guta_height),
            "v1 groups are not valid"
        );
        assert_eq!(n_group_levels, e_group_levels, "group levels differ");
    }
    #[test]
    fn run_many_random_nodes() {
        let nodes = random_nodes_in_tree(32, 1000 * 1000);
        let start_time = std::time::Instant::now();
        let ncas = generate_nca_tree(&nodes);
        let duration = start_time.elapsed();
        println!("Generated {} NCAs for {} leaves in {:?}", ncas.len(), nodes.len(), duration);
    }
    #[test]
    fn test_with_prompt_example() {
        // This is the example from the prompt where linear aggregation works by
        // coincidence. Our algorithm must also produce the correct result here.
        let x0 = SimpleMerkleNodeKey::new(24, 10);
        let x1 = SimpleMerkleNodeKey::new(24, 26);
        let x2 = SimpleMerkleNodeKey::new(24, 76);
        let x3 = SimpleMerkleNodeKey::new(24, 140);

        let leaves = vec![x0, x1, x2, x3];
        let path = generate_nca_tree(&leaves);

        // Expected aggregations
        let nca_01 = x0.find_nearest_common_ancestor(&x1);
        let nca_012 = nca_01.find_nearest_common_ancestor(&x2);
        let nca_0123 = nca_012.find_nearest_common_ancestor(&x3);

        assert_eq!(path.len(), 3);
        // The recursive algorithm might produce a different but valid order.
        // Let's check that the final aggregation is correct.
        let final_agg = path.last().unwrap();
        assert_eq!(final_agg.nca, nca_0123);

        // Let's check the individual steps more carefully. The dependencies must be
        // met. In this case, because the leaves are spread out, the tree is
        // very unbalanced.
        // 1. nca(x0, x1) -> nca_01
        // 2. nca(nca_01, x2) -> nca_012
        // 3. nca(nca_012, x3) -> nca_0123
        assert_eq!(
            path[0],
            SimpleMerkleNodeNCAAggregation {
                nca: nca_01,
                left: x0,
                right: x1
            }
        );
        assert_eq!(
            path[1],
            SimpleMerkleNodeNCAAggregation {
                nca: nca_012,
                left: nca_01,
                right: x2
            }
        );
        assert_eq!(
            path[2],
            SimpleMerkleNodeNCAAggregation {
                nca: nca_0123,
                left: nca_012,
                right: x3
            }
        );
    }

    #[test]
    fn test_with_sparse_subtree_example() {
        // Your example: leaves at indices 0, 1, 3, 5, 6 in a tree of height 3
        let h = 3;
        let x0 = SimpleMerkleNodeKey::new(h, 0);
        let x1 = SimpleMerkleNodeKey::new(h, 1);
        let x3 = SimpleMerkleNodeKey::new(h, 3);
        let x5 = SimpleMerkleNodeKey::new(h, 5);
        let x6 = SimpleMerkleNodeKey::new(h, 6);

        let leaves = vec![x0, x1, x3, x5, x6];
        let path = generate_nca_tree(&leaves);

        assert_eq!(path.len(), 4); // 5 leaves require 4 aggregations.

        // Expected individual calculations
        let nca_01 = x0.find_nearest_common_ancestor(&x1); // {2, 0}
        let nca_56 = x5.find_nearest_common_ancestor(&x6); // {1, 1}
        println!("nca_01: {:?}, nca_56: {:?}", nca_01, nca_56);

        // Root of the left sub-tree (indices 0-3)
        let nca_left_half = nca_01.find_nearest_common_ancestor(&x3); // {1, 0}
                                                                      // Root of the right sub-tree (indices 4-7) is just nca_56 in this case.
        println!("nca_left_half: {:?}", nca_left_half);
        let nca_right_half = nca_56;

        // Final combination
        let final_nca = nca_left_half.find_nearest_common_ancestor(&nca_right_half); // {0, 0}
        println!("final_nca: {:?}", final_nca);
        // The path should contain these aggregations. The order is determined by
        // post-order traversal.
        // 1. nca(x0, x1) -> {2, 0}
        // 2. nca(x5, x6) -> {1, 1}
        // 3. nca({2, 0}, x3) -> {1, 0}
        // 4. nca({1, 0}, {1, 2}) -> {0, 0}

        let expected_path = vec![
            SimpleMerkleNodeNCAAggregation {
                nca: nca_01,
                left: x0,
                right: x1,
            },
            SimpleMerkleNodeNCAAggregation {
                nca: nca_left_half,
                left: nca_01,
                right: x3,
            },
            SimpleMerkleNodeNCAAggregation {
                nca: nca_56,
                left: x5,
                right: x6,
            },
            SimpleMerkleNodeNCAAggregation {
                nca: final_nca,
                left: nca_left_half,
                right: nca_right_half,
            },
        ];

        assert_eq!(path, expected_path);
    }
    #[test]
    fn it_test_bad() {
        let x0 = SimpleMerkleNodeKey::new(24, 10);

        let x1 = SimpleMerkleNodeKey::new(24, 26);

        let x2 = SimpleMerkleNodeKey::new(24, 76);

        let x3 = SimpleMerkleNodeKey::new(24, 140);

        let x01 = x0.find_nearest_common_ancestor(&x1);
        let x23 = x2.find_nearest_common_ancestor(&x3);

        let x0123 = x01.find_nearest_common_ancestor(&x23);

        println!("bad nca({:?}, {:?}) = {:?}", x0, x1, x01);
        println!("bad nca({:?}, {:?}) = {:?}", x2, x3, x23);
        println!("bad nca({:?}, {:?}) = {:?}", x01, x23, x0123);
    }
    #[test]
    fn it_test_good() {
        let x0 = SimpleMerkleNodeKey::new(24, 10);

        let x1 = SimpleMerkleNodeKey::new(24, 26);

        let x2 = SimpleMerkleNodeKey::new(24, 76);

        let x3 = SimpleMerkleNodeKey::new(24, 140);

        let x01 = x0.find_nearest_common_ancestor(&x1);
        let x012 = x01.find_nearest_common_ancestor(&x2);
        let x0123 = x012.find_nearest_common_ancestor(&x3);

        println!("good nca({:?}, {:?}) = {:?}", x0, x1, x01);
        println!("good nca({:?}, {:?}) = {:?}", x01, x2, x012);
        println!("good nca({:?}, {:?}) = {:?}", x012, x3, x0123);
    }
}
