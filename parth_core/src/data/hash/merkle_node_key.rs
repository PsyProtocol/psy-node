use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Ord)]
pub struct SimpleMerkleNodeKey {
    pub level: u8,
    pub index: u64,
}
impl PartialOrd for SimpleMerkleNodeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.level != other.level {
            self.level.partial_cmp(&other.level)
        }else{
            self.index.partial_cmp(&other.index)
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

    // if self or other are on the same merkle path
    pub fn is_direct_path_related(&self, other: &SimpleMerkleNodeKey) -> bool {
        if other.level == self.level {
            self.index == other.index
        }else if other.level < self.level {
            // opt?: (self.index>>(self.level-other.level)) == other.index
            self.parent_at_level(other.level).index == other.index

        }else{
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
        }else{
            let mut my_node = self.clone();
            let mut siblings = Vec::with_capacity((self.level-to_level) as usize);
            while my_node.level != to_level {
                siblings.push(my_node.sibling());
                my_node = my_node.parent();
            }

            siblings
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
            anyhow::bail!(
                "error deserializing SimpleMerkleNodeKey, expected 9 bytes, got {}",
                bytes.len()
            );
        }
    }
}
impl QPDSerializableFixed for SimpleMerkleNodeKey {
    fn get_fixed_size() -> usize {
        9
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Ord)]
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
        }else if self.key.index != other.key.index {
            self.key.index.partial_cmp(&other.key.index)
        }else {
            self.value.partial_cmp(&other.value)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleMerkleNodeNCAAggregation {
    pub nca: SimpleMerkleNodeKey,
    pub left: SimpleMerkleNodeKey,
    pub right: SimpleMerkleNodeKey,
}


// --- Function Implementation ---

/// Recursively builds the aggregation path for a given set of nodes within a specific sub-tree.
///
/// This is the helper function that implements the core divide-and-conquer logic.
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
    // Base case: If there is only one node, it is the de-facto root of this sub-tree.
    if nodes.len() == 1 {
        return Some(nodes[0]);
    }

    // --- Divide Phase ---
    // Find the split point to partition the nodes into the left and right children's domains.
    // The first leaf index belonging to the right child of our current sub-tree root serves
    // as the partition boundary.
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;

    // Since `nodes` is sorted, we can efficiently find the partition point.
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
/// recursive, divide-and-conquer strategy that respects the Merkle tree's binary structure.
///
/// This method avoids path conflicts by building up sub-proofs for distinct sub-trees
/// before combining them, correctly handling sparse distributions of leaves.
///
/// # Arguments
///
/// * `leaves` - A slice of `SimpleMerkleNodeKey` representing the initial nodes. It's assumed
///   all leaves are at the same level (tree height).
///
/// # Returns
///
/// A `Vec<SimpleMerkleNodeNCAAggregation>` detailing the correct aggregation path. The
/// vector is ordered such that independent sub-tree aggregations appear before the
/// steps that combine them.
pub fn generate_nca_tree(leaves: &[SimpleMerkleNodeKey]) -> Vec<SimpleMerkleNodeNCAAggregation> {
    if leaves.len() < 2 {
        return vec![];
    }
    
    // Assume all leaves are at the same level and use the first to determine tree height.
    let tree_height = leaves[0].level;

    // Sorting is crucial for the partitioning logic to work correctly.
    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    build_recursive(&sorted_leaves, root_node, tree_height, &mut aggregations);

    aggregations
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
#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use crate::data::hash::merkle_node_key::{generate_nca_tree, SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation};


    fn is_unique_node_set(node_set: &[SimpleMerkleNodeKey]) -> bool {
        let unique_len = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.to_vec().into_iter()).len();

        node_set.len() == unique_len
    }

    fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
        let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
        hset.into_iter().collect::<Vec<_>>()
    }

    fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey>{

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

    fn random_nodes_test_gen(count: usize, height: u8){

        let leaves = random_nodes_in_tree(height, count);
        let ncas = generate_nca_tree(&leaves);
        let ncp= ncas.iter().map(|x|x.nca).collect::<Vec<_>>();

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
    fn test_with_prompt_example() {
        // This is the example from the prompt where linear aggregation works by coincidence.
        // Our algorithm must also produce the correct result here.
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
        
        // Let's check the individual steps more carefully. The dependencies must be met.
        // In this case, because the leaves are spread out, the tree is very unbalanced.
        // 1. nca(x0, x1) -> nca_01
        // 2. nca(nca_01, x2) -> nca_012
        // 3. nca(nca_012, x3) -> nca_0123
        assert_eq!(path[0], SimpleMerkleNodeNCAAggregation { nca: nca_01, left: x0, right: x1 });
        assert_eq!(path[1], SimpleMerkleNodeNCAAggregation { nca: nca_012, left: nca_01, right: x2 });
        assert_eq!(path[2], SimpleMerkleNodeNCAAggregation { nca: nca_0123, left: nca_012, right: x3 });
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
        let nca_56 = x5.find_nearest_common_ancestor(&x6); // {2, 2}
        
        // Root of the left sub-tree (indices 0-3)
        let nca_left_half = nca_01.find_nearest_common_ancestor(&x3); // {1, 0}
        // Root of the right sub-tree (indices 4-7) is just nca_56 in this case.
        let nca_right_half = nca_56;

        // Final combination
        let final_nca = nca_left_half.find_nearest_common_ancestor(&nca_right_half); // {0, 0}

        // The path should contain these aggregations. The order is determined by post-order traversal.
        // 1. nca(x0, x1) -> {2, 0}
        // 2. nca(x5, x6) -> {2, 2}
        // 3. nca({2, 0}, x3) -> {1, 0}
        // 4. nca({1, 0}, {2, 2}) -> {0, 0}
        
        let expected_path = vec![
            SimpleMerkleNodeNCAAggregation { nca: nca_01, left: x0, right: x1 },
            SimpleMerkleNodeNCAAggregation { nca: nca_56, left: x5, right: x6 },
            SimpleMerkleNodeNCAAggregation { nca: nca_left_half, left: nca_01, right: x3 },
            SimpleMerkleNodeNCAAggregation { nca: final_nca, left: nca_left_half, right: nca_right_half },
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