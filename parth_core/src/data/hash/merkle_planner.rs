use std::collections::HashMap;

use async_trait::async_trait;
use auto_impl::auto_impl;

use crate::data::hash::merkle_node_key::{generate_nca_tree_groups_v1, SimpleMerkleNodeKey};

pub trait NCAMerklePlannerVisitor<T> {
    fn visit(
        &mut self,
        left_child: &T,
        left_child_merkle_tree_key: SimpleMerkleNodeKey,
        right_child: &T,
        right_child_merkle_tree_key: SimpleMerkleNodeKey,
        nca_merkle_tree_key: SimpleMerkleNodeKey,
        nca_reward_tree_key: SimpleMerkleNodeKey,
    ) -> T;
    fn init_with_reward_tree_height(&mut self, _reward_tree_height: u8) {}
}

#[async_trait]
pub trait NCAMerklePlannerVisitorWithTreeStores<T, TreeReader, RWTreeStore> {
    fn visit(
        &mut self,
        read_tree: &TreeReader,
        rw_tree: &mut RWTreeStore,
        left_child: &T,
        left_child_merkle_tree_key: SimpleMerkleNodeKey,
        right_child: &T,
        right_child_merkle_tree_key: SimpleMerkleNodeKey,
        nca_merkle_tree_key: SimpleMerkleNodeKey,
        nca_reward_tree_key: SimpleMerkleNodeKey,
        is_reward_root: bool,
    ) -> anyhow::Result<T>;
    fn init_with_reward_tree_height(&mut self, _total_jobs: usize, _jobs_per_level: Vec<usize>, _reward_tree_height: u8) {}
}

#[async_trait]
pub trait NCAMerklePlannerVisitorWithTreeReaderAndTempStore<T, TreeReader, TempStore> {
    async fn visit(
        &mut self,
        tree_reader: &TreeReader,
        temp_store: &TempStore,
        left_child: &T,
        left_child_merkle_tree_key: SimpleMerkleNodeKey,
        right_child: &T,
        right_child_merkle_tree_key: SimpleMerkleNodeKey,
        nca_merkle_tree_key: SimpleMerkleNodeKey,
        nca_reward_tree_key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<T>;
    fn init_with_reward_tree_height(&mut self, _reward_tree_height: u8) {}
}
pub fn run_merkle_planner_visitor<T: Clone, V: NCAMerklePlannerVisitor<T>>(
    leaves: Vec<(SimpleMerkleNodeKey, T)>,
    merkle_tree_height: u8,
    visitor: &mut V,
) -> T {
    let mut result_map = HashMap::<SimpleMerkleNodeKey, T>::new();
    let mut leaf_keys = Vec::with_capacity(leaves.len());
    for (leaf_key, leaf) in leaves {
        leaf_keys.push(leaf_key);
        result_map.insert(leaf_key, leaf);
    }
    let group_levels = generate_nca_tree_groups_v1(&leaf_keys, merkle_tree_height);
    let reward_tree_height = group_levels.len() - 1;
    //let mut merkle_key_to_reward_key_map = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
    for (level, gl) in group_levels.iter().enumerate() {
        for (index, g) in gl.iter().enumerate() {
            let nca_reward_tree_key = SimpleMerkleNodeKey::new((reward_tree_height - level) as u8, index as u64);
            let left_child = result_map.get(&g.left).unwrap();
            let right_child = result_map.get(&g.right).unwrap();

            //merkle_key_to_reward_key_map.insert(g.nca, reward_key);
            let parent_result = visitor.visit(
                left_child,
                g.left,
                right_child,
                g.right,
                g.nca,
                nca_reward_tree_key,
            );
            result_map.insert(g.nca, parent_result);
        }
    }
    let root_key = group_levels.last().unwrap()[0].nca;
    result_map.remove(&root_key).unwrap()
}

pub fn run_merkle_planner_visitor_with_offset_root<T: Clone, V: NCAMerklePlannerVisitor<T>>(
    leaves: Vec<(SimpleMerkleNodeKey, T)>,
    merkle_tree_height: u8,
    reward_tree_root_level: u8,
    reward_tree_root_index: u64,
    visitor: &mut V,
) -> T {
    let mut result_map = HashMap::<SimpleMerkleNodeKey, T>::new();
    let mut leaf_keys = Vec::with_capacity(leaves.len());
    for (leaf_key, leaf) in leaves {
        leaf_keys.push(leaf_key);
        result_map.insert(leaf_key, leaf);
    }
    let group_levels = generate_nca_tree_groups_v1(&leaf_keys, merkle_tree_height);
    let reward_tree_height = group_levels.len() - 1;
    visitor.init_with_reward_tree_height(reward_tree_height as u8);
    //let mut merkle_key_to_reward_key_map = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
    for (level, gl) in group_levels.iter().enumerate() {
        for (index, g) in gl.iter().enumerate() {
            let base_reward_tree_level =  (reward_tree_height - level) as u8;
            let reward_tree_node_index= (reward_tree_root_index << base_reward_tree_level) | (index as u64);
            let reward_tree_node_level = base_reward_tree_level + reward_tree_root_level;

            let nca_reward_tree_key = SimpleMerkleNodeKey::new(reward_tree_node_level, reward_tree_node_index);
            let left_child = result_map.get(&g.left).unwrap();
            let right_child = result_map.get(&g.right).unwrap();

            //merkle_key_to_reward_key_map.insert(g.nca, reward_key);
            let parent_result = visitor.visit(
                left_child,
                g.left,
                right_child,
                g.right,
                g.nca,
                nca_reward_tree_key,
            );
            result_map.insert(g.nca, parent_result);
        }
    }
    let root_key = group_levels.last().unwrap()[0].nca;
    result_map.remove(&root_key).unwrap()
}

pub fn run_merkle_planner_visitor_with_offset_root_and_trees<T: Clone, V: NCAMerklePlannerVisitorWithTreeStores<T, TreeReader, RWTreeStore>, TreeReader, RWTreeStore>(
    read_tree: &TreeReader,
    rw_tree: &mut RWTreeStore,
    leaves: Vec<(SimpleMerkleNodeKey, T)>,
    merkle_tree_height: u8,
    reward_tree_root_level: u8,
    reward_tree_root_index: u64,
    visitor: &mut V,
) -> anyhow::Result<T> {
    if leaves.len() < 2 {
        anyhow::bail!("At least two leaves must be provided to merkle planner");
    }
    let mut result_map = HashMap::<SimpleMerkleNodeKey, T>::new();
    let mut leaf_keys = Vec::with_capacity(leaves.len());
    for (leaf_key, leaf) in leaves {
        leaf_keys.push(leaf_key);
        result_map.insert(leaf_key, leaf);
    }
    let group_levels = generate_nca_tree_groups_v1(&leaf_keys, merkle_tree_height);
    let reward_tree_height = group_levels.len() - 1;

    let group_level_lengths = group_levels.iter().map(|gl| gl.len()).collect::<Vec<usize>>();
    let total_jobs = group_level_lengths.iter().sum::<usize>();
    visitor.init_with_reward_tree_height(total_jobs, group_level_lengths, reward_tree_height as u8);
    //let mut merkle_key_to_reward_key_map = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
    for (level, gl) in group_levels.iter().enumerate() {
        for (index, g) in gl.iter().enumerate() {
            let base_reward_tree_level =  (reward_tree_height - level) as u8;
            let is_reward_root = level == 0;
            let reward_tree_node_index= (reward_tree_root_index << base_reward_tree_level) | (index as u64);
            let reward_tree_node_level = base_reward_tree_level + reward_tree_root_level;

            let nca_reward_tree_key = SimpleMerkleNodeKey::new(reward_tree_node_level, reward_tree_node_index);
            let left_child = result_map.get(&g.left).unwrap();
            let right_child = result_map.get(&g.right).unwrap();

            //merkle_key_to_reward_key_map.insert(g.nca, reward_key);
            let parent_result = visitor.visit(
                read_tree,
                rw_tree,
                left_child,
                g.left,
                right_child,
                g.right,
                g.nca,
                nca_reward_tree_key,
                is_reward_root,
            )?;
            result_map.insert(g.nca, parent_result);
        }
    }
    let root_key = group_levels.last().unwrap()[0].nca;
    Ok(result_map.remove(&root_key).unwrap())
}


#[cfg(test)]
mod tests {
    use super::*;

    struct SumVisitor;

    impl NCAMerklePlannerVisitor<u64> for SumVisitor {
        fn visit(
            &mut self,
            left_child: &u64,
            _left_child_merkle_tree_key: SimpleMerkleNodeKey,
            right_child: &u64,
            _right_child_merkle_tree_key: SimpleMerkleNodeKey,
            _nca_merkle_tree_key: SimpleMerkleNodeKey,
            _nca_reward_tree_key: SimpleMerkleNodeKey,
        ) -> u64 {
            left_child + right_child
        }
    }

    #[test]
    fn test_run_merkle_planner_visitor() {
        let leaves = vec![
            (SimpleMerkleNodeKey::new(2, 0), 1u64),
            (SimpleMerkleNodeKey::new(2, 1), 2u64),
            (SimpleMerkleNodeKey::new(2, 2), 3u64),
            (SimpleMerkleNodeKey::new(2, 3), 4u64),
        ];
        let merkle_tree_height = 3;
        let mut visitor = SumVisitor;
        let result = run_merkle_planner_visitor(leaves, merkle_tree_height, &mut visitor);
        assert_eq!(result, 10u64); // 1 + 2 + 3 + 4 = 10
    }
}