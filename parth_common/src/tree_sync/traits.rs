use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
};

use futures::{stream, StreamExt}; 
use crate::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;

pub trait FastTreeSyncBasicMetadata {
    fn fts_get_tree_height(&self) -> u8;
}

#[async_trait]
pub trait FastTreeSyncAsyncSource<Hash> {
    async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

pub trait FastTreeSyncLocalSource<Hash>: FastTreeSyncBasicMetadata {
    fn fts_get_merkle_node(&self, key: SimpleMerkleNodeKey) -> Hash;
    fn fts_get_merkle_nodes(&self, keys: &[SimpleMerkleNodeKey]) -> Vec<Hash>;
}

pub trait FastTreeSyncLocalDestination<Hash>: FastTreeSyncBasicMetadata + FastTreeSyncLocalSource<Hash> {
    fn fts_set_merkle_node(&mut self, node: SimpleMerkleNode<Hash>);
    fn fts_set_merkle_nodes(&mut self, entries: &[SimpleMerkleNode<Hash>]);
    // recomputes the hash of the merkle path from node_key to its parent on level =
    // sub_root_level, remember that the root is level 0, and leaves are on level
    // tree_height
    fn fts_rehash_from_node_to_level(&mut self, node_key: SimpleMerkleNodeKey, sub_root_level: u8) -> Hash;
    // rehashes all nodes in the range [start_index_inclusive, end_index_inclusive]
    // on level `level` and all their parents up to the root, for example to rehash
    // the left of the tree, call with level = tree_height, start_index_inclusive =
    // 0, end_index_inclusive = total_leaves/2 - 1
    fn fts_rehash_range_to_root(&mut self, level: u8, start_index_inclusive: u64, end_index_inclusive: u64) -> Hash;
    // rehashes the entire sub tree of tree leaves where (sub_root_cap.index <<
    // tree_height-sub_root_cap.level) <= leaf index < ((sub_root_cap.index + 1) <<
    // (tree_height-sub_root_cap.level)), up to the sub_root_cap provided.
    fn fts_rehash_sub_tree(&mut self, sub_root_cap: SimpleMerkleNodeKey) -> Hash;
    fn fts_hash_two_to_one(left: &Hash, right: &Hash) -> Hash;
}

#[derive(Clone)]
pub struct LocalTreeSourceAsyncAdapter<Hash, LocalTree: FastTreeSyncLocalSource<Hash>> {
    pub local_tree: LocalTree,
    pub _marker: std::marker::PhantomData<Hash>,
}
impl<Hash: Copy, LocalTree: FastTreeSyncLocalSource<Hash>> LocalTreeSourceAsyncAdapter<Hash, LocalTree> {
    pub fn new(local_tree: LocalTree) -> Self {
        Self {
            local_tree,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Hash: Copy + Send + Sync + 'static, LocalTree: FastTreeSyncLocalSource<Hash> + Send + Sync + 'static> FastTreeSyncAsyncSource<Hash>
    for LocalTreeSourceAsyncAdapter<Hash, LocalTree>
{
    async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        Ok(self.local_tree.fts_get_merkle_node(key))
    }
    async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        Ok(self.local_tree.fts_get_merkle_nodes(keys))
    }
}

fn combine_keys_and_hashes<Hash: Copy>(keys: &[SimpleMerkleNodeKey], hashes: &[Hash]) -> Vec<SimpleMerkleNode<Hash>> {
    keys.iter()
        .zip(hashes.iter())
        .map(|(key, value)| SimpleMerkleNode { key: *key, value: *value })
        .collect()
}

/*
const REMOTE_SCAN_WIDTH: usize = 32;

fn chunked<'a, T>(items: &'a [T], chunk_size: usize) -> impl Iterator<Item = &'a [T]> {
    (0..items.len()).step_by(chunk_size).map(move |start| {
        let end = (start + chunk_size).min(items.len());
        &items[start..end]
    })
}
const BATCH_LEVEL_DEPTH: u8 = 5;
async fn fetch_remote_nodes_batched<Hash: Copy, Source: FastTreeSyncAsyncSource<Hash>>(
    remote_tree: &Source,
    keys: &[SimpleMerkleNodeKey],
) -> anyhow::Result<Vec<Hash>> {
    let mut result = Vec::with_capacity(keys.len());
    for chunk in chunked(keys, REMOTE_SCAN_WIDTH) {
        let chunk_hashes = remote_tree.fts_get_merkle_nodes_async(chunk).await?;
        result.extend(chunk_hashes);
    }
    Ok(result)
}
pub async fn sync_local_sub_tree_from_remote<
    Hash: Copy + PartialEq,
    Destination: FastTreeSyncLocalDestination<Hash>,
    Source: FastTreeSyncAsyncSource<Hash>,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
    sub_root_cap: SimpleMerkleNodeKey,
    sub_root_target_hash: Hash,
) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>> {
    let tree_height = local_tree.fts_get_tree_height();
    let sub_tree_height = tree_height - sub_root_cap.level;
    let root_key = sub_root_cap;
    let total_leaves = 1u64 << sub_tree_height;
    let total_leaves_usize = total_leaves as usize;

    if sub_root_cap.level == tree_height {
        local_tree.fts_set_merkle_node(SimpleMerkleNode {
            key: root_key,
            value: sub_root_target_hash,
        });
        return Ok(Vec::new());
    } else if sub_tree_height < BATCH_LEVEL_DEPTH + 2 {
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, sub_root_cap.index << (sub_tree_height), total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        local_tree.fts_set_merkle_nodes(&nodes);
        local_tree.fts_rehash_sub_tree(root_key);
        return Ok(Vec::new());
    }

    let mut range = SimpleMerkleNodeKey::get_range_at_level(tree_height, sub_root_cap.index << (BATCH_LEVEL_DEPTH + 1), 1<<BATCH_LEVEL_DEPTH);

    let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
    let mut diff_nodes = range
        .iter()
        .zip(remote_nodes.iter())
        .filter_map(|(key, remote_hash)| {
            let local_hash = local_tree.fts_get_merkle_node(*key);
            if local_hash != *remote_hash {
                local_tree.fts_set_merkle_node(SimpleMerkleNode {
                    key: *key,
                    value: *remote_hash,
                });
                Some(SimpleMerkleNode {
                    key: *key,
                    value: *remote_hash,
                })
            } else {
                None
            }
        })
        .collect::<Vec<SimpleMerkleNode<Hash>>>();
    let nodes = combine_keys_and_hashes(&range, &remote_nodes);
    local_tree.fts_set_merkle_nodes(&nodes);
    local_tree.fts_rehash_sub_tree(root_key.left_child());
    let combined = local_tree.fts_rehash_from_node_to_level(sub_root_cap.left_child(), sub_root_cap.level);
    if combined == sub_root_target_hash {
        if sub_tree_height == 6 {
            return Ok(Vec::new());
        }else{
            return Ok(diff_nodes);
        }
    }else{
        for k in range.iter_mut() {
            k.index += 1;
        }
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        for (n, k) in range.into_iter().zip(remote_nodes.into_iter()) {
                let local_hash = local_tree.fts_get_merkle_node(n);
                if local_hash != k {
                    local_tree.fts_set_merkle_node(SimpleMerkleNode {
                        key: n,
                        value: k,
                    });
                    diff_nodes.push(SimpleMerkleNode {
                        key: n,
                        value: k,
                    });
                }
            }
            local_tree.fts_rehash_sub_tree(root_key.right_child());
            let combined = local_tree.fts_rehash_from_node_to_level(sub_root_cap.right_child(), sub_root_cap.level);
            if combined != sub_root_target_hash {
                anyhow::bail!("Failed to sync sub tree from remote: root hash mismatch after syncing both children");
            }else{
                Ok(diff_nodes)
            }
        }

}

fn diff_key_hash<Hash: PartialEq + Copy>(keys: &[SimpleMerkleNodeKey], original: &[Hash], new: &[Hash]) -> Vec<SimpleMerkleNode<Hash>> {
    keys.iter()
        .zip(original.iter())
        .zip(new.iter())
        .filter_map(|((key, old_hash), new_hash)| {
            if old_hash != new_hash {
                Some(SimpleMerkleNode {
                    key: *key,
                    value: *new_hash,
                })
            } else {
                None
            }
        })
        .collect()
}

pub async fn sync_local_sub_tree_from_remote2<
    Hash: Copy + PartialEq,
    Destination: FastTreeSyncLocalDestination<Hash>,
    Source: FastTreeSyncAsyncSource<Hash>,
>(
    local_base_level: &[Hash],
    below_base_level: &[Hash],
    tree_height: u8,
    remote_tree: &Source,
    sub_root_cap: SimpleMerkleNode<Hash>,
) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>> {
    let sub_tree_height = tree_height - sub_root_cap.key.level;
    let total_leaves = 1u64 << sub_tree_height;
    let total_leaves_usize = total_leaves as usize;

    if sub_root_cap.key.level == tree_height {
        return Ok(Vec::new());
    } else if sub_tree_height < BATCH_LEVEL_DEPTH + 2 {
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, sub_root_cap.key.index << (sub_tree_height), total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        return Ok(nodes);
    }

    let range = SimpleMerkleNodeKey::get_even_nodes_in_range_at_level(sub_root_cap.key.level + 1, sub_root_cap.key.index << (BATCH_LEVEL_DEPTH+1), 1<<BATCH_LEVEL_DEPTH);
    let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
    let mut diff_nodes = Vec::new();
    for (i, remote_hash) in remote_nodes.into_iter().enumerate() {

        let computed_parent_hash = Destination::fts_hash_two_to_one(&remote_hash, & &below_base_level[i*2 + 1]);

        let local_hash = below_base_level[i*2];
        if local_hash != remote_hash {
            diff_nodes.push(SimpleMerkleNode {
                key: range[i],
                value: remote_hash,
            });
        }
    }
    let computed_base_level = remote_nodes.iter().enumerate().map(|(i, x)| Destination::fts_hash_two_to_one(x, &below_base_level[i]))
    let diff_nodes = diff_key_hash(&range, &base_level, &remote_nodes);

    Ok(diff_nodes)

}

pub async fn sync_local_tree_from_remote_v3_parallel_for_cap_32<
    Hash: Copy + PartialEq,
    Destination: FastTreeSyncLocalDestination<Hash>,
    Source: FastTreeSyncAsyncSource<Hash>,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
    sub_root_cap: SimpleMerkleNodeKey,
    remote_tree_root: Hash,
) -> anyhow::Result<()> {
    let tree_height = local_tree.fts_get_tree_height();
    let total_leaves = 1u64 << (tree_height- sub_root_cap.level);
    let total_leaves_usize = total_leaves as usize;
    if tree_height == 0 {
        local_tree.fts_set_merkle_node(SimpleMerkleNode {
            key: sub_root_cap,
            value: remote_tree_root,
        });
        return Ok(());
    } else if tree_height < 7 {
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, 0, total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        local_tree.fts_set_merkle_nodes(&nodes);
        local_tree.fts_rehash_sub_tree(sub_root_cap);
        return Ok(());
    }

    let depth_5_cap_keys = SimpleMerkleNodeKey::get_range_at_level(5, 0, 32);
    let local_hashes = local_tree.fts_get_merkle_nodes(&depth_5_cap_keys);

    let remote_depth_5_hashes = remote_tree.fts_get_merkle_nodes_async(&depth_5_cap_keys).await?;
    let mut depth_5_nodes = combine_keys_and_hashes(&depth_5_cap_keys, &remote_depth_5_hashes).into_iter().filter_map(|n| {
        let local_hash = local_tree.fts_get_merkle_node(n.key);
        if local_hash != n.value {
            Some(n)
        } else {
            None
        }
    }).collect::<Vec<_>>();

    while depth_5_nodes.len < 32 {
        depth_5_nodes = futures::future::try_join_all(
            depth_5_nodes.into_iter().map(|n| {
                let local_tree = local_tree;
                let remote_tree = remote_tree;
                async move {
                    let diffs = sync_local_sub_tree_from_remote(local_tree, remote_tree, n.key, n.value).await?;
                    Ok::<_, anyhow::Error>(diffs)
                }
            })
        ).await?.into_iter().flatten().collect();
    }
    Ok(())

}
pub async fn sync_local_tree_from_remote_v1<
    Hash: Copy + PartialEq,
    Destination: FastTreeSyncLocalDestination<Hash>,
    Source: FastTreeSyncAsyncSource<Hash>,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
) -> anyhow::Result<()> {
    let tree_height = local_tree.fts_get_tree_height();
    let root_key = SimpleMerkleNodeKey::new(0, 0);
    let start_local_tree_root = local_tree.fts_get_merkle_node(root_key);
    let remote_tree_root = remote_tree.fts_get_merkle_node_async(root_key).await?;
    let total_leaves = 1u64 << tree_height;
    let total_leaves_usize = total_leaves as usize;

    if start_local_tree_root == remote_tree_root {
        return Ok(());
    } else if tree_height == 0 {
        local_tree.fts_set_merkle_node(SimpleMerkleNode {
            key: root_key,
            value: remote_tree_root,
        });
        return Ok(());
    } else if tree_height < 6 {
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, 0, total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        local_tree.fts_set_merkle_nodes(&nodes);
        local_tree.fts_rehash_sub_tree(root_key);
        return Ok(());
    }

    #[derive(Copy, Clone)]
    struct NodeTask<Hash> {
        key: SimpleMerkleNodeKey,
        remote_hash: Hash,
    }

    let tree_height = local_tree.fts_get_tree_height();
    let root_key = SimpleMerkleNodeKey::new(0, 0);
    let mut stack = Vec::new();
    stack.push(NodeTask {
        key: root_key,
        remote_hash: remote_tree_root,
    });

    while !stack.is_empty() {
        let mut batch = Vec::new();
        for _ in 0..REMOTE_SCAN_WIDTH {
            if let Some(task) = stack.pop() {
                batch.push(task);
            } else {
                break;
            }
        }

        if batch.is_empty() {
            continue;
        }

        let mut leaves = Vec::new();
        let mut internal = Vec::new();

        for task in batch {
            let local_hash = local_tree.fts_get_merkle_node(task.key);
            if local_hash == task.remote_hash {
                continue;
            }
            if task.key.level == tree_height {
                leaves.push(task);
            } else {
                internal.push(task);
            }
        }

        for leaf in leaves {
            local_tree.fts_set_merkle_node(SimpleMerkleNode {
                key: leaf.key,
                value: leaf.remote_hash,
            });
            local_tree.fts_rehash_from_node_to_level(leaf.key, 0);
        }

        if internal.is_empty() {
            continue;
        }

        let mut child_keys = Vec::with_capacity(internal.len() * 2);
        for task in &internal {
            let child_level = task.key.level + 1;
            let left_index = task.key.index << 1;
            child_keys.push(SimpleMerkleNodeKey::new(child_level, left_index));
            child_keys.push(SimpleMerkleNodeKey::new(child_level, left_index + 1));
        }

        let child_hashes = fetch_remote_nodes_batched(remote_tree, &child_keys).await?;

        for (child_key, remote_hash) in child_keys.into_iter().zip(child_hashes.into_iter()) {
            let local_hash = local_tree.fts_get_merkle_node(child_key);
            if local_hash != remote_hash {
                stack.push(NodeTask { key: child_key, remote_hash });
            }
        }
    }
    Ok(())
}*/
/*

finish the code for sync_local_tree_from_remote which finds the differences between the local and remote trees and syncs them efficiently.
The method should require at most O(n log n) calls to fts_get_merkle_node_async and O(n) calls to fts_set_merkle_node, where n is the number of leaves in the tree which differ from the remote tree.
Also, you should scan 32 nodes at a time when possible to reduce the number of async calls.

*/

const FTS_REMOTE_BATCH: usize = 32;

async fn fts_collect_differing_leaf_updates<
    Hash: Copy + PartialEq,
    Local: FastTreeSyncLocalSource<Hash> + FastTreeSyncBasicMetadata,
    Remote: FastTreeSyncAsyncSource<Hash>,
>(
    local_tree: &Local,
    remote_tree: &Remote,
) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>> {
    let tree_height = local_tree.fts_get_tree_height();
    debug_assert!(tree_height > 0);

    // We already know the root differs when this is called.
    let mut current_caps: Vec<SimpleMerkleNodeKey> = vec![SimpleMerkleNodeKey::new(0, 0)];

    for level in 0..tree_height {
        let child_level = level + 1;

        // Expand all mismatching caps into their children on the next level.
        let mut child_keys: Vec<SimpleMerkleNodeKey> = Vec::with_capacity(current_caps.len().saturating_mul(2));
        for cap in &current_caps {
            let base = cap.index << 1;
            child_keys.push(SimpleMerkleNodeKey::new(child_level, base));
            child_keys.push(SimpleMerkleNodeKey::new(child_level, base + 1));
        }

        let mut next_caps: Vec<SimpleMerkleNodeKey> = Vec::new();
        let mut leaf_updates: Vec<SimpleMerkleNode<Hash>> = Vec::new();

        // Fetch remote hashes in batches (scan 32 nodes at a time when possible).
        let mut i = 0usize;
        while i < child_keys.len() {
            let end = (i + FTS_REMOTE_BATCH).min(child_keys.len());
            let batch_keys = &child_keys[i..end];
            let remote_hashes = remote_tree.fts_get_merkle_nodes_async(batch_keys).await?;

            for (k, r) in batch_keys.iter().zip(remote_hashes.iter()) {
                let l = local_tree.fts_get_merkle_node(*k);
                if l != *r {
                    if child_level == tree_height {
                        leaf_updates.push(SimpleMerkleNode { key: *k, value: *r });
                    } else {
                        next_caps.push(*k);
                    }
                }
            }

            i = end;
        }

        if child_level == tree_height {
            return Ok(leaf_updates);
        }

        current_caps = next_caps;

        // If nothing differs at this level, nothing differs below it.
        if current_caps.is_empty() {
            return Ok(Vec::new());
        }
    }

    Ok(Vec::new())
}

fn fts_rehash_from_changed_leaves_bottom_up<Hash: Copy, Destination: FastTreeSyncLocalDestination<Hash>>(
    local_tree: &mut Destination,
    changed_leaf_keys: &[SimpleMerkleNodeKey],
) {
    let tree_height = local_tree.fts_get_tree_height();
    if tree_height == 0 || changed_leaf_keys.is_empty() {
        return;
    }

    // Track affected indices at the current level; start at leaves.
    let mut affected: Vec<u64> = changed_leaf_keys.iter().map(|k| k.index).collect();
    affected.sort_unstable();
    affected.dedup();

    // For each level `l` (children level), compute affected parents at `l-1`,
    // and rehash each affected parent once from its left child at level `l`.
    for l in (1..=tree_height).rev() {
        let mut parents: Vec<u64> = Vec::with_capacity(affected.len());
        for &idx in &affected {
            parents.push(idx >> 1);
        }
        parents.sort_unstable();
        parents.dedup();

        for &p in &parents {
            // Rehash this parent using its left child as the starting node.
            // This recomputes the hash at level l-1 for index p (and nothing above).
            let left_child = SimpleMerkleNodeKey::new(l, p << 1);
            local_tree.fts_rehash_from_node_to_level(left_child, l - 1);
        }

        affected = parents;
        if affected.len() == 1 && affected[0] == 0 && l == 1 {
            break;
        }
    }
}

pub async fn sync_local_tree_from_remote_serial<
    Hash: Copy + PartialEq,
    Destination: FastTreeSyncLocalDestination<Hash>,
    Source: FastTreeSyncAsyncSource<Hash>,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
) -> anyhow::Result<()> {
    let tree_height = local_tree.fts_get_tree_height();
    let start_local_tree_root = local_tree.fts_get_merkle_node(SimpleMerkleNodeKey::new(0, 0));
    let remote_tree_root = remote_tree.fts_get_merkle_node_async(SimpleMerkleNodeKey::new(0, 0)).await?;
    let total_leaves = 1u64 << tree_height;
    let total_leaves_usize = total_leaves as usize;

    if start_local_tree_root == remote_tree_root {
        // already synced
        return Ok(());
    } else if tree_height == 0 {
        // single node tree, just set the root
        local_tree.fts_set_merkle_node(SimpleMerkleNode {
            key: SimpleMerkleNodeKey::new(0, 0),
            value: remote_tree_root,
        });
        return Ok(());
    } else if tree_height < 6 {
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, 0, total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        local_tree.fts_set_merkle_nodes(&nodes);
        local_tree.fts_rehash_sub_tree(SimpleMerkleNodeKey::new(0, 0));
        return Ok(());
    }

    // Collect the exact differing leaves by descending only into caps whose hashes
    // differ.
    let leaf_updates = fts_collect_differing_leaf_updates(local_tree, remote_tree).await?;

    if leaf_updates.is_empty() {
        // If the root differs but we couldn't find differing leaves, the local tree is
        // likely inconsistent (e.g. stale internal nodes vs leaves). We refuse
        // to "sync" silently.
        anyhow::bail!("root differs but no differing leaves were found; local tree may be inconsistent");
    }

    // Apply only the differing leaves (O(n) writes).
    local_tree.fts_set_merkle_nodes(&leaf_updates);

    // Rehash only affected internal nodes (bottom-up), not whole subtrees.
    let changed_leaf_keys: Vec<SimpleMerkleNodeKey> = leaf_updates.iter().map(|n| n.key).collect();
    fts_rehash_from_changed_leaves_bottom_up(local_tree, &changed_leaf_keys);

    // Sanity check.
    let new_local_root = local_tree.fts_get_merkle_node(SimpleMerkleNodeKey::new(0, 0));
    if new_local_root != remote_tree_root {
        anyhow::bail!("sync completed but roots still differ (local != remote)");
    }
    Ok(())
}


// --- Configuration ---
const FTS_SMALL_TREE_THRESHOLD: u8 = 6;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const REMOTE_BATCH_SIZE: usize = 32;
const DENSE_UPDATE_THRESHOLD_RATIO: f64 = 0.125;

pub async fn sync_local_tree_from_remote_parallel<
    Hash: Copy + PartialEq + Send + Sync + 'static + std::fmt::Debug,
    Destination: FastTreeSyncLocalDestination<Hash> + Send + Sync,
    Source: FastTreeSyncAsyncSource<Hash> + Sync,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
) -> anyhow::Result<()> {
    let tree_height = local_tree.fts_get_tree_height();
    let root_key = SimpleMerkleNodeKey::new(0, 0);

    let local_root = local_tree.fts_get_merkle_node(root_key);
    let remote_root = remote_tree.fts_get_merkle_node_async(root_key).await?;

    if local_root == remote_root {
        return Ok(());
    }

    // Handle tiny trees (height 0)
    if tree_height == 0 {
        local_tree.fts_set_merkle_node(SimpleMerkleNode { key: root_key, value: remote_root });
        return Ok(());
    }else if tree_height <= FTS_SMALL_TREE_THRESHOLD {
        // For small trees, we can fetch all nodes in one go.
        let total_leaves = 1u64 << tree_height;
        let total_leaves_usize = total_leaves as usize;
        let range = SimpleMerkleNodeKey::get_range_at_level(tree_height, 0, total_leaves_usize);
        let remote_nodes = remote_tree.fts_get_merkle_nodes_async(&range).await?;
        let nodes = combine_keys_and_hashes(&range, &remote_nodes);
        local_tree.fts_set_merkle_nodes(&nodes);
        local_tree.fts_rehash_sub_tree(root_key);
        let new_local_root = local_tree.fts_get_merkle_node(root_key);
        if new_local_root != remote_root {
            anyhow::bail!("Sync failed: root mismatch after rehash. Expected {:?}, got {:?}", remote_root, new_local_root);
        }
        return Ok(());
    }

    // --- Diffing Phase ---
    let mut divergent_nodes = vec![root_key];
    let mut leaf_updates = Vec::new();

    while !divergent_nodes.is_empty() {
        let current_level = divergent_nodes[0].level;
        let next_level = current_level + 1;
        
        if next_level > tree_height { break; }

        let child_keys: Vec<SimpleMerkleNodeKey> = divergent_nodes
            .iter()
            .flat_map(|parent| {
                let base = parent.index << 1;
                [
                    SimpleMerkleNodeKey::new(next_level, base),
                    SimpleMerkleNodeKey::new(next_level, base + 1),
                ]
            })
            .collect();

        divergent_nodes.clear();

        let chunks: Vec<Vec<SimpleMerkleNodeKey>> = child_keys
            .chunks(REMOTE_BATCH_SIZE)
            .map(|c| c.to_vec())
            .collect();

        let mut fetch_stream = stream::iter(chunks)
            .map(|chunk| async move {
                let hashes = remote_tree.fts_get_merkle_nodes_async(&chunk).await?;
                Ok::<_, anyhow::Error>((chunk, hashes))
            })
            .buffer_unordered(MAX_CONCURRENT_REQUESTS);

        while let Some(result) = fetch_stream.next().await {
            let (keys, remote_hashes) = result?;
            for (key, remote_val) in keys.into_iter().zip(remote_hashes.into_iter()) {
                let local_val = local_tree.fts_get_merkle_node(key);
                if local_val != remote_val {
                    if key.level == tree_height {
                        leaf_updates.push(SimpleMerkleNode { key, value: remote_val });
                    } else {
                        divergent_nodes.push(key);
                    }
                }
            }
        }
    }

    if leaf_updates.is_empty() {
        anyhow::bail!("Tree roots differ, but no differing leaves were found.");
    }

    // --- Update Phase ---
    local_tree.fts_set_merkle_nodes(&leaf_updates);

    // --- Rehash Phase ---

    if tree_height <= FTS_SMALL_TREE_THRESHOLD {
        // For small trees, we can rehash the whole tree directly.
        local_tree.fts_rehash_sub_tree(root_key);
    }else{
        perform_smart_rehash(local_tree, &leaf_updates)?;

    }

    // Final Sanity Check
    let new_local_root = local_tree.fts_get_merkle_node(root_key);
    if new_local_root != remote_root {
        anyhow::bail!("Sync failed: root mismatch after rehash. Expected {:?}, got {:?}", remote_root, new_local_root);
    }

    Ok(())
}

fn perform_smart_rehash<Hash: Copy + PartialEq, Destination: FastTreeSyncLocalDestination<Hash>>(
    local_tree: &mut Destination,
    updated_leaves: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<()> {
    let tree_height = local_tree.fts_get_tree_height();
    
    // If the tree is small, just rehash the whole thing from the root down.
    if tree_height <= FTS_SMALL_TREE_THRESHOLD {
        local_tree.fts_rehash_sub_tree(SimpleMerkleNodeKey::new(0, 0));
        return Ok(());
    }

    let sub_root_level = tree_height - FTS_SMALL_TREE_THRESHOLD;
    let leaves_per_subtree = 1u64 << FTS_SMALL_TREE_THRESHOLD;
    let threshold_count = (leaves_per_subtree as f64 * DENSE_UPDATE_THRESHOLD_RATIO) as usize;

    let mut updates_by_sub_root: HashMap<u64, Vec<SimpleMerkleNodeKey>> = HashMap::new();
    for node in updated_leaves {
        let sub_root_idx = node.key.index >> FTS_SMALL_TREE_THRESHOLD;
        updates_by_sub_root.entry(sub_root_idx).or_default().push(node.key);
    }

    let mut dirty_sub_roots = Vec::new();

    for (sub_root_idx, keys) in updates_by_sub_root {
        let sub_root_key = SimpleMerkleNodeKey::new(sub_root_level, sub_root_idx);

        if keys.len() >= threshold_count {
            // Optimization: If many leaves changed in this chunk, full rehash of this subtree
            local_tree.fts_rehash_sub_tree(sub_root_key);
        } else {
            // Sparse rehash from leaves up to the sub_root_level
            rehash_sparse_paths(local_tree, &keys, sub_root_level);
        }
        dirty_sub_roots.push(sub_root_key);
    }

    // Finally, rehash from the sub-roots up to the actual root (level 0)
    rehash_sparse_paths(local_tree, &dirty_sub_roots, 0);

    Ok(())
}

fn rehash_sparse_paths<Hash: Copy, Destination: FastTreeSyncLocalDestination<Hash>>(
    local_tree: &mut Destination,
    nodes: &[SimpleMerkleNodeKey],
    target_level: u8,
) {
    if nodes.is_empty() { return; }
    
    let start_level = nodes[0].level;
    if start_level <= target_level { return; }

    let mut current_indices: HashSet<u64> = nodes.iter().map(|n| n.index).collect();

    // Iterate from the level of the nodes provided up to the target level
    for current_lvl in (target_level..start_level).rev() {
        let mut parent_indices = HashSet::with_capacity(current_indices.len());
        let child_lvl = current_lvl + 1;

        for idx in current_indices {
            let parent_idx = idx >> 1;
            if parent_indices.insert(parent_idx) {
                // Rehash parent at current_lvl using its children at child_lvl
                let left_child = SimpleMerkleNodeKey::new(child_lvl, parent_idx << 1);
                local_tree.fts_rehash_from_node_to_level(left_child, current_lvl);
            }
        }
        current_indices = parent_indices;
    }
}
impl<Hash: Copy + PartialEq + Default + std::fmt::Debug, Hasher: MerkleZeroHasher<Hash>> FastTreeSyncBasicMetadata for SimpleMemoryMerkleRecorderStore<Hasher, Hash> {
    fn fts_get_tree_height(&self) -> u8 {
        self.get_height()
    }
}

impl<Hash: Copy + PartialEq + Default + std::fmt::Debug, Hasher: MerkleZeroHasher<Hash>> FastTreeSyncLocalSource<Hash>
    for SimpleMemoryMerkleRecorderStore<Hasher, Hash>
{
    fn fts_get_merkle_node(&self, key: SimpleMerkleNodeKey) -> Hash {
        self.get_node_value(&key)
    }

    fn fts_get_merkle_nodes(&self, keys: &[SimpleMerkleNodeKey]) -> Vec<Hash> {
        keys.iter().map(|key| self.get_node_value(key)).collect()
    }
}

#[async_trait]
impl<Hash: Copy + PartialEq + Default + Send + Sync + 'static + std::fmt::Debug, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static> FastTreeSyncAsyncSource<Hash>
    for SimpleMemoryMerkleRecorderStore<Hasher, Hash>
{
    async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        Ok(self.get_node_value(&key))
    }

    async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        Ok(keys.iter().map(|key| self.get_node_value(key)).collect())
    }
}

impl<Hash: Copy + PartialEq + Default + std::fmt::Debug, Hasher: MerkleZeroHasher<Hash>> FastTreeSyncLocalDestination<Hash>
    for SimpleMemoryMerkleRecorderStore<Hasher, Hash>
{
    fn fts_set_merkle_node(&mut self, node: SimpleMerkleNode<Hash>) {
        self.set_node_value(node.key, node.value);
    }

    fn fts_set_merkle_nodes(&mut self, entries: &[SimpleMerkleNode<Hash>]) {
        for entry in entries {
            self.set_node_value(entry.key, entry.value);
        }
    }

    fn fts_rehash_from_node_to_level(&mut self, node_key: SimpleMerkleNodeKey, sub_root_level: u8) -> Hash {
        self.rehash_from_node_to_level(node_key, sub_root_level);
        self.get_node_value(&node_key)
    }

    fn fts_rehash_range_to_root(&mut self, level: u8, start_index_inclusive: u64, end_index_inclusive: u64) -> Hash {
        self.rehash_range(level, start_index_inclusive, end_index_inclusive);
        self.get_root()
    }

    fn fts_rehash_sub_tree(&mut self, sub_root_cap: SimpleMerkleNodeKey) -> Hash {
        self.rehash_sub_tree(self.get_height() - sub_root_cap.level, sub_root_cap.index)
    }
    fn fts_hash_two_to_one(left: &Hash, right: &Hash) -> Hash {
        Hasher::two_to_one(left, right)
    }
}

pub async fn sync_local_tree_from_remote<
    Hash: Copy + PartialEq + Send + Sync + 'static + std::fmt::Debug,
    Destination: FastTreeSyncLocalDestination<Hash> + Send + Sync,
    Source: FastTreeSyncAsyncSource<Hash> + Sync,
>(
    local_tree: &mut Destination,
    remote_tree: &Source,
) -> anyhow::Result<()> {
    sync_local_tree_from_remote_parallel(local_tree, remote_tree).await
}
#[cfg(test)]
mod tests {
    use std::{sync::{Arc, atomic::AtomicUsize}, time::Duration};

    use cf_utils::{rand_utils::unique_random_u64_array_in_range, timer::DebugTimer};
    use dashmap::DashMap;
    use parth_core::{crypto::hash::traits::FromU64x4, pgoldilocks::PoseidonHasher, utils::QPGenRandom};
    use tokio::time::sleep;

    use super::*;
    use crate::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    type Hasher = PoseidonHasher;
    type Hash = parth_core::PHash;
    // type F = parth_core::PF;

    pub struct LocalTreeSourceAsyncAdapterCounter<Hash, LocalTree: FastTreeSyncLocalSource<Hash>> {
        pub local_tree: LocalTree,
        pub get_node_counter: Arc<AtomicUsize>,
        pub get_batch_counter: DashMap<usize, AtomicUsize>,
        pub _marker: std::marker::PhantomData<Hash>,
    }
    impl<Hash: Copy, LocalTree: FastTreeSyncLocalSource<Hash>> LocalTreeSourceAsyncAdapterCounter<Hash, LocalTree> {
        pub fn new(local_tree: LocalTree) -> Self {
            Self {
                local_tree,
                _marker: std::marker::PhantomData,
                get_node_counter: Arc::new(AtomicUsize::new(0)),
                get_batch_counter: DashMap::new(),
            }
        }
        pub fn get_total_nodes_in_batches_read(&self) -> usize {
            self.get_batch_counter
                .iter()
                .map(|entry| entry.value().load(std::sync::atomic::Ordering::Relaxed) * entry.key())
                .sum()
        }
        pub fn get_total_nodes_read(&self) -> usize {
            self.get_node_counter.load(std::sync::atomic::Ordering::Relaxed) + self.get_total_nodes_in_batches_read()
        }
        pub fn get_total_requests_made(&self) -> usize {
            self.get_batch_counter
                .iter()
                .map(|entry| entry.value().load(std::sync::atomic::Ordering::Relaxed))
                .sum::<usize>()
                + self.get_node_counter.load(std::sync::atomic::Ordering::Relaxed)
        }
        pub fn get_average_nodes_per_request(&self) -> f64 {
            let total_nodes = self.get_total_nodes_read() as f64;
            let total_requests = self.get_total_requests_made();
            if total_requests == 0 {
                0.0
            } else {
                total_nodes / (total_requests as f64)
            }
        }
        pub fn print_stats(&self) {
            println!("Total nodes read: {} (less is better)", self.get_total_nodes_read());
            println!("Total requests made: {} (less is better)", self.get_total_requests_made());
            println!(
                "Average nodes per request: {:.2} (more is better, up to a point)",
                self.get_average_nodes_per_request()
            );
        }
    }

    #[async_trait]
    impl<Hash: Copy + Send + Sync + 'static, LocalTree: FastTreeSyncLocalSource<Hash> + Send + Sync + 'static> FastTreeSyncAsyncSource<Hash>
        for LocalTreeSourceAsyncAdapterCounter<Hash, LocalTree>
    {
        async fn fts_get_merkle_node_async(&self, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
            sleep(Duration::from_millis(2)).await;
            println!("Fetching single node at level {}, index {}", key.level, key.index);
            self.get_node_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.local_tree.fts_get_merkle_node(key))
        }
        async fn fts_get_merkle_nodes_async(&self, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
            sleep(Duration::from_millis(4)).await;
            println!("Fetching batch of {} nodes", keys.len());
            let batch_size = keys.len();
            let counter_entry = self.get_batch_counter.entry(batch_size).or_insert_with(|| AtomicUsize::new(0));
            counter_entry.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.local_tree.fts_get_merkle_nodes(keys))
        }
    }
    fn modify_tree_with_random_leaves(tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>, mut modified_leaves: usize) {
        let total_leaves = 1u64 << tree.get_height();
        modified_leaves = modified_leaves.min(total_leaves as usize);
        let modified_indices = unique_random_u64_array_in_range(0, total_leaves, modified_leaves).unwrap();
        for index in modified_indices {
            tree.set_leaf(index, Hash::qp_rand_gen());
        }
    }

    fn modify_tree_with_sequential_leaves(tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>, mut modified_leaves: usize) {
        let total_leaves = 1u64 << tree.get_height();
        modified_leaves = modified_leaves.min(total_leaves as usize);

        for index in 0..modified_leaves as u64 {
            tree.set_leaf(index, Hash::qp_rand_gen());
        }
    }

    fn random_tree_with_n_modified_leaves(tree_height: u8, modified_leaves: usize) -> SimpleMemoryMerkleRecorderStore<Hasher, Hash> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height);
        modify_tree_with_random_leaves(&mut tree, modified_leaves);
        tree
    }
    fn random_tree_with_n_modified_sequential_leaves(tree_height: u8, modified_leaves: usize) -> SimpleMemoryMerkleRecorderStore<Hasher, Hash> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height);
        modify_tree_with_sequential_leaves(&mut tree, modified_leaves);
        tree
    }
    #[tokio::test]
    async fn test_sync_local_tree_from_remote_random() -> anyhow::Result<()> {
        let tree_height = 32;
        let mut local_tree = random_tree_with_n_modified_leaves(tree_height, 10000);
        local_tree.commit_changes();
        let mut remote_tree = local_tree.clone();
        modify_tree_with_random_leaves(&mut remote_tree, 500);
        remote_tree.commit_changes();
        
        let remote_tree_1 = LocalTreeSourceAsyncAdapterCounter::new(remote_tree.clone());
        let remote_tree_2 = LocalTreeSourceAsyncAdapterCounter::new(remote_tree.clone());

        
        let mut local_tree_1 = local_tree.clone();
        let mut local_tree_2 = local_tree.clone();


        let mut timer = DebugTimer::new("sync_local_tree_from_remote v1");
        
        sync_local_tree_from_remote_serial(&mut local_tree_1, &remote_tree_1).await?;
        println!("remote tree 1 stats:");
        remote_tree_1.print_stats();
        timer.lap("sync_local_tree_from_remote_serial");
        sync_local_tree_from_remote_parallel(&mut local_tree_2, &remote_tree_2).await?;
        println!("remote tree 2 stats:");
        remote_tree_2.print_stats();
        timer.lap("sync_local_tree_from_remote_parallel");
        assert_eq!(local_tree_1.get_root(), remote_tree_1.local_tree.get_root());
        assert_eq!(local_tree_2.get_root(), remote_tree_2.local_tree.get_root());
        Ok(())
    }

    async fn test_tree_with_n_leaves(tree_height: u8, modified_leaves: usize) -> anyhow::Result<()> {
        let mut local_tree_1 = random_tree_with_n_modified_leaves(tree_height, 10000);
        local_tree_1.commit_changes();
        let mut local_tree_2 = local_tree_1.clone();

        
        let mut remote_tree = local_tree_1.clone();
        modify_tree_with_sequential_leaves(&mut remote_tree, modified_leaves);
        remote_tree.commit_changes();
        let mut expected_nodes = remote_tree.get_all_non_zero_nodes_including_changes();
        expected_nodes.sort();

        remote_tree.verify_root_slow()?;
        
        let remote_tree_1 = LocalTreeSourceAsyncAdapterCounter::new(remote_tree.clone());
        let remote_tree_2 = LocalTreeSourceAsyncAdapterCounter::new(remote_tree.clone());



        let mut timer = DebugTimer::new("test_tree_with_n_leaves");
        
        sync_local_tree_from_remote_serial(&mut local_tree_1, &remote_tree_1).await?;
        println!("remote tree 1 stats:");
        remote_tree_1.print_stats();
        local_tree_1.commit_changes();
        local_tree_1.verify_root_slow()?;
        let mut l_nodes_1 = local_tree_1.get_all_non_zero_nodes_including_changes();
        l_nodes_1.sort();
        assert_eq!(expected_nodes, l_nodes_1);
        timer.lap("sync_local_tree_from_remote_serial");
        sync_local_tree_from_remote_parallel(&mut local_tree_2, &remote_tree_2).await?;
        println!("remote tree 2 stats:");
        remote_tree_2.print_stats();
        local_tree_2.commit_changes();
        local_tree_2.verify_root_slow()?;
        let mut l_nodes_2 = local_tree_2.get_all_non_zero_nodes_including_changes();
        l_nodes_2.sort();
        assert_eq!(expected_nodes, l_nodes_2);
        timer.lap("sync_local_tree_from_remote_parallel");
        assert_eq!(local_tree_1.get_root(), remote_tree_1.local_tree.get_root());
        assert_eq!(local_tree_2.get_root(), remote_tree_2.local_tree.get_root());
        Ok(())
    }
    #[tokio::test]
    async fn test_small_trees_zero_through_four_leaves() -> anyhow::Result<()> {
        for i in (0..10).rev() {
            for j in 0..(1 << i).min(5) {
                println!("testing tree height {}, modified leaves {}", i, j);
                test_tree_with_n_leaves(i, j).await?;
            }
        }
        Ok(())
    }
    #[tokio::test]
    async fn test_sync_local_tree_from_remote_sequential() -> anyhow::Result<()> {
        let tree_height = 32;
        let mut local_tree = random_tree_with_n_modified_sequential_leaves(tree_height, 1000);
        local_tree.commit_changes();
        let mut remote_tree = local_tree.clone();
        modify_tree_with_random_leaves(&mut remote_tree, 500);
        remote_tree.commit_changes();
        let remote_tree = LocalTreeSourceAsyncAdapterCounter::new(remote_tree);
        sync_local_tree_from_remote(&mut local_tree, &remote_tree).await?;
        remote_tree.print_stats();

        local_tree.verify_root_slow()?;
        remote_tree.local_tree.verify_root_slow()?;

        assert_eq!(local_tree.get_root(), remote_tree.local_tree.get_root());
        Ok(())
    }
    #[tokio::test]
    async fn test_simple_tree_change() -> anyhow::Result<()> {
        let tree_height = 24;
        let mut local_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(tree_height);

        local_tree.commit_changes();
        let mut remote_tree = local_tree.clone();
        let res = remote_tree.set_leaf(0, Hash::from_u64s(
                16704634758078785427,
                3079133732809502003,
                11524985806763553013,
                6946341379493811756,
        ));
        let expected_root = Hash::from_u64s(
                1619220428794454652,
                455605370924774441,
                752311024673143156,
                12274833379856076453,
        );
        assert_eq!(res.old_root, local_tree.get_root());
        assert_eq!(expected_root, res.new_root);
        remote_tree.commit_changes();
        let mut nodes = remote_tree.get_nodes().iter().map(|(k,h)| SimpleMerkleNode{
            key: *k,
            value: *h,
        }).collect::<Vec<SimpleMerkleNode<Hash>>>();
        nodes.sort();

        remote_tree.verify_root_slow()?;
        let remote_tree = LocalTreeSourceAsyncAdapterCounter::new(remote_tree);
        sync_local_tree_from_remote(&mut local_tree, &remote_tree).await?;
        remote_tree.print_stats();
        local_tree.commit_changes();
        let mut l_nodes = local_tree.get_nodes().iter().map(|(k,h)| SimpleMerkleNode{
            key: *k,
            value: *h,
        }).collect::<Vec<SimpleMerkleNode<Hash>>>();
        l_nodes.sort();
        assert_eq!(nodes, l_nodes);

        local_tree.verify_root_slow()?;
        remote_tree.local_tree.verify_root_slow()?;

        assert_eq!(local_tree.get_root(), remote_tree.local_tree.get_root());
        Ok(())
    }
}
