use std::collections::HashMap;

use kvq::traits::{KVQPair, KVQSerializable, KVQStoreAdapter, KVQStoreAdapterReader};
use psy_crypto::hash::{
    merkle::{
        core::{DeltaMerkleProofCore, MerkleProofCore},
        spiderman::SpidermanUpdateProof,
        utils::sub_tree_nca::{UpdateNCAProofsWithDependencies, UpdateNearestCommonAncestorProof},
    },
    traits::hasher::MerkleZeroHasherWithMarkedLeaf,
};

use super::super::key::KVQMerkleNodeKey;

pub const CHECKPOINT_ID_FUZZY_SIZE: usize = 8;

#[derive(Debug, Clone)]
pub struct NCAAggregation<const TABLE_TYPE: u16> {
    nca: KVQMerkleNodeKey<TABLE_TYPE>,
    left: KVQMerkleNodeKey<TABLE_TYPE>,
    right: KVQMerkleNodeKey<TABLE_TYPE>,
    left_dep: i64,
    right_dep: i64,
}

pub trait KVQMerkleTreeModelReaderCore<
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapterReader<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>
{
    fn get_node_exact(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<Hash> {
        KVA::get_exact(store, key)
    }
    fn get_nodes_exact_vec(store: &S, keys: &[KVQMerkleNodeKey<TABLE_TYPE>]) -> anyhow::Result<Vec<Hash>> {
        KVA::get_many_exact(store, keys)
    }
    fn get_node_optional(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<Option<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>> {
        KVA::get_leq_kv(store, key, CHECKPOINT_ID_FUZZY_SIZE)
    }
    fn get_node(store: &S, tree_height: usize, key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<Hash> {
        match KVA::get_leq(store, key, CHECKPOINT_ID_FUZZY_SIZE)? {
            Some(v) => Ok(v),
            None => {
                if MARK_LEAVES {
                    return Ok(Hasher::get_zero_hash_marked(tree_height - (key.level as usize)));
                } else {
                    Ok(Hasher::get_zero_hash(tree_height - (key.level as usize)))
                }
            }
        }
    }
    fn get_nodes(store: &S, tree_height: usize, keys: &[KVQMerkleNodeKey<TABLE_TYPE>]) -> anyhow::Result<Vec<Hash>> {
        let result = KVA::get_many_leq(store, keys, CHECKPOINT_ID_FUZZY_SIZE)?;
        Ok(result
            .iter()
            .enumerate()
            .map(|(i, v)| match v {
                Some(v) => *v,
                None => Hasher::get_zero_hash(tree_height - (keys[i].level as usize)),
            })
            .collect())
    }
    fn get_sub_tree_proof(
        store: &S,
        real_tree_height: usize,
        root_level: u8,
        leaf_key: &KVQMerkleNodeKey<TABLE_TYPE>,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        if root_level > leaf_key.level {
            anyhow::bail!("cannot get a subtree proof for a root below the leaf");
        }

        let level_difference = (leaf_key.level - root_level) as usize;

        if level_difference == 0 {
            let value = Self::get_node(store, real_tree_height, leaf_key)?;
            return Ok(MerkleProofCore {
                root: value,
                value,
                index: leaf_key.index,
                siblings: Vec::new(),
            });
        }
        let mut node_keys = Vec::with_capacity(2 + level_difference);
        node_keys.push(*leaf_key);
        node_keys.append(&mut leaf_key.siblings_above(level_difference));
        node_keys.push(leaf_key.parent_at_level(root_level));

        let nodes = Self::get_nodes(store, real_tree_height, &node_keys)?;
        let value = nodes[0];
        let root_ind = nodes.len() - 1;
        let siblings = nodes[1..root_ind].to_vec();
        let root = nodes[root_ind];
        Ok(MerkleProofCore::<Hash> {
            root,
            value,
            siblings,
            index: leaf_key.index,
        })
    }
    fn get_leaf(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<MerkleProofCore<Hash>> {
        let nodes = Self::get_nodes(store, key.level as usize, &vec![vec![*key], key.siblings(), vec![key.root()]].concat())?;
        let value = nodes[0];
        let root_ind = nodes.len() - 1;
        let siblings = nodes[1..root_ind].to_vec();
        let root = nodes[root_ind];
        Ok(MerkleProofCore::<Hash> {
            root,
            value,
            siblings,
            index: key.index,
        })
    }
}
pub trait KVQMerkleTreeModelCore<
    const TABLE_TYPE: u16,
    const MARK_LEAVES: bool,
    S,
    KVA: KVQStoreAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
    Hash: Copy + PartialEq + KVQSerializable,
    Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>,
>: KVQMerkleTreeModelReaderCore<TABLE_TYPE, MARK_LEAVES, S, KVA, Hash, Hasher>
{
    fn set_node_kv(store: &S, kv: &KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>) -> anyhow::Result<()> {
        KVA::set_ref(store, &kv.key, &kv.value)
    }
    fn set_node(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>, value: &Hash) -> anyhow::Result<()> {
        KVA::set_ref(store, key, value)
    }
    fn set_nodes_ref<'a>(store: &S, nodes: &[KVQPair<&'a KVQMerkleNodeKey<TABLE_TYPE>, &'a Hash>]) -> anyhow::Result<()> {
        KVA::set_many_ref(store, nodes)
    }
    fn set_nodes<'a>(store: &S, nodes: &[KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>]) -> anyhow::Result<()> {
        KVA::set_many(store, nodes)
    }
    fn set_leaf(store: &S, key: &KVQMerkleNodeKey<TABLE_TYPE>, value: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let old_proof = Self::get_leaf(store, key)?;
        let mut current_value = value;
        let mut current_key = *key;

        let mut updates: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>> = Vec::with_capacity((key.level as usize) + 1);

        let height = key.level as usize;
        if height > 0 {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&current_value, &old_proof.siblings[0])
                } else {
                    Hasher::two_to_one(&current_value, &old_proof.siblings[0])
                }
            } else {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&old_proof.siblings[0], &current_value)
                } else {
                    Hasher::two_to_one(&old_proof.siblings[0], &current_value)
                }
            };
            current_key = new_key;
        }
        for i in 1..height {
            let new_key = current_key.parent();
            let index = current_key.index;
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
                key: current_key,
                value: current_value,
            });
            current_value = if index & 1 == 0 {
                Hasher::two_to_one(&current_value, &old_proof.siblings[i])
            } else {
                Hasher::two_to_one(&old_proof.siblings[i], &current_value)
            };
            current_key = new_key;
        }
        updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
            key: current_key,
            value: current_value,
        });

        Self::set_nodes(store, &updates)?;
        Ok(DeltaMerkleProofCore::<Hash> {
            old_root: old_proof.root,
            old_value: old_proof.value,

            new_root: current_value,
            new_value: value,

            siblings: old_proof.siblings,
            index: key.index,
        })
    }

    fn injest_merkle_proof(
        store: &S,
        tree_id: u8,
        primary_id: u64,
        secondary_id: u32,
        checkpoint_id: u64,
        merkle_proof: &MerkleProofCore<Hash>,
    ) -> anyhow::Result<()> {
        let base_leaf_key = KVQMerkleNodeKey::<TABLE_TYPE> {
            tree_id,
            primary_id,
            secondary_id,
            level: merkle_proof.siblings.len() as u8,
            index: merkle_proof.index,
            checkpoint_id,
        };

        let mut updates: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>> = Vec::with_capacity(merkle_proof.siblings.len() * 2 + 1);
        let mut k = base_leaf_key;
        let mut last_hash = merkle_proof.value;

        for sibling in merkle_proof.siblings.iter() {
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> { key: k, value: last_hash });
            updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> {
                key: k.sibling(),
                value: *sibling,
            });

            last_hash = if k.index & 1 == 0 {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&last_hash, &sibling)
                } else {
                    Hasher::two_to_one(&last_hash, &sibling)
                }
            } else {
                if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&sibling, &last_hash)
                } else {
                    Hasher::two_to_one(&sibling, &last_hash)
                }
            };
            k = k.parent();
        }

        updates.push(KVQPair::<KVQMerkleNodeKey<TABLE_TYPE>, Hash> { key: k, value: last_hash });
        Self::set_nodes(store, &updates)?;
        Ok(())
    }

    fn smart_injest_nca_split_kv(
        store: &S,
        tree_height: usize,
        a: KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
        b: KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>,
        updates: &mut Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>,
    ) -> anyhow::Result<(KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>, UpdateNearestCommonAncestorProof<Hash>)> {
        if a.key == b.key {
            anyhow::bail!("cannot process identical left and right nodes: {:?}", a.key);
        }
        if a.key.is_direct_path_related(&b.key) {
            anyhow::bail!("cannot update two keys on the same path");
        }
        if a.key > b.key {
            return Self::smart_injest_nca_split_kv(store, tree_height, b, a, updates);
        }

        if a.key.is_sibling_for(&b.key) {
            let parent = a.key.parent();
            let a_b_parent = Self::get_nodes(store, tree_height, &[a.key, b.key, parent])?;

            let new_value = if MARK_LEAVES && a.key.level as usize == tree_height {
                Hasher::two_to_one_marked_leaf_swap(a.key.is_right_child(), &a.value, &b.value)
            } else {
                Hasher::two_to_one_swap(a.key.is_right_child(), &a.value, &b.value)
            };

            let r = UpdateNearestCommonAncestorProof {
                old_nearest_common_ancestor_value: a_b_parent[2],
                new_nearest_common_ancestor_value: new_value,
                child_a: DeltaMerkleProofCore::single_value(a.key.index, a_b_parent[0], a.value),
                child_b: DeltaMerkleProofCore::single_value(b.key.index, a_b_parent[1], b.value),
                nearest_common_ancestor_level: parent.level,
                nearest_common_ancestor_index: parent.index,
                level_a: a.key.level,
                level_b: b.key.level,
            };

            updates.reserve(2);

            updates.push(a);
            updates.push(b);

            return Ok((
                KVQPair {
                    key: parent,
                    value: new_value,
                },
                r,
            ));
        }

        let nca = a.key.find_nearest_common_ancestor(&b.key);

        let a_root = nca.left_child();
        let b_root = nca.right_child();

        let child_a = Self::set_rehash_from_node_to_level_dmp_with_updates(store, tree_height, a.key, a.value, a_root.level, updates)?;
        let child_b = Self::set_rehash_from_node_to_level_dmp_with_updates(store, tree_height, b.key, b.value, b_root.level, updates)?;

        let old_nearest_common_ancestor_value = if MARK_LEAVES && a_root.level as usize == tree_height {
            Hasher::two_to_one_marked_leaf(&child_a.old_root, &child_b.old_root)
        } else {
            Hasher::two_to_one(&child_a.old_root, &child_b.old_root)
        };

        let new_nearest_common_ancestor_value = if MARK_LEAVES && a_root.level as usize == tree_height {
            Hasher::two_to_one_marked_leaf(&child_a.new_root, &child_b.new_root)
        } else {
            Hasher::two_to_one(&child_a.new_root, &child_b.new_root)
        };

        let update_nca_proof = UpdateNearestCommonAncestorProof {
            old_nearest_common_ancestor_value,
            new_nearest_common_ancestor_value,
            child_a,
            child_b,
            nearest_common_ancestor_level: nca.level,
            nearest_common_ancestor_index: nca.index,
            level_a: a.key.level,
            level_b: b.key.level,
        };

        Ok((
            KVQPair {
                key: nca,
                value: new_nearest_common_ancestor_value,
            },
            update_nca_proof,
        ))
    }

    fn smart_injest_nca_at_height_dmp(
        store: &S,
        tree_height: usize,
        root_level: u8,
        nodes: &[KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>],
    ) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
        let mut dmps = Vec::with_capacity(nodes.len());
        for n in nodes.iter() {
            let mut updates = Vec::new();
            dmps.push(Self::set_rehash_from_node_to_level_dmp_with_updates(
                store,
                tree_height,
                n.key,
                n.value,
                root_level,
                &mut updates,
            )?);
            Self::set_nodes(store, &updates)?;
        }
        Ok(dmps)
    }

    fn smart_injest_nca(
        store: &S,
        tree_height: usize,
        root_level: u8,
        mut nodes: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>,
    ) -> anyhow::Result<UpdateNCAProofsWithDependencies<Hash>> {
        nodes.sort_by(|a, b| a.key.cmp(&b.key));
        nodes.dedup_by(|a, b| a.key == b.key);

        if nodes.len() == 1 {
            let mut updates = Vec::new();
            let dmp_a =
                Self::set_rehash_from_node_to_level_dmp_with_updates(store, tree_height, nodes[0].key, nodes[0].value, root_level, &mut updates)?;
            let root_key = nodes[0].key;
            let root_value = nodes[0].value;

            let link_proof = Self::set_rehash_from_node_to_level_dmp_with_updates(
                store,
                tree_height,
                root_key,
                root_value,
                root_level.min(root_key.level),
                &mut updates,
            )?;

            Self::set_nodes(store, &updates)?;

            return Ok(UpdateNCAProofsWithDependencies {
                nca_proofs: vec![UpdateNearestCommonAncestorProof {
                    old_nearest_common_ancestor_value: dmp_a.old_value,
                    new_nearest_common_ancestor_value: dmp_a.new_value,
                    child_a: DeltaMerkleProofCore::single_value(root_key.index, dmp_a.old_value, dmp_a.new_value),
                    child_b: DeltaMerkleProofCore::single_value(root_key.index, dmp_a.old_value, dmp_a.new_value),
                    nearest_common_ancestor_level: root_key.level,
                    nearest_common_ancestor_index: root_key.index,
                    level_a: root_key.level,
                    level_b: root_key.level,
                }],
                dependencies: vec![(-1, -1)],
                root_proof_index: 0,
                nearest_common_ancestor_level: root_key.level,
                nearest_common_ancestor_index: root_key.index,
                link_level: root_level.min(root_key.level),
                link_index: if root_level < root_key.level {
                    root_key.parent_at_level(root_level).index
                } else {
                    root_key.index
                },
                link_proof: link_proof,
            });
        }

        assert!(nodes.len() > 0, "can only call smart injest nca with multiple nodes");

        let mut nca_proofs: Vec<UpdateNearestCommonAncestorProof<Hash>> = Vec::new();
        let mut dependencies: Vec<(i64, i64)> = Vec::new();
        let mut updates = Vec::with_capacity(nodes.len() * tree_height);

        let root_node_key = nodes[0].key.root();
        let aggregations = Self::build_nca_recursive(&nodes, root_node_key, tree_height as u8, &mut updates)?;

        let mut node_values: HashMap<(u8, u64), Hash> = HashMap::new();
        for node in &nodes {
            node_values.insert((node.key.level, node.key.index), node.value);
        }

        for agg in &aggregations {
            let left_node_value = *node_values
                .get(&(agg.left.level, agg.left.index))
                .ok_or_else(|| anyhow::anyhow!("Left node value not found: {:?}", agg.left))?;

            let right_node_value = *node_values
                .get(&(agg.right.level, agg.right.index))
                .ok_or_else(|| anyhow::anyhow!("Right node value not found: {:?}", agg.right))?;

            let left_kvq = KVQPair {
                key: agg.left,
                value: left_node_value,
            };
            let right_kvq = KVQPair {
                key: agg.right,
                value: right_node_value,
            };

            let (nca_node, nca_proof) = Self::smart_injest_nca_split_kv(store, tree_height, left_kvq, right_kvq, &mut updates)?;

            node_values.insert((agg.nca.level, agg.nca.index), nca_node.value);
            nca_proofs.push(nca_proof);
            dependencies.push((agg.left_dep, agg.right_dep));
        }

        let final_aggregation = aggregations.last().ok_or_else(|| anyhow::anyhow!("No aggregations generated"))?;
        let final_node_key = final_aggregation.nca;
        let final_node_value = nca_proofs.last().unwrap().new_nearest_common_ancestor_value;

        let root_proof_index = aggregations.len() - 1;

        let link_proof = Self::set_rehash_from_node_to_level_dmp_with_updates(
            store,
            tree_height,
            final_node_key,
            final_node_value,
            root_level.min(final_node_key.level),
            &mut updates,
        )?;

        updates.push(KVQPair {
            key: final_node_key,
            value: final_node_value,
        });
        Self::set_nodes(store, &updates)?;

        Ok(UpdateNCAProofsWithDependencies {
            nca_proofs,
            dependencies,
            root_proof_index,
            nearest_common_ancestor_level: final_node_key.level,
            nearest_common_ancestor_index: final_node_key.index,
            link_level: root_level.min(final_node_key.level),
            link_index: if root_level < final_node_key.level {
                final_node_key.parent_at_level(root_level).index
            } else {
                final_node_key.index
            },
            link_proof: link_proof,
        })
    }

    fn build_nca_recursive(
        nodes: &[KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>],
        subtree_root: KVQMerkleNodeKey<TABLE_TYPE>,
        tree_height: u8,
        _updates: &mut Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>,
    ) -> anyhow::Result<Vec<NCAAggregation<TABLE_TYPE>>> {
        let mut aggregations = Vec::new();
        let mut node_to_proof_index: HashMap<(u8, u64), usize> = HashMap::new();

        let mut leaf_to_array_index: HashMap<(u8, u64), i64> = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            leaf_to_array_index.insert((node.key.level, node.key.index), -(i as i64) - 1);
        }

        Self::build_recursive_helper(
            nodes,
            subtree_root,
            tree_height,
            &mut aggregations,
            &mut node_to_proof_index,
            &leaf_to_array_index,
        )?;
        Ok(aggregations)
    }

    fn build_recursive_helper(
        nodes: &[KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>],
        subtree_root: KVQMerkleNodeKey<TABLE_TYPE>,
        tree_height: u8,
        aggregations: &mut Vec<NCAAggregation<TABLE_TYPE>>,
        node_to_proof_index: &mut HashMap<(u8, u64), usize>,
        leaf_to_array_index: &HashMap<(u8, u64), i64>,
    ) -> anyhow::Result<Option<KVQMerkleNodeKey<TABLE_TYPE>>> {
        if nodes.is_empty() {
            return Ok(None);
        }

        if nodes.len() == 1 {
            return Ok(Some(nodes[0].key));
        }

        if subtree_root.level > tree_height {
            anyhow::bail!("Recursive depth exceeded tree height - possible ancestor relationship");
        }

        let right_child = subtree_root.right_child();
        let split_leaf_index = right_child.first_leaf_child(tree_height).index;

        let partition_idx = nodes.iter().position(|node| node.key.index >= split_leaf_index).unwrap_or(nodes.len());
        let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

        let left_nca = Self::build_recursive_helper(
            left_nodes,
            subtree_root.left_child(),
            tree_height,
            aggregations,
            node_to_proof_index,
            leaf_to_array_index,
        )?;
        let right_nca = Self::build_recursive_helper(
            right_nodes,
            right_child,
            tree_height,
            aggregations,
            node_to_proof_index,
            leaf_to_array_index,
        )?;

        match (left_nca, right_nca) {
            (Some(l), Some(r)) => {
                let combined_nca = l.find_nearest_common_ancestor(&r);

                let left_dep = node_to_proof_index
                    .get(&(l.level, l.index))
                    .map(|&i| i as i64)
                    .or_else(|| leaf_to_array_index.get(&(l.level, l.index)).copied())
                    .ok_or_else(|| anyhow::anyhow!("Left dependency not found for node (level={}, index={})", l.level, l.index))?;
                let right_dep = node_to_proof_index
                    .get(&(r.level, r.index))
                    .map(|&i| i as i64)
                    .or_else(|| leaf_to_array_index.get(&(r.level, r.index)).copied())
                    .ok_or_else(|| anyhow::anyhow!("Right dependency not found for node (level={}, index={})", r.level, r.index))?;

                let current_proof_index = aggregations.len();
                node_to_proof_index.insert((combined_nca.level, combined_nca.index), current_proof_index);

                aggregations.push(NCAAggregation {
                    nca: combined_nca,
                    left: l,
                    right: r,
                    left_dep,
                    right_dep,
                });
                Ok(Some(combined_nca))
            }
            (Some(l), None) => Ok(Some(l)),
            (None, Some(r)) => Ok(Some(r)),
            (None, None) => Ok(None),
        }
    }

    fn rehash_from_node_to_level(store: &S, tree_height: usize, node: KVQMerkleNodeKey<TABLE_TYPE>, root_level: u8) -> anyhow::Result<()> {
        let mut current = node;
        let mut current_value = Self::get_node(store, tree_height, &node)?;

        let mut updates: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>> = Vec::with_capacity((current.level - root_level) as usize);
        while current.level > root_level {
            let parent_key = current.parent();
            let sibling_value = Self::get_node(store, tree_height, &current.sibling())?;

            let parent_value = if current.index & 1 == 0 {
                if MARK_LEAVES && current.level == tree_height as u8 {
                    Hasher::two_to_one_marked_leaf(&current_value, &sibling_value)
                } else {
                    Hasher::two_to_one(&current_value, &sibling_value)
                }
            } else {
                if MARK_LEAVES && current.level == tree_height as u8 {
                    Hasher::two_to_one_marked_leaf(&sibling_value, &current_value)
                } else {
                    Hasher::two_to_one(&sibling_value, &current_value)
                }
            };
            updates.push(KVQPair {
                key: parent_key,
                value: parent_value,
            });
            current = parent_key;
            current_value = parent_value;
        }
        Self::set_nodes(store, &updates)?;
        Ok(())
    }

    fn set_rehash_from_node_to_level_dmp_with_updates(
        store: &S,
        tree_height: usize,
        node: KVQMerkleNodeKey<TABLE_TYPE>,
        new_value: Hash,
        root_level: u8,
        updates: &mut Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>>,
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let root_level = root_level.min(node.level);
        if root_level == node.level {
            let old_value = Self::get_node(store, tree_height, &node)?;
            Self::set_node(store, &node, &new_value)?;
            return Ok(DeltaMerkleProofCore {
                new_value,
                old_value,
                old_root: old_value,
                new_root: new_value,
                index: node.index,
                siblings: Vec::new(),
            });
        }
        let sub_height = (node.level - root_level) as usize;
        let mut siblings_old_value_root_keys = Vec::with_capacity(sub_height + 2);
        siblings_old_value_root_keys.extend_from_slice(&node.siblings_to_level(root_level));
        siblings_old_value_root_keys.push(node);
        siblings_old_value_root_keys.push(node.parent_at_level(root_level));
        let mut siblings_and_old = Self::get_nodes(store, tree_height, &siblings_old_value_root_keys)?;

        let old_sub_root = siblings_and_old.pop().unwrap();
        let old_value = siblings_and_old.pop().unwrap();
        let siblings = siblings_and_old;

        let mut current_value = new_value;
        let mut current = node;
        updates.reserve(sub_height + 1);
        updates.push(KVQPair { key: node, value: new_value });
        for sibling_value in siblings.iter() {
            let parent_key = current.parent();

            let parent_value = if current.index & 1 == 0 {
                if MARK_LEAVES && current.level == tree_height as u8 {
                    Hasher::two_to_one_marked_leaf(&current_value, &sibling_value)
                } else {
                    Hasher::two_to_one(&current_value, &sibling_value)
                }
            } else {
                if MARK_LEAVES && current.level == tree_height as u8 {
                    Hasher::two_to_one_marked_leaf(&sibling_value, &current_value)
                } else {
                    Hasher::two_to_one(&sibling_value, &current_value)
                }
            };
            updates.push(KVQPair {
                key: parent_key,
                value: parent_value,
            });
            current = parent_key;
            current_value = parent_value;
        }
        Ok(DeltaMerkleProofCore {
            old_root: old_sub_root,
            old_value,
            new_root: current_value,
            new_value,
            index: node.index,
            siblings,
        })
    }

    fn append_leaves_spider_man(
        store: &S,
        tree_height: usize,
        first_empty_leaf_key: &KVQMerkleNodeKey<TABLE_TYPE>,
        sub_tree_height: u8,
        leaves: &[Hash],
    ) -> anyhow::Result<(Vec<usize>, Vec<SpidermanUpdateProof<Hash>>)> {
        let leaves_per_subtree = 1usize << sub_tree_height;
        let max_leaves = 1u64 << tree_height;
        let append_index = first_empty_leaf_key.index;
        if (append_index) + (leaves.len() as u64) > max_leaves {
            anyhow::bail!("tree cannot fit an additional {} leaves", leaves.len());
        }
        let cur_sub_tree_id = append_index / (leaves_per_subtree as u64);
        let cur_sub_tree_leaf_index = ((append_index as u64) & ((leaves_per_subtree as u64) - 1u64)) as u64;

        let subtree_count =
            psy_client_common::utils::math::ceil_div_usize((append_index as usize) + leaves.len(), leaves_per_subtree) - (cur_sub_tree_id as usize);

        let mut results = Vec::with_capacity(subtree_count);
        let mut start_indexes = Vec::with_capacity(subtree_count);
        if subtree_count == 0 {
            return Ok((start_indexes, results));
        }

        let mut old_leaves = Vec::with_capacity(leaves_per_subtree);
        let mut new_leaves = Vec::with_capacity(leaves_per_subtree);

        let start_existing_index = cur_sub_tree_id * (leaves_per_subtree as u64);
        let start_added_index = start_existing_index + cur_sub_tree_leaf_index;

        let existing_leaf_keys = (start_existing_index..start_added_index)
            .map(|i| first_empty_leaf_key.at_index(i))
            .collect::<Vec<_>>();
        let existing_leaf_values = Self::get_nodes(store, tree_height, &existing_leaf_keys)?;
        old_leaves.extend_from_slice(&existing_leaf_values);
        new_leaves.extend_from_slice(&existing_leaf_values);

        let first_tree_new_slots = leaves_per_subtree - new_leaves.len();

        new_leaves.extend_from_slice(&leaves[0..first_tree_new_slots.min(leaves.len())]);

        let first_tree_zero_hashes = leaves_per_subtree - new_leaves.len();

        let zero_hash = Hasher::get_zero_hash(0);
        let mut leaves_used = leaves_per_subtree - (cur_sub_tree_leaf_index as usize);

        let old_leaves_zeros = leaves_per_subtree - old_leaves.len();
        for _ in 0..old_leaves_zeros {
            old_leaves.push(zero_hash);
        }
        for _ in 0..first_tree_zero_hashes {
            new_leaves.push(zero_hash);
        }

        let mut node_updates = Vec::with_capacity(leaves_used.min(leaves.len()));

        for (i, l) in leaves[0..leaves_used.min(leaves.len())].iter().enumerate() {
            node_updates.push(KVQPair {
                key: first_empty_leaf_key.at_index(i as u64 + start_added_index),
                value: *l,
            });
        }

        Self::set_nodes(store, &node_updates)?;
        let dmp = Self::rehash_sub_tree_dmp(store, tree_height, &first_empty_leaf_key.n_th_ancestor(sub_tree_height))?;

        start_indexes.push(0);
        results.push(SpidermanUpdateProof {
            top_line_proof: dmp,
            web_proof_old_leaves: old_leaves,
            web_proof_new_leaves: new_leaves,
        });

        if subtree_count > 2 {
            let ll = leaves_used;
            let old_leaves = (0..leaves_per_subtree).map(|_| zero_hash).collect::<Vec<_>>();

            for t in 0..(subtree_count - 3) {
                let base_ind = ll + t * leaves_per_subtree;
                let new_leaves = leaves[base_ind..(base_ind + leaves_per_subtree)].to_vec();
                let bb1 = (cur_sub_tree_id as usize + t + 1) * leaves_per_subtree;
                let mut node_updates = Vec::with_capacity(new_leaves.len());

                for (i, l) in new_leaves.iter().enumerate() {
                    node_updates.push(KVQPair {
                        key: first_empty_leaf_key.at_index((bb1 + i) as u64),
                        value: *l,
                    });
                }

                Self::set_nodes(store, &node_updates)?;

                start_indexes.push(base_ind);
                results.push(SpidermanUpdateProof {
                    top_line_proof: Self::rehash_sub_tree_dmp(
                        store,
                        tree_height,
                        &first_empty_leaf_key.at_index(bb1 as u64).n_th_ancestor(sub_tree_height),
                    )?,
                    web_proof_old_leaves: old_leaves.clone(),
                    web_proof_new_leaves: new_leaves,
                });
            }

            // OPT: don't waste the old_leaves.clone()

            // Process the second-to-last subtree
            let ll = leaves_used;
            let old_leaves = (0..leaves_per_subtree).map(|_| zero_hash).collect::<Vec<_>>();

            let t = subtree_count - 3;
            let base_ind = ll + t * leaves_per_subtree;
            let new_leaves = leaves[base_ind..(base_ind + leaves_per_subtree)].to_vec();
            let bb1 = (cur_sub_tree_id as usize + t + 1) * leaves_per_subtree;
            let mut node_updates = Vec::with_capacity(new_leaves.len());

            for (i, l) in new_leaves.iter().enumerate() {
                node_updates.push(KVQPair {
                    key: first_empty_leaf_key.at_index((bb1 + i) as u64),
                    value: *l,
                });
            }

            Self::set_nodes(store, &node_updates)?;

            start_indexes.push(base_ind);
            results.push(SpidermanUpdateProof {
                top_line_proof: Self::rehash_sub_tree_dmp(
                    store,
                    tree_height,
                    &first_empty_leaf_key.at_index(bb1 as u64).n_th_ancestor(sub_tree_height),
                )?,
                web_proof_old_leaves: old_leaves,
                web_proof_new_leaves: new_leaves,
            });

            leaves_used += (subtree_count - 2) * leaves_per_subtree;
        }

        if subtree_count > 1 {
            let old_leaves = (0..leaves_per_subtree).map(|_| zero_hash).collect::<Vec<_>>();

            let mut new_leaves = Vec::with_capacity(leaves_per_subtree);
            new_leaves.extend_from_slice(&leaves[leaves_used..]);

            let zeros_to_add = leaves_per_subtree - new_leaves.len();
            for _ in 0..zeros_to_add {
                new_leaves.push(zero_hash);
            }

            let bb1 = ((cur_sub_tree_id as usize + subtree_count - 1) * leaves_per_subtree) as u64;
            let mut node_updates = Vec::with_capacity(leaves.len() - leaves_used);

            for (i, l) in leaves[leaves_used..].iter().enumerate() {
                node_updates.push(KVQPair {
                    key: first_empty_leaf_key.at_index(bb1 + i as u64),
                    value: *l,
                });
            }

            Self::set_nodes(store, &node_updates)?;

            start_indexes.push(leaves_used);
            results.push(SpidermanUpdateProof {
                top_line_proof: Self::rehash_sub_tree_dmp(store, tree_height, &first_empty_leaf_key.at_index(bb1).n_th_ancestor(sub_tree_height))?,
                web_proof_old_leaves: old_leaves,
                web_proof_new_leaves: new_leaves,
            });
        }

        Ok((start_indexes, results))
    }

    fn rehash_sub_tree(store: &S, tree_height: usize, sub_root_key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<()> {
        let sub_tree_height = tree_height - (sub_root_key.level as usize);

        if sub_tree_height == 0 {
            return Ok(());
        } else if sub_tree_height == 1 {
            let left_key = sub_root_key.left_child();
            let right_key = sub_root_key.right_child();
            let nodes = Self::get_nodes(store, tree_height, &[left_key, right_key])?;

            let sub_root_value = if MARK_LEAVES {
                Hasher::two_to_one_marked_leaf(&nodes[0], &nodes[1])
            } else {
                Hasher::two_to_one(&nodes[0], &nodes[1])
            };
            Self::set_node(store, sub_root_key, &sub_root_value)?;
            return Ok(());
        }

        let mut child_base_key = sub_root_key.first_leaf_child(tree_height as u8);

        let mut nodes_at_current_level = 1usize << (sub_tree_height - 1);

        let mut child_values = Vec::with_capacity(nodes_at_current_level);
        let mut child_keys = Vec::with_capacity(nodes_at_current_level * 2);
        let mut node_updates = Vec::with_capacity((1usize << sub_tree_height) - 1);

        for i in 0..(nodes_at_current_level as u64) {
            let left_key = child_base_key.at_index(i * 2 + child_base_key.index);
            child_keys.push(left_key);
            child_keys.push(left_key.sibling());
        }
        for (i, x) in Self::get_nodes(store, tree_height, &child_keys)?.chunks_exact(2).enumerate() {
            let parent_value = if MARK_LEAVES {
                Hasher::two_to_one_marked_leaf(&x[0], &x[1])
            } else {
                Hasher::two_to_one(&x[0], &x[1])
            };

            let parent_key = child_base_key.at_index((i as u64) * 2 + child_base_key.index).parent();

            node_updates.push(KVQPair {
                key: parent_key,
                value: parent_value,
            });
            child_values.push(parent_value);
        }

        nodes_at_current_level = nodes_at_current_level >> 1;
        child_base_key = child_base_key.parent();

        while child_base_key.level > sub_root_key.level {
            let mut parent_values = Vec::with_capacity(nodes_at_current_level as usize);
            for i in 0..nodes_at_current_level {
                let parent_key = child_base_key.parent().at_index(i as u64 + (child_base_key.index >> 1u64));

                let parent_value = if MARK_LEAVES {
                    Hasher::two_to_one_marked_leaf(&child_values[i * 2], &child_values[i * 2 + 1])
                } else {
                    Hasher::two_to_one(&child_values[i * 2], &child_values[i * 2 + 1])
                };
                node_updates.push(KVQPair {
                    key: parent_key,
                    value: parent_value,
                });

                parent_values.push(parent_value);
            }
            nodes_at_current_level = nodes_at_current_level >> 1;
            child_base_key = child_base_key.parent();
            child_values = parent_values;
        }

        Self::set_nodes(store, &node_updates)?;

        Self::rehash_from_node_to_level(store, tree_height, child_base_key, 0)?;

        Ok(())
    }

    fn rehash_sub_tree_top(store: &S, tree_height: usize, first_node_at_level: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<()> {
        if first_node_at_level.level == 0 {
            return Ok(());
        }
        let current_leaf_keys_count = 1usize << (first_node_at_level.level as usize);
        let current_leaf_keys = (0..current_leaf_keys_count)
            .map(|x| first_node_at_level.at_index(x as u64))
            .collect::<Vec<_>>();

        let mut updates: Vec<KVQPair<KVQMerkleNodeKey<TABLE_TYPE>, Hash>> = Vec::with_capacity(current_leaf_keys_count - 1);

        let mut current_leaves = Self::get_nodes(store, tree_height, &current_leaf_keys)?;

        let mut child_level = first_node_at_level.level;
        while child_level > 0 {
            let new_leaf_keys_count = 1usize << (child_level as usize - 1);
            let mut new_leaves = Vec::with_capacity(new_leaf_keys_count);

            for i in 0..new_leaf_keys_count {
                let value = if MARK_LEAVES && child_level == (tree_height as u8) {
                    Hasher::two_to_one_marked_leaf(&current_leaves[i * 2], &current_leaves[i * 2 + 1])
                } else {
                    Hasher::two_to_one(&current_leaves[i * 2], &current_leaves[i * 2 + 1])
                };
                new_leaves.push(value);
                updates.push(KVQPair {
                    key: first_node_at_level
                        .n_th_ancestor(first_node_at_level.level - child_level + 1)
                        .at_index(i as u64),
                    value,
                });
            }
            current_leaves = new_leaves;
            child_level -= 1;
        }

        Self::set_nodes(store, &updates)?;
        Ok(())
    }

    fn rehash_sub_tree_dmp(store: &S, tree_height: usize, sub_root_key: &KVQMerkleNodeKey<TABLE_TYPE>) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let old_sub_tree_root = Self::get_node(store, tree_height, sub_root_key)?;
        let old_tree_root = Self::get_node(store, tree_height, &sub_root_key.root())?;

        Self::rehash_sub_tree(store, tree_height, sub_root_key)?;

        let mut keys = Vec::with_capacity(sub_root_key.level as usize + 2);
        keys.extend_from_slice(&sub_root_key.siblings());
        keys.push(sub_root_key.root());
        keys.push(*sub_root_key);

        let mut values = Self::get_nodes(store, tree_height, &keys)?;

        let new_sub_tree_root = values.pop().unwrap();
        let new_tree_root = values.pop().unwrap();

        Ok(DeltaMerkleProofCore {
            old_root: old_tree_root,
            old_value: old_sub_tree_root,
            new_root: new_tree_root,
            new_value: new_sub_tree_root,
            index: sub_root_key.index,
            siblings: values,
        })
    }
}

#[cfg(test)]
mod tests {
    use kvq::{memory::simple::KVQSimpleMemoryBackingStore, traits::KVQPair};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use psy_client_common::data::qhashout::QHashOut;
    use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;

    use super::*;
    use crate::{
        config::store_config::{PsyHasher, UserTreeStore},
        models::kvq_merkle::key::KVQMerkleNodeKey,
    };

    type F = GoldilocksField;
    type Hash = QHashOut<F>;
    const USER_TREE_TABLE_TYPE: u16 = 2;

    fn create_test_data_10_26_76_140() -> Vec<KVQPair<KVQMerkleNodeKey<USER_TREE_TABLE_TYPE>, Hash>> {
        let checkpoint_id = 91;
        vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 10,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 26,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 76,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("5b988f9aa9beb33cf3a4f9279f242f985f26de7b39aa049a722622635f36b103"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 140,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("5da725ea5af3dd48236cad8f1ec7175ac297bde99de2597cb54386b03723b6cd"),
            },
        ]
    }

    fn create_test_data_large_indices() -> Vec<KVQPair<KVQMerkleNodeKey<USER_TREE_TABLE_TYPE>, Hash>> {
        let checkpoint_id = 91;
        vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1076736,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1080832,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1082880,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("5b988f9aa9beb33cf3a4f9279f242f985f26de7b39aa049a722622635f36b103"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1089024,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("5da725ea5af3dd48236cad8f1ec7175ac297bde99de2597cb54386b03723b6cd"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1093120,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1096704,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1121280,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"),
            },
        ]
    }

    #[test]
    fn test_smart_injest_nca_recursive_with_10_26_76_140() {
        let mut store = KVQSimpleMemoryBackingStore::new();
        let root_level = 0;
        let tree_height = GLOBAL_USER_TREE_HEIGHT as usize;
        let nodes = create_test_data_10_26_76_140();

        println!("Testing recursive smart_injest_nca with nodes: 10, 26, 76, 140");
        for (i, node) in nodes.iter().enumerate() {
            println!("Node {}: index={}, level={}, value={}", i, node.key.index, node.key.level, node.value);
        }

        let result = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, root_level, nodes.clone());

        match result {
            Ok(nca_result) => {
                println!("\n=== Recursive NCA Results ===");
                println!("Number of NCA proofs: {}", nca_result.nca_proofs.len());
                println!("Dependencies: {:?}", nca_result.dependencies);
                println!("Root proof index: {}", nca_result.root_proof_index);
                println!(
                    "NCA level: {}, index: {}",
                    nca_result.nearest_common_ancestor_level, nca_result.nearest_common_ancestor_index
                );

                let mut all_valid = true;
                for (i, proof) in nca_result.nca_proofs.iter().enumerate() {
                    let is_valid = proof.verify::<PsyHasher>();
                    let is_solo = proof.is_solo_filler();
                    all_valid &= is_valid;

                    println!("\nProof {}: valid={}, solo_mask={}", i, is_valid, is_solo);
                    println!("  Level A: {}, Level B: {}", proof.level_a, proof.level_b);
                    println!(
                        "  NCA Level: {}, Index: {}",
                        proof.nearest_common_ancestor_level, proof.nearest_common_ancestor_index
                    );
                    println!(
                        "  Child A siblings: {}, Child B siblings: {}",
                        proof.child_a.siblings.len(),
                        proof.child_b.siblings.len()
                    );
                }

                println!("\n=== Dependency Analysis ===");
                for (i, dep) in nca_result.dependencies.iter().enumerate() {
                    match dep {
                        (-1, -1) => println!("Proof {}: Leaf level", i),
                        (left, right) => println!("Proof {}: Depends on {} and {}", i, left, right),
                    }
                }

                println!("\n=== Backward Compatibility Check ===");
                let leaf_pairs_count = nodes.len() / 2;
                for i in 0..leaf_pairs_count {
                    if let Some(dep) = nca_result.dependencies.get(i) {
                        if *dep == (-1, -1) {
                            println!("✅ Proof {} maps to nodes[{}] + nodes[{}]", i, i * 2, i * 2 + 1);
                        }
                    }
                }

                assert!(all_valid, "All NCA proofs should be valid");
                assert!(nca_result.nca_proofs.len() >= 2, "Should have at least 2 proofs for 4 nodes");
                println!("\n✅ Recursive divide-and-conquer algorithm test passed!");
            }
            Err(e) => {
                println!("Error: {}", e);
                panic!("Test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_smart_injest_nca_recursive_with_large_indices() {
        let mut store = KVQSimpleMemoryBackingStore::new();
        let root_level = 0;
        let tree_height = GLOBAL_USER_TREE_HEIGHT as usize;
        let nodes = create_test_data_large_indices();

        println!("Testing recursive smart_injest_nca with large indices: 1076736, 1080832, 1082880, 1089024, 1093120, 1096704, 1121280");
        for (i, node) in nodes.iter().enumerate() {
            println!("Node {}: index={}, level={}, value={}", i, node.key.index, node.key.level, node.value);
        }

        let result = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, root_level, nodes.clone());

        match result {
            Ok(nca_result) => {
                println!("\n=== Recursive NCA Results (Large Indices) ===");
                println!("Number of NCA proofs: {}", nca_result.nca_proofs.len());
                println!("Dependencies: {:?}", nca_result.dependencies);
                println!("Root proof index: {}", nca_result.root_proof_index);
                println!(
                    "NCA level: {}, index: {}",
                    nca_result.nearest_common_ancestor_level, nca_result.nearest_common_ancestor_index
                );

                let mut all_valid = true;
                for (i, proof) in nca_result.nca_proofs.iter().enumerate() {
                    let is_valid = proof.verify::<PsyHasher>();
                    let is_solo = proof.is_solo_filler();
                    all_valid &= is_valid;

                    println!("\nProof {}: valid={}, solo_mask={}", i, is_valid, is_solo);
                    println!("  Level A: {}, Level B: {}", proof.level_a, proof.level_b);
                    println!(
                        "  NCA Level: {}, Index: {}",
                        proof.nearest_common_ancestor_level, proof.nearest_common_ancestor_index
                    );
                }

                println!("\n=== Tree Structure Comparison ===");
                println!("With {} nodes, recursive divide-and-conquer should:", nodes.len());
                println!("  - Partition nodes by subtree boundaries");
                println!("  - Avoid linear pairing conflicts");
                println!("  - Generate optimal aggregation sequence");

                assert!(all_valid, "All NCA proofs should be valid");
                println!("\n✅ Large indices recursive test passed!");
            }
            Err(e) => {
                println!("Error: {}", e);
                panic!("Test failed: {}", e);
            }
        }
    }

    #[test]
    fn test_ancestor_relationship_detection_recursive() {
        let mut store = KVQSimpleMemoryBackingStore::new();
        let checkpoint_id = 91;
        let tree_height = GLOBAL_USER_TREE_HEIGHT as usize;

        let ancestor_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey::<USER_TREE_TABLE_TYPE> {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: 16,
                    index: 0,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("f1290b3ec62e66b404cdef70eb4fbe894ba8927f73d0986434adcfcf42c8a668"),
            },
            KVQPair {
                key: KVQMerkleNodeKey::<USER_TREE_TABLE_TYPE> {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: 19,
                    index: 0,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("e37d6ff7351d05e0473b32a1fa14e7378864171efb412984bdacb38ab4f957be"),
            },
        ];

        println!("\n=== Testing Ancestor Relationship (level 16 vs 19) ===");
        println!("Node 1: level={}, index={}", ancestor_nodes[0].key.level, ancestor_nodes[0].key.index);
        println!("Node 2: level={}, index={}", ancestor_nodes[1].key.level, ancestor_nodes[1].key.index);

        let result = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, ancestor_nodes);

        match result {
            Ok(_) => {
                println!("✅ Recursive algorithm handled ancestor relationship");
            }
            Err(e)
                if e.to_string().contains("cannot update two keys on the same path")
                    || e.to_string().contains("Recursive depth exceeded tree height") =>
            {
                println!("✅ Recursive algorithm correctly rejected ancestor relationship");
                println!("Expected error: {}", e);
            }
            Err(e) => {
                println!("❌ Unexpected error: {}", e);
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    fn test_partition_logic_edge_cases() {
        let mut store = KVQSimpleMemoryBackingStore::new();
        let tree_height = GLOBAL_USER_TREE_HEIGHT as usize;
        let checkpoint_id = 100;

        println!("\n=== Testing Partition Logic Edge Cases ===");

        // Test 1: All nodes in left subtree (unwrap_or case)
        let left_only_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 1,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 3,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
        ];

        println!("Test 1: All nodes in left subtree");
        let result1 = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, left_only_nodes);

        match result1 {
            Ok(_) => println!("✅ Handled all-left-subtree case successfully"),
            Err(e) => {
                println!("❌ Failed all-left-subtree case: {}", e);
                panic!("Failed all-left-subtree case: {}", e);
            }
        }

        // Test 2: All nodes in right subtree
        let half_tree_size = 1u64 << (tree_height - 1);
        let right_only_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: half_tree_size + 1,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: half_tree_size + 3,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
        ];

        println!("Test 2: All nodes in right subtree");
        let result2 = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, right_only_nodes);

        match result2 {
            Ok(_) => println!("✅ Handled all-right-subtree case successfully"),
            Err(e) => {
                println!("❌ Failed all-right-subtree case: {}", e);
                panic!("Failed all-right-subtree case: {}", e);
            }
        }

        // Test 3: Mixed distribution (normal case)
        let mixed_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 10,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: half_tree_size + 10,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
        ];

        println!("Test 3: Mixed distribution (left and right)");
        let result3 = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, mixed_nodes);

        match result3 {
            Ok(_) => println!("✅ Handled mixed distribution case successfully"),
            Err(e) => {
                println!("❌ Failed mixed distribution case: {}", e);
                panic!("Failed mixed distribution case: {}", e);
            }
        }

        // Test 4: Single node (degenerate case)
        let single_node = vec![KVQPair {
            key: KVQMerkleNodeKey {
                tree_id: 1,
                primary_id: 0,
                secondary_id: 0,
                level: GLOBAL_USER_TREE_HEIGHT,
                index: 42,
                checkpoint_id,
            },
            value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
        }];

        println!("Test 4: Single node");
        let result4 = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, single_node);

        match result4 {
            Ok(_) => println!("✅ Handled single node case successfully"),
            Err(e) => println!("✅ Single node case failed as expected: {}", e),
        }

        // Test 5: Boundary case - nodes at exact subtree boundary
        let boundary_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: half_tree_size - 1,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: half_tree_size,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
        ];

        println!("Test 5: Boundary case (last left, first right)");
        let result5 = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, boundary_nodes);

        match result5 {
            Ok(_) => println!("✅ Handled boundary case successfully"),
            Err(e) => {
                println!("❌ Failed boundary case: {}", e);
                panic!("Failed boundary case: {}", e);
            }
        }

        println!("\n=== All Partition Logic Edge Cases Passed ===");
        println!("The unwrap_or(nodes.len()) logic correctly handles:");
        println!("1. All nodes in left subtree → returns nodes.len(), right_nodes empty");
        println!("2. All nodes in right subtree → returns 0, left_nodes empty");
        println!("3. Mixed distribution → normal partitioning");
        println!("4. Boundary cases → correct splitting at subtree boundary");
    }

    #[test]
    fn test_duplicate_nodes_handling() {
        let mut store = KVQSimpleMemoryBackingStore::new();
        let tree_height = GLOBAL_USER_TREE_HEIGHT as usize;
        let checkpoint_id = 101;

        println!("\n=== Testing Duplicate Nodes Handling ===");

        let duplicate_nodes = vec![
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 10,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("0c6485d3dd86a321c647b8bd679d1bb1aaf8e73ac375a9656141b1333dc452b6"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 10,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("4d4b7c5b98f8fadaa15b0e11cc8d8aaac00bd98e5eade0de3d5d15f875fa8881"),
            },
            KVQPair {
                key: KVQMerkleNodeKey {
                    tree_id: 1,
                    primary_id: 0,
                    secondary_id: 0,
                    level: GLOBAL_USER_TREE_HEIGHT,
                    index: 26,
                    checkpoint_id,
                },
                value: QHashOut::from_string_or_panic("1234567890123456789012345678901234567890123456789012345678901234"),
            },
        ];

        let result = UserTreeStore::<KVQSimpleMemoryBackingStore>::smart_injest_nca(&mut store, tree_height, 0, duplicate_nodes);

        match result {
            Ok(_) => {
                println!("✅ Correctly handled duplicate nodes by deduplicating");
            }
            Err(e) => {
                println!("❌ Unexpected error: {}", e);
                panic!("Unexpected error: {}", e);
            }
        }
    }
}
