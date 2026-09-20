//! FFS byte layout, coordinate transforms, and layout invariants.

use std::collections::{HashMap, HashSet};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher, QFieldHashable},
    },
    data::hash::{
        fast_node_serializer::{
            QMerkleStoreFastDoubleNodeSerializer, QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
        },
        merkle_node_key::SimpleMerkleNodeKey,
    },
    felt::FromPrimitiveValuesFelt,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    v1::qdata::contract::{
        deserialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf, IMT_LEAF_FFS_ENTRY_SIZE_V2,
    },
};

pub(super) fn gut_local_key(
    key: SimpleMerkleNodeKey,
    coordinator_height: u8,
    realm_id: u64,
) -> anyhow::Result<SimpleMerkleNodeKey> {
    anyhow::ensure!(
        key.level >= coordinator_height,
        "InvalidStateUpdates: GUT node level {} is below coordinator height {}",
        key.level,
        coordinator_height
    );
    let local_level = key.level - coordinator_height;
    let expected_realm_id = if local_level >= 64 {
        anyhow::ensure!(key.index == 0, "InvalidStateUpdates: GUT node index does not fit local level");
        0
    } else {
        key.index >> local_level
    };
    anyhow::ensure!(
        expected_realm_id == realm_id,
        "InvalidStateUpdates: GUT node realm {expected_realm_id} does not match {realm_id}"
    );
    let local_index = if local_level == 0 {
        0
    } else if local_level >= 64 {
        key.index
    } else {
        key.index & ((1u64 << local_level) - 1)
    };
    Ok(SimpleMerkleNodeKey {
        level: local_level,
        index: local_index,
    })
}

pub(crate) fn require_width(bytes: &[u8], width: usize, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.is_empty() || bytes.len() % width == 0,
        "InvalidStateUpdates: {what} length {} is not a multiple of {width}",
        bytes.len()
    );
    Ok(())
}

pub(crate) fn decode_double_id_node_ffs(
    bytes: &[u8],
    width: usize,
    mut visit: impl FnMut(&[u8]),
) -> anyhow::Result<()> {
    require_width(bytes, width, "tree node FFS")?;
    for chunk in bytes.chunks_exact(width) {
        visit(chunk);
    }
    Ok(())
}

pub(super) fn seed_tree_from_merkle_proof<H, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    proof: &MerkleProofCore<Hash>,
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash> + MerkleHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    anyhow::ensure!(
        proof.verify::<H>(),
        "MissingAuthenticatedState: previous merkle proof does not verify"
    );
    let mut key = SimpleMerkleNodeKey::new(tree.get_height(), proof.index);
    for sibling in &proof.siblings {
        tree.set_node_value(key.sibling(), *sibling);
        key = key.parent();
    }
    tree.set_leaf(proof.index, proof.value);
    Ok(())
}

fn require_declared_double_id_nodes_match<H, Hash>(
    tree: &SimpleMemoryMerkleRecorderStore<H, Hash>,
    nodes: &[(u8, u64, Hash)],
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    for (level, index, value) in nodes {
        let key = SimpleMerkleNodeKey {
            level: *level,
            index: *index,
        };
        anyhow::ensure!(
            tree.get_node_value(&key) == *value,
            "InvalidStateUpdates: declared tree node {:?}={:?} does not match recomputed {:?}",
            key,
            value,
            tree.get_node_value(&key)
        );
    }
    Ok(())
}

pub(super) fn double_id_leaves_at_level<Hash: Copy>(
    nodes: &[(u8, u64, Hash)],
    height: u8,
) -> HashMap<u64, Hash> {
    let mut last_leaf = HashMap::new();
    for (level, index, value) in nodes {
        if *level == height {
            last_leaf.insert(*index, *value);
        }
    }
    last_leaf
}

pub(super) fn replay_double_id_nodes_from_leaves<H, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    nodes: &[(u8, u64, Hash)],
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    let height = tree.get_height();
    for (index, value) in double_id_leaves_at_level(nodes, height) {
        tree.set_leaf(index, value);
    }
    require_declared_double_id_nodes_match(tree, nodes)
}

pub(super) fn require_imt_leaf_ffs_consistency<F, Hash, H>(bytes: &[u8]) -> anyhow::Result<()>
where
    F: parth_core::felt::QFelt64 + FromPrimitiveValuesFelt,
    Hash: Q256BitHash + QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
    H: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash>,
{
    require_width(bytes, IMT_LEAF_FFS_ENTRY_SIZE_V2, "IMT leaf FFS")?;
    let mut first: HashMap<(u64, u64, u64), ([u8; 32], bool)> = HashMap::new();
    let mut first_key_index: HashMap<(u64, u64, [u8; 32]), u64> = HashMap::new();
    let mut first_new_keys: HashSet<(u64, u64, [u8; 32])> = HashSet::new();
    for chunk in bytes.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        let (tree_id, tree_sub_id, leaf_index, leaf_hash, leaf_key, leaf_value, next_key, next_index, is_new_key) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        let leaf = IMTContractStateLeaf::<F, Hash> {
            key: Hash::from_owned_32bytes(leaf_key),
            value: Hash::from_owned_32bytes(leaf_value),
            next_key: Hash::from_owned_32bytes(next_key),
            next_index: F::from_u64_value(next_index),
        };
        anyhow::ensure!(
            leaf.qfhash::<H>().into_owned_32bytes() == leaf_hash,
            "InvalidStateUpdates: IMT leaf preimage does not bind leaf_hash"
        );
        let id = (tree_id, tree_sub_id, leaf_index);
        let key_id = (tree_id, tree_sub_id, leaf_key);
        if let Some(first_index) = first_key_index.get(&key_id) {
            if *first_index != leaf_index {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
        } else {
            first_key_index.insert(key_id, leaf_index);
        }
        if let Some((first_key, first_new)) = first.get(&id) {
            if is_new_key && !first_new_keys.contains(&key_id) {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
            if !*first_new && is_new_key {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
            if *first_key != leaf_key {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
        } else {
            first.insert(id, (leaf_key, is_new_key));
            if is_new_key {
                first_new_keys.insert(key_id);
            }
        }
    }
    let mut finals: HashMap<(u64, u64, u64), ([u8; 32], [u8; 32], u64)> = HashMap::new();
    let mut seen_final = HashSet::new();
    for chunk in bytes.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        let (tree_id, tree_sub_id, leaf_index, _, leaf_key, _, next_key, next_index, _) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        if seen_final.insert((tree_id, tree_sub_id, leaf_index)) {
            finals.insert((tree_id, tree_sub_id, leaf_index), (leaf_key, next_key, next_index));
        }
    }
    for ((tree_id, tree_sub_id, leaf_index), (leaf_key, next_key, next_index)) in &finals {
        if *next_index == 0 {
            anyhow::ensure!(
                *next_key == [0u8; 32],
                "InvalidStateUpdates: IMT terminal next_key must be zero user={tree_id} contract={tree_sub_id} index={leaf_index}"
            );
            continue;
        }
        let Some((successor_key, _, _)) = finals.get(&(*tree_id, *tree_sub_id, *next_index)) else {
            continue;
        };
        anyhow::ensure!(
            successor_key == next_key,
            "InvalidStateUpdates: IMT next_key does not match successor leaf user={tree_id} contract={tree_sub_id} index={leaf_index} next_index={next_index}"
        );
        anyhow::ensure!(
            successor_key != leaf_key || *next_index == *leaf_index,
            "InvalidStateUpdates: IMT successor key collides with source user={tree_id} contract={tree_sub_id} index={leaf_index}"
        );
    }
    Ok(())
}

/// Changed contract-state leaves keyed by (user, contract, index).
pub(crate) fn contract_state_leaves_from_ffs<Hash>(
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
) -> anyhow::Result<HashMap<(u64, u64, u64), Hash>>
where
    Hash: Copy + Q256BitHash,
{
    let empty_leaf = Hash::from_owned_32bytes([0u8; 32]);
    let mut contract_state_leaves: HashMap<(u64, u64, u64), Hash> = HashMap::new();
    if !updates.update_contract_state_tree_nodes_ffs.is_empty() {
        let mut grouped: HashMap<(u64, u64), Vec<(u8, u64, Hash)>> = HashMap::new();
        decode_double_id_node_ffs(
            &updates.update_contract_state_tree_nodes_ffs,
            QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_from_slice::<Hash>(
                    chunk,
                );
                grouped
                    .entry((node.key.tree_id, node.key.tree_sub_id))
                    .or_default()
                    .push((node.key.level, node.key.index, node.value));
            },
        )?;
        for ((user_id, contract_id), nodes) in grouped {
            let height = nodes.iter().map(|(level, _, _)| *level).max().unwrap_or(0);
            for (index, value) in double_id_leaves_at_level(&nodes, height) {
                contract_state_leaves.insert((user_id, contract_id, index), value);
            }
        }
    }
    Ok(contract_state_leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        data::hash::fast_node_serializer::QMerkleStoreFastZeroNodeSerializer,
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher},
        protocol::core_types::Q256BitHash,
    };
    use psy_data::{
        prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
        v1::qdata::contract::IMTContractStateLeaf,
    };
    use crate::realm::processor::ffs::baseline_replay::replay_state_updates_into_tree;
    use std::collections::{HashMap, HashSet};

    fn empty_updates(old: PGoldilocksHash, new: PGoldilocksHash) -> PsyPreparedRealmBlockStateUpdates<PGoldilocksHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 0,
            realm_sub_id: 0,
            unique_pending_id: 0,
            proc_checkpoint_unique_id: Default::default(),
            old_realm_root: old,
            new_realm_root: new,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        }
    }

    #[test]
    fn history_duplicate_imt() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let first_next_key = PGoldilocksHash::from_owned_32bytes([0u8; 32]);
        let first_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let first_hash = first_leaf.qfhash::<PoseidonHasher>();
        let first_entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
        );
        let second_entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &first_hash, &first_key, &first_value, &first_next_key, 7, true,
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first_entry);
        bytes.extend_from_slice(&second_entry);
        updates.update_contract_state_imt_leaves_ffs = bytes;
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("conflicting IMT history must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        let moved = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 9, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
        );
        let mut moved_bytes = Vec::new();
        moved_bytes.extend_from_slice(&first_entry);
        moved_bytes.extend_from_slice(&moved);
        let mut moved_updates = empty_updates(old, old);
        moved_updates.update_contract_state_imt_leaves_ffs = moved_bytes;
        let moved_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &moved_updates,
            8,
            8,
            0,
            1,
            &HashSet::new(),
        )
        .expect_err("same IMT key at a second leaf index must fail");
        assert!(moved_error.to_string().contains("InvalidStateUpdates"), "{moved_error}");
        let successor_key = PGoldilocksHash::from_owned_32bytes([0x44u8; 32]);
        let successor_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: successor_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let successor_hash = successor_leaf.qfhash::<PoseidonHasher>();
        let successor = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 4, &successor_hash, &successor_key, &first_value, &first_next_key, 0, false,
        );
        let mismatched_next = PGoldilocksHash::from_owned_32bytes([0x99u8; 32]);
        let mismatched_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: mismatched_next,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(4),
        };
        let mismatched_hash = mismatched_leaf.qfhash::<PoseidonHasher>();
        let mismatched = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &mismatched_hash, &first_key, &first_value, &mismatched_next, 4, false,
        );
        let mut successor_bytes = Vec::new();
        successor_bytes.extend_from_slice(&mismatched);
        successor_bytes.extend_from_slice(&successor);
        let successor_error = require_imt_leaf_ffs_consistency::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(&successor_bytes)
            .expect_err("IMT next_key must match the successor leaf in the same FFS");
        assert!(successor_error.to_string().contains("InvalidStateUpdates"), "{successor_error}");
    }

    #[test]
    fn history_imt_terminal_next_key_must_be_zero() {
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let nonzero_next = PGoldilocksHash::from_owned_32bytes([0x99; 32]);
        let leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: nonzero_next,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let leaf_hash = leaf.qfhash::<PoseidonHasher>();
        let entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &leaf_hash, &first_key, &first_value, &nonzero_next, 0, false,
        );
        let error = require_imt_leaf_ffs_consistency::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(&entry)
            .expect_err("terminal IMT next_index=0 with nonzero next_key must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("terminal next_key"), "{error}");
    }
}
