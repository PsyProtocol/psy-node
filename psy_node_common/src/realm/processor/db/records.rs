//! Commit-path FFS record coverage for contract-state and IMT leaves.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use parth_core::{
    data::hash::fast_node_serializer::{
        QMerkleStoreFastSingleNodeSerializer, QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
        QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE,
    },
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    v1::qdata::{
        contract::{deserialize_imt_leaf_ffs_entry_v2, IMT_LEAF_FFS_ENTRY_SIZE_V2},
        ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
    },
};

use crate::realm::processor::ffs::layout::{
    contract_state_leaves_from_ffs, decode_double_id_node_ffs, require_width,
};

pub(crate) fn require_state_update_record_coverage<Hash>(
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
    checkpoint_id: u64,
    changed_leaves_on_imt_indexed_trees: &HashSet<(u64, u64, u64)>,
) -> anyhow::Result<()>
where
    Hash: Copy + Q256BitHash,
{
    require_width(
        &updates.update_global_user_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE,
        "global user tree FFS",
    )?;
    require_width(
        &updates.update_user_contract_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
        "user contract tree FFS",
    )?;
    require_width(
        &updates.update_contract_state_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
        "contract state tree FFS",
    )?;
    require_width(
        &updates.update_user_leaves_ffs,
        PSY_OBJECT_FFS_SIZE_USER_LEAF,
        "user leaf FFS",
    )?;
    require_width(
        &updates.update_contract_state_imt_leaves_ffs,
        IMT_LEAF_FFS_ENTRY_SIZE_V2,
        "IMT leaf FFS",
    )?;
    if checkpoint_id == 0 {
        return Ok(());
    }
    let contract_state_leaves = contract_state_leaves_from_ffs(updates)?;
    let mut imt_leaves: HashSet<(u64, u64, u64)> = HashSet::new();
    for chunk in updates
        .update_contract_state_imt_leaves_ffs
        .chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2)
    {
        let (tree_id, tree_sub_id, leaf_index, _, _, _, _, _, _) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        imt_leaves.insert((tree_id, tree_sub_id, leaf_index));
    }
    for (user_id, contract_id, index) in changed_leaves_on_imt_indexed_trees {
        anyhow::ensure!(
            imt_leaves.contains(&(*user_id, *contract_id, *index)),
            "InvalidStateUpdates: contract-state leaf user={user_id} contract={contract_id} index={index} has no IMT record"
        );
    }
    let mut user_contract_leaves: HashSet<(u64, u64)> = HashSet::new();
    if !updates.update_user_contract_tree_nodes_ffs.is_empty() {
        let mut grouped: HashMap<u64, Vec<(u8, u64)>> = HashMap::new();
        decode_double_id_node_ffs(
            &updates.update_user_contract_tree_nodes_ffs,
            QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice::<Hash>(
                    chunk,
                );
                grouped
                    .entry(node.key.tree_id)
                    .or_default()
                    .push((node.key.level, node.key.index));
            },
        )?;
        for (user_id, nodes) in grouped {
            let height = nodes.iter().map(|(level, _)| *level).max().unwrap_or(0);
            for (level, index) in nodes {
                if level == height {
                    user_contract_leaves.insert((user_id, index));
                }
            }
        }
    }
    let contract_pairs: HashSet<(u64, u64)> = contract_state_leaves
        .keys()
        .map(|(user_id, contract_id, _)| (*user_id, *contract_id))
        .collect();
    for (user_id, contract_id) in &user_contract_leaves {
        anyhow::ensure!(
            contract_pairs.contains(&(*user_id, *contract_id)),
            "InvalidStateUpdates: user-contract leaf user={user_id} contract={contract_id} has no contract-state FFS"
        );
    }
    Ok(())
}

/// Nonempty FFS-changed leaves on IMT-indexed trees.
/// Zeroed leaves omitted. Append index is the previous checkpoint's.
pub(crate) async fn load_changed_leaves_on_imt_indexed_trees<S, F, Hash>(
    db: &S,
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
) -> anyhow::Result<HashSet<(u64, u64, u64)>>
where
    S: psy_node_core::psy_core_db::traits::full::PsyNodeContractStateIMTDatabaseReader<F, Hash> + Sync,
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + Copy + PartialEq,
{
    let empty_leaf = Hash::from_owned_32bytes([0u8; 32]);
    let mut changed_trees: HashMap<(u64, u64), Vec<u64>> = HashMap::new();
    for ((user_id, contract_id, index), new_value) in contract_state_leaves_from_ffs(updates)? {
        if new_value == empty_leaf {
            continue;
        }
        changed_trees
            .entry((user_id, contract_id))
            .or_default()
            .push(index);
    }
    let mut changed_leaves_on_imt_indexed_trees = HashSet::new();
    for ((user_id, contract_id), leaves) in changed_trees {
        let next_append_index = db
            .contract_state_imt_get_next_append_index(user_id, contract_id)
            .await
            .with_context(|| format!("previous-checkpoint IMT append index read failed user={user_id} contract={contract_id}"))?;
        if next_append_index == 0 {
            continue;
        }
        for index in leaves {
            changed_leaves_on_imt_indexed_trees.insert((user_id, contract_id, index));
        }
    }
    Ok(changed_leaves_on_imt_indexed_trees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        data::hash::merkle_node_key::SimpleMerkleNode,
        pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher},
        protocol::core_types::Q256BitHash,
    };
    use psy_data::{
        prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
        v1::qdata::contract::IMTContractStateLeaf,
    };
    use parth_core::data::hash::fast_node_serializer::QMerkleStoreFastDoubleNodeSerializer;
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
    fn history_ffs_coverage_requires_imt_for_changed_contract_leaf() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut updates = empty_updates(old, old);
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        updates.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&contract_leaf);
        let error = require_state_update_record_coverage(&updates, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect_err("changed contract-state leaf without IMT must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("no IMT record"), "{error}");
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
        updates.update_contract_state_imt_leaves_ffs =
            psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
                1, 2, 0, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
            )
            .to_vec();
        require_state_update_record_coverage(&updates, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect("matching IMT record must close the coverage set");
        require_state_update_record_coverage(&updates, 0, &HashSet::new())
            .expect("genesis may carry contract-state FFS with empty IMT");
        let mut genesis = empty_updates(old, old);
        genesis.update_contract_state_tree_nodes_ffs = updates.update_contract_state_tree_nodes_ffs.clone();
        require_state_update_record_coverage(&genesis, 0, &HashSet::new())
            .expect("genesis contract-state leaves with empty IMT are a legal empty IMT");
        let genesis_error = require_state_update_record_coverage(&genesis, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect_err("the same missing IMT must fail after genesis");
        assert!(genesis_error.to_string().contains("no IMT record"), "{genesis_error}");
        require_state_update_record_coverage(&empty_updates(old, old), 1, &HashSet::new())
            .expect("empty contract-state FFS and empty IMT is a legal no-op");
    }

    #[test]
    fn history_ffs_user_contract_requires_contract_state() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut updates = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 2,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        updates.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        let error = require_state_update_record_coverage(&updates, 1, &HashSet::new())
            .expect_err("user-contract leaf without contract-state FFS must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("no contract-state FFS"), "{error}");
        require_state_update_record_coverage(&updates, 0, &HashSet::new())
            .expect("genesis may register a user-contract leaf with empty contract-state and IMT");
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        updates.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&contract_leaf);
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
        updates.update_contract_state_imt_leaves_ffs =
            psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
                1, 2, 0, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
            )
            .to_vec();
        require_state_update_record_coverage(&updates, 1, &HashSet::new())
            .expect("user-contract plus matching contract-state and IMT must close the coverage set");
    }

    #[test]
    fn history_ffs_genesis_skips_imt_coverage() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut registered = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 262144,
                level: 8,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        registered.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        require_state_update_record_coverage(&registered, 0, &HashSet::new())
            .expect("genesis contract registration has empty contract-state and IMT");
        let registered_error = require_state_update_record_coverage(&registered, 1, &HashSet::new())
            .expect_err("non-genesis registration without contract-state FFS must fail");
        assert!(
            registered_error.to_string().contains("no contract-state FFS"),
            "{registered_error}"
        );
        let mut empty_value = empty_updates(old, old);
        let empty_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 262144,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0u8; 32]),
        };
        empty_value.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&empty_contract_leaf);
        require_state_update_record_coverage(&empty_value, 0, &HashSet::new())
            .expect("genesis empty contract-state leaf with empty IMT is trusted setup");
        require_state_update_record_coverage(&empty_value, 1, &HashSet::new())
            .expect("new empty contract-state leaf does not require IMT");
        let mut nonempty = empty_updates(old, old);
        let nonempty_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 262144,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x11; 32]),
        };
        nonempty.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&nonempty_contract_leaf);
        require_state_update_record_coverage(&nonempty, 0, &HashSet::new())
            .expect("genesis non-empty contract-state leaf with empty IMT is trusted setup");
        let nonempty_error = require_state_update_record_coverage(&nonempty, 1, &HashSet::from_iter([(262144u64, 0u64, 0u64)]))
            .expect_err("updated non-empty contract-state leaf without IMT must fail");
        assert!(nonempty_error.to_string().contains("no IMT record"), "{nonempty_error}");
        replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &nonempty, 8, 8, 0, 0, &HashSet::new(),
        )
        .expect("verify path must honor checkpoint_id=0 and skip IMT pairing");
        let verify_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &nonempty,
            8,
            8,
            0,
            1,
            &HashSet::from_iter([(262144u64, 0u64, 0u64)]),
        )
        .expect_err("verify path at C=1 must still require IMT for a non-empty leaf");
        assert!(verify_error.to_string().contains("no IMT record"), "{verify_error}");
        let mut poisoned = empty_updates(old, old);
        poisoned.update_user_leaves_ffs = vec![0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF + 1];
        let width_error = require_state_update_record_coverage(&poisoned, 0, &HashSet::new())
            .expect_err("genesis still rejects poisoned FFS widths");
        assert!(width_error.to_string().contains("user leaf FFS"), "{width_error}");
    }

    #[test]
    fn history_ffs_positional_contract_leaf_needs_no_imt() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut positional = empty_updates(old, old);
        let positional_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1310720,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        positional.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&positional_leaf);
        require_state_update_record_coverage(&positional, 1, &HashSet::new())
            .expect("positional non-empty contract-state leaf with no previous IMT entry is exempt");
        let mut cleared = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 2,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        cleared.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        let zero_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0u8; 32]),
        };
        cleared.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&zero_leaf);
        require_state_update_record_coverage(&cleared, 1, &HashSet::new())
            .expect("user-contract pairing survives a contract-state leaf cleared to zero");
        require_state_update_record_coverage(&cleared, 0, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect("genesis skips IMT coverage even with a declared managed set");
    }

    struct IMTPreimageFixture {
        next_append: HashMap<(u64, u64), u64>,
    }

    #[async_trait::async_trait]
    impl psy_node_core::psy_core_db::traits::full::PsyNodeContractStateIMTDatabaseReader<PGoldilocksFelt, PGoldilocksHash> for IMTPreimageFixture {
        async fn contract_state_imt_get_leaf_preimage(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _leaf_index: u64,
        ) -> anyhow::Result<Option<IMTContractStateLeaf<PGoldilocksFelt, PGoldilocksHash>>> {
            Ok(None)
        }

        async fn contract_state_imt_get_leaf_index_for_key(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _key: &PGoldilocksHash,
        ) -> anyhow::Result<Option<u64>> {
            Ok(None)
        }

        async fn contract_state_imt_find_predecessor(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _key: &PGoldilocksHash,
        ) -> anyhow::Result<(u64, IMTContractStateLeaf<PGoldilocksFelt, PGoldilocksHash>)> {
            Ok((0, IMTContractStateLeaf::default()))
        }

        async fn contract_state_imt_get_next_append_index(&self, user_id: u64, contract_id: u64) -> anyhow::Result<u64> {
            Ok(self.next_append.get(&(user_id, contract_id)).copied().unwrap_or(0))
        }
    }


    fn contract_state_leaf_ffs(user_id: u64, contract_id: u64, index: u64, value_byte: u8) -> Vec<u8> {
        QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(
            &parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
                key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                    tree_id: user_id,
                    tree_sub_id: contract_id,
                    level: 4,
                    index,
                },
                value: PGoldilocksHash::from_owned_32bytes([value_byte; 32]),
            },
        )
    }

    #[tokio::test]
    async fn history_changed_leaves_on_imt_indexed_trees_follow_append_index() {
        let mut imt_indexed_tree = IMTPreimageFixture { next_append: HashMap::new() };
        imt_indexed_tree.next_append.insert((1, 2), 2);

        let mut new_key = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        new_key.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 5, 0x07);
        let changed_leaves_on_imt_indexed_trees = load_changed_leaves_on_imt_indexed_trees::<_, PGoldilocksFelt, PGoldilocksHash>(&imt_indexed_tree, &new_key)
            .await
            .unwrap();
        assert_eq!(changed_leaves_on_imt_indexed_trees, HashSet::from_iter([(1u64, 2u64, 5u64)]));
        let error = require_state_update_record_coverage(&new_key, 1, &changed_leaves_on_imt_indexed_trees)
            .expect_err("new key on an IMT-indexed tree without IMT record must fail");
        assert!(error.to_string().contains("no IMT record"), "{error}");

        let mut tracked_changed = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        tracked_changed.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 0, 0x05);
        let tracked_changed_leaves = load_changed_leaves_on_imt_indexed_trees::<_, PGoldilocksFelt, PGoldilocksHash>(&imt_indexed_tree, &tracked_changed)
            .await
            .unwrap();
        assert_eq!(tracked_changed_leaves, HashSet::from_iter([(1u64, 2u64, 0u64)]));

        let positional_tree = IMTPreimageFixture { next_append: HashMap::new() };
        let positional_changed_leaves = load_changed_leaves_on_imt_indexed_trees::<_, PGoldilocksFelt, PGoldilocksHash>(&positional_tree, &tracked_changed)
            .await
            .unwrap();
        assert!(positional_changed_leaves.is_empty(), "trees with no IMT entries are positional");
        require_state_update_record_coverage(&tracked_changed, 1, &positional_changed_leaves)
            .expect("collector output for a positional leaf must pass coverage");

        let mut cleared = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        cleared.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 0, 0x00);
        let cleared_leaves = load_changed_leaves_on_imt_indexed_trees::<_, PGoldilocksFelt, PGoldilocksHash>(&imt_indexed_tree, &cleared)
            .await
            .unwrap();
        assert!(cleared_leaves.is_empty(), "leaf cleared to zero keeps the no-IMT behavior");
    }
}
