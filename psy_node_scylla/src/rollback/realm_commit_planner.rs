//! Enumerates the rows one Realm commit writes (design-r1 §6.3).
//!
//! Structurally the Coordinator's planner with a different table set, because
//! §6.3 says the Realm's physical tables are the same shapes in its own
//! keyspace.  Two things do not carry over.
//!
//! **The contract state tree is partitioned by a pair.** `(user, contract)` is
//! ordered, not a set: swapping the halves names another user's contract, and
//! both are `u64`, so nothing but care catches it.
//!
//! **One IMT blob writes three tables.** `contract_state_imt_set_leaves_ffs`
//! appends leaves, inserts key-index rows for keys it has not seen, and advances
//! the append cursor.  The last two are derived writes that appear nowhere in the
//! blob's own shape, which is precisely the I5 case: a planner that recorded only
//! the leaves would leave the index and the cursor unrecorded, and rollback would
//! leave them behind.
//!
//! The index is planned for every entry rather than only for new keys.  Over-
//! recording is safe -- a locator for a row that was never written deletes
//! nothing -- while depending on the blob's `is_new_key` flag would make the
//! manifest's completeness rest on a producer-side decision the planner cannot
//! check.

use psy_node_core::store::commit_planner::{
    PhysicalMutationSink, RealmCommitPlanInputs, RealmCommitPlanner,
};
use psy_node_core::store::typed::{
    CheckpointId, ImtEncodedKey, LeafIndex, RealmId, TreeId, TreeSubId, TypedTableKey,
    UniquePendingId,
};

use super::{
    ScyllaPhysicalTableId, describe_existing_key, double_merkle_node_key, single_merkle_node_key,
    zero_merkle_node_key,
};

/// Byte layouts of the blobs a Realm commit hands over.
///
/// Taken from the serializers themselves rather than assumed: a wrong stride
/// reads plausible garbage and plans rows that do not exist, and -- worse --
/// misses rows that do.
const DOUBLE_MERKLE_NODE_LEN: usize = 57; // tree(8) + sub(8) + level(1) + index(8) + value(32)
const SINGLE_MERKLE_NODE_LEN: usize = 49; // tree(8) + level(1) + index(8) + value(32)
const ZERO_MERKLE_NODE_LEN: usize = 41; // level(1) + index(8) + value(32)
const IMT_LEAF_ENTRY_LEN: usize = 161; // see psy_data imt_proof::IMT_LEAF_FFS_ENTRY_SIZE_V2

pub struct ScyllaRealmCommitPlanner;

impl ScyllaRealmCommitPlanner {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ScyllaRealmCommitPlanner {
    fn default() -> Self {
        Self::new()
    }
}

fn record(sink: &dyn PhysicalMutationSink, key: &TypedTableKey) -> anyhow::Result<()> {
    let resolved = describe_existing_key(key);
    sink.record_physical_put(
        resolved.physical_table() as u16,
        resolved.locator_bytes().to_vec(),
    )
}

fn require_stride(field: &'static str, len: usize, stride: usize) -> anyhow::Result<()> {
    if len % stride != 0 {
        anyhow::bail!("{field} is {len} bytes, not a whole number of {stride}-byte rows");
    }
    Ok(())
}

impl RealmCommitPlanner for ScyllaRealmCommitPlanner {
    fn encode_planned_locators(
        &self,
        rows: Vec<(u16, Vec<u8>)>,
    ) -> anyhow::Result<psy_node_core::store::commit_planner::PlannedLocatorArtifact> {
        // The chunk codec is the manifest's, not an authority's: both sides must
        // produce artifacts a single rollback planner can decode.
        super::ScyllaCoordinatorCommitPlanner::encode_locators(rows)
    }

    fn plan_realm_commit(
        &self,
        inputs: &RealmCommitPlanInputs<'_>,
        sink: &dyn PhysicalMutationSink,
    ) -> anyhow::Result<()> {
        let checkpoint = inputs.checkpoint_id;

        // 1. The two mappings, written before anything else so a crash can be
        //    recovered from, and therefore the first rows a rollback must undo.
        record(sink, &TypedTableKey::CheckpointToPending(CheckpointId::try_new(checkpoint)?))?;
        record(
            sink,
            &TypedTableKey::PendingToCheckpoint(UniquePendingId::try_new(inputs.unique_pending_id)?),
        )?;
        record(
            sink,
            &TypedTableKey::PendingToProc(UniquePendingId::try_new(inputs.unique_pending_id)?),
        )?;

        // 2. User leaves: an object row per user at this checkpoint.
        require_stride(
            "update_user_leaves_ffs",
            inputs.update_user_leaves_ffs.len(),
            USER_LEAF_ENTRY_LEN,
        )?;
        for chunk in inputs.update_user_leaves_ffs.chunks(USER_LEAF_ENTRY_LEN) {
            let user = u64::from_le_bytes(
                chunk[USER_LEAF_ID_OFFSET..USER_LEAF_ID_OFFSET + 8]
                    .try_into()
                    .expect("checked stride"),
            );
            record(
                sink,
                &TypedTableKey::UserLeaf {
                    user: psy_node_core::store::typed::UserId::new(user),
                    checkpoint: CheckpointId::try_new(checkpoint)?,
                },
            )?;
        }

        // 3. The per-user contract tree.
        require_stride(
            "update_user_contract_tree_nodes_ffs",
            inputs.update_user_contract_tree_nodes_ffs.len(),
            SINGLE_MERKLE_NODE_LEN,
        )?;
        for chunk in inputs
            .update_user_contract_tree_nodes_ffs
            .chunks(SINGLE_MERKLE_NODE_LEN)
        {
            let tree_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked stride"));
            let level = chunk[8];
            let index = u64::from_le_bytes(chunk[9..17].try_into().expect("checked stride"));
            let key = single_merkle_node_key(
                ScyllaPhysicalTableId::UserContractTree,
                tree_id,
                level,
                index,
                CheckpointId::try_new(checkpoint)?,
            )?;
            record(sink, &key)?;
        }

        // 4. The contract state tree, partitioned by the ordered pair.
        require_stride(
            "update_contract_state_tree_nodes_ffs",
            inputs.update_contract_state_tree_nodes_ffs.len(),
            DOUBLE_MERKLE_NODE_LEN,
        )?;
        for chunk in inputs
            .update_contract_state_tree_nodes_ffs
            .chunks(DOUBLE_MERKLE_NODE_LEN)
        {
            let tree_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked stride"));
            let tree_sub_id = u64::from_le_bytes(chunk[8..16].try_into().expect("checked stride"));
            let level = chunk[16];
            let index = u64::from_le_bytes(chunk[17..25].try_into().expect("checked stride"));
            let key = double_merkle_node_key(
                ScyllaPhysicalTableId::ContractStateTree,
                tree_id,
                tree_sub_id,
                level,
                index,
                CheckpointId::try_new(checkpoint)?,
            )?;
            record(sink, &key)?;
        }

        // 5. The IMT: leaves, plus the index and cursor rows the writer derives.
        require_stride(
            "update_contract_state_imt_leaves_ffs",
            inputs.update_contract_state_imt_leaves_ffs.len(),
            IMT_LEAF_ENTRY_LEN,
        )?;
        let mut cursors: Vec<(u64, u64)> = Vec::new();
        for chunk in inputs
            .update_contract_state_imt_leaves_ffs
            .chunks(IMT_LEAF_ENTRY_LEN)
        {
            let tree_id = u64::from_le_bytes(chunk[0..8].try_into().expect("checked stride"));
            let tree_sub_id = u64::from_le_bytes(chunk[8..16].try_into().expect("checked stride"));
            let leaf_index = u64::from_le_bytes(chunk[16..24].try_into().expect("checked stride"));
            let leaf_key: [u8; 32] = chunk[56..88].try_into().expect("checked stride");

            record(
                sink,
                &TypedTableKey::ImtLeaf {
                    tree: TreeId::new(tree_id),
                    tree_sub: TreeSubId::new(tree_sub_id),
                    leaf: LeafIndex::new(leaf_index),
                    checkpoint: CheckpointId::try_new(checkpoint)?,
                },
            )?;
            record(
                sink,
                &TypedTableKey::ImtKeyIndex {
                    tree: TreeId::new(tree_id),
                    tree_sub: TreeSubId::new(tree_sub_id),
                    encoded_key: ImtEncodedKey::new(leaf_key),
                },
            )?;
            if !cursors.contains(&(tree_id, tree_sub_id)) {
                cursors.push((tree_id, tree_sub_id));
            }
        }
        for (tree_id, tree_sub_id) in cursors {
            record(
                sink,
                &TypedTableKey::ImtCursor {
                    tree: TreeId::new(tree_id),
                    tree_sub: TreeSubId::new(tree_sub_id),
                },
            )?;
        }

        // 6. The shared global user tree.
        require_stride(
            "update_global_user_tree_nodes_ffs",
            inputs.update_global_user_tree_nodes_ffs.len(),
            ZERO_MERKLE_NODE_LEN,
        )?;
        for chunk in inputs
            .update_global_user_tree_nodes_ffs
            .chunks(ZERO_MERKLE_NODE_LEN)
        {
            let level = chunk[0];
            let index = u64::from_le_bytes(chunk[1..9].try_into().expect("checked stride"));
            let key = zero_merkle_node_key(
                ScyllaPhysicalTableId::GlobalUserTree,
                level,
                index,
                CheckpointId::try_new(checkpoint)?,
            )?;
            record(sink, &key)?;
        }

        // 7. The singletons this commit overwrites in place.  They have no
        //    version axis, so a rollback restores rather than uncovers them.
        record(
            sink,
            &TypedTableKey::U64Singleton(
                psy_node_core::store::typed::U64SingletonSlot::LatestCheckpoint,
            ),
        )?;
        record(
            sink,
            &TypedTableKey::LatestInfo(
                psy_node_core::store::typed::LatestInfoSlot::LatestL2BlockState,
            ),
        )?;

        let _ = RealmId::new(inputs.realm_id);
        Ok(())
    }
}

/// A user leaf row.
///
/// Taken from `PSY_OBJECT_FFS_SIZE_USER_LEAF` and the writer's own
/// `object_id_location`, not from the shape the name suggests: the id sits at
/// offset 96 inside a 104-byte row, not at its start.  An earlier draft assumed
/// `id + hash` and would have read every row at the wrong stride and every user
/// id from the wrong bytes -- planning rows that do not exist while missing the
/// ones that do.
const USER_LEAF_ENTRY_LEN: usize = 104;
const USER_LEAF_ID_OFFSET: usize = 96;

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_core::store::commit_planner::CollectingPhysicalMutationSink;

    fn inputs<'a>(
        user_leaves: &'a [u8],
        contract_state: &'a [u8],
        imt: &'a [u8],
    ) -> RealmCommitPlanInputs<'a> {
        RealmCommitPlanInputs {
            checkpoint_id: 41,
            unique_pending_id: 77,
            realm_id: 0,
            update_user_leaves_ffs: user_leaves,
            update_user_contract_tree_nodes_ffs: &[],
            update_contract_state_tree_nodes_ffs: contract_state,
            update_contract_state_imt_leaves_ffs: imt,
            update_global_user_tree_nodes_ffs: &[],
        }
    }

    #[test]
    fn one_imt_entry_plans_a_leaf_an_index_and_a_cursor() {
        // The index and cursor writes appear nowhere in the blob's shape; a
        // planner that recorded only what the blob obviously contains would leave
        // both unrecorded, which is the I5 case.
        let entry = vec![0u8; IMT_LEAF_ENTRY_LEN];
        let sink = CollectingPhysicalMutationSink::new();
        ScyllaRealmCommitPlanner::new()
            .plan_realm_commit(&inputs(&[], &[], &entry), &sink)
            .expect("a well-formed entry plans");
        let rows = sink.take();
        let tables: Vec<u16> = rows.iter().map(|(table, _)| *table).collect();
        for expected in [
            ScyllaPhysicalTableId::ImtLeaf,
            ScyllaPhysicalTableId::ImtKeyIndex,
            ScyllaPhysicalTableId::ImtNextAppendIndex,
        ] {
            assert!(
                tables.contains(&(expected as u16)),
                "{expected:?} was not planned for an IMT entry"
            );
        }
    }

    #[test]
    fn one_cursor_row_per_tree_pair_not_per_entry() {
        // Two leaves in one tree advance one cursor.  Recording it twice would be
        // harmless but recording it per entry hides whether the planner
        // understands that the cursor is per pair.
        let mut blob = vec![0u8; IMT_LEAF_ENTRY_LEN * 2];
        blob[IMT_LEAF_ENTRY_LEN + 16..IMT_LEAF_ENTRY_LEN + 24]
            .copy_from_slice(&7u64.to_le_bytes());
        let sink = CollectingPhysicalMutationSink::new();
        ScyllaRealmCommitPlanner::new()
            .plan_realm_commit(&inputs(&[], &[], &blob), &sink)
            .expect("plans");
        let cursors = sink
            .take()
            .into_iter()
            .filter(|(table, _)| *table == ScyllaPhysicalTableId::ImtNextAppendIndex as u16)
            .count();
        assert_eq!(cursors, 1);
    }

    #[test]
    fn the_contract_state_pair_is_ordered() {
        // (user, contract) and (contract, user) are both pairs of u64 and name
        // different partitions; only the locator distinguishes them.
        let mut node = vec![0u8; DOUBLE_MERKLE_NODE_LEN];
        node[0..8].copy_from_slice(&5u64.to_le_bytes());
        node[8..16].copy_from_slice(&9u64.to_le_bytes());
        let mut swapped = node.clone();
        swapped[0..8].copy_from_slice(&9u64.to_le_bytes());
        swapped[8..16].copy_from_slice(&5u64.to_le_bytes());

        let first = CollectingPhysicalMutationSink::new();
        ScyllaRealmCommitPlanner::new()
            .plan_realm_commit(&inputs(&[], &node, &[]), &first)
            .expect("plans");
        let second = CollectingPhysicalMutationSink::new();
        ScyllaRealmCommitPlanner::new()
            .plan_realm_commit(&inputs(&[], &swapped, &[]), &second)
            .expect("plans");
        assert_ne!(first.take(), second.take());
    }

    #[test]
    fn a_user_leaf_id_is_read_from_the_writer_s_offset() {
        // The id sits at offset 96 of a 104-byte row, not at its start.  Reading
        // it from the wrong place plans a real table with fabricated ids, which
        // deletes nothing and leaves the real rows behind.
        let mut row = vec![0u8; USER_LEAF_ENTRY_LEN];
        row[..8].copy_from_slice(&9_999u64.to_le_bytes());
        row[USER_LEAF_ID_OFFSET..USER_LEAF_ID_OFFSET + 8].copy_from_slice(&7u64.to_le_bytes());

        let sink = CollectingPhysicalMutationSink::new();
        ScyllaRealmCommitPlanner::new()
            .plan_realm_commit(&inputs(&row, &[], &[]), &sink)
            .expect("plans");
        let planned = sink.take();
        let expected = describe_existing_key(&TypedTableKey::UserLeaf {
            user: psy_node_core::store::typed::UserId::new(7),
            checkpoint: CheckpointId::try_new(41).unwrap(),
        });
        assert!(
            planned
                .iter()
                .any(|(_, locator)| locator.as_slice() == expected.locator_bytes()),
            "the planned user leaf does not name user 7"
        );
    }

    #[test]
    fn a_blob_that_is_not_a_whole_number_of_rows_is_refused() {
        // A wrong stride reads plausible garbage: it plans rows that do not exist
        // and, worse, misses rows that do.
        let sink = CollectingPhysicalMutationSink::new();
        assert!(
            ScyllaRealmCommitPlanner::new()
                .plan_realm_commit(&inputs(&[], &vec![0u8; DOUBLE_MERKLE_NODE_LEN + 1], &[]), &sink)
                .is_err()
        );
    }
}
