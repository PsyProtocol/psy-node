use parth_core::{protocol::core_types::Q256BitHash, PHash, PF};
use psy_data::v1::qdata::contract::encode_imt_key_for_sorting;
use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs},
    typed::{
        CheckpointId, LeafIndex, LogicalMutation, MutationValue, StructuredValueSchema, TreeId,
        TreeSubId, TypedTableKey,
    },
};
use psy_node_scylla::rollback::*;

fn checkpoint(value: u64) -> CheckpointId { CheckpointId::try_new(value).unwrap() }
fn timestamp(value: i64) -> CommitWriteTimestampUs { CommitWriteTimestampUs::try_from_i128(value as i128).unwrap() }
fn fence(write: i64, value: i64) -> DeleteFenceTimestampUs { DeleteFenceTimestampUs::try_after(timestamp(write), value as i128).unwrap() }

#[allow(clippy::too_many_arguments)]
fn row(
    tree: u64,
    tree_sub: u64,
    leaf: u64,
    leaf_hash: [u8; 32],
    leaf_key: [u8; 32],
    leaf_value: [u8; 32],
    next_key: [u8; 32],
    next_index: u64,
    is_new: bool,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 161];
    bytes[0..8].copy_from_slice(&tree.to_le_bytes());
    bytes[8..16].copy_from_slice(&tree_sub.to_le_bytes());
    bytes[16..24].copy_from_slice(&leaf.to_le_bytes());
    bytes[24..56].copy_from_slice(&leaf_hash);
    bytes[56..88].copy_from_slice(&leaf_key);
    bytes[88..120].copy_from_slice(&leaf_value);
    bytes[120..152].copy_from_slice(&next_key);
    bytes[152..160].copy_from_slice(&next_index.to_le_bytes());
    bytes[160] = u8::from(is_new);
    bytes
}

fn seal_leaf(tree: u64, tree_sub: u64, leaf: u64, cp: u64, row: Vec<u8>, ts: i64) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::ImtLeaf {
                tree: TreeId::new(tree), tree_sub: TreeSubId::new(tree_sub),
                leaf: LeafIndex::new(leaf), checkpoint: checkpoint(cp),
            },
            value: MutationValue::Structured { schema: StructuredValueSchema::ImtLeafRowV1, canonical_bytes: row },
        },
        timestamp(ts),
    ).unwrap()
}

#[test]
fn registry_keeps_the_three_distinct_imt_rollback_semantics() {
    let leaf = physical_descriptor(ScyllaPhysicalTableId::ImtLeaf);
    let index = physical_descriptor(ScyllaPhysicalTableId::ImtKeyIndex);
    let cursor = physical_descriptor(ScyllaPhysicalTableId::ImtNextAppendIndex);
    assert_eq!(leaf.version_axis, VersionAxis::CheckpointClustering);
    assert_eq!(leaf.rollback_policy, RollbackPolicy::ArchiveVersioned);
    assert_eq!(leaf.delete_candidates, &[DeleteStrategy::Point, DeleteStrategy::BoundedRange, DeleteStrategy::SnapshotOnly]);
    assert_eq!(index.version_axis, VersionAxis::ImtBirthOrdinaryColumn);
    assert_eq!(index.rollback_policy, RollbackPolicy::DerivedBirth);
    assert_eq!(cursor.version_axis, VersionAxis::MutableCursor);
    assert_eq!(cursor.rollback_policy, RollbackPolicy::RestoreSingleton);
    assert!(cursor.delete_candidates.is_empty());
}

#[test]
fn query_catalog_matches_all_three_real_schemas() {
    let queries = ImtQueries::new(&CqlKeyspaceName::try_new("psy_d02t6").unwrap());
    assert_eq!(queries.render_golden(), include_str!("golden/rollback_imt_family_v1.txt"));
    for query in [queries.leaf_put(), queries.leaf_point_delete(), queries.leaf_range_delete(), queries.index_put(), queries.index_point_delete(), queries.cursor_put()] {
        assert!(query.cql().contains("USING TIMESTAMP ?"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
}

#[test]
fn raw_key_sort_encoding_matches_the_existing_network_codec() {
    let mut raw = [0_u8; 32];
    raw[0..8].copy_from_slice(&1_u64.to_le_bytes());
    raw[8..16].copy_from_slice(&2_u64.to_le_bytes());
    raw[16..24].copy_from_slice(&3_u64.to_le_bytes());
    raw[24..32].copy_from_slice(&4_u64.to_le_bytes());
    let hash = PHash::from_owned_32bytes(raw);
    assert_eq!(encode_raw_imt_key_for_sorting(raw), encode_imt_key_for_sorting::<PF, PHash>(&hash));
}

#[test]
fn one_plan_dedupes_checkpoint_final_leaf_and_derives_index_and_cursor() {
    let key = [0x31; 32];
    let newest = seal_leaf(9, 2, 3, 50, row(9, 2, 3, [1; 32], key, [2; 32], [3; 32], 8, true), 1_000);
    let older_same_leaf = seal_leaf(9, 2, 3, 50, row(9, 2, 3, [4; 32], key, [5; 32], [6; 32], 7, false), 1_000);
    let another_leaf = seal_leaf(9, 2, 7, 50, row(9, 2, 7, [7; 32], [8; 32], [9; 32], [10; 32], 9, false), 1_000);
    let before = [ImtCursorSnapshot::new(TreeId::new(9), TreeSubId::new(2), 4)];
    let plan = ImtCheckpointWritePlan::try_from_sealed_leaves(&[newest.clone(), older_same_leaf, another_leaf], &before).unwrap();
    let retry = ImtCheckpointWritePlan::try_from_sealed_leaves(&[newest, seal_leaf(9, 2, 3, 50, row(9, 2, 3, [4; 32], key, [5; 32], [6; 32], 7, false), 1_000), seal_leaf(9, 2, 7, 50, row(9, 2, 7, [7; 32], [8; 32], [9; 32], [10; 32], 9, false), 1_000)], &before).unwrap();
    assert_eq!(plan, retry);
    assert_eq!(plan.checkpoint(), checkpoint(50));
    assert_eq!(plan.leaf_puts().len(), 2);
    assert_eq!(plan.leaf_puts()[0].leaf(), LeafIndex::new(3));
    assert_eq!(plan.leaf_puts()[0].next_index(), 8);
    assert_eq!(plan.index_puts().len(), 1);
    assert_eq!(plan.index_puts()[0].birth_checkpoint(), checkpoint(50));
    assert_eq!(plan.index_puts()[0].leaf(), LeafIndex::new(3));
    assert_eq!(plan.cursor_puts().len(), 1);
    assert_eq!(plan.cursor_puts()[0].before().next_append_index(), 4);
    assert_eq!(plan.cursor_puts()[0].after().next_append_index(), 8);
    assert_ne!(plan.digest().as_bytes(), &[0; 32]);
}

#[test]
fn zero_sentinel_derives_an_index_even_without_the_new_key_flag() {
    let sentinel = seal_leaf(
        3,
        4,
        0,
        5,
        row(3, 4, 0, [1; 32], [0; 32], [0; 32], [0; 32], 0, false),
        100,
    );
    let plan = ImtCheckpointWritePlan::try_from_sealed_leaves(
        &[sentinel],
        &[ImtCursorSnapshot::new(TreeId::new(3), TreeSubId::new(4), 0)],
    )
    .unwrap();
    assert_eq!(plan.index_puts().len(), 1);
    assert_eq!(plan.index_puts()[0].leaf(), LeafIndex::new(0));
}

#[test]
fn leaf_row_key_timestamp_checkpoint_and_cursor_coverage_fail_closed() {
    let good_row = row(1, 2, 3, [1; 32], [2; 32], [3; 32], [4; 32], 4, false);
    assert!(matches!(
        ImtLeafPutBinding::try_from_sealed(&seal_leaf(1, 2, 4, 10, good_row.clone(), 100)),
        Err(ImtPlanError::LeafKeyRowMismatch)
    ));
    let truncated = seal_leaf(1, 2, 3, 10, good_row[..160].to_vec(), 100);
    assert!(matches!(ImtLeafPutBinding::try_from_sealed(&truncated), Err(ImtPlanError::InvalidLeafRowLength { actual: 160 })));

    let a = seal_leaf(1, 2, 3, 10, good_row.clone(), 100);
    let different_checkpoint = seal_leaf(1, 2, 4, 11, row(1, 2, 4, [1; 32], [2; 32], [3; 32], [4; 32], 5, false), 100);
    let different_timestamp = seal_leaf(1, 2, 4, 10, row(1, 2, 4, [1; 32], [2; 32], [3; 32], [4; 32], 5, false), 101);
    let snapshot = [ImtCursorSnapshot::new(TreeId::new(1), TreeSubId::new(2), 0)];
    assert!(matches!(ImtCheckpointWritePlan::try_from_sealed_leaves(&[a.clone(), different_checkpoint], &snapshot), Err(ImtPlanError::MixedCheckpoints { .. })));
    assert!(matches!(ImtCheckpointWritePlan::try_from_sealed_leaves(&[a.clone(), different_timestamp], &snapshot), Err(ImtPlanError::MixedWriteTimestamps { .. })));
    assert!(matches!(ImtCheckpointWritePlan::try_from_sealed_leaves(&[a.clone()], &[]), Err(ImtPlanError::CursorBeforeImageCoverage)));
    let extra = [snapshot[0], ImtCursorSnapshot::new(TreeId::new(9), TreeSubId::new(9), 0)];
    assert!(matches!(ImtCheckpointWritePlan::try_from_sealed_leaves(&[a.clone()], &extra), Err(ImtPlanError::CursorBeforeImageCoverage)));
    assert!(matches!(ImtCheckpointWritePlan::try_from_sealed_leaves(&[a], &[snapshot[0], snapshot[0]]), Err(ImtPlanError::DuplicateCursorBeforeImage)));
}

#[test]
fn leaf_and_index_delete_require_orphan_birth_and_complete_keys() {
    let sealed = seal_leaf(5, 6, 7, 101, row(5, 6, 7, [1; 32], [2; 32], [3; 32], [4; 32], 8, true), 1_000);
    let plan = ImtCheckpointWritePlan::try_from_sealed_leaves(&[sealed], &[ImtCursorSnapshot::new(TreeId::new(5), TreeSubId::new(6), 7)]).unwrap();
    let delete_fence = fence(1_000, 2_000);
    let leaf = ImtLeafPointDeletePlan::try_from_orphaned_version(&plan.leaf_puts()[0], checkpoint(100), delete_fence).unwrap();
    let index = ImtIndexPointDeletePlan::try_from_orphaned_birth(&plan.index_puts()[0], checkpoint(100), delete_fence).unwrap();
    assert_eq!(leaf.bind_values().len(), 5);
    assert_eq!(index.bind_values().len(), 5);
    assert!(matches!(ImtLeafPointDeletePlan::try_from_orphaned_version(&plan.leaf_puts()[0], checkpoint(101), delete_fence), Err(ImtPlanError::VersionNotAfterTarget { .. })));
    assert!(matches!(ImtIndexPointDeletePlan::try_from_orphaned_birth(&plan.index_puts()[0], checkpoint(101), delete_fence), Err(ImtPlanError::VersionNotAfterTarget { .. })));
    let stale_fence = fence(999, 1_000);
    assert!(matches!(ImtLeafPointDeletePlan::try_from_orphaned_version(&plan.leaf_puts()[0], checkpoint(100), stale_fence), Err(ImtPlanError::FenceNotAfterWrite { .. })));
    assert!(matches!(ImtIndexPointDeletePlan::try_from_orphaned_birth(&plan.index_puts()[0], checkpoint(100), stale_fence), Err(ImtPlanError::FenceNotAfterWrite { .. })));

    let range = ImtLeafBoundedRangeDeletePlan::try_new(TreeId::new(5), TreeSubId::new(6), LeafIndex::new(7), checkpoint(100), checkpoint(120), delete_fence).unwrap();
    assert_eq!(range.bind_values().len(), 6);
    assert!(matches!(ImtLeafBoundedRangeDeletePlan::try_new(TreeId::new(5), TreeSubId::new(6), LeafIndex::new(7), checkpoint(100), checkpoint(100), delete_fence), Err(ImtPlanError::InvalidRange { .. })));
}

#[test]
fn cursor_restore_requires_a_post_fence_new_branch_timestamp() {
    let delete_fence = fence(1_000, 2_000);
    let new_branch = NewBranchWriteTimestampUs::try_after(delete_fence, 3_000).unwrap();
    let target = ImtCursorSnapshot::new(TreeId::new(8), TreeSubId::new(9), 12);
    let plan = ImtCursorRestorePlan::try_new(checkpoint(100), target, new_branch).unwrap();
    assert_eq!(plan.target_checkpoint(), checkpoint(100));
    assert_eq!(plan.target(), target);
    assert_eq!(plan.write_timestamp_us(), 3_000);
    assert_eq!(plan.bind_values()[2], PrototypeBindValue::BigInt(12));
}

#[test]
fn d02t6_remains_isolated_from_the_legacy_indirect_writer() {
    let adapter = include_str!("../src/rollback/imt_family.rs");
    let legacy = include_str!("../../psy_node_core/src/psy_core_db/v3_implementation/full.rs");
    let setup = include_str!("../src/psy_setup.rs");
    assert!(adapter.contains("ImtCheckpointWritePlan"));
    assert!(adapter.contains("put_leaf"));
    assert!(adapter.contains("put_index"));
    assert!(adapter.contains("put_cursor"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!legacy.contains("ImtFamilyAdapter"));
    assert!(!setup.contains("ImtFamilyAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
