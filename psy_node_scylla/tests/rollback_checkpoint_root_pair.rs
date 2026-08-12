use std::collections::BTreeMap;

use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs},
    typed::{
        CheckpointId, CheckpointLeafKey, CheckpointRootKey, LogicalMutation, ProcCheckpointUniqueId,
        UniquePendingId,
    },
};
use psy_node_scylla::{compression, rollback::*};

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
}

fn fence(value: i64) -> DeleteFenceTimestampUs {
    DeleteFenceTimestampUs::try_after(timestamp(value - 1), value as i128).unwrap()
}

fn root_intent(root: &[u8], checkpoint_id: u64) -> LogicalMutation {
    LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(root.to_vec()),
        checkpoint: checkpoint(checkpoint_id),
    }
}

fn sealed(root: &[u8], checkpoint_id: u64, ts: i64) -> SealedTimestampedPutBatch {
    seal_commit_put_batch(root_intent(root, checkpoint_id), timestamp(ts)).unwrap()
}

#[test]
fn two_active_directions_and_two_retired_leaf_directions_are_exact() {
    let k1 = physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1);
    let k2 = physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2);
    assert_eq!(
        CheckpointRootPairDirection::RootToCheckpoint.physical_table(),
        k1.id
    );
    assert_eq!(
        CheckpointRootPairDirection::CheckpointToRoot.physical_table(),
        k2.id
    );
    assert_eq!(k1.readiness, RegistryReadiness::Ready);
    assert_eq!(k2.readiness, RegistryReadiness::Ready);
    assert_eq!(
        k1.delete_candidates,
        &[DeleteStrategy::Point, DeleteStrategy::SnapshotOnly]
    );
    assert_eq!(
        k2.delete_candidates,
        &[
            DeleteStrategy::VersionPartition,
            DeleteStrategy::SnapshotOnly,
        ]
    );
    for retired in [
        ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1,
        ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK2,
    ] {
        assert_eq!(
            physical_descriptor(retired).readiness,
            RegistryReadiness::RetireCandidate
        );
    }
}

#[test]
fn query_catalog_uses_both_real_physical_names_and_matches_golden() {
    let queries =
        CheckpointRootPairQueries::new(&CqlKeyspaceName::try_new("psy_d02t4").unwrap());
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_checkpoint_root_pair_v1.txt")
    );
    for query in [
        queries.k1_put(),
        queries.k2_put(),
        queries.k1_delete(),
        queries.k2_delete(),
    ] {
        assert!(query.cql().contains("USING TIMESTAMP ?"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
    for query in [queries.k1_exact_read(), queries.k2_exact_read()] {
        assert_eq!(query.kind(), CheckpointRootPairQueryKind::ExactRead);
        assert!(query.cql().starts_with("SELECT value, writetime(value) FROM "));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
    assert!(queries
        .k1_put()
        .cql()
        .contains("checkpoint_root_to_checkpoint_id_table_k1"));
    assert!(queries
        .k2_put()
        .cql()
        .contains("checkpoint_root_to_checkpoint_id_table_k2"));
}

#[test]
fn sealed_pair_is_consistent_timestamped_and_uses_the_real_blob_codec() {
    let root = [0xa1; 32];
    let sealed = sealed(&root, 7, 1_000);
    let plan = CheckpointRootPairPutPlan::try_from_sealed(&sealed).unwrap();
    let retry = CheckpointRootPairPutPlan::try_from_sealed(&sealed).unwrap();
    assert_eq!(plan, retry);
    assert_eq!(plan.root(), &root);
    assert_eq!(plan.checkpoint(), checkpoint(7));
    assert_eq!(plan.write_timestamp_us(), 1_000);
    assert_eq!(plan.intent_digest(), sealed.intent_digest());
    assert_eq!(
        plan.expected_canonical_values(),
        [7_u64.to_le_bytes().to_vec(), root.to_vec()]
    );

    let k1 = plan.k1_bind_values();
    let k2 = plan.k2_bind_values();
    assert_eq!(k1[0], PrototypeBindValue::Blob(root.to_vec()));
    assert_eq!(k2[0], PrototypeBindValue::Blob(7_u64.to_le_bytes().to_vec()));
    let PrototypeBindValue::Blob(k1_value) = &k1[1] else {
        panic!("k1 value must be a blob")
    };
    let PrototypeBindValue::Blob(k2_value) = &k2[1] else {
        panic!("k2 value must be a blob")
    };
    assert!(k1_value.starts_with(b"PSZ1"));
    assert!(k2_value.starts_with(b"PSZ1"));
    assert_eq!(
        compression::decompress(k1_value).unwrap(),
        7_u64.to_le_bytes()
    );
    assert_eq!(compression::decompress(k2_value).unwrap(), root);
    assert_eq!(k1[2], PrototypeBindValue::BigInt(1_000));
    assert_eq!(k2[2], PrototypeBindValue::BigInt(1_000));
}

#[test]
fn pair_requires_batch_sealing_exact_shape_and_a_32_byte_root() {
    let intent = root_intent(&[1; 32], 7);
    assert!(matches!(
        seal_commit_put(intent, timestamp(100)),
        Err(TimestampedMutationError::ExpectedOnePhysicalMutation { actual: 2 })
    ));
    assert!(matches!(
        CheckpointRootPairPutPlan::try_from_sealed(&sealed(&[1; 31], 7, 100)),
        Err(CheckpointRootPairPlanError::InvalidRootLength { actual: 31 })
    ));

    let pending_pair = seal_commit_put_batch(
        LogicalMutation::PendingProcMapping {
            pending: UniquePendingId::try_new(1).unwrap(),
            proc_id: ProcCheckpointUniqueId::from_bytes([2; 16]),
        },
        timestamp(100),
    )
    .unwrap();
    assert!(matches!(
        CheckpointRootPairPutPlan::try_from_sealed(&pending_pair),
        Err(CheckpointRootPairPlanError::WrongPhysicalTable { .. })
    ));
}

#[test]
fn retired_checkpoint_leaf_pair_cannot_become_executable() {
    let result = seal_commit_put_batch(
        LogicalMutation::CheckpointLeafMapping {
            leaf: CheckpointLeafKey::new(vec![3; 32]),
            checkpoint: checkpoint(8),
        },
        timestamp(100),
    );
    assert!(result.is_err());
}

#[test]
fn delete_plan_always_contains_orphan_root_and_reused_checkpoint_partition() {
    let root = CheckpointRootKey::new(vec![0x41; 32]);
    let plan = CheckpointRootPairDeletePlan::try_new(root, checkpoint(100), fence(2_000))
        .unwrap();
    assert_eq!(plan.root(), &[0x41; 32]);
    assert_eq!(plan.checkpoint(), checkpoint(100));
    assert_eq!(plan.fence().as_i64(), 2_000);
    assert_eq!(
        plan.k1_bind_values(),
        vec![
            PrototypeBindValue::BigInt(2_000),
            PrototypeBindValue::Blob(vec![0x41; 32]),
        ]
    );
    assert_eq!(
        plan.k2_bind_values(),
        vec![
            PrototypeBindValue::BigInt(2_000),
            PrototypeBindValue::Blob(100_u64.to_le_bytes().to_vec()),
        ]
    );
    assert!(matches!(
        CheckpointRootPairDeletePlan::try_new(
            CheckpointRootKey::new(vec![0; 31]),
            checkpoint(100),
            fence(2_000),
        ),
        Err(CheckpointRootPairPlanError::InvalidRootLength { actual: 31 })
    ));
}

#[derive(Clone, Debug)]
struct LwwCell {
    timestamp: i64,
    value: Option<Vec<u8>>,
}

fn apply_lww(
    cells: &mut BTreeMap<Vec<u8>, LwwCell>,
    key: Vec<u8>,
    timestamp: i64,
    value: Option<Vec<u8>>,
) {
    if cells
        .get(&key)
        .is_none_or(|current| timestamp > current.timestamp)
    {
        cells.insert(key, LwwCell { timestamp, value });
    }
}

#[test]
fn orphan_root_cannot_resurrect_when_height_is_reused() {
    let old_root = vec![0x11; 32];
    let new_root = vec![0x22; 32];
    let checkpoint_key = 100_u64.to_le_bytes().to_vec();
    let mut k1 = BTreeMap::new();
    let mut k2 = BTreeMap::new();

    apply_lww(&mut k1, old_root.clone(), 100, Some(checkpoint_key.clone()));
    apply_lww(&mut k2, checkpoint_key.clone(), 100, Some(old_root.clone()));
    apply_lww(&mut k1, old_root.clone(), 200, None);
    apply_lww(&mut k2, checkpoint_key.clone(), 200, None);

    // A late retry from the discarded branch retains its old timestamp.
    apply_lww(&mut k1, old_root.clone(), 100, Some(checkpoint_key.clone()));
    apply_lww(&mut k2, checkpoint_key.clone(), 100, Some(old_root.clone()));
    apply_lww(&mut k1, new_root.clone(), 300, Some(checkpoint_key.clone()));
    apply_lww(&mut k2, checkpoint_key.clone(), 300, Some(new_root.clone()));

    assert_eq!(k1.get(&old_root).unwrap().value, None);
    assert_eq!(
        k1.get(&new_root).unwrap().value.as_deref(),
        Some(checkpoint_key.as_slice())
    );
    assert_eq!(
        k2.get(&checkpoint_key).unwrap().value.as_deref(),
        Some(new_root.as_slice())
    );
}

#[test]
fn d02t4_is_logged_pair_only_and_not_wired_into_production() {
    let adapter = include_str!("../src/rollback/checkpoint_root_pair.rs");
    let legacy = include_str!("../src/tables/blob.rs");
    let setup = include_str!("../src/psy_setup.rs");
    let core_db = include_str!("../src/core_db.rs");
    assert!(adapter.contains("BatchType::Logged"));
    assert!(adapter.contains("append_statement(self.prepared.k1_put.clone())"));
    assert!(adapter.contains("append_statement(self.prepared.k2_put.clone())"));
    assert!(adapter.contains("append_statement(self.prepared.k1_delete.clone())"));
    assert!(adapter.contains("append_statement(self.prepared.k2_delete.clone())"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!legacy.contains("DELETE FROM"));
    assert!(!setup.contains("CheckpointRootPairAdapter"));
    assert!(!core_db.contains("CheckpointRootPairAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
