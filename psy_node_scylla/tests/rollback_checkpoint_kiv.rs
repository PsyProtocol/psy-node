use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs},
    typed::{
        CheckpointId, LatestInfoSlot, LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        TypedTableKey,
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

fn key(table: CheckpointKivTable, value: u64) -> TypedTableKey {
    let checkpoint = checkpoint(value);
    match table {
        CheckpointKivTable::CheckpointLeaf => TypedTableKey::CheckpointLeaf(checkpoint),
        CheckpointKivTable::L2BlockState => TypedTableKey::L2BlockState(checkpoint),
        CheckpointKivTable::CheckpointStateRoots => {
            TypedTableKey::CheckpointStateRoots(checkpoint)
        }
        CheckpointKivTable::CheckpointZkProofAndTransition => {
            TypedTableKey::CheckpointZkProof(checkpoint)
        }
    }
}

fn sealed(table: CheckpointKivTable, checkpoint: u64, value: &[u8], ts: i64) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: key(table, checkpoint),
            value: MutationValue::PsyCanonicalBytes(value.to_vec()),
        },
        timestamp(ts),
    )
    .unwrap()
}

#[test]
fn active_checkpoint_kiv_set_is_exact_and_registry_backed() {
    assert_eq!(CHECKPOINT_KIV_TABLES.len(), 4);
    assert_eq!(
        CHECKPOINT_KIV_TABLES.map(CheckpointKivTable::physical_table),
        [
            ScyllaPhysicalTableId::CheckpointLeaf,
            ScyllaPhysicalTableId::L2BlockState,
            ScyllaPhysicalTableId::CheckpointStateRoots,
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
        ]
    );
    for table in CHECKPOINT_KIV_TABLES {
        let descriptor = physical_descriptor(table.physical_table());
        assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::Kiv);
        assert_eq!(descriptor.version_axis, VersionAxis::CheckpointPartition);
        assert_eq!(
            descriptor.delete_candidates,
            &[
                DeleteStrategy::VersionPartition,
                DeleteStrategy::SnapshotOnly,
            ]
        );
        assert_eq!(descriptor.rollback_policy, RollbackPolicy::ArchiveVersioned);
        assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
    }
}

#[test]
fn closed_query_catalog_matches_golden_and_always_binds_timestamp() {
    let queries = CheckpointKivQueries::new(&CqlKeyspaceName::try_new("psy_d02t1").unwrap());
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_checkpoint_kiv_v1.txt")
    );
    assert_eq!(queries.all().len(), 4);
    for table in CHECKPOINT_KIV_TABLES {
        let queries = queries.for_table(table);
        assert_eq!(queries.table(), table);
        assert!(queries.put().cql().contains("USING TIMESTAMP ?"));
        assert_eq!(queries.put().cql().matches('?').count(), 3);
        assert_eq!(
            queries.put().bind_shape(),
            ["obj_id:BIGINT", "value:BLOB", "write_timestamp_us:BIGINT"]
        );
        assert!(queries
            .version_partition_delete()
            .cql()
            .contains("USING TIMESTAMP ? WHERE obj_id = ?"));
        assert_eq!(
            queries.version_partition_delete().cql().matches('?').count(),
            2
        );
        assert_eq!(
            queries.version_partition_delete().bind_shape(),
            ["delete_fence_us:BIGINT", "obj_id:BIGINT"]
        );
        assert_eq!(queries.exact_read().kind(), CheckpointKivQueryKind::ExactRead);
        assert!(queries.exact_read().cql().contains("writetime(value)"));
        assert_eq!(queries.exact_read().bind_shape(), ["obj_id:BIGINT"]);
    }
}

#[test]
fn all_four_put_bindings_use_the_existing_kiv_codec_and_stable_order() {
    for (index, table) in CHECKPOINT_KIV_TABLES.into_iter().enumerate() {
        let canonical = vec![index as u8, 7, 8, 9];
        let sealed = sealed(table, 42 + index as u64, &canonical, 1_000);
        let first = CheckpointKivPutBinding::try_from_sealed(&sealed).unwrap();
        let second = CheckpointKivPutBinding::try_from_sealed(&sealed).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.table(), table);
        assert_eq!(first.checkpoint(), checkpoint(42 + index as u64));
        assert_eq!(first.write_timestamp_us(), 1_000);

        let values = first.bind_values();
        assert_eq!(values.len(), 3);
        assert_eq!(
            values[0],
            PrototypeBindValue::BigInt((42 + index as u64) as i64)
        );
        let PrototypeBindValue::Blob(stored) = &values[1] else {
            panic!("expected compressed KIV BLOB")
        };
        assert_eq!(compression::decompress(stored).unwrap(), canonical);
        assert_eq!(values[2], PrototypeBindValue::BigInt(1_000));
    }
}

#[test]
fn all_four_version_partition_deletes_require_typed_key_and_fence() {
    for (index, table) in CHECKPOINT_KIV_TABLES.into_iter().enumerate() {
        let plan = CheckpointKivVersionDeletePlan::try_new(
            key(table, 100 + index as u64),
            fence(2_000),
        )
        .unwrap();
        assert_eq!(plan.table(), table);
        assert_eq!(plan.checkpoint(), checkpoint(100 + index as u64));
        assert_eq!(plan.fence().as_i64(), 2_000);
        assert_eq!(
            plan.bind_values(),
            vec![
                PrototypeBindValue::BigInt(2_000),
                PrototypeBindValue::BigInt((100 + index as u64) as i64),
            ]
        );
    }
}

#[test]
fn same_table_same_timestamp_batch_is_deterministic() {
    let rows = vec![
        sealed(CheckpointKivTable::L2BlockState, 7, &[1], 3_000),
        sealed(CheckpointKivTable::L2BlockState, 8, &[2], 3_000),
        sealed(CheckpointKivTable::L2BlockState, 9, &[3], 3_000),
    ];
    let first = CheckpointKivPutBatch::try_from_sealed(&rows).unwrap();
    let second = CheckpointKivPutBatch::try_from_sealed(&rows).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.table(), CheckpointKivTable::L2BlockState);
    assert_eq!(first.write_timestamp_us(), 3_000);
    assert_eq!(first.members().len(), 3);
    assert_eq!(
        first
            .members()
            .iter()
            .map(CheckpointKivPutBinding::checkpoint)
            .collect::<Vec<_>>(),
        vec![checkpoint(7), checkpoint(8), checkpoint(9)]
    );
}

#[test]
fn empty_mixed_table_and_mixed_timestamp_batches_fail_closed() {
    assert_eq!(
        CheckpointKivPutBatch::try_from_sealed(&[]),
        Err(CheckpointKivPlanError::EmptyBatch)
    );

    let mixed_table = vec![
        sealed(CheckpointKivTable::CheckpointLeaf, 1, &[1], 10),
        sealed(CheckpointKivTable::CheckpointStateRoots, 1, &[1], 10),
    ];
    assert!(matches!(
        CheckpointKivPutBatch::try_from_sealed(&mixed_table),
        Err(CheckpointKivPlanError::MixedPhysicalTables { .. })
    ));

    let mixed_timestamp = vec![
        sealed(CheckpointKivTable::CheckpointLeaf, 1, &[1], 10),
        sealed(CheckpointKivTable::CheckpointLeaf, 2, &[1], 11),
    ];
    assert_eq!(
        CheckpointKivPutBatch::try_from_sealed(&mixed_timestamp),
        Err(CheckpointKivPlanError::MixedWriteTimestamps {
            expected: 10,
            actual: 11,
        })
    );

    let duplicate = sealed(CheckpointKivTable::CheckpointLeaf, 1, &[1], 10);
    assert_eq!(
        CheckpointKivPutBatch::try_from_sealed(&[duplicate.clone(), duplicate]),
        Err(CheckpointKivPlanError::DuplicatePhysicalKey)
    );
}

#[test]
fn sibling_kiv_and_other_families_cannot_reach_checkpoint_kiv_adapter() {
    let latest = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        timestamp(10),
    )
    .unwrap();
    assert!(matches!(
        CheckpointKivPutBinding::try_from_sealed(&latest),
        Err(CheckpointKivPlanError::UnsupportedPhysicalTable(
            ScyllaPhysicalTableId::LatestInfo
        ))
    ));
    assert!(matches!(
        CheckpointKivVersionDeletePlan::try_new(
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            fence(20)
        ),
        Err(CheckpointKivPlanError::UnsupportedPhysicalTable(
            ScyllaPhysicalTableId::LatestInfo
        ))
    ));

    assert!(matches!(
        CheckpointKivVersionDeletePlan::try_new(
            TypedTableKey::UnusedCheckpointRealmRoot(checkpoint(1)),
            fence(20)
        ),
        Err(CheckpointKivPlanError::RegistryReadiness(
            RegistryReadinessError::RetireCandidate
        ))
    ));

    let merkle = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::GlobalUserMerkle {
                node: MerkleNode::new(1, NodeIndex::new(2)),
                checkpoint: checkpoint(3),
            },
            value: MutationValue::PsyCanonicalBytes(vec![7; 32]),
        },
        timestamp(10),
    )
    .unwrap();
    assert!(matches!(
        CheckpointKivPutBinding::try_from_sealed(&merkle),
        Err(CheckpointKivPlanError::UnsupportedPhysicalTable(
            ScyllaPhysicalTableId::GlobalUserTree
        ))
    ));
}

#[test]
fn d02t1_is_not_wired_into_legacy_writers_or_promoted_to_full_capability() {
    assert_eq!(
        PRODUCTION_CQL_CAPABILITIES,
        ProductionCqlCapabilities {
            explicit_write_timestamp: false,
            delete_adapter: false,
        }
    );
    let setup = include_str!("../src/psy_setup.rs");
    let core_db = include_str!("../src/core_db.rs");
    let legacy_kiv = include_str!("../src/tables/object/kiv.rs");
    for source in [setup, core_db, legacy_kiv] {
        assert!(!source.contains("CheckpointKivAdapter"));
        assert!(!source.contains("CheckpointKivPutBatch"));
    }
    assert!(!legacy_kiv.contains("USING TIMESTAMP"));
    assert!(!legacy_kiv.contains("DELETE FROM"));
}
