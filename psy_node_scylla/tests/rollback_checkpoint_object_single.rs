use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs},
    typed::{
        CheckpointId, CheckpointedObjectKey, ContractId, LogicalMutation, MutationValue,
        RealmId, TypedTableKey, UniquePendingId, UserId, ValueDigestAlgorithm,
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

fn key(
    table: CheckpointObjectSingleTable,
    object_id: u64,
    checkpoint_id: u64,
) -> TypedTableKey {
    let checkpoint = checkpoint(checkpoint_id);
    match table {
        CheckpointObjectSingleTable::UserLeaf => TypedTableKey::UserLeaf {
            user: UserId::new(object_id),
            checkpoint,
        },
        CheckpointObjectSingleTable::UserPublicKey => TypedTableKey::UserPublicKey {
            user: UserId::new(object_id),
            checkpoint,
        },
        CheckpointObjectSingleTable::ContractStateTreeHeight => {
            TypedTableKey::ContractStateTreeHeight {
                contract: ContractId::new(object_id),
                checkpoint,
            }
        }
        CheckpointObjectSingleTable::ContractLeaf => TypedTableKey::ContractLeaf {
            contract: ContractId::new(object_id),
            checkpoint,
        },
        CheckpointObjectSingleTable::ContractCodeDefinition => {
            TypedTableKey::ContractCodeDefinition {
                contract: ContractId::new(object_id),
                checkpoint,
            }
        }
    }
}

fn sealed(
    table: CheckpointObjectSingleTable,
    object_id: u64,
    checkpoint_id: u64,
    value: &[u8],
    ts: i64,
) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: key(table, object_id, checkpoint_id),
            value: MutationValue::PsyCanonicalBytes(value.to_vec()),
        },
        timestamp(ts),
    )
    .unwrap()
}

#[test]
fn five_table_set_is_exact_ready_object_single_registry_subset() {
    assert_eq!(CHECKPOINT_OBJECT_SINGLE_TABLES.len(), 5);
    let object_single_descriptors = physical_registry()
        .into_iter()
        .filter(|descriptor| descriptor.schema_family == ScyllaSchemaFamily::ObjectSingle)
        .collect::<Vec<_>>();
    assert_eq!(object_single_descriptors.len(), 7);
    assert_eq!(
        object_single_descriptors
            .iter()
            .filter(|descriptor| descriptor.readiness == RegistryReadiness::Ready)
            .count(),
        5
    );
    assert_eq!(
        object_single_descriptors
            .iter()
            .filter(|descriptor| matches!(descriptor.readiness, RegistryReadiness::Blocked(_)))
            .map(|descriptor| descriptor.id)
            .collect::<Vec<_>>(),
        vec![
            ScyllaPhysicalTableId::CheckpointedObject,
            ScyllaPhysicalTableId::RealmRewardsTreeNodeKey,
        ]
    );
    let physical = CHECKPOINT_OBJECT_SINGLE_TABLES.map(|table| table.physical_table());
    assert_eq!(
        physical,
        [
            ScyllaPhysicalTableId::UserLeaf,
            ScyllaPhysicalTableId::UserPublicKey,
            ScyllaPhysicalTableId::ContractStateTreeHeight,
            ScyllaPhysicalTableId::ContractLeaf,
            ScyllaPhysicalTableId::ContractCodeDefinition,
        ]
    );
    for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
        let descriptor = physical_descriptor(table.physical_table());
        assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::ObjectSingle);
        assert_eq!(descriptor.version_axis, VersionAxis::CheckpointClustering);
        assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
        assert_eq!(
            descriptor.delete_candidates,
            &[
                DeleteStrategy::Point,
                DeleteStrategy::BoundedRange,
                DeleteStrategy::SnapshotOnly,
            ]
        );
    }
    assert!(!physical.contains(&ScyllaPhysicalTableId::CheckpointedObject));
    assert!(!physical.contains(&ScyllaPhysicalTableId::RealmRewardsTreeNodeKey));
}

#[test]
fn query_catalog_is_closed_timestamped_and_matches_golden() {
    let queries =
        CheckpointObjectSingleQueries::new(&CqlKeyspaceName::try_new("psy_d02t3").unwrap());
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_checkpoint_object_single_v1.txt")
    );
    assert_eq!(queries.all().len(), 5);
    for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
        let table_queries = queries.for_table(table);
        assert_eq!(table_queries.table(), table);
        for query in [
            table_queries.put(),
            table_queries.point_delete(),
            table_queries.bounded_range_delete(),
        ] {
            assert!(query.cql().contains("USING TIMESTAMP ?"));
            assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
        }
        assert!(table_queries
            .bounded_range_delete()
            .cql()
            .contains("obj_id = ? AND checkpoint_id > ? AND checkpoint_id <= ?"));
        assert_eq!(
            table_queries.exact_read().kind(),
            CheckpointObjectSingleQueryKind::ExactRead,
        );
        assert!(table_queries.exact_read().cql().contains("writetime(value)"));
        assert_eq!(
            table_queries.exact_read().bind_shape(),
            ["obj_id:BIGINT", "checkpoint_id:BIGINT"],
        );
    }
}

#[test]
fn put_uses_real_psz1_codec_complete_key_and_stable_binding() {
    let canonical = (0_u8..=255).collect::<Vec<_>>();
    let sealed = sealed(
        CheckpointObjectSingleTable::UserLeaf,
        u64::MAX,
        20,
        &canonical,
        1_000,
    );
    let first = CheckpointObjectSinglePutBinding::try_from_sealed(&sealed).unwrap();
    let second = CheckpointObjectSinglePutBinding::try_from_sealed(&sealed).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.object_id(), u64::MAX);
    assert_eq!(first.checkpoint(), checkpoint(20));
    assert_eq!(first.write_timestamp_us(), 1_000);
    assert!(first.compressed_value().starts_with(b"PSZ1"));
    assert_eq!(compression::decompress(first.compressed_value()).unwrap(), canonical);
    assert_eq!(
        first.bind_values(),
        vec![
            PrototypeBindValue::BigInt(-1),
            PrototypeBindValue::BigInt(20),
            PrototypeBindValue::Blob(first.compressed_value().to_vec()),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
}

#[test]
fn all_five_typed_keys_bind_complete_point_and_range_keys() {
    for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
        let put = CheckpointObjectSinglePutBinding::try_from_sealed(&sealed(
            table,
            table as u64 + 10,
            20,
            &[table as u8; 64],
            1_000,
        ))
        .unwrap();
        assert_eq!(put.table(), table);
        assert_eq!(put.object_id(), table as u64 + 10);

        let point = CheckpointObjectSinglePointDeletePlan::try_new(
            key(table, table as u64 + 10, 20),
            fence(2_000),
        )
        .unwrap();
        assert_eq!(
            point.bind_values(),
            vec![
                PrototypeBindValue::BigInt(2_000),
                PrototypeBindValue::BigInt(table as i64 + 10),
                PrototypeBindValue::BigInt(20),
            ]
        );

        let range = CheckpointObjectSingleBoundedRangeDeletePlan::try_new(
            key(table, table as u64 + 10, 20),
            checkpoint(25),
            fence(2_000),
        )
        .unwrap();
        assert_eq!(range.target(), checkpoint(20));
        assert_eq!(range.old_head(), checkpoint(25));
        assert_eq!(
            range.bind_values(),
            vec![
                PrototypeBindValue::BigInt(2_000),
                PrototypeBindValue::BigInt(table as i64 + 10),
                PrototypeBindValue::BigInt(20),
                PrototypeBindValue::BigInt(25),
            ]
        );
    }
}

#[test]
fn bounded_range_rejects_empty_or_reversed_bounds() {
    for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
        for old_head in [9, 10] {
            assert!(matches!(
                CheckpointObjectSingleBoundedRangeDeletePlan::try_new(
                    key(table, 1, 10),
                    checkpoint(old_head),
                    fence(100),
                ),
                Err(CheckpointObjectSinglePlanError::EmptyOrReversedRange { .. })
            ));
        }
    }
}

#[test]
fn blocked_object_single_domains_and_non_object_family_fail_closed() {
    let checkpointed = TypedTableKey::CheckpointedObject(
        CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint(5)),
    );
    assert!(matches!(
        CheckpointObjectSinglePointDeletePlan::try_new(checkpointed, fence(100)),
        Err(CheckpointObjectSinglePlanError::Registry(_))
    ));

    let reward = TypedTableKey::RealmRewardNode {
        realm: RealmId::new(7),
        pending: UniquePendingId::try_new(8).unwrap(),
    };
    assert!(matches!(
        CheckpointObjectSinglePointDeletePlan::try_new(reward, fence(100)),
        Err(CheckpointObjectSinglePlanError::Registry(_))
    ));

    assert!(matches!(
        CheckpointObjectSinglePointDeletePlan::try_new(
            TypedTableKey::CheckpointLeaf(checkpoint(5)),
            fence(100),
        ),
        Err(CheckpointObjectSinglePlanError::UnsupportedPhysicalTable(
            ScyllaPhysicalTableId::CheckpointLeaf
        ))
    ));

    assert!(seal_commit_put(
        LogicalMutation::Put {
            key: key(CheckpointObjectSingleTable::UserLeaf, 1, 5),
            value: MutationValue::Digest {
                algorithm: ValueDigestAlgorithm::Sha256,
                digest: [1; 32],
            },
        },
        timestamp(100),
    )
    .is_err());
}

#[test]
fn batch_is_homogeneous_stable_and_rejects_ambiguous_members() {
    let first = sealed(
        CheckpointObjectSingleTable::ContractLeaf,
        1,
        10,
        b"first",
        100,
    );
    let second = sealed(
        CheckpointObjectSingleTable::ContractLeaf,
        2,
        10,
        b"second",
        100,
    );
    let batch =
        CheckpointObjectSinglePutBatch::try_from_sealed(&[first.clone(), second]).unwrap();
    assert_eq!(batch.table(), CheckpointObjectSingleTable::ContractLeaf);
    assert_eq!(batch.write_timestamp_us(), 100);
    assert_eq!(batch.members().len(), 2);
    assert!(matches!(
        CheckpointObjectSinglePutBatch::try_from_sealed(&[]),
        Err(CheckpointObjectSinglePlanError::EmptyBatch)
    ));
    assert!(matches!(
        CheckpointObjectSinglePutBatch::try_from_sealed(&[
            first.clone(),
            sealed(
                CheckpointObjectSingleTable::UserLeaf,
                2,
                10,
                b"second",
                100,
            ),
        ]),
        Err(CheckpointObjectSinglePlanError::MixedPhysicalTables { .. })
    ));
    assert!(matches!(
        CheckpointObjectSinglePutBatch::try_from_sealed(&[
            first.clone(),
            sealed(
                CheckpointObjectSingleTable::ContractLeaf,
                2,
                10,
                b"second",
                101,
            ),
        ]),
        Err(CheckpointObjectSinglePlanError::MixedWriteTimestamps { .. })
    ));
    assert!(matches!(
        CheckpointObjectSinglePutBatch::try_from_sealed(&[
            first,
            sealed(
                CheckpointObjectSingleTable::ContractLeaf,
                1,
                10,
                b"different value",
                100,
            ),
        ]),
        Err(CheckpointObjectSinglePlanError::DuplicatePhysicalKey)
    ));
}

#[test]
fn legacy_object_writer_and_production_composition_remain_unchanged() {
    let legacy = include_str!("../src/tables/object/single.rs");
    let setup = include_str!("../src/psy_setup.rs");
    let core_db = include_str!("../src/core_db.rs");
    assert!(legacy.contains(
        "INSERT INTO {}.{} (obj_id, checkpoint_id, value) VALUES (?, ?, ?)"
    ));
    assert!(legacy.contains("crate::compression::compress"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!legacy.contains("DELETE FROM"));
    assert!(!setup.contains("CheckpointObjectSingleAdapter"));
    assert!(!core_db.contains("CheckpointObjectSingleAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
