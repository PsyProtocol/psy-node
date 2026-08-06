use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs},
    typed::{
        CheckpointId, ContractId, LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        TypedTableKey, UserId,
    },
};
use psy_node_scylla::rollback::*;

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
    table: CheckpointMerkleTable,
    checkpoint_id: u64,
    level: u8,
    index: u64,
) -> TypedTableKey {
    let checkpoint = checkpoint(checkpoint_id);
    let node = MerkleNode::new(level, NodeIndex::new(index));
    match table {
        CheckpointMerkleTable::GlobalUserTree => {
            TypedTableKey::GlobalUserMerkle { node, checkpoint }
        }
        CheckpointMerkleTable::UserContractTree => TypedTableKey::UserContractMerkle {
            user: UserId::new(11),
            node,
            checkpoint,
        },
        CheckpointMerkleTable::ContractStateTree => TypedTableKey::ContractStateMerkle {
            user: UserId::new(11),
            contract: ContractId::new(12),
            node,
            checkpoint,
        },
        CheckpointMerkleTable::GlobalCheckpointTree => {
            TypedTableKey::GlobalCheckpointMerkle { node, checkpoint }
        }
        CheckpointMerkleTable::UserRegistrationTree => {
            TypedTableKey::UserRegistrationMerkle { node, checkpoint }
        }
        CheckpointMerkleTable::GlobalContractTree => {
            TypedTableKey::GlobalContractMerkle { node, checkpoint }
        }
        CheckpointMerkleTable::ContractFunctionTree => {
            TypedTableKey::ContractFunctionMerkle {
                contract: ContractId::new(12),
                node,
                checkpoint,
            }
        }
    }
}

fn sealed(
    table: CheckpointMerkleTable,
    checkpoint: u64,
    level: u8,
    index: u64,
    value: &[u8],
    ts: i64,
) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: key(table, checkpoint, level, index),
            value: MutationValue::PsyCanonicalBytes(value.to_vec()),
        },
        timestamp(ts),
    )
    .unwrap()
}

#[test]
fn seven_table_set_and_three_schema_families_match_registry() {
    assert_eq!(CHECKPOINT_MERKLE_TABLES.len(), 7);
    let families = CHECKPOINT_MERKLE_TABLES.map(CheckpointMerkleTable::schema_family);
    assert_eq!(
        families
            .iter()
            .filter(|family| **family == ScyllaSchemaFamily::MerkleZero)
            .count(),
        4
    );
    assert_eq!(
        families
            .iter()
            .filter(|family| **family == ScyllaSchemaFamily::MerkleSingle)
            .count(),
        2
    );
    assert_eq!(
        families
            .iter()
            .filter(|family| **family == ScyllaSchemaFamily::MerkleDouble)
            .count(),
        1
    );
    for table in CHECKPOINT_MERKLE_TABLES {
        let descriptor = physical_descriptor(table.physical_table());
        assert_eq!(descriptor.schema_family, table.schema_family());
        assert_eq!(descriptor.version_axis, VersionAxis::CheckpointClustering);
        assert_eq!(descriptor.rollback_policy, RollbackPolicy::ArchiveVersioned);
        assert_eq!(
            descriptor.delete_candidates,
            &[
                DeleteStrategy::Point,
                DeleteStrategy::BoundedRange,
                DeleteStrategy::SnapshotOnly,
            ]
        );
        assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
    }
}

#[test]
fn query_catalog_is_closed_timestamped_and_matches_golden() {
    let queries =
        CheckpointMerkleQueries::new(&CqlKeyspaceName::try_new("psy_d02t2").unwrap());
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_checkpoint_merkle_v1.txt")
    );
    assert_eq!(queries.all().len(), 7);
    for table in CHECKPOINT_MERKLE_TABLES {
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
            .contains("checkpoint_id > ? AND checkpoint_id <= ?"));
    }
}

#[test]
fn zero_single_and_double_bind_complete_real_primary_keys() {
    let cases = [
        (CheckpointMerkleTable::GlobalUserTree, 5),
        (CheckpointMerkleTable::UserContractTree, 6),
        (CheckpointMerkleTable::ContractStateTree, 7),
    ];
    for (table, expected_len) in cases {
        let put = CheckpointMerklePutBinding::try_from_sealed(&sealed(
            table,
            20,
            255,
            u64::MAX,
            &[9; 32],
            1_000,
        ))
        .unwrap();
        assert_eq!(put.table(), table);
        assert_eq!(put.checkpoint(), checkpoint(20));
        assert_eq!(put.write_timestamp_us(), 1_000);
        let values = put.bind_values();
        assert_eq!(values.len(), expected_len);
        assert_eq!(values[values.len() - 2], PrototypeBindValue::Blob(vec![9; 32]));
        assert_eq!(values[values.len() - 1], PrototypeBindValue::BigInt(1_000));

        let point = CheckpointMerklePointDeletePlan::try_new(
            key(table, 20, 255, u64::MAX),
            fence(2_000),
        )
        .unwrap();
        assert_eq!(point.bind_values().len(), expected_len - 1);
        assert_eq!(point.bind_values()[0], PrototypeBindValue::BigInt(2_000));

        let range = CheckpointMerkleBoundedRangeDeletePlan::try_new(
            key(table, 20, 255, u64::MAX),
            checkpoint(25),
            fence(2_000),
        )
        .unwrap();
        assert_eq!(range.bind_values().len(), expected_len);
        assert_eq!(range.target(), checkpoint(20));
        assert_eq!(range.old_head(), checkpoint(25));
        assert_eq!(range.bind_values()[0], PrototypeBindValue::BigInt(2_000));
    }
}

#[test]
fn every_table_resolves_its_exact_typed_position() {
    for table in CHECKPOINT_MERKLE_TABLES {
        let binding = CheckpointMerklePutBinding::try_from_sealed(&sealed(
            table, 7, 3, 99, &[table as u8; 32], 100,
        ))
        .unwrap();
        assert_eq!(binding.table(), table);
        assert_eq!(binding.position().node(), MerkleNode::new(3, NodeIndex::new(99)));
        match table.schema_family() {
            ScyllaSchemaFamily::MerkleZero => {
                assert!(matches!(binding.position(), CheckpointMerklePosition::Zero { .. }));
            }
            ScyllaSchemaFamily::MerkleSingle => assert!(matches!(
                binding.position(),
                CheckpointMerklePosition::Single { .. }
            )),
            ScyllaSchemaFamily::MerkleDouble => assert!(matches!(
                binding.position(),
                CheckpointMerklePosition::Double { .. }
            )),
            _ => unreachable!(),
        }
    }
}

#[test]
fn bounded_range_rejects_empty_or_reversed_bounds_for_all_schemas() {
    for table in [
        CheckpointMerkleTable::GlobalUserTree,
        CheckpointMerkleTable::UserContractTree,
        CheckpointMerkleTable::ContractStateTree,
    ] {
        for old_head in [9, 10] {
            assert!(matches!(
                CheckpointMerkleBoundedRangeDeletePlan::try_new(
                    key(table, 10, 1, 2),
                    checkpoint(old_head),
                    fence(100)
                ),
                Err(CheckpointMerklePlanError::EmptyOrReversedRange { .. })
            ));
        }
    }
}

#[test]
fn non_hash_and_non_merkle_mutations_fail_closed() {
    for length in [0, 1, 31, 33] {
        let bad = sealed(
            CheckpointMerkleTable::GlobalUserTree,
            1,
            1,
            1,
            &vec![1; length],
            10,
        );
        assert_eq!(
            CheckpointMerklePutBinding::try_from_sealed(&bad),
            Err(CheckpointMerklePlanError::InvalidHashLength {
                expected: 32,
                actual: length,
            })
        );
    }

    let kiv = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::CheckpointLeaf(checkpoint(1)),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        timestamp(10),
    )
    .unwrap();
    assert!(matches!(
        CheckpointMerklePutBinding::try_from_sealed(&kiv),
        Err(CheckpointMerklePlanError::UnsupportedPhysicalTable(
            ScyllaPhysicalTableId::CheckpointLeaf
        ))
    ));
}

#[test]
fn homogeneous_batch_is_stable_and_conflicts_are_rejected() {
    let rows = vec![
        sealed(
            CheckpointMerkleTable::ContractStateTree,
            7,
            1,
            10,
            &[1; 32],
            300,
        ),
        sealed(
            CheckpointMerkleTable::ContractStateTree,
            7,
            1,
            11,
            &[2; 32],
            300,
        ),
    ];
    let first = CheckpointMerklePutBatch::try_from_sealed(&rows).unwrap();
    let second = CheckpointMerklePutBatch::try_from_sealed(&rows).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.table(), CheckpointMerkleTable::ContractStateTree);
    assert_eq!(first.write_timestamp_us(), 300);
    assert_eq!(first.members().len(), 2);

    assert_eq!(
        CheckpointMerklePutBatch::try_from_sealed(&[]),
        Err(CheckpointMerklePlanError::EmptyBatch)
    );
    let mixed_table = vec![
        sealed(
            CheckpointMerkleTable::GlobalUserTree,
            1,
            1,
            1,
            &[1; 32],
            10,
        ),
        sealed(
            CheckpointMerkleTable::GlobalCheckpointTree,
            1,
            1,
            1,
            &[1; 32],
            10,
        ),
    ];
    assert!(matches!(
        CheckpointMerklePutBatch::try_from_sealed(&mixed_table),
        Err(CheckpointMerklePlanError::MixedPhysicalTables { .. })
    ));
    let mixed_timestamp = vec![
        sealed(
            CheckpointMerkleTable::GlobalUserTree,
            1,
            1,
            1,
            &[1; 32],
            10,
        ),
        sealed(
            CheckpointMerkleTable::GlobalUserTree,
            1,
            1,
            2,
            &[1; 32],
            11,
        ),
    ];
    assert!(matches!(
        CheckpointMerklePutBatch::try_from_sealed(&mixed_timestamp),
        Err(CheckpointMerklePlanError::MixedWriteTimestamps { .. })
    ));

    let duplicate = sealed(
        CheckpointMerkleTable::GlobalUserTree,
        1,
        1,
        1,
        &[1; 32],
        10,
    );
    assert_eq!(
        CheckpointMerklePutBatch::try_from_sealed(&[duplicate.clone(), duplicate]),
        Err(CheckpointMerklePlanError::DuplicatePhysicalKey)
    );
}

#[test]
fn production_writers_and_capability_remain_unchanged() {
    assert_eq!(
        PRODUCTION_CQL_CAPABILITIES,
        ProductionCqlCapabilities {
            explicit_write_timestamp: false,
            delete_adapter: false,
        }
    );
    for source in [
        include_str!("../src/psy_setup.rs"),
        include_str!("../src/core_db.rs"),
        include_str!("../src/tables/merkle/zero.rs"),
        include_str!("../src/tables/merkle/single.rs"),
        include_str!("../src/tables/merkle/double.rs"),
    ] {
        assert!(!source.contains("CheckpointMerkleAdapter"));
        assert!(!source.contains("CheckpointMerklePutBatch"));
    }
    for legacy in [
        include_str!("../src/tables/merkle/zero.rs"),
        include_str!("../src/tables/merkle/single.rs"),
        include_str!("../src/tables/merkle/double.rs"),
    ] {
        assert!(!legacy.contains("USING TIMESTAMP"));
        assert!(!legacy.contains("DELETE FROM"));
    }
}

