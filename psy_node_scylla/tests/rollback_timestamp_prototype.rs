use psy_node_core::store::{
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs, TimestampOrderingError,
    },
    typed::{
        CheckpointId, CheckpointLeafKey, CheckpointRootKey, CheckpointedObjectKey, LogicalMutation, MerkleNode, MutationValue,
        NodeIndex, RealmId, TypedTableKey, UniquePendingId,
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

fn checkpoint_leaf_intent(checkpoint: u64, value: &[u8]) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(self::checkpoint(checkpoint)),
        value: MutationValue::PsyCanonicalBytes(value.to_vec()),
    }
}

fn global_user_intent(level: u8, index: u64, checkpoint: u64, value: &[u8]) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::GlobalUserMerkle {
            node: MerkleNode::new(level, NodeIndex::new(index)),
            checkpoint: self::checkpoint(checkpoint),
        },
        value: MutationValue::PsyCanonicalBytes(value.to_vec()),
    }
}

#[test]
fn query_and_bind_contract_matches_golden() {
    let keyspace = CqlKeyspaceName::try_new("psy_g006").unwrap();
    let queries = TimestampPrototypeQueries::new(&keyspace);
    assert_eq!(queries.render_golden(), include_str!("golden/rollback_timestamp_prototype_v1.txt"));

    assert!(queries.checkpoint_leaf_put().cql().contains("USING TIMESTAMP ?"));
    assert!(queries.global_user_merkle_put().cql().contains("USING TIMESTAMP ?"));
    assert_eq!(queries.checkpoint_leaf_put().cql().matches('?').count(), 3);
    assert_eq!(queries.checkpoint_leaf_delete().cql().matches('?').count(), 2);
    assert_eq!(queries.global_user_merkle_put().cql().matches('?').count(), 5);
    assert_eq!(queries.global_user_merkle_point_delete().cql().matches('?').count(), 4);
    assert_eq!(queries.global_user_merkle_range_delete().cql().matches('?').count(), 5);
    assert_eq!(queries.global_user_merkle_exact_read().cql().matches('?').count(), 3);
    assert!(!queries.global_user_merkle_exact_read().cql().contains("<="));
}

#[test]
fn invalid_keyspace_cannot_inject_dynamic_cql() {
    for name in ["", "9psy", "psy-node", "psy; DROP KEYSPACE x", "quoted.name"] {
        assert!(CqlKeyspaceName::try_new(name).is_err(), "{name:?} should fail");
    }
    assert!(CqlKeyspaceName::try_new("_psy_123").is_ok());
}

#[test]
fn sealed_put_is_deterministic_and_retry_is_exact() {
    let intent = checkpoint_leaf_intent(7, &[1, 2, 3]);
    let sealed = seal_commit_put(intent.clone(), timestamp(1_000)).unwrap();
    let independently_sealed = seal_commit_put(intent.clone(), timestamp(1_000)).unwrap();
    let cloned = sealed.clone();
    assert_eq!(sealed, cloned);
    assert_eq!(sealed, independently_sealed);
    assert_eq!(sealed.canonical_bytes(), cloned.canonical_bytes());
    assert_eq!(sealed.intent_digest(), cloned.intent_digest());
    sealed
        .ensure_exact_retry(intent.clone(), timestamp(1_000), TimestampedWriteKind::AuthorityCommit)
        .unwrap();

    assert!(matches!(
        sealed.ensure_exact_retry(intent.clone(), timestamp(1_001), TimestampedWriteKind::AuthorityCommit),
        Err(TimestampedMutationError::RetryTimestampChanged { .. })
    ));
    assert!(matches!(
        sealed.ensure_exact_retry(intent, timestamp(1_000), TimestampedWriteKind::NewBranchAfterFence),
        Err(TimestampedMutationError::RetryWriteKindChanged { .. })
    ));
    assert!(matches!(
        sealed.ensure_exact_retry(checkpoint_leaf_intent(7, &[1, 2, 4]), timestamp(1_000), TimestampedWriteKind::AuthorityCommit),
        Err(TimestampedMutationError::RetryMutationChanged)
    ));

    let resealed = seal_commit_put(checkpoint_leaf_intent(7, &[1, 2, 3]), timestamp(1_001)).unwrap();
    assert_ne!(sealed.intent_digest(), resealed.intent_digest());
    assert_eq!(sealed.timestamp().as_i64(), 1_000);
}

#[test]
fn new_branch_seal_requires_a_proven_post_fence_timestamp() {
    let old = timestamp(10);
    let delete = DeleteFenceTimestampUs::try_after(old, 11).unwrap();
    assert!(matches!(
        NewBranchWriteTimestampUs::try_after(delete, 11),
        Err(TimestampOrderingError::NewBranchNotStrictlyAfterFence { .. })
    ));
    let new_write = NewBranchWriteTimestampUs::try_after(delete, 12).unwrap();
    let sealed = seal_new_branch_put(checkpoint_leaf_intent(2, &[9]), new_write).unwrap();
    assert_eq!(sealed.timestamp().as_i64(), 12);
    assert_eq!(sealed.write_kind(), TimestampedWriteKind::NewBranchAfterFence);
}

#[test]
fn digest_only_blocked_and_retired_mutations_never_become_executable() {
    let digest_only = LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(checkpoint(1)),
        value: MutationValue::Digest { algorithm: psy_node_core::store::typed::ValueDigestAlgorithm::Sha256, digest: [7; 32] },
    };
    assert!(matches!(
        seal_commit_put(digest_only, timestamp(10)),
        Err(TimestampedMutationError::CommitmentOnlyPayload)
    ));

    let blocked = [
        LogicalMutation::Put {
            key: TypedTableKey::CheckpointedObject(CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint(2))),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        LogicalMutation::Put {
            key: TypedTableKey::CheckpointToPending(checkpoint(2)),
            value: MutationValue::CqlU64(3),
        },
        LogicalMutation::Put {
            key: TypedTableKey::RealmRewardNode {
                realm: RealmId::new(1),
                pending: UniquePendingId::try_new(2).unwrap(),
            },
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
    ];
    for intent in blocked {
        assert!(matches!(
            seal_commit_put(intent, timestamp(10)),
            Err(TimestampedMutationError::MutationBuild(MutationBuildError::Readiness(
                RegistryReadinessError::Blocked(_)
            )))
        ));
    }

    let retired = LogicalMutation::CheckpointLeafMapping {
        leaf: CheckpointLeafKey::new(vec![1; 32]),
        checkpoint: checkpoint(2),
    };
    assert!(matches!(
        seal_commit_put(retired, timestamp(10)),
        Err(TimestampedMutationError::MutationBuild(MutationBuildError::Readiness(
            RegistryReadinessError::RetireCandidate
        )))
    ));
}

#[test]
fn checkpoint_leaf_binding_uses_real_kiv_codec_and_order() {
    let canonical = vec![0, 1, 2, 3, 4, 5];
    let sealed = seal_commit_put(checkpoint_leaf_intent(42, &canonical), timestamp(1_234)).unwrap();
    let first = CheckpointLeafPutBinding::try_from_sealed(&sealed).unwrap();
    let second = CheckpointLeafPutBinding::try_from_sealed(&sealed).unwrap();
    assert_eq!(first, second);
    let values = first.bind_values();
    assert!(validate_bind_shape(
        TimestampPrototypeQueries::new(&CqlKeyspaceName::try_new("psy_g006").unwrap()).checkpoint_leaf_put(),
        &values
    ));
    assert_eq!(values[0], PrototypeBindValue::BigInt(42));
    let stored = match &values[1] {
        PrototypeBindValue::Blob(value) => value,
        _ => panic!("expected KIV BLOB"),
    };
    assert_eq!(compression::decompress(stored).unwrap(), canonical);
    let second_stored = match &second.bind_values()[1] {
        PrototypeBindValue::Blob(value) => value.clone(),
        _ => panic!("expected second KIV BLOB"),
    };
    assert_eq!(compression::decompress(&second_stored).unwrap(), canonical);
    assert_eq!(values[2], PrototypeBindValue::BigInt(1_234));
}

#[test]
fn checkpoint_leaf_delete_is_complete_and_wrong_kiv_is_rejected() {
    let delete = CheckpointLeafVersionDeletePlan::try_new(TypedTableKey::CheckpointLeaf(checkpoint(42)), fence(2_000)).unwrap();
    assert_eq!(
        delete.bind_values(),
        vec![PrototypeBindValue::BigInt(2_000), PrototypeBindValue::BigInt(42)]
    );

    let wrong = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::L2BlockState(checkpoint(42)),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        timestamp(3_000),
    )
    .unwrap();
    assert!(matches!(
        CheckpointLeafPutBinding::try_from_sealed(&wrong),
        Err(TimestampPrototypePlanError::WrongPhysicalTable { .. })
    ));
    assert!(matches!(
        CheckpointLeafVersionDeletePlan::try_new(TypedTableKey::L2BlockState(checkpoint(42)), fence(2_000)),
        Err(TimestampPrototypePlanError::WrongPhysicalTable { .. })
    ));
}

#[test]
fn merkle_put_and_point_delete_bind_complete_primary_key() {
    let sealed = seal_commit_put(global_user_intent(255, u64::MAX, 50, &[8; 32]), timestamp(4_000)).unwrap();
    let put = GlobalUserMerklePutBinding::try_from_sealed(&sealed).unwrap();
    assert_eq!(
        put.bind_values(),
        vec![
            PrototypeBindValue::TinyInt(-1),
            PrototypeBindValue::BigInt(-1),
            PrototypeBindValue::BigInt(50),
            PrototypeBindValue::Blob(vec![8; 32]),
            PrototypeBindValue::BigInt(4_000),
        ]
    );

    let key = TypedTableKey::GlobalUserMerkle {
        node: MerkleNode::new(255, NodeIndex::new(u64::MAX)),
        checkpoint: checkpoint(50),
    };
    let point = GlobalUserMerklePointDeletePlan::try_new(key, fence(5_000)).unwrap();
    assert_eq!(
        point.bind_values(),
        vec![
            PrototypeBindValue::BigInt(5_000),
            PrototypeBindValue::TinyInt(-1),
            PrototypeBindValue::BigInt(-1),
            PrototypeBindValue::BigInt(50),
        ]
    );
}

#[test]
fn merkle_put_rejects_non_hash_payloads() {
    for length in [0, 1, 31, 33] {
        let sealed = seal_commit_put(global_user_intent(1, 2, 3, &vec![7; length]), timestamp(4_000)).unwrap();
        assert_eq!(
            GlobalUserMerklePutBinding::try_from_sealed(&sealed),
            Err(TimestampPrototypePlanError::InvalidMerkleValueLength { expected: 32, actual: length })
        );
    }
}

#[test]
fn merkle_bounded_delete_is_exactly_target_old_head_and_fail_closed() {
    let target_key = TypedTableKey::GlobalUserMerkle {
        node: MerkleNode::new(7, NodeIndex::new(99)),
        checkpoint: checkpoint(100),
    };
    let plan = GlobalUserMerkleBoundedRangeDeletePlan::try_new(target_key.clone(), checkpoint(120), fence(6_000)).unwrap();
    assert_eq!(
        plan.bind_values(),
        vec![
            PrototypeBindValue::BigInt(6_000),
            PrototypeBindValue::TinyInt(7),
            PrototypeBindValue::BigInt(99),
            PrototypeBindValue::BigInt(100),
            PrototypeBindValue::BigInt(120),
        ]
    );
    for old_head in [99, 100] {
        assert!(matches!(
            GlobalUserMerkleBoundedRangeDeletePlan::try_new(target_key.clone(), checkpoint(old_head), fence(6_000)),
            Err(TimestampPrototypePlanError::EmptyOrReversedRange { .. })
        ));
    }

    let wrong_family = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::GlobalCheckpointMerkle {
                node: MerkleNode::new(7, NodeIndex::new(99)),
                checkpoint: checkpoint(100),
            },
            value: MutationValue::PsyCanonicalBytes(vec![1; 32]),
        },
        timestamp(7_000),
    )
    .unwrap();
    assert!(matches!(
        GlobalUserMerklePutBinding::try_from_sealed(&wrong_family),
        Err(TimestampPrototypePlanError::WrongPhysicalTable { .. })
    ));

    let wrong_key = TypedTableKey::GlobalCheckpointMerkle {
        node: MerkleNode::new(7, NodeIndex::new(99)),
        checkpoint: checkpoint(100),
    };
    assert!(matches!(
        GlobalUserMerklePointDeletePlan::try_new(wrong_key.clone(), fence(7_000)),
        Err(TimestampPrototypePlanError::WrongPhysicalTable { .. })
    ));
    assert!(matches!(
        GlobalUserMerkleBoundedRangeDeletePlan::try_new(wrong_key, checkpoint(120), fence(7_000)),
        Err(TimestampPrototypePlanError::WrongPhysicalTable { .. })
    ));
}

#[test]
fn every_query_bind_shape_matches_a_real_plan() {
    let queries = TimestampPrototypeQueries::new(&CqlKeyspaceName::try_new("psy_g006").unwrap());
    let leaf = seal_commit_put(checkpoint_leaf_intent(1, &[1]), timestamp(10)).unwrap();
    let merkle = seal_commit_put(global_user_intent(1, 2, 3, &[4; 32]), timestamp(10)).unwrap();
    let merkle_key = TypedTableKey::GlobalUserMerkle {
        node: MerkleNode::new(1, NodeIndex::new(2)),
        checkpoint: checkpoint(3),
    };
    let pairs = [
        (
            queries.checkpoint_leaf_put(),
            CheckpointLeafPutBinding::try_from_sealed(&leaf).unwrap().bind_values(),
        ),
        (
            queries.checkpoint_leaf_delete(),
            CheckpointLeafVersionDeletePlan::try_new(TypedTableKey::CheckpointLeaf(checkpoint(1)), fence(20))
                .unwrap()
                .bind_values(),
        ),
        (
            queries.global_user_merkle_put(),
            GlobalUserMerklePutBinding::try_from_sealed(&merkle).unwrap().bind_values(),
        ),
        (
            queries.global_user_merkle_point_delete(),
            GlobalUserMerklePointDeletePlan::try_new(merkle_key.clone(), fence(20)).unwrap().bind_values(),
        ),
        (
            queries.global_user_merkle_range_delete(),
            GlobalUserMerkleBoundedRangeDeletePlan::try_new(merkle_key, checkpoint(4), fence(20))
                .unwrap()
                .bind_values(),
        ),
    ];
    for (query, values) in pairs {
        assert!(validate_bind_shape(query, &values), "shape mismatch for {:?}", query.id());
        assert_eq!(query.cql().matches('?').count(), values.len());
    }
}

#[test]
fn prototype_does_not_claim_production_coverage_or_change_production_callsites() {
    assert_eq!(
        PRODUCTION_CQL_CAPABILITIES,
        ProductionCqlCapabilities { explicit_write_timestamp: false, delete_adapter: false }
    );

    let setup = include_str!("../src/psy_setup.rs");
    let kiv = include_str!("../src/tables/object/kiv.rs");
    let merkle = include_str!("../src/tables/merkle/zero.rs");
    let core_db = include_str!("../src/core_db.rs");
    let core_db_base = include_str!("../../psy_node_core/src/psy_core_db/core_implementation/base.rs");
    let core_db_v3 = include_str!("../../psy_node_core/src/psy_core_db/v3_implementation/full.rs");
    let coordinator = include_str!("../../psy_node_common/src/coordinator/processor/db.rs");
    let realm_commit = include_str!("../../psy_node_common/src/realm/processor/db/commit.rs");
    let realm_sync = include_str!("../../psy_node_common/src/realm/processor/db/sync.rs");
    for production_source in [
        setup,
        kiv,
        merkle,
        core_db,
        core_db_base,
        core_db_v3,
        coordinator,
        realm_commit,
        realm_sync,
    ] {
        assert!(!production_source.contains("TimestampPrototypeAdapter"));
        assert!(!production_source.contains("CheckpointRootPrototypeAdapter"));
    }
    assert!(!kiv.contains("USING TIMESTAMP"));
    assert!(!kiv.contains("DELETE FROM"));
    assert!(!merkle.contains("USING TIMESTAMP"));
    assert!(!merkle.contains("DELETE FROM"));
}

#[test]
fn unrelated_pair_intent_cannot_be_sealed_as_representative_put() {
    let pair = LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(vec![1; 32]),
        checkpoint: checkpoint(1),
    };
    assert!(matches!(
        seal_commit_put(pair, timestamp(1)),
        Err(TimestampedMutationError::ExpectedOnePhysicalMutation { actual: 2 })
    ));
}

#[test]
fn checkpoint_root_pair_has_one_timestamp_and_two_ordered_physical_mutations() {
    let intent = LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(vec![0xa1; 32]),
        checkpoint: checkpoint(7),
    };
    let sealed = seal_commit_put_batch(intent.clone(), timestamp(1_000)).unwrap();
    assert_eq!(sealed.members().len(), 2);
    assert_eq!(
        sealed.members()[0].resolved().mutation().physical_table(),
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
    );
    assert_eq!(
        sealed.members()[1].resolved().mutation().physical_table(),
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2
    );
    assert!(sealed.members().iter().all(|member| member.timestamp().as_i64() == 1_000));
    sealed
        .ensure_exact_retry(intent, timestamp(1_000), TimestampedWriteKind::AuthorityCommit)
        .unwrap();

    let queries = CheckpointRootPrototypeQueries::new(&CqlKeyspaceName::try_new("psy_g006").unwrap());
    assert!(queries.k1_put().contains("checkpoint_root_to_checkpoint_id_table_k1"));
    assert!(queries.k2_put().contains("checkpoint_root_to_checkpoint_id_table_k2"));
    assert!(queries.k1_put().contains("USING TIMESTAMP ?"));
    assert!(queries.k2_put().contains("USING TIMESTAMP ?"));
    assert_eq!(
        queries.k1_delete(),
        "DELETE FROM psy_g006.checkpoint_root_to_checkpoint_id_table_k1 USING TIMESTAMP ? WHERE obj_id = ?"
    );
}
