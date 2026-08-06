use psy_node_core::store::{
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs,
        NewBranchWriteTimestampUs,
    },
    typed::{
        LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        ProcCheckpointUniqueId, StructuredValueSchema, TypedTableKey,
        UniquePendingId,
    },
};
use psy_node_scylla::rollback::*;

fn pending(value: u64) -> UniquePendingId {
    UniquePendingId::try_new(value).unwrap()
}

fn proc_id(value: u128) -> ProcCheckpointUniqueId {
    ProcCheckpointUniqueId::from_u128(value)
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
}

fn rollback_timestamp(value: i64) -> NewBranchWriteTimestampUs {
    let old = timestamp(value - 2);
    let fence = DeleteFenceTimestampUs::try_after(
        old,
        (value - 1) as i128,
    )
    .unwrap();
    NewBranchWriteTimestampUs::try_after(fence, value as i128).unwrap()
}

fn current_owner(
    expected: u64,
    proc: u128,
    opened_at: i64,
) -> VerifiedCurrentPendingOwnership {
    let allocation = SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Present(pending(expected)),
        proc_id(proc),
        timestamp(opened_at),
    )
    .unwrap();
    let PendingCounterReconcileAction::Owned(owner) = allocation.reconcile(
        PendingCounterReadState::Current(pending(expected + 1)),
        PendingOwnershipReadState::OwnedBy(proc_id(proc)),
    ) else {
        panic!("current counter and exact owner must verify")
    };
    owner.try_into_current().unwrap()
}

fn rollback_owner(
    expected: u64,
    proc: u128,
    opened_at: i64,
) -> VerifiedCurrentPendingOwnership {
    let allocation = SealedPendingCounterAllocation::try_for_rollback(
        PendingCounterExpected::Present(pending(expected)),
        proc_id(proc),
        rollback_timestamp(opened_at),
    )
    .unwrap();
    let PendingCounterReconcileAction::Owned(owner) = allocation.reconcile(
        PendingCounterReadState::Current(pending(expected + 1)),
        PendingOwnershipReadState::OwnedBy(proc_id(proc)),
    ) else {
        panic!("rollback counter and exact owner must verify")
    };
    owner.try_into_current().unwrap()
}

fn full_intent(
    pending_id: u64,
    level: u8,
    index: u64,
    value: u8,
    tag: u8,
) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::RewardTagMerkle {
            pending: pending(pending_id),
            node: MerkleNode::new(level, NodeIndex::new(index)),
        },
        value: RewardTagTreeNodePayloadV1::try_full(
            &[value; 32],
            &[tag; 32],
        )
        .unwrap()
        .into_mutation_value(),
    }
}

fn value_only_intent(
    pending_id: u64,
    level: u8,
    index: u64,
    value: u8,
) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::RewardTagMerkle {
            pending: pending(pending_id),
            node: MerkleNode::new(level, NodeIndex::new(index)),
        },
        value: RewardTagTreeNodePayloadV1::try_value_only(&[value; 32])
            .unwrap()
            .into_mutation_value(),
    }
}

fn sealed_full(
    pending_id: u64,
    level: u8,
    index: u64,
    ts: i64,
) -> SealedTimestampedPut {
    seal_commit_put(
        full_intent(pending_id, level, index, 0x11, 0x22),
        timestamp(ts),
    )
    .unwrap()
}

#[test]
fn registry_declares_pending_partition_rotation_without_rollback_delete() {
    let descriptor =
        physical_descriptor(ScyllaPhysicalTableId::GutaRewardTagTree);
    assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::TagTree);
    assert_eq!(descriptor.classification, StorageClassification::Operational);
    assert_eq!(descriptor.version_axis, VersionAxis::UniquePendingPartition);
    assert_eq!(
        descriptor.rollback_policy,
        RollbackPolicy::PreserveOperational
    );
    assert_eq!(descriptor.recovery_action, RecoveryAction::RotateNamespace);
    assert_eq!(
        descriptor.manifest_requirement,
        ManifestRequirement::NoneOperational
    );
    assert!(descriptor.delete_candidates.is_empty());
    assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
}

#[test]
fn payload_codec_is_canonical_and_fails_closed() {
    let full =
        RewardTagTreeNodePayloadV1::try_full(&[1; 32], &[2; 32]).unwrap();
    let full_bytes = full.encode_canonical();
    assert_eq!(full_bytes.len(), 71);
    assert_eq!(
        RewardTagTreeNodePayloadV1::try_decode(&full_bytes).unwrap(),
        full
    );
    let value =
        RewardTagTreeNodePayloadV1::try_value_only(&[3; 32]).unwrap();
    let value_bytes = value.encode_canonical();
    assert_eq!(value_bytes.len(), 39);
    assert_eq!(
        RewardTagTreeNodePayloadV1::try_decode(&value_bytes).unwrap(),
        value
    );
    assert!(matches!(
        RewardTagTreeNodePayloadV1::try_full(&[1; 31], &[2; 32]),
        Err(RewardTagTreePayloadError::InvalidHashLength { .. })
    ));

    let mut unknown_version = full_bytes.clone();
    unknown_version[5] = 2;
    assert!(matches!(
        RewardTagTreeNodePayloadV1::try_decode(&unknown_version),
        Err(RewardTagTreePayloadError::UnknownVersion(2))
    ));
    assert!(RewardTagTreeNodePayloadV1::try_decode(&full_bytes[..70]).is_err());
    let mut trailing = full_bytes;
    trailing.push(0);
    assert!(RewardTagTreeNodePayloadV1::try_decode(&trailing).is_err());
}

#[test]
fn queries_match_real_schema_golden_and_expose_no_rollback_delete() {
    let queries = RewardTagTreeQueries::new(
        &CqlKeyspaceName::try_new("psy_d02t10").unwrap(),
    );
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_reward_tag_tree_v1.txt")
    );
    assert!(queries.full_node_put().cql().contains(
        "(unique_pending_id, level, node_index, node_value, node_tag)"
    ));
    assert!(queries
        .value_only_put()
        .cql()
        .contains("SET node_value = ? WHERE unique_pending_id = ?"));
    for query in [queries.full_node_put(), queries.value_only_put()] {
        assert!(query.cql().contains("USING TIMESTAMP ?"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
    assert!(!queries.render_golden().contains("DELETE FROM"));
}

#[test]
fn full_and_value_only_bind_the_complete_pending_position() {
    let owner = current_owner(10, 0x111, 1_000);
    let full = sealed_full(11, 0xfe, u64::MAX, 1_001);
    let full_binding =
        RewardTagTreePutBinding::try_from_sealed(&full, owner).unwrap();
    assert_eq!(full_binding.pending(), pending(11));
    assert_eq!(full_binding.proc_id(), proc_id(0x111));
    assert_eq!(
        full_binding.node(),
        MerkleNode::new(0xfe, NodeIndex::new(u64::MAX))
    );
    assert_eq!(
        full_binding.bind_values(),
        vec![
            PrototypeBindValue::BigInt(11),
            PrototypeBindValue::TinyInt(-2),
            PrototypeBindValue::BigInt(-1),
            PrototypeBindValue::Blob(vec![0x11; 32]),
            PrototypeBindValue::Blob(vec![0x22; 32]),
            PrototypeBindValue::BigInt(1_001),
        ]
    );

    let value = seal_commit_put(
        value_only_intent(11, 7, 9, 0x33),
        timestamp(1_002),
    )
    .unwrap();
    let value_binding =
        RewardTagTreePutBinding::try_from_sealed(&value, owner).unwrap();
    assert_eq!(
        value_binding.bind_values(),
        vec![
            PrototypeBindValue::BigInt(1_002),
            PrototypeBindValue::Blob(vec![0x33; 32]),
            PrototypeBindValue::BigInt(11),
            PrototypeBindValue::TinyInt(7),
            PrototypeBindValue::BigInt(9),
        ]
    );
}

#[test]
fn historical_mapping_token_cannot_authorize_namespace_writes() {
    let allocation = SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Present(pending(10)),
        proc_id(0x111),
        timestamp(1_000),
    )
    .unwrap();
    let PendingCounterReconcileAction::Owned(historical) =
        allocation.reconcile(
            PendingCounterReadState::Current(pending(12)),
            PendingOwnershipReadState::OwnedBy(proc_id(0x111)),
        )
    else {
        panic!("exact historical owner must support mapping backfill")
    };
    assert_eq!(
        historical.status(),
        PendingOwnershipStatus::HistoricalBackfill
    );
    assert!(historical.try_into_current().is_err());
}

#[test]
fn wrong_pending_kind_timestamp_or_table_fails_closed() {
    let owner = current_owner(10, 0x111, 1_000);
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(
            &sealed_full(12, 1, 2, 1_001),
            owner,
        ),
        Err(RewardTagTreePlanError::PendingMismatch { .. })
    ));
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(
            &sealed_full(11, 1, 2, 999),
            owner,
        ),
        Err(RewardTagTreePlanError::WriteBeforeNamespace { .. })
    ));

    let rollback = seal_new_branch_put(
        full_intent(11, 1, 2, 1, 2),
        rollback_timestamp(1_002),
    )
    .unwrap();
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(&rollback, owner),
        Err(RewardTagTreePlanError::WriteKindMismatch { .. })
    ));

    let malformed = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::RewardTagMerkle {
                pending: pending(11),
                node: MerkleNode::new(1, NodeIndex::new(2)),
            },
            value: MutationValue::Structured {
                schema: StructuredValueSchema::TagTreeNodeV1,
                canonical_bytes: vec![1, 2],
            },
        },
        timestamp(1_001),
    )
    .unwrap();
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(&malformed, owner),
        Err(RewardTagTreePlanError::Payload(_))
    ));

    let other = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::PendingToCheckpoint(pending(11)),
            value: MutationValue::CqlU64(7),
        },
        timestamp(1_001),
    )
    .unwrap();
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(&other, owner),
        Err(RewardTagTreePlanError::WrongPhysicalTable(_))
    ));
}

#[test]
fn rollback_namespace_accepts_only_post_fence_write_kind() {
    let owner = rollback_owner(20, 0x2021, 2_000);
    let sealed = seal_new_branch_put(
        full_intent(21, 3, 4, 5, 6),
        rollback_timestamp(2_001),
    )
    .unwrap();
    let binding =
        RewardTagTreePutBinding::try_from_sealed(&sealed, owner).unwrap();
    assert_eq!(binding.pending(), pending(21));
    assert_eq!(binding.write_kind(), TimestampedWriteKind::NewBranchAfterFence);

    let ordinary = sealed_full(21, 3, 4, 2_001);
    assert!(matches!(
        RewardTagTreePutBinding::try_from_sealed(&ordinary, owner),
        Err(RewardTagTreePlanError::WriteKindMismatch { .. })
    ));
}

#[test]
fn retry_identity_includes_mutation_and_namespace_ownership() {
    let owner = current_owner(10, 0x111, 1_000);
    let sealed = sealed_full(11, 1, 2, 1_001);
    let binding =
        RewardTagTreePutBinding::try_from_sealed(&sealed, owner).unwrap();
    assert!(binding.ensure_exact_retry(&sealed, owner).is_ok());
    assert_eq!(
        binding,
        RewardTagTreePutBinding::try_from_sealed(&sealed, owner).unwrap()
    );

    let changed_owner = current_owner(10, 0x222, 1_000);
    assert!(matches!(
        binding.ensure_exact_retry(&sealed, changed_owner),
        Err(RewardTagTreePlanError::RetryChanged)
            | Err(RewardTagTreePlanError::PendingMismatch { .. })
    ));
    let changed = sealed_full(11, 1, 2, 1_002);
    assert!(matches!(
        binding.ensure_exact_retry(&changed, owner),
        Err(RewardTagTreePlanError::RetryChanged)
    ));
}

#[test]
fn full_batch_is_deterministic_and_rejects_partial_mixed_or_duplicate_rows() {
    let owner = current_owner(10, 0x111, 1_000);
    let a = sealed_full(11, 1, 2, 1_001);
    let b = sealed_full(11, 1, 3, 1_001);
    let batch = RewardTagTreeFullPutBatch::try_from_sealed(
        &[a.clone(), b.clone()],
        owner,
    )
    .unwrap();
    let retry = RewardTagTreeFullPutBatch::try_from_sealed(&[a.clone(), b], owner)
        .unwrap();
    assert_eq!(batch, retry);
    assert_eq!(batch.pending(), pending(11));
    assert_eq!(batch.write_timestamp_us(), 1_001);
    assert_eq!(batch.members().len(), 2);
    assert!(matches!(
        RewardTagTreeFullPutBatch::try_from_sealed(&[], owner),
        Err(RewardTagTreePlanError::EmptyBatch)
    ));
    assert!(matches!(
        RewardTagTreeFullPutBatch::try_from_sealed(
            &[a.clone(), sealed_full(11, 1, 4, 1_002)],
            owner,
        ),
        Err(RewardTagTreePlanError::MixedWriteTimestamps { .. })
    ));
    assert!(matches!(
        RewardTagTreeFullPutBatch::try_from_sealed(&[a.clone(), a], owner),
        Err(RewardTagTreePlanError::DuplicatePhysicalKey)
    ));
    let value_only = seal_commit_put(
        value_only_intent(11, 1, 4, 7),
        timestamp(1_001),
    )
    .unwrap();
    assert!(matches!(
        RewardTagTreeFullPutBatch::try_from_sealed(&[value_only], owner),
        Err(RewardTagTreePlanError::ExpectedFullNode)
    ));
}

#[test]
fn d02t10_remains_isolated_and_does_not_promote_production_capability() {
    let adapter = include_str!("../src/rollback/reward_tag_tree.rs");
    let legacy = include_str!("../src/tables/tag_tree.rs");
    let setup = include_str!("../src/psy_setup.rs");
    let core_db = include_str!("../src/core_db.rs");
    let production = include_str!(
        "../../psy_node_core/src/psy_core_db/v3_implementation/full.rs"
    );
    assert!(adapter.contains("RewardTagTreeAdapter"));
    assert!(adapter.contains("BatchType::Unlogged"));
    assert!(!adapter.contains("DELETE FROM"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!legacy.contains("DELETE FROM"));
    assert!(!setup.contains("RewardTagTreeAdapter"));
    assert!(!core_db.contains("RewardTagTreeAdapter"));
    assert!(!production.contains("RewardTagTreeAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
