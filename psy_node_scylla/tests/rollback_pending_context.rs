use psy_node_core::store::{
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs,
        NewBranchWriteTimestampUs,
    },
    typed::{
        CheckpointId, LogicalMutation, MutationValue,
        ProcCheckpointUniqueId, TypedTableKey, UniquePendingId,
        U64SingletonSlot,
    },
};
use psy_node_scylla::rollback::*;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn pending(value: u64) -> UniquePendingId {
    UniquePendingId::try_new(value).unwrap()
}

fn proc_id(value: u128) -> ProcCheckpointUniqueId {
    ProcCheckpointUniqueId::from_u128(value)
}

fn context(pending_id: u64, proc: u128) -> PendingContext {
    PendingContext::try_new(pending(pending_id), proc_id(proc)).unwrap()
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
}

fn new_branch_timestamp(
    orphan_write: i64,
    fence_value: i64,
    write: i64,
) -> NewBranchWriteTimestampUs {
    let fence = DeleteFenceTimestampUs::try_after(
        timestamp(orphan_write),
        fence_value as i128,
    )
    .unwrap();
    NewBranchWriteTimestampUs::try_after(fence, write as i128).unwrap()
}

fn commit_mapping(
    pending_id: u64,
    checkpoint_id: u64,
    ts: i64,
) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::PendingToCheckpoint(pending(pending_id)),
            value: MutationValue::CqlU64(checkpoint_id),
        },
        timestamp(ts),
    )
    .unwrap()
}

fn commit_pair(
    pending_id: u64,
    proc: u128,
    ts: i64,
) -> SealedTimestampedPutBatch {
    seal_commit_put_batch(
        LogicalMutation::PendingProcMapping {
            pending: pending(pending_id),
            proc_id: proc_id(proc),
        },
        timestamp(ts),
    )
    .unwrap()
}

fn rollback_mapping(
    pending_id: u64,
    checkpoint_id: u64,
    ts: NewBranchWriteTimestampUs,
) -> SealedTimestampedPut {
    seal_new_branch_put(
        LogicalMutation::Put {
            key: TypedTableKey::PendingToCheckpoint(pending(pending_id)),
            value: MutationValue::CqlU64(checkpoint_id),
        },
        ts,
    )
    .unwrap()
}

fn rollback_pair(
    pending_id: u64,
    proc: u128,
    ts: NewBranchWriteTimestampUs,
) -> SealedTimestampedPutBatch {
    seal_new_branch_put_batch(
        LogicalMutation::PendingProcMapping {
            pending: pending(pending_id),
            proc_id: proc_id(proc),
        },
        ts,
    )
    .unwrap()
}

#[test]
fn registry_declares_three_mapping_tables_as_preserved_operational() {
    let expected = [
        (
            ScyllaPhysicalTableId::PendingIdToCheckpointId,
            ManifestRequirement::NoneOperational,
        ),
        (
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
            ManifestRequirement::PairPhysicalDirection,
        ),
        (
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
            ManifestRequirement::PairPhysicalDirection,
        ),
    ];
    for (table, manifest) in expected {
        let descriptor = physical_descriptor(table);
        assert_eq!(descriptor.classification, StorageClassification::Operational);
        assert_eq!(descriptor.rollback_policy, RollbackPolicy::PreserveOperational);
        assert_eq!(descriptor.recovery_action, RecoveryAction::PreserveOperational);
        assert_eq!(descriptor.manifest_requirement, manifest);
        assert!(descriptor.delete_candidates.is_empty());
        assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
    }
}

#[test]
fn queries_use_real_physical_names_uuid_types_and_explicit_timestamp() {
    let queries = PendingContextQueries::new(
        &CqlKeyspaceName::try_new("psy_d02t8").unwrap(),
    );
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_pending_context_v1.txt")
    );
    for query in [
        queries.pending_to_checkpoint_put(),
        queries.pending_to_proc_put(),
        queries.proc_to_pending_put(),
    ] {
        assert!(query.cql().contains("USING TIMESTAMP ?"));
        assert!(!query.cql().contains("DELETE"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
    assert!(queries.pending_to_proc_put().bind_shape().contains(&"proc_id:UUID"));
    assert!(queries.proc_to_pending_put().bind_shape().contains(&"proc_id:UUID"));
}

#[test]
fn authority_rotation_builds_three_consistent_physical_bindings() {
    let mapping = commit_mapping(10, 50, 1_000);
    let pair = commit_pair(10, 0x1010, 1_000);
    let plan = PendingContextMappingPlan::try_for_commit(
        &mapping,
        &pair,
        context(9, 0x0909),
        checkpoint(50),
    )
    .unwrap();
    assert_eq!(plan.kind(), PendingContextTransitionKind::AuthorityRotation);
    assert_eq!(plan.previous(), context(9, 0x0909));
    assert_eq!(plan.candidate(), context(10, 0x1010));
    assert_eq!(plan.checkpoint(), checkpoint(50));
    assert_eq!(
        plan.pending_to_checkpoint().bind_values(),
        vec![
            PrototypeBindValue::BigInt(10),
            PrototypeBindValue::BigInt(50),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
    assert_eq!(
        plan.pending_to_proc().bind_values(),
        vec![
            PrototypeBindValue::BigInt(10),
            PrototypeBindValue::Uuid(0x1010_u128.to_be_bytes()),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
    assert_eq!(
        plan.proc_to_pending().bind_values(),
        vec![
            PrototypeBindValue::Uuid(0x1010_u128.to_be_bytes()),
            PrototypeBindValue::BigInt(10),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
}

#[test]
fn rollback_rotation_allows_reused_lower_checkpoint_only_in_fresh_pending_namespace() {
    let ts = new_branch_timestamp(1_000, 2_000, 3_000);
    let mapping = rollback_mapping(11, 40, ts);
    let pair = rollback_pair(11, 0x1111, ts);
    let plan = PendingContextMappingPlan::try_for_rollback(
        &mapping,
        &pair,
        context(10, 0x1010),
        checkpoint(40),
    )
    .unwrap();
    assert_eq!(plan.kind(), PendingContextTransitionKind::RollbackRotation);
    assert_eq!(plan.candidate(), context(11, 0x1111));
    assert_eq!(plan.checkpoint(), checkpoint(40));

    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &mapping,
            &pair,
            context(10, 0x1010),
            checkpoint(40),
        ),
        Err(PendingContextPlanError::WrongWriteKind { .. })
    ));
}

#[test]
fn pending_namespace_must_advance_exactly_once_and_stay_in_cql_range() {
    for candidate in [10, 12] {
        assert!(matches!(
            PendingContextMappingPlan::try_for_commit(
                &commit_mapping(candidate, 50, 1_000),
                &commit_pair(candidate, 0x2020, 1_000),
                context(10, 0x1010),
                checkpoint(50),
            ),
            Err(PendingContextPlanError::PendingNotNext { .. })
        ));
    }

    let max = i64::MAX as u64;
    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &commit_mapping(max, 50, 1_000),
            &commit_pair(max, 0x2020, 1_000),
            context(max, 0x1010),
            checkpoint(50),
        ),
        Err(PendingContextPlanError::PendingOverflow)
    ));
}

#[test]
fn proc_id_must_be_nonzero_new_and_zero_context_is_all_or_nothing() {
    assert!(matches!(
        PendingContext::try_new(pending(0), proc_id(1)),
        Err(PendingContextPlanError::InconsistentZeroContext)
    ));
    assert!(matches!(
        PendingContext::try_new(pending(1), proc_id(0)),
        Err(PendingContextPlanError::InconsistentZeroContext)
    ));

    for candidate_proc in [0, 0x1010] {
        let error = PendingContextMappingPlan::try_for_commit(
            &commit_mapping(11, 50, 1_000),
            &commit_pair(11, candidate_proc, 1_000),
            context(10, 0x1010),
            checkpoint(50),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PendingContextPlanError::ZeroCandidateProcId
                | PendingContextPlanError::ProcIdNotRotated
        ));
    }
}

#[test]
fn mismatched_checkpoint_timestamp_kind_and_table_fail_closed() {
    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &commit_mapping(10, 51, 1_000),
            &commit_pair(10, 0x1010, 1_000),
            context(9, 0x0909),
            checkpoint(50),
        ),
        Err(PendingContextPlanError::CheckpointMismatch { .. })
    ));
    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &commit_mapping(10, 50, 1_000),
            &commit_pair(10, 0x1010, 1_001),
            context(9, 0x0909),
            checkpoint(50),
        ),
        Err(PendingContextPlanError::MixedWriteTimestamps)
    ));

    let ts = new_branch_timestamp(1_000, 2_000, 3_000);
    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &commit_mapping(10, 50, 1_000),
            &rollback_pair(10, 0x1010, ts),
            context(9, 0x0909),
            checkpoint(50),
        ),
        Err(PendingContextPlanError::WrongWriteKind { .. })
    ));

    let wrong_table = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ),
            value: MutationValue::CqlU64(50),
        },
        timestamp(1_000),
    )
    .unwrap();
    assert!(matches!(
        PendingContextMappingPlan::try_for_commit(
            &wrong_table,
            &commit_pair(10, 0x1010, 1_000),
            context(9, 0x0909),
            checkpoint(50),
        ),
        Err(PendingContextPlanError::WrongPhysicalTable { .. })
    ));
}

#[test]
fn plan_digest_is_stable_and_commits_to_mapping_pair_timestamp_and_previous() {
    let mapping = commit_mapping(10, 50, 1_000);
    let pair = commit_pair(10, 0x1010, 1_000);
    let build = |mapping: &SealedTimestampedPut,
                 pair: &SealedTimestampedPutBatch,
                 previous| {
        PendingContextMappingPlan::try_for_commit(
            mapping,
            pair,
            previous,
            checkpoint(50),
        )
        .unwrap()
    };
    let a = build(&mapping, &pair, context(9, 0x0909));
    let retry = build(&mapping, &pair, context(9, 0x0909));
    let changed_timestamp = build(
        &commit_mapping(10, 50, 1_001),
        &commit_pair(10, 0x1010, 1_001),
        context(9, 0x0909),
    );
    assert_eq!(a, retry);
    assert_ne!(a.digest(), changed_timestamp.digest());
    assert_ne!(a.digest().as_bytes(), &[0; 32]);
}

#[test]
fn mapping_pair_expansion_order_is_stable_and_old_namespaces_are_not_deleted() {
    let pair = commit_pair(10, 0x1010, 1_000);
    assert_eq!(pair.members().len(), 2);
    assert_eq!(
        pair.members()[0].resolved().mutation().physical_table(),
        ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128
    );
    assert_eq!(
        pair.members()[1].resolved().mutation().physical_table(),
        ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64
    );
    let source = include_str!("../src/rollback/pending_context.rs");
    let delete_prefix = ["DELETE", "FROM"].join(" ");
    assert!(!source.contains(&delete_prefix));
    assert!(source.contains("forward direction first"));
}

#[test]
fn d02t8_remains_isolated_from_counter_production_writers_and_setup() {
    let adapter = include_str!("../src/rollback/pending_context.rs");
    let legacy = include_str!(
        "../../psy_node_core/src/psy_core_db/v3_implementation/full.rs"
    );
    let setup = include_str!("../src/psy_setup.rs");
    assert!(adapter.contains("PendingContextAdapter"));
    assert!(!adapter.contains("atomic_increment"));
    assert!(!legacy.contains("PendingContextAdapter"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!setup.contains("PendingContextAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
