use psy_node_core::store::{
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs,
        NewBranchWriteTimestampUs,
    },
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};
use psy_node_scylla::rollback::*;
use scylla::statement::{Consistency, SerialConsistency};

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

fn allocation(
    expected: u64,
    proc: u128,
    ts: i64,
) -> SealedPendingCounterAllocation {
    SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Present(pending(expected)),
        proc_id(proc),
        timestamp(ts),
    )
    .unwrap()
}

#[test]
fn registry_keeps_counter_operational_no_tablet_and_never_deleted() {
    let descriptor =
        physical_descriptor(ScyllaPhysicalTableId::U64CounterSingleton);
    assert_eq!(descriptor.keyspace, ScyllaKeyspaceKind::NoTablet);
    assert_eq!(descriptor.classification, StorageClassification::Operational);
    assert_eq!(descriptor.version_axis, VersionAxis::MonotonicCounter);
    assert_eq!(descriptor.rollback_policy, RollbackPolicy::PreserveOperational);
    assert_eq!(descriptor.recovery_action, RecoveryAction::PreserveOperational);
    assert_eq!(descriptor.manifest_requirement, ManifestRequirement::NoneOperational);
    assert!(descriptor.delete_candidates.is_empty());
    assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
}

#[test]
fn query_golden_uses_real_tables_lwt_and_no_client_cell_timestamp() {
    let queries = PendingCounterQueries::new(
        &CqlKeyspaceName::try_new("psy_d02t9_no_tablet").unwrap(),
        &CqlKeyspaceName::try_new("psy_d02t9").unwrap(),
    );
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_pending_counter_v1.txt")
    );
    for query in [
        queries.insert_counter_if_absent(),
        queries.compare_and_set_counter(),
        queries.claim_ownership_if_absent(),
    ] {
        assert!(query.cql().contains(" IF "));
        assert!(!query.cql().contains("USING TIMESTAMP"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
    assert!(queries.read_counter().cql().contains("u64_counter_singleton_table"));
    assert!(queries.read_ownership().cql().contains("_u64_to_u128"));
    assert!(!queries.render_golden().contains("DELETE"));
}

#[test]
fn lwt_contract_is_quorum_plus_local_serial() {
    let contract = PendingCounterLwtContract::rf3_default();
    assert_eq!(contract.regular(), Consistency::Quorum);
    assert_eq!(contract.serial(), SerialConsistency::LocalSerial);
    assert_eq!(contract.read(), Consistency::LocalSerial);
}

#[test]
fn absent_and_present_plans_allocate_exactly_one_and_bind_stably() {
    let initial = SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Absent,
        proc_id(0x101),
        timestamp(1_000),
    )
    .unwrap();
    assert_eq!(initial.candidate(), pending(1));
    assert_eq!(
        initial.counter_lwt_bind_values(),
        vec![PrototypeBindValue::BigInt(2), PrototypeBindValue::BigInt(1)]
    );

    let next = allocation(10, 0x111, 1_001);
    assert_eq!(next.candidate(), pending(11));
    assert_eq!(
        next.counter_lwt_bind_values(),
        vec![
            PrototypeBindValue::BigInt(11),
            PrototypeBindValue::BigInt(2),
            PrototypeBindValue::BigInt(10),
        ]
    );
    assert_eq!(
        next.ownership_claim_bind_values(),
        vec![
            PrototypeBindValue::BigInt(11),
            PrototypeBindValue::Uuid(0x111_u128.to_be_bytes()),
        ]
    );
}

#[test]
fn rollback_plan_carries_post_fence_intent_without_timestamping_lwt_cells() {
    let write = rollback_timestamp(3_000);
    let plan = SealedPendingCounterAllocation::try_for_rollback(
        PendingCounterExpected::Present(pending(20)),
        proc_id(0x2021),
        write,
    )
    .unwrap();
    assert_eq!(plan.candidate(), pending(21));
    assert_eq!(plan.write_timestamp_us(), write.as_commit_timestamp());
    assert_eq!(plan.write_kind(), TimestampedWriteKind::NewBranchAfterFence);
    assert!(plan
        .counter_lwt_bind_values()
        .iter()
        .all(|value| value != &PrototypeBindValue::BigInt(3_000)));
}

#[test]
fn zero_proc_and_counter_exhaustion_fail_closed() {
    assert!(matches!(
        SealedPendingCounterAllocation::try_for_commit(
            PendingCounterExpected::Present(pending(1)),
            proc_id(0),
            timestamp(1_000),
        ),
        Err(PendingCounterPlanError::ZeroProcId)
    ));
    assert!(matches!(
        SealedPendingCounterAllocation::try_for_commit(
            PendingCounterExpected::Present(pending(i64::MAX as u64)),
            proc_id(1),
            timestamp(1_000),
        ),
        Err(PendingCounterPlanError::CounterExhausted)
    ));
}

#[test]
fn reconciliation_requires_counter_then_exact_owner() {
    let plan = allocation(10, 0x111, 1_000);
    assert_eq!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(10)),
            PendingOwnershipReadState::Unclaimed,
        ),
        PendingCounterReconcileAction::ClaimOwnership
    );
    assert_eq!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(10)),
            PendingOwnershipReadState::OwnedBy(proc_id(0x111)),
        ),
        PendingCounterReconcileAction::ApplyCounterLwt
    );
    let owned = plan.reconcile(
        PendingCounterReadState::Current(pending(11)),
        PendingOwnershipReadState::OwnedBy(proc_id(0x111)),
    );
    let PendingCounterReconcileAction::Owned(token) = owned else {
        panic!("exact owner must produce a verified token")
    };
    assert_eq!(token.pending(), pending(11));
    assert_eq!(token.proc_id(), proc_id(0x111));
    assert_eq!(token.write_timestamp_us(), timestamp(1_000));
    assert_eq!(token.write_kind(), TimestampedWriteKind::AuthorityCommit);

    assert!(matches!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(11)),
            PendingOwnershipReadState::OwnedBy(proc_id(0x222)),
        ),
        PendingCounterReconcileAction::Conflict(
            PendingCounterConflict::OwnedByOther { .. }
        )
    ));
    assert!(matches!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(11)),
            PendingOwnershipReadState::Unclaimed,
        ),
        PendingCounterReconcileAction::Conflict(
            PendingCounterConflict::CounterAdvancedWithoutOwner { .. }
        )
    ));
}

#[test]
fn exact_historical_owner_can_recover_mapping_but_other_owner_is_superseded() {
    let plan = allocation(10, 0x111, 1_000);
    assert!(matches!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(12)),
            PendingOwnershipReadState::OwnedBy(proc_id(0x111)),
        ),
        PendingCounterReconcileAction::Owned(_)
    ));
    assert!(matches!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(12)),
            PendingOwnershipReadState::OwnedBy(proc_id(0x222)),
        ),
        PendingCounterReconcileAction::Conflict(
            PendingCounterConflict::CandidateSuperseded { .. }
        )
    ));
}

#[test]
fn concurrent_claim_model_has_exactly_one_owner() {
    let plans: Vec<_> = (1_u128..=64)
        .map(|proc| allocation(10, proc, 1_000))
        .collect();
    let winner = plans[17].proc_id();
    assert!(plans.iter().all(|plan| matches!(
        plan.reconcile(
            PendingCounterReadState::Current(pending(10)),
            PendingOwnershipReadState::Unclaimed,
        ),
        PendingCounterReconcileAction::ClaimOwnership
    )));
    assert_eq!(
        plans
            .iter()
            .filter(|plan| matches!(
                plan.reconcile(
                    PendingCounterReadState::Current(pending(10)),
                    PendingOwnershipReadState::OwnedBy(winner),
                ),
                PendingCounterReconcileAction::ApplyCounterLwt
            ))
            .count(),
        1
    );
    let owned = plans
        .iter()
        .filter(|plan| {
            matches!(
                plan.reconcile(
                    PendingCounterReadState::Current(pending(11)),
                    PendingOwnershipReadState::OwnedBy(winner),
                ),
                PendingCounterReconcileAction::Owned(_)
            )
        })
        .count();
    assert_eq!(owned, 1);
    assert_eq!(
        plans
            .iter()
            .filter(|plan| matches!(
                plan.reconcile(
                    PendingCounterReadState::Current(pending(11)),
                    PendingOwnershipReadState::OwnedBy(winner),
                ),
                PendingCounterReconcileAction::Conflict(
                    PendingCounterConflict::OwnedByOther { .. }
                )
            ))
            .count(),
        63
    );
}

#[test]
fn retry_is_byte_stable_and_timestamp_replacement_changes_intent() {
    let first = allocation(10, 0x111, 1_000);
    let retry = allocation(10, 0x111, 1_000);
    let changed = allocation(10, 0x111, 1_001);
    assert_eq!(first, retry);
    assert_eq!(first.digest(), retry.digest());
    assert_eq!(first.counter_lwt_bind_values(), retry.counter_lwt_bind_values());
    assert_eq!(
        first.ownership_claim_bind_values(),
        retry.ownership_claim_bind_values()
    );
    assert_ne!(first.digest(), changed.digest());
}

#[test]
fn pending_context_materialization_requires_matching_verified_owner() {
    let counter = allocation(10, 0x111, 1_000);
    let PendingCounterReconcileAction::Owned(owner) = counter.reconcile(
        PendingCounterReadState::Current(pending(11)),
        PendingOwnershipReadState::OwnedBy(proc_id(0x111)),
    ) else {
        panic!("owner must verify")
    };

    let mapping = seal_commit_put(
        psy_node_core::store::typed::LogicalMutation::Put {
            key: psy_node_core::store::typed::TypedTableKey::PendingToCheckpoint(
                pending(11),
            ),
            value: psy_node_core::store::typed::MutationValue::CqlU64(50),
        },
        timestamp(1_000),
    )
    .unwrap();
    let pair = seal_commit_put_batch(
        psy_node_core::store::typed::LogicalMutation::PendingProcMapping {
            pending: pending(11),
            proc_id: proc_id(0x111),
        },
        timestamp(1_000),
    )
    .unwrap();
    let context = PendingContextMappingPlan::try_for_commit(
        &mapping,
        &pair,
        PendingContext::try_new(pending(10), proc_id(0x1010)).unwrap(),
        psy_node_core::store::typed::CheckpointId::try_new(50).unwrap(),
    )
    .unwrap();
    assert_eq!(context.ensure_ownership(owner), Ok(()));

    let wrong = allocation(10, 0x222, 1_000);
    let PendingCounterReconcileAction::Owned(wrong_owner) = wrong.reconcile(
        PendingCounterReadState::Current(pending(11)),
        PendingOwnershipReadState::OwnedBy(proc_id(0x222)),
    ) else {
        panic!("second model owner must verify")
    };
    assert!(matches!(
        context.ensure_ownership(wrong_owner),
        Err(PendingContextPlanError::OwnershipMismatch)
    ));
}

#[test]
fn prototype_stays_isolated_and_production_capability_remains_false() {
    let adapter = include_str!("../src/rollback/pending_counter.rs");
    let legacy = include_str!(
        "../../psy_node_scylla/src/tables/counter/u64_counter.rs"
    );
    let production = include_str!(
        "../../psy_node_core/src/psy_core_db/v3_implementation/full.rs"
    );
    let setup = include_str!("../src/psy_setup.rs");
    assert!(adapter.contains("PendingCounterAdapter"));
    assert!(adapter.contains("set_serial_consistency"));
    assert!(!adapter.contains("DELETE FROM"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!production.contains("PendingCounterAdapter"));
    assert!(!setup.contains("PendingCounterAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
