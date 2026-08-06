use parth_core::PHash;
use psy_data::{
    protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash,
            CheckpointId as ProtocolCheckpointId, CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
            AuthorityStateRoot,
        },
    },
    v1::qdata::checkpoint::QEDL2BlockState,
};
use psy_node_core::store::{
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs,
        NewBranchWriteTimestampUs,
    },
    typed::{
        CheckpointId, LatestInfoSlot, LogicalMutation, MutationValue,
        TypedTableKey, U64SingletonSlot,
    },
};
use psy_node_scylla::rollback::*;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
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

fn l2_state(checkpoint_id: u64) -> QEDL2BlockState {
    QEDL2BlockState {
        checkpoint_id,
        next_add_withdrawal_id: 2,
        next_process_withdrawal_id: 3,
        next_deposit_id: 4,
        total_deposits_claimed_epoch: 5,
        next_user_id: 6,
        end_balance: 7,
        next_contract_id: 8,
    }
}

fn l2_bytes(checkpoint_id: u64) -> Vec<u8> {
    l2_state(checkpoint_id).psy_ser_to_bytes_vec().unwrap()
}

fn chain(checkpoint_id: u64) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        NetworkId::try_from_chain_id(0).unwrap(),
        ChainEpoch::new(3),
        CheckpointRef::new(
            ProtocolCheckpointId::new(checkpoint_id),
            CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
        ),
    )
}

fn observation_bytes(
    checkpoint_id: u64,
    state_checkpoint_id: u64,
    authority: AuthorityScope,
) -> Vec<u8> {
    AuthorityObservation::try_new(
        chain(checkpoint_id),
        authority,
        AuthorityStateCheckpointId::new(state_checkpoint_id),
        AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
    )
    .unwrap()
    .to_canonical_bytes()
    .to_vec()
}

fn realm_observation(checkpoint_id: u64, state_checkpoint_id: u64) -> Vec<u8> {
    observation_bytes(
        checkpoint_id,
        state_checkpoint_id,
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        },
    )
}

fn commit_latest(
    slot: LatestInfoSlot,
    value: Vec<u8>,
    ts: i64,
) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::LatestInfo(slot),
            value: MutationValue::PsyCanonicalBytes(value),
        },
        timestamp(ts),
    )
    .unwrap()
}

fn restore_latest(
    slot: LatestInfoSlot,
    value: Vec<u8>,
    ts: NewBranchWriteTimestampUs,
) -> SealedTimestampedPut {
    seal_new_branch_put(
        LogicalMutation::Put {
            key: TypedTableKey::LatestInfo(slot),
            value: MutationValue::PsyCanonicalBytes(value),
        },
        ts,
    )
    .unwrap()
}

fn commit_checkpoint(value: u64, ts: i64) -> SealedTimestampedPut {
    seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ),
            value: MutationValue::CqlU64(value),
        },
        timestamp(ts),
    )
    .unwrap()
}

fn restore_checkpoint(
    value: u64,
    ts: NewBranchWriteTimestampUs,
) -> SealedTimestampedPut {
    seal_new_branch_put(
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ),
            value: MutationValue::CqlU64(value),
        },
        ts,
    )
    .unwrap()
}

#[test]
fn registry_declares_both_tables_as_restore_singletons_without_delete() {
    for table in [
        ScyllaPhysicalTableId::LatestInfo,
        ScyllaPhysicalTableId::U64Singleton,
    ] {
        let descriptor = physical_descriptor(table);
        assert_eq!(descriptor.version_axis, VersionAxis::Singleton);
        assert_eq!(descriptor.rollback_policy, RollbackPolicy::RestoreSingleton);
        assert!(descriptor.delete_candidates.is_empty());
        assert_eq!(
            descriptor.manifest_requirement,
            ManifestRequirement::SingletonBeforeAfter
        );
    }
}

#[test]
fn query_catalog_uses_real_schemas_explicit_timestamp_and_no_delete() {
    let queries = MutableSingletonQueries::new(
        &CqlKeyspaceName::try_new("psy_d02t7").unwrap(),
    );
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_mutable_singleton_v1.txt")
    );
    for query in [queries.latest_info_put(), queries.latest_checkpoint_put()] {
        assert!(query.cql().contains("USING TIMESTAMP ?"));
        assert!(!query.cql().contains("DELETE"));
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
}

#[test]
fn l2_state_commit_uses_real_codec_checkpoint_and_psz1_storage() {
    let sealed = commit_latest(
        LatestInfoSlot::LatestL2BlockState,
        l2_bytes(10),
        1_000,
    );
    let plan = LatestInfoTransitionPlan::try_for_commit(
        &sealed,
        checkpoint(10),
        LatestInfoBeforeImage::Present(l2_bytes(9)),
    )
    .unwrap();
    assert_eq!(plan.kind(), SingletonTransitionKind::AuthorityCommit);
    assert_eq!(plan.put().slot(), LatestInfoSlot::LatestL2BlockState);
    assert_eq!(plan.put().checkpoint(), checkpoint(10));
    assert_eq!(plan.put().canonical_value(), l2_bytes(10));
    assert!(plan.put().stored_value().starts_with(b"PSZ1"));
    assert_eq!(
        psy_node_scylla::compression::decompress(plan.put().stored_value())
            .unwrap(),
        l2_bytes(10)
    );
    assert_eq!(
        plan.put().bind_values(),
        vec![
            PrototypeBindValue::BigInt(1),
            PrototypeBindValue::Blob(plan.put().stored_value().to_vec()),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
}

#[test]
fn realm_observation_uses_the_real_122_byte_codec_and_exact_chain_height() {
    let before = realm_observation(9, 7);
    let after = realm_observation(10, 7);
    assert_eq!(after.len(), 122);
    let plan = LatestInfoTransitionPlan::try_for_commit(
        &commit_latest(
            LatestInfoSlot::RealmAuthorityObservation,
            after.clone(),
            1_100,
        ),
        checkpoint(10),
        LatestInfoBeforeImage::Present(before),
    )
    .unwrap();
    assert_eq!(plan.put().slot(), LatestInfoSlot::RealmAuthorityObservation);
    assert_eq!(plan.put().canonical_value(), after);

    let coordinator = observation_bytes(
        10,
        10,
        AuthorityScope::Coordinator,
    );
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::RealmAuthorityObservation,
                coordinator,
                1_100,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::ExpectedRealmObservation)
    ));
}

#[test]
fn reader_only_root_slot_is_restore_only_and_requires_32_bytes() {
    let root = vec![0x44; 32];
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::LatestCheckpointTreeRoot,
                root.clone(),
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::ReaderOnlySlotRequiresRestore)
    ));
    let post_fence = new_branch_timestamp(1_000, 2_000, 3_000);
    let restored = LatestInfoTransitionPlan::try_for_restore(
        &restore_latest(
            LatestInfoSlot::LatestCheckpointTreeRoot,
            root,
            post_fence,
        ),
        checkpoint(10),
        vec![0x55; 32],
    )
    .unwrap();
    assert_eq!(restored.kind(), SingletonTransitionKind::TargetRestore);
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_restore(
            &restore_latest(
                LatestInfoSlot::LatestCheckpointTreeRoot,
                vec![0x44; 31],
                post_fence,
            ),
            checkpoint(10),
            vec![0x55; 32],
        ),
        Err(MutableSingletonPlanError::InvalidCheckpointRootLength { actual: 31 })
    ));
}

#[test]
fn restore_requires_post_fence_write_kind_and_accepts_old_head_before_image() {
    let current = l2_bytes(20);
    let target = l2_bytes(10);
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_restore(
            &commit_latest(
                LatestInfoSlot::LatestL2BlockState,
                target.clone(),
                3_000,
            ),
            checkpoint(10),
            current.clone(),
        ),
        Err(MutableSingletonPlanError::WrongWriteKind { .. })
    ));
    let plan = LatestInfoTransitionPlan::try_for_restore(
        &restore_latest(
            LatestInfoSlot::LatestL2BlockState,
            target,
            new_branch_timestamp(1_000, 2_000, 3_000),
        ),
        checkpoint(10),
        current,
    )
    .unwrap();
    assert_eq!(plan.put().write_timestamp_us(), 3_000);
}

#[test]
fn latest_checkpoint_commit_and_restore_bind_exact_target_value() {
    let commit = U64SingletonTransitionPlan::try_for_commit(
        &commit_checkpoint(10, 1_000),
        checkpoint(10),
        U64SingletonBeforeImage::Present(9),
    )
    .unwrap();
    assert_eq!(commit.put().slot(), U64SingletonSlot::LatestCheckpoint);
    assert_eq!(commit.put().value(), 10);
    assert_eq!(
        commit.put().bind_values(),
        vec![
            PrototypeBindValue::BigInt(1),
            PrototypeBindValue::BigInt(10),
            PrototypeBindValue::BigInt(1_000),
        ]
    );

    assert!(matches!(
        U64SingletonTransitionPlan::try_for_commit(
            &commit_checkpoint(11, 1_000),
            checkpoint(10),
            U64SingletonBeforeImage::Present(9),
        ),
        Err(MutableSingletonPlanError::TargetCheckpointMismatch { .. })
    ));
    assert!(matches!(
        U64SingletonTransitionPlan::try_for_commit(
            &commit_checkpoint(10, 1_000),
            checkpoint(10),
            U64SingletonBeforeImage::Present(11),
        ),
        Err(MutableSingletonPlanError::PriorCheckpointAhead { .. })
    ));

    let restore = U64SingletonTransitionPlan::try_for_restore(
        &restore_checkpoint(10, new_branch_timestamp(1_000, 2_000, 3_000)),
        checkpoint(10),
        20,
    )
    .unwrap();
    assert_eq!(restore.before(), U64SingletonBeforeImage::Present(20));
    assert_eq!(restore.kind(), SingletonTransitionKind::TargetRestore);
}

#[test]
fn malformed_checkpoint_context_wrong_family_and_value_kind_fail_closed() {
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::LatestL2BlockState,
                vec![0; 59],
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::InvalidL2BlockStateLength { actual: 59 })
    ));
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::LatestL2BlockState,
                l2_bytes(11),
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::TargetCheckpointMismatch { .. })
    ));
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::LatestL2BlockState,
                l2_bytes(10),
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Present(l2_bytes(11)),
        ),
        Err(MutableSingletonPlanError::PriorCheckpointAhead { .. })
    ));

    let mut invalid_observation = realm_observation(10, 9);
    invalid_observation[0] ^= 1;
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::RealmAuthorityObservation,
                invalid_observation,
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::InvalidAuthorityObservationHeader)
    ));
    let mut state_ahead = realm_observation(10, 9);
    state_ahead[82..90].copy_from_slice(&11_u64.to_le_bytes());
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &commit_latest(
                LatestInfoSlot::RealmAuthorityObservation,
                state_ahead,
                1_000,
            ),
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::ObservationStateAhead { .. })
    ));

    let wrong_family = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::CheckpointLeaf(checkpoint(10)),
            value: MutationValue::PsyCanonicalBytes(vec![1; 32]),
        },
        timestamp(1_000),
    )
    .unwrap();
    assert!(matches!(
        LatestInfoTransitionPlan::try_for_commit(
            &wrong_family,
            checkpoint(10),
            LatestInfoBeforeImage::Absent,
        ),
        Err(MutableSingletonPlanError::WrongPhysicalTable(_))
    ));

    assert!(seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        timestamp(1_000),
    )
    .is_err());
}

#[test]
fn transition_digest_is_stable_and_commits_to_before_after_and_timestamp() {
    let sealed = commit_latest(
        LatestInfoSlot::LatestL2BlockState,
        l2_bytes(10),
        1_000,
    );
    let a = LatestInfoTransitionPlan::try_for_commit(
        &sealed,
        checkpoint(10),
        LatestInfoBeforeImage::Present(l2_bytes(9)),
    )
    .unwrap();
    let retry = LatestInfoTransitionPlan::try_for_commit(
        &sealed,
        checkpoint(10),
        LatestInfoBeforeImage::Present(l2_bytes(9)),
    )
    .unwrap();
    let changed_before = LatestInfoTransitionPlan::try_for_commit(
        &sealed,
        checkpoint(10),
        LatestInfoBeforeImage::Present(l2_bytes(8)),
    )
    .unwrap();
    let changed_timestamp = LatestInfoTransitionPlan::try_for_commit(
        &commit_latest(
            LatestInfoSlot::LatestL2BlockState,
            l2_bytes(10),
            1_001,
        ),
        checkpoint(10),
        LatestInfoBeforeImage::Present(l2_bytes(9)),
    )
    .unwrap();
    assert_eq!(a, retry);
    assert_ne!(a.digest(), changed_before.digest());
    assert_ne!(a.digest(), changed_timestamp.digest());
    assert_ne!(a.digest().as_bytes(), &[0; 32]);
}

#[test]
fn d02t7_remains_isolated_from_production_writers_and_setup() {
    let adapter = include_str!("../src/rollback/mutable_singleton.rs");
    let legacy = include_str!(
        "../../psy_node_core/src/psy_core_db/v3_implementation/full.rs"
    );
    let setup = include_str!("../src/psy_setup.rs");
    assert!(adapter.contains("MutableSingletonAdapter"));
    assert!(adapter.contains("put_latest_info"));
    assert!(adapter.contains("put_latest_checkpoint"));
    assert!(!legacy.contains("MutableSingletonAdapter"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!setup.contains("MutableSingletonAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
