use parth_core::{protocol::core_types::Q256BitHash, PHash};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::{
        AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        ObservedAuthorityTimestampState, StoredAuthorityTimestampState,
    },
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityLocalHeadModelError, AuthorityLocalHeadWriteOutcome,
        AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
        AuthorityStorageNamespaceId, StoredAuthorityLocalHead,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        ManifestArtifactSetCommitment, SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadPublicationKind,
        AuthorityHeadView, AuthorityPostWriteObservation,
        AuthorityProofObservation, PersistedAuthorityManifest,
    },
    manifest_record::PreparedAuthorityManifestRecord,
    normal_commit::{
        authorize_normal_head_publish, classify_normal_head_publish,
        plan_normal_commit_recovery, seal_verified_normal_commit,
        NormalCommitOrchestrationError, NormalCommitRecoveryAction,
        NormalHeadPublishProgress,
    },
    timestamp::CommitWriteTimestampUs,
};

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1337).unwrap()
}

fn chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(7),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

#[derive(Clone)]
struct Fixture {
    prepared: PreparedAuthorityManifestRecord<PHash>,
    allocator_active: StoredAuthorityTimestampState,
    local_head: StoredAuthorityLocalHead<PHash>,
}

fn fixture(seed: u8) -> Fixture {
    let authority = AuthorityScope::Realm {
        realm_id: 4,
        realm_sub_id: 2,
    };
    let key = AuthorityTimestampKey::new(network(), authority);
    let summary = vec![0xA0 | seed; 24];
    let mutation_digest = [0x50 | seed; 32];
    let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
        &summary,
        mutation_digest,
        1,
        1,
        0,
        1,
    )
    .unwrap();
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(10, seed.wrapping_add(1)),
        chain(11, seed.wrapping_add(2)),
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(8),
            root: AuthorityStateRoot::from_local_state_root(hash(
                seed.wrapping_add(3),
            )),
        },
        AuthorityHeadPayload::try_new(vec![seed; 16]).unwrap(),
        artifacts,
    )
    .unwrap();
    let bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(1_000_000).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let reservation = bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128(1_000_001).unwrap(),
        )
        .unwrap();
    let prepared_intent = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    let prepared =
        PreparedAuthorityManifestRecord::seal(&prepared_intent, summary).unwrap();
    let local_head = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::expected(&prepared),
        CommitWriteTimestampUs::try_from_i128(999_999).unwrap(),
        prepared.digest(),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(0).unwrap(),
            AuthorityStorageNamespaceId::from_verified_namespace_id([
                0xE0 | seed;
                32
            ]),
        ),
    )
    .candidate()
    .clone();
    Fixture {
        prepared,
        allocator_active: reservation.candidate(),
        local_head,
    }
}

fn observation(
    prepared: &PreparedAuthorityManifestRecord<PHash>,
) -> AuthorityPostWriteObservation<PHash> {
    AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(prepared),
        prepared.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            prepared.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    )
}

fn completed_allocator(fixture: &Fixture) -> StoredAuthorityTimestampState {
    let key = fixture.prepared.identity().timestamp_key();
    let lease = fixture
        .allocator_active
        .observe_intent(key, fixture.prepared.intent().digest());
    let lease = match lease {
        psy_node_core::store::authority_commit::AuthorityIntentObservation::Active(
            lease,
        ) => lease,
        other => panic!("unexpected allocator observation: {other:?}"),
    };
    fixture
        .allocator_active
        .seal_completion(key, lease)
        .unwrap()
        .candidate()
}

fn observed_allocator(fixture: &Fixture) -> ObservedAuthorityTimestampState {
    ObservedAuthorityTimestampState::from_selected_row(
        fixture.prepared.identity().timestamp_key(),
        fixture.allocator_active,
    )
}

fn observed_state(
    fixture: &Fixture,
    state: StoredAuthorityTimestampState,
) -> ObservedAuthorityTimestampState {
    ObservedAuthorityTimestampState::from_selected_row(
        fixture.prepared.identity().timestamp_key(),
        state,
    )
}

fn local_head_with_view(
    fixture: &Fixture,
    view: AuthorityHeadView<PHash>,
) -> StoredAuthorityLocalHead<PHash> {
    AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        view,
        fixture.local_head.commit_write_timestamp(),
        fixture.prepared.digest(),
        fixture.local_head.storage_binding(),
    )
    .candidate()
    .clone()
}

#[test]
fn happy_path_has_one_unskippable_typed_action_per_durable_phase() {
    let fixture = fixture(1);
    let mut manifest = PersistedAuthorityManifest::Prepared(fixture.prepared.clone());

    match plan_normal_commit_recovery(
        &manifest,
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::ReapplyExactMutationsAndVerify {
            prepared,
        } => {
            assert_eq!(prepared.digest(), fixture.prepared.digest());
            assert_eq!(
                prepared.commit_write_timestamp(),
                fixture.prepared.commit_write_timestamp()
            );
        }
        other => panic!("unexpected PREPARED action: {other:?}"),
    }

    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    manifest = PersistedAuthorityManifest::Sealed(sealed.clone());
    assert!(matches!(
        plan_normal_commit_recovery(
            &manifest,
            &fixture.local_head,
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalCommitRecoveryAction::PublishExactHead { .. }
    ));

    let publish = match plan_normal_commit_recovery(
        &manifest,
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected SEALED action: {other:?}"),
    };
    assert_eq!(*publish.manifest(), sealed);
    let candidate_local = publish.head_cas().candidate().clone();
    let committed = match classify_normal_head_publish(
        publish,
        AuthorityLocalHeadWriteOutcome::Applied(candidate_local.clone()),
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalHeadPublishProgress::PersistCommitted { committed } => committed,
        other => panic!("unexpected head result: {other:?}"),
    };
    manifest = PersistedAuthorityManifest::Committed(committed.clone());
    let completion = match plan_normal_commit_recovery(
        &manifest,
        &candidate_local,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::CompleteTimestampLease { completion } => {
            completion
        }
        other => panic!("unexpected COMMITTED action: {other:?}"),
    };
    assert_eq!(completion.lease().timestamp(), fixture.prepared.commit_write_timestamp());

    assert!(matches!(
        plan_normal_commit_recovery(
            &manifest,
            &candidate_local,
            observed_state(&fixture, completion.candidate()),
        )
        .unwrap(),
        NormalCommitRecoveryAction::Done { committed: current }
            if current == committed
    ));
}

#[test]
fn every_crash_boundary_resumes_from_durable_state_without_reinterpretation() {
    let fixture = fixture(2);
    let prepared = PersistedAuthorityManifest::Prepared(fixture.prepared.clone());

    let first = plan_normal_commit_recovery(
        &prepared,
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    let retry = plan_normal_commit_recovery(
        &prepared,
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    assert_eq!(first, retry);

    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    let publish = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed.clone()),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected SEALED publish plan: {other:?}"),
    };
    let candidate_local = publish.head_cas().candidate().clone();
    let recovered_committed = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        &candidate_local,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PersistRecoveredCommitted { committed } => committed,
        other => panic!("unexpected SEALED recovery: {other:?}"),
    };
    assert_eq!(
        recovered_committed.publication_kind(),
        AuthorityHeadPublicationKind::RecoveredCandidate
    );

    assert!(matches!(
        plan_normal_commit_recovery(
            &PersistedAuthorityManifest::Committed(recovered_committed),
            &candidate_local,
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalCommitRecoveryAction::CompleteTimestampLease { .. }
    ));
}

#[test]
fn verification_or_head_conflict_cannot_publish_or_seal() {
    let other = fixture(4);
    let fixture = fixture(3);
    let conflict = local_head_with_view(
        &fixture,
        AuthorityHeadView::candidate(&other.prepared),
    );
    let premature = local_head_with_view(
        &fixture,
        AuthorityHeadView::candidate(&fixture.prepared),
    );

    assert_eq!(
        plan_normal_commit_recovery(
            &PersistedAuthorityManifest::Prepared(fixture.prepared.clone()),
            &premature,
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::PreparedHeadIsNotExpected
    );
    assert_eq!(
        seal_verified_normal_commit(
            fixture.prepared.clone(),
            observation(&fixture.prepared),
            &conflict,
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AuthorityHeadChangedBeforeSeal
    );

    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    let publish = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected publish plan: {other:?}"),
    };
    assert_eq!(
        classify_normal_head_publish(
            publish,
            AuthorityLocalHeadWriteOutcome::Conflict(conflict),
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AuthorityHeadConflict
    );
}

#[test]
fn head_retry_and_lost_success_have_distinct_safe_results() {
    let fixture = fixture(5);
    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();

    let publish = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected publish plan: {other:?}"),
    };

    assert_eq!(
        classify_normal_head_publish(
            publish.clone(),
            AuthorityLocalHeadWriteOutcome::Conflict(
                fixture.local_head.clone(),
            ),
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalHeadPublishProgress::RetryExactSealedIntent
    );
    assert!(matches!(
        classify_normal_head_publish(
            publish.clone(),
            AuthorityLocalHeadWriteOutcome::Idempotent(
                publish.head_cas().candidate().clone(),
            ),
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalHeadPublishProgress::PersistCommitted { committed }
            if committed.publication_kind()
                == AuthorityHeadPublicationKind::Idempotent
    ));
}

#[test]
fn delayed_head_publish_is_reauthorized_before_io() {
    let other = fixture(16);
    let fixture = fixture(15);
    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    let publish = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected publish plan: {other:?}"),
    };

    authorize_normal_head_publish(&publish, observed_allocator(&fixture))
        .unwrap();
    assert_eq!(
        authorize_normal_head_publish(
            &publish,
            ObservedAuthorityTimestampState::from_selected_row(
                fixture.prepared.identity().timestamp_key(),
                other.allocator_active,
            ),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorOwnedByOtherIntent
    );
}

#[test]
fn allocator_ownership_and_coordinates_are_checked_at_every_phase() {
    let other = fixture(7);
    let fixture = fixture(6);
    let prepared = PersistedAuthorityManifest::Prepared(fixture.prepared.clone());

    let wrong_key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 99,
            realm_sub_id: 1,
        },
    );
    assert_eq!(
        plan_normal_commit_recovery(
            &prepared,
            &fixture.local_head,
            ObservedAuthorityTimestampState::from_selected_row(
                wrong_key,
                fixture.allocator_active,
            ),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorKeyMismatch
    );

    assert_eq!(
        plan_normal_commit_recovery(
            &prepared,
            &fixture.local_head,
            ObservedAuthorityTimestampState::from_selected_row(
                fixture.prepared.identity().timestamp_key(),
                other.allocator_active,
            ),
        )
            .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorOwnedByOtherIntent
    );
    assert_eq!(
        plan_normal_commit_recovery(
            &prepared,
            &fixture.local_head,
            observed_state(&fixture, completed_allocator(&fixture)),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorCompletedBeforeManifest
    );

    let key = fixture.prepared.identity().timestamp_key();
    let alternate = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(2_000_000).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    )
    .candidate()
    .seal_reservation(
        key,
        fixture.prepared.intent().digest(),
        AuthorityClockSampleUs::try_from_i128(2_000_001).unwrap(),
    )
    .unwrap()
    .candidate();
    assert_eq!(
        plan_normal_commit_recovery(
            &prepared,
            &fixture.local_head,
            observed_state(&fixture, alternate),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorCoordinatesMismatch
    );
}

#[test]
fn durable_head_codec_binds_partition_revision_manifest_and_namespace() {
    let fixture = fixture(8);
    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    let publish = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        &fixture.local_head,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected publish plan: {other:?}"),
    };
    let candidate = publish.head_cas().candidate();
    let payload = candidate.encode_canonical();
    let decoded = StoredAuthorityLocalHead::<PHash>::decode_persisted(
        fixture.prepared.identity().timestamp_key(),
        candidate.revision().as_i64(),
        &payload,
    )
    .unwrap();
    assert_eq!(decoded, *candidate);
    assert_eq!(
        decoded.storage_binding(),
        fixture.local_head.storage_binding()
    );
    assert_eq!(
        decoded.manifest_digest().as_bytes(),
        fixture.prepared.digest().as_bytes()
    );

    let aba_current = StoredAuthorityLocalHead::<PHash>::decode_persisted(
        fixture.prepared.identity().timestamp_key(),
        2,
        &publish.head_cas().expected_payload(),
    )
    .unwrap();
    assert!(matches!(
        publish
            .head_cas()
            .classify_lwt_observation(false, aba_current),
        Ok(AuthorityLocalHeadWriteOutcome::Conflict(current))
            if current.revision().get() == 2
    ));

    let wrong_key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 88,
            realm_sub_id: 1,
        },
    );
    assert_eq!(
        StoredAuthorityLocalHead::<PHash>::decode_persisted(
            wrong_key,
            candidate.revision().as_i64(),
            &payload,
        )
        .unwrap_err(),
        AuthorityLocalHeadModelError::SelectedKeyMismatch
    );

    let mut corrupted = payload;
    corrupted[0] ^= 1;
    assert_eq!(
        StoredAuthorityLocalHead::<PHash>::decode_persisted(
            fixture.prepared.identity().timestamp_key(),
            candidate.revision().as_i64(),
            &corrupted,
        )
        .unwrap_err(),
        AuthorityLocalHeadModelError::InvalidPayloadMagic
    );
}

#[test]
fn normal_head_cas_requires_timestamp_to_advance_strictly() {
    let fixture = fixture(9);
    let equal_timestamp_head = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::expected(&fixture.prepared),
        fixture.prepared.commit_write_timestamp(),
        fixture.prepared.digest(),
        fixture.local_head.storage_binding(),
    )
    .candidate()
    .clone();
    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        &equal_timestamp_head,
        observed_allocator(&fixture),
    )
    .unwrap();
    assert!(matches!(
        plan_normal_commit_recovery(
            &PersistedAuthorityManifest::Sealed(sealed),
            &equal_timestamp_head,
            observed_allocator(&fixture),
        ),
        Err(NormalCommitOrchestrationError::AuthorityLocalHead(
            AuthorityLocalHeadModelError::TimestampDidNotAdvance { .. }
        ))
    ));
}
