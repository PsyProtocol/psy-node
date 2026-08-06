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
        classify_normal_head_publish, plan_normal_commit_recovery,
        seal_verified_normal_commit, NormalCommitOrchestrationError,
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
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
    Fixture {
        prepared,
        allocator_active: reservation.candidate(),
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

#[test]
fn happy_path_has_one_unskippable_typed_action_per_durable_phase() {
    let fixture = fixture(1);
    let expected = AuthorityHeadView::expected(&fixture.prepared);
    let candidate = AuthorityHeadView::candidate(&fixture.prepared);
    let mut manifest = PersistedAuthorityManifest::Prepared(fixture.prepared.clone());

    match plan_normal_commit_recovery(
        &manifest,
        expected,
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
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();
    manifest = PersistedAuthorityManifest::Sealed(sealed.clone());
    assert!(matches!(
        plan_normal_commit_recovery(
            &manifest,
            expected,
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalCommitRecoveryAction::PublishExactHead { .. }
    ));

    let committed = match classify_normal_head_publish(
        sealed,
        true,
        candidate,
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
        candidate,
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
            candidate,
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
    let expected = AuthorityHeadView::expected(&fixture.prepared);
    let candidate = AuthorityHeadView::candidate(&fixture.prepared);
    let prepared = PersistedAuthorityManifest::Prepared(fixture.prepared.clone());

    let first = plan_normal_commit_recovery(
        &prepared,
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();
    let retry = plan_normal_commit_recovery(
        &prepared,
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();
    assert_eq!(first, retry);

    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();
    let recovered_committed = match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed),
        candidate,
        observed_allocator(&fixture),
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PersistRecoveredCommitted { committed } => {
            committed
        }
        other => panic!("unexpected SEALED recovery: {other:?}"),
    };
    assert_eq!(
        recovered_committed.publication_kind(),
        AuthorityHeadPublicationKind::RecoveredCandidate
    );

    assert!(matches!(
        plan_normal_commit_recovery(
            &PersistedAuthorityManifest::Committed(recovered_committed),
            candidate,
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
    let expected = AuthorityHeadView::expected(&fixture.prepared);
    let conflict = AuthorityHeadView::candidate(&other.prepared);

    assert_eq!(
        plan_normal_commit_recovery(
            &PersistedAuthorityManifest::Prepared(fixture.prepared.clone()),
            AuthorityHeadView::candidate(&fixture.prepared),
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::PreparedHeadIsNotExpected
    );
    assert_eq!(
        seal_verified_normal_commit(
            fixture.prepared.clone(),
            observation(&fixture.prepared),
            conflict,
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AuthorityHeadChangedBeforeSeal
    );

    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();
    assert_eq!(
        classify_normal_head_publish(
            sealed,
            false,
            conflict,
            observed_allocator(&fixture),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AuthorityHeadConflict
    );
}

#[test]
fn head_retry_and_lost_success_have_distinct_safe_results() {
    let fixture = fixture(5);
    let expected = AuthorityHeadView::expected(&fixture.prepared);
    let candidate = AuthorityHeadView::candidate(&fixture.prepared);
    let sealed = seal_verified_normal_commit(
        fixture.prepared.clone(),
        observation(&fixture.prepared),
        expected,
        observed_allocator(&fixture),
    )
    .unwrap();

    assert_eq!(
        classify_normal_head_publish(
            sealed.clone(),
            false,
            expected,
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalHeadPublishProgress::RetryExactSealedIntent
    );
    assert!(matches!(
        classify_normal_head_publish(
            sealed,
            false,
            candidate,
            observed_allocator(&fixture),
        )
        .unwrap(),
        NormalHeadPublishProgress::PersistCommitted { committed }
            if committed.publication_kind()
                == AuthorityHeadPublicationKind::Idempotent
    ));
}

#[test]
fn allocator_ownership_and_coordinates_are_checked_at_every_phase() {
    let other = fixture(7);
    let fixture = fixture(6);
    let expected = AuthorityHeadView::expected(&fixture.prepared);
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
            expected,
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
            expected,
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
            expected,
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
            expected,
            observed_state(&fixture, alternate),
        )
        .unwrap_err(),
        NormalCommitOrchestrationError::AllocatorCoordinatesMismatch
    );
}
