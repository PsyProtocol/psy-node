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
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        ManifestArtifactSetCommitment, SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        prepared_recovery_action, AuthorityHeadPublishDecision,
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityManifestLifecyclePhase,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        CommittedManifestRecoveryAction, ManifestLifecycleError,
        PreparedManifestRecoveryAction, SealedAuthorityManifest,
        SealedManifestRecoveryAction,
    },
    manifest_record::{
        AuthorityManifestStatus, ManifestRecordError,
        PreparedAuthorityManifestRecord,
    },
    timestamp::CommitWriteTimestampUs,
};

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn network(chain_id: u32) -> NetworkId {
    NetworkId::try_from_chain_id(chain_id).unwrap()
}

fn chain(
    network: NetworkId,
    checkpoint: u64,
    seed: u8,
) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network,
        ChainEpoch::new(7),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn prepared(
    authority: AuthorityScope,
    checkpoint: u64,
    seed: u8,
) -> PreparedAuthorityManifestRecord<PHash> {
    prepared_with_state_change(authority, checkpoint, seed, true)
}

fn prepared_with_state_change(
    authority: AuthorityScope,
    checkpoint: u64,
    seed: u8,
    state_changed: bool,
) -> PreparedAuthorityManifestRecord<PHash> {
    let network = network(1337);
    let key = AuthorityTimestampKey::new(network, authority);
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
    let (previous_state, candidate_state) = match authority {
        AuthorityScope::Coordinator => (checkpoint - 1, checkpoint),
        AuthorityScope::Realm { .. } => (checkpoint - 3, checkpoint),
    };
    let state_transition = if state_changed {
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(previous_state),
            checkpoint: AuthorityStateCheckpointId::new(candidate_state),
            old_root: AuthorityStateRoot::from_local_state_root(hash(
                seed.wrapping_add(3),
            )),
            new_root: AuthorityStateRoot::from_local_state_root(hash(
                seed.wrapping_add(4),
            )),
        }
    } else {
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(previous_state),
            root: AuthorityStateRoot::from_local_state_root(hash(
                seed.wrapping_add(3),
            )),
        }
    };
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(network, checkpoint - 1, seed.wrapping_add(1)),
        chain(network, checkpoint, seed.wrapping_add(2)),
        state_transition,
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
    let with_lease = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    PreparedAuthorityManifestRecord::seal(&with_lease, summary).unwrap()
}

fn realm_prepared(seed: u8) -> PreparedAuthorityManifestRecord<PHash> {
    prepared(
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
        11,
        seed,
    )
}

fn coordinator_prepared(seed: u8) -> PreparedAuthorityManifestRecord<PHash> {
    prepared(AuthorityScope::Coordinator, 11, seed)
}

fn realm_observation(
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

fn coordinator_observation(
    prepared: &PreparedAuthorityManifestRecord<PHash>,
) -> AuthorityPostWriteObservation<PHash> {
    AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(prepared),
        prepared.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            prepared.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::CoordinatorPublicInput(
            CheckpointHash::from_proof_public_inputs_hash(
                *prepared
                    .intent()
                    .candidate_chain()
                    .checkpoint()
                    .checkpoint_hash()
                    .as_inner(),
            ),
        ),
    )
}

#[test]
fn phases_have_exact_monotonic_status_and_revision() {
    assert_eq!(
        AuthorityManifestLifecyclePhase::Prepared.status(),
        AuthorityManifestStatus::Prepared
    );
    assert_eq!(
        AuthorityManifestLifecyclePhase::Sealed.status(),
        AuthorityManifestStatus::Sealed
    );
    assert_eq!(
        AuthorityManifestLifecyclePhase::Committed.status(),
        AuthorityManifestStatus::Committed
    );
    assert_eq!(AuthorityManifestLifecyclePhase::Prepared.revision().get(), 0);
    assert_eq!(AuthorityManifestLifecyclePhase::Sealed.revision().get(), 1);
    assert_eq!(AuthorityManifestLifecyclePhase::Committed.revision().get(), 2);
}

#[test]
fn realm_requires_exact_candidate_state_and_mutation_digest() {
    let record = realm_prepared(1);
    let sealed = SealedAuthorityManifest::verify_and_seal(
        record.clone(),
        realm_observation(&record),
    )
    .unwrap();
    assert_eq!(sealed.phase(), AuthorityManifestLifecyclePhase::Sealed);
    assert_eq!(sealed.revision().get(), 1);

    let other = realm_prepared(2);
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            record.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&other),
                record.intent().artifacts().mutation_digest(),
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    record.intent().head_payload().as_bytes(),
                ),
                AuthorityProofObservation::NotApplicableForRealm,
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::PostWriteHeadMismatch
    );
    let mut wrong_digest = record.intent().artifacts().mutation_digest();
    wrong_digest[0] ^= 1;
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            record.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&record),
                wrong_digest,
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    record.intent().head_payload().as_bytes(),
                ),
                AuthorityProofObservation::NotApplicableForRealm,
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::MutationDigestMismatch
    );
}

#[test]
fn root_match_does_not_hide_head_payload_mismatch() {
    let record = realm_prepared(15);
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            record.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&record),
                record.intent().artifacts().mutation_digest(),
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    b"wrong singleton and cursor payload",
                ),
                AuthorityProofObservation::NotApplicableForRealm,
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::HeadPayloadDigestMismatch
    );
}

#[test]
fn unchanged_realm_state_remains_sparse_while_manifest_advances() {
    let record = prepared_with_state_change(
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
        11,
        14,
        false,
    );
    let candidate = AuthorityHeadView::candidate(&record);
    assert_eq!(candidate.chain().checkpoint().checkpoint_id().get(), 11);
    assert_eq!(candidate.state_checkpoint().get(), 8);
    let sealed = SealedAuthorityManifest::verify_and_seal(
        record.clone(),
        realm_observation(&record),
    )
    .unwrap();
    assert_eq!(sealed.verified_head(), &candidate);
}

#[test]
fn coordinator_requires_exact_proof_public_input_and_realm_rejects_it() {
    let coordinator = coordinator_prepared(3);
    SealedAuthorityManifest::verify_and_seal(
        coordinator.clone(),
        coordinator_observation(&coordinator),
    )
    .unwrap();
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            coordinator.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&coordinator),
                coordinator.intent().artifacts().mutation_digest(),
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    coordinator.intent().head_payload().as_bytes(),
                ),
                AuthorityProofObservation::NotApplicableForRealm,
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::CoordinatorProofRequired
    );
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            coordinator.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&coordinator),
                coordinator.intent().artifacts().mutation_digest(),
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    coordinator.intent().head_payload().as_bytes(),
                ),
                AuthorityProofObservation::CoordinatorPublicInput(
                    CheckpointHash::from_proof_public_inputs_hash(hash(0xEE)),
                ),
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::ProofCheckpointHashMismatch
    );

    let realm = realm_prepared(4);
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            realm.clone(),
            AuthorityPostWriteObservation::new(
                AuthorityHeadView::candidate(&realm),
                realm.intent().artifacts().mutation_digest(),
                AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                    realm.intent().head_payload().as_bytes(),
                ),
                AuthorityProofObservation::CoordinatorPublicInput(
                    CheckpointHash::from_proof_public_inputs_hash(hash(6)),
                ),
            ),
        )
        .unwrap_err(),
        ManifestLifecycleError::RealmProofMustBeAbsent
    );
}

#[test]
fn head_cas_has_applied_idempotent_retry_and_conflict_outcomes() {
    let record = realm_prepared(5);
    let sealed = SealedAuthorityManifest::verify_and_seal(
        record.clone(),
        realm_observation(&record),
    )
    .unwrap();
    let expected = AuthorityHeadView::expected(&record);
    let candidate = AuthorityHeadView::candidate(&record);
    let conflict = AuthorityHeadView::candidate(&realm_prepared(6));

    assert!(matches!(
        sealed.classify_head_cas(true, candidate).unwrap(),
        AuthorityHeadPublishDecision::Published(_)
    ));
    assert!(matches!(
        sealed.classify_head_cas(false, candidate).unwrap(),
        AuthorityHeadPublishDecision::Idempotent(_)
    ));
    assert_eq!(
        sealed.classify_head_cas(false, expected).unwrap(),
        AuthorityHeadPublishDecision::RetryExactSealedIntent
    );
    assert!(matches!(
        sealed.classify_head_cas(false, conflict).unwrap(),
        AuthorityHeadPublishDecision::Conflict { current } if current == conflict
    ));
    assert_eq!(
        sealed.classify_head_cas(true, expected).unwrap_err(),
        ManifestLifecycleError::AppliedHeadCasMismatch
    );
}

#[test]
fn only_candidate_head_receipt_can_mark_the_same_manifest_committed() {
    let first_record = realm_prepared(7);
    let first = SealedAuthorityManifest::verify_and_seal(
        first_record.clone(),
        realm_observation(&first_record),
    )
    .unwrap();
    let receipt = match first
        .classify_head_cas(true, AuthorityHeadView::candidate(&first_record))
        .unwrap()
    {
        AuthorityHeadPublishDecision::Published(receipt) => receipt,
        other => panic!("unexpected decision: {other:?}"),
    };
    let committed = first.mark_committed(receipt).unwrap();
    assert_eq!(committed.phase(), AuthorityManifestLifecyclePhase::Committed);
    assert_eq!(committed.revision().get(), 2);

    let second_record = realm_prepared(8);
    let second = SealedAuthorityManifest::verify_and_seal(
        second_record.clone(),
        realm_observation(&second_record),
    )
    .unwrap();
    assert_eq!(
        second.mark_committed(receipt).unwrap_err(),
        ManifestLifecycleError::HeadPublishReceiptMismatch
    );
}

#[test]
fn crash_recovery_matrix_is_fail_closed() {
    let record = realm_prepared(9);
    assert_eq!(
        prepared_recovery_action(&record),
        PreparedManifestRecoveryAction::ReapplyExactMutationsAndVerify
    );
    let sealed = SealedAuthorityManifest::verify_and_seal(
        record.clone(),
        realm_observation(&record),
    )
    .unwrap();
    let expected = AuthorityHeadView::expected(&record);
    let candidate = AuthorityHeadView::candidate(&record);
    let conflict = AuthorityHeadView::candidate(&realm_prepared(10));
    assert_eq!(
        sealed.recovery_action(expected),
        SealedManifestRecoveryAction::PublishExactCandidate
    );
    let receipt = match sealed.recovery_action(candidate) {
        SealedManifestRecoveryAction::MarkCommitted(receipt) => receipt,
        other => panic!("unexpected recovery action: {other:?}"),
    };
    assert!(matches!(
        sealed.recovery_action(conflict),
        SealedManifestRecoveryAction::Conflict { current } if current == conflict
    ));
    let committed = sealed.mark_committed(receipt).unwrap();
    assert_eq!(
        committed.recovery_action(candidate).unwrap(),
        CommittedManifestRecoveryAction::CompleteTimestampLease
    );
    assert_eq!(
        committed.recovery_action(conflict).unwrap_err(),
        ManifestLifecycleError::CommittedHeadMismatch
    );
}

#[test]
fn observed_head_validates_network_and_sparse_state_rules() {
    let realm = realm_prepared(11);
    let realm_candidate = AuthorityHeadView::candidate(&realm);
    assert_eq!(
        AuthorityHeadView::try_from_observed(
            realm_candidate.key(),
            chain(network(1), 11, 1),
            realm_candidate.state_checkpoint(),
            *realm_candidate.state_root(),
        )
        .unwrap_err(),
        ManifestLifecycleError::HeadNetworkMismatch
    );
    assert_eq!(
        AuthorityHeadView::try_from_observed(
            realm_candidate.key(),
            *realm_candidate.chain(),
            AuthorityStateCheckpointId::new(12),
            *realm_candidate.state_root(),
        )
        .unwrap_err(),
        ManifestLifecycleError::RealmStateAheadOfChain {
            state_checkpoint: 12,
            chain_checkpoint: 11,
        }
    );

    let coordinator = coordinator_prepared(12);
    let coordinator_candidate = AuthorityHeadView::candidate(&coordinator);
    assert!(matches!(
        AuthorityHeadView::try_from_observed(
            coordinator_candidate.key(),
            *coordinator_candidate.chain(),
            AuthorityStateCheckpointId::new(10),
            *coordinator_candidate.state_root(),
        ),
        Err(ManifestLifecycleError::CoordinatorStateCheckpointMismatch { .. })
    ));
}

#[test]
fn prepared_decoder_cannot_accept_future_lifecycle_status() {
    let record = realm_prepared(13);
    assert_eq!(
        PreparedAuthorityManifestRecord::decode_persisted(
            *record.identity(),
            0,
            AuthorityManifestStatus::Sealed as i8,
            record.digest().as_bytes(),
            record.encode_canonical(),
        )
        .unwrap_err(),
        ManifestRecordError::UnsupportedPreparedStatus(
            AuthorityManifestStatus::Sealed as i8
        )
    );
}
