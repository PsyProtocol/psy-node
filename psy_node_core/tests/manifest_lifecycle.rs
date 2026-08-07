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
        AuthorityHeadPayloadDigest, AuthorityHeadPublicationKind,
        AuthorityHeadView, AuthorityManifestLifecyclePhase,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        CommittedAuthorityManifest, CommittedManifestRecoveryAction,
        ManifestLifecycleError, PersistedAuthorityManifest,
        PreparedManifestRecoveryAction, SealedAuthorityManifest,
        SealedManifestRecoveryAction,
    },
    manifest_record::{
        AuthorityManifestStatus, ManifestRecordError,
        PreparedAuthorityManifestRecord,
    },
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

fn lifecycle_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

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
    prepared_with_state_change(
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
        11,
        seed,
        false,
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

fn sealed_realm(seed: u8) -> SealedAuthorityManifest<PHash> {
    let record = realm_prepared(seed);
    SealedAuthorityManifest::verify_and_seal(
        record.clone(),
        realm_observation(&record),
    )
    .unwrap()
}

fn committed_realm(seed: u8) -> CommittedAuthorityManifest<PHash> {
    let sealed = sealed_realm(seed);
    let candidate = *sealed.verified_head();
    let receipt = match sealed.classify_head_cas(true, candidate).unwrap() {
        AuthorityHeadPublishDecision::Published(receipt) => receipt,
        other => panic!("unexpected publication decision: {other:?}"),
    };
    sealed.mark_committed(receipt).unwrap()
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
fn changed_realm_cannot_use_the_unchanged_proof_marker() {
    let record = prepared_with_state_change(
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
        11,
        16,
        true,
    );
    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(
            record.clone(),
            realm_observation(&record),
        )
        .unwrap_err(),
        ManifestLifecycleError::ChangedRealmEvidenceRequired
    );
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

#[test]
fn sealed_and_committed_codecs_round_trip_exactly() {
    let sealed = sealed_realm(16);
    let sealed_decoded = SealedAuthorityManifest::decode_persisted(
        *sealed.prepared().identity(),
        sealed.revision().as_i64(),
        sealed.status() as i8,
        sealed.prepared().digest().as_bytes(),
        sealed.lifecycle_digest().as_bytes(),
        sealed.encode_canonical(),
    )
    .unwrap();
    assert_eq!(sealed_decoded, sealed);
    assert_eq!(
        sealed_decoded.encode_canonical(),
        sealed.encode_canonical()
    );

    let committed = committed_realm(17);
    let committed_decoded = CommittedAuthorityManifest::decode_persisted(
        *committed.sealed().prepared().identity(),
        committed.revision().as_i64(),
        committed.status() as i8,
        committed.sealed().prepared().digest().as_bytes(),
        committed.lifecycle_digest().as_bytes(),
        committed.encode_canonical(),
    )
    .unwrap();
    assert_eq!(committed_decoded, committed);
    assert_eq!(
        committed_decoded.publication_kind(),
        AuthorityHeadPublicationKind::Applied
    );
}

#[test]
fn lifecycle_codec_is_deterministic_and_keeps_prepared_digest_immutable() {
    let first = committed_realm(18);
    let second = committed_realm(18);
    assert_eq!(first, second);
    assert_eq!(first.encode_canonical(), second.encode_canonical());
    assert_eq!(first.lifecycle_digest(), second.lifecycle_digest());
    assert_ne!(
        first.sealed().lifecycle_digest().as_bytes(),
        first.lifecycle_digest().as_bytes()
    );
    assert_eq!(
        first.sealed().prepared().digest(),
        second.sealed().prepared().digest()
    );
    assert_eq!(
        hex::encode(first.sealed().lifecycle_digest().as_bytes()),
        "7c8328ca69d28208cfb1ac2df7f93e9a74bbfa8b30ee2632b3f623b8c002e552"
    );
    assert_eq!(
        hex::encode(first.lifecycle_digest().as_bytes()),
        "d47703f5825434a41e1013964811f65faf502c7c65dc29ecc4328c855b6fd469"
    );
}

#[test]
fn sealed_codec_rejects_cell_and_payload_corruption() {
    let sealed = sealed_realm(19);
    let decode = |revision: i64,
                  status: i8,
                  prepared_digest: &[u8],
                  lifecycle_digest: &[u8],
                  payload: &[u8]| {
        SealedAuthorityManifest::decode_persisted(
            *sealed.prepared().identity(),
            revision,
            status,
            prepared_digest,
            lifecycle_digest,
            payload,
        )
    };
    assert!(matches!(
        decode(
            0,
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            sealed.lifecycle_digest().as_bytes(),
            sealed.encode_canonical(),
        ),
        Err(ManifestLifecycleError::LifecycleRevisionMismatch { .. })
    ));
    assert!(matches!(
        decode(
            sealed.revision().as_i64(),
            AuthorityManifestStatus::Committed as i8,
            sealed.prepared().digest().as_bytes(),
            sealed.lifecycle_digest().as_bytes(),
            sealed.encode_canonical(),
        ),
        Err(ManifestLifecycleError::LifecycleStatusMismatch { .. })
    ));
    let mut wrong_prepared_digest = *sealed.prepared().digest().as_bytes();
    wrong_prepared_digest[0] ^= 1;
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            &wrong_prepared_digest,
            sealed.lifecycle_digest().as_bytes(),
            sealed.encode_canonical(),
        )
        .unwrap_err(),
        ManifestLifecycleError::PreparedDigestMismatch
    );
    let mut wrong_lifecycle_digest = *sealed.lifecycle_digest().as_bytes();
    wrong_lifecycle_digest[0] ^= 1;
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &wrong_lifecycle_digest,
            sealed.encode_canonical(),
        )
        .unwrap_err(),
        ManifestLifecycleError::LifecycleDigestMismatch
    );
    let bytes = sealed.encode_canonical();
    let sealed_domain = b"psy.rollback.sealed-authority-manifest.v1\0";
    let truncated = &bytes[..bytes.len() - 1];
    let truncated_digest = lifecycle_digest(sealed_domain, truncated);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &truncated_digest,
            truncated,
        )
        .unwrap_err(),
        ManifestLifecycleError::TruncatedLifecyclePayload
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    let trailing_digest = lifecycle_digest(sealed_domain, &trailing);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &trailing_digest,
            &trailing,
        )
        .unwrap_err(),
        ManifestLifecycleError::TrailingLifecyclePayloadBytes
    );
    let mut bad_magic = bytes.to_vec();
    bad_magic[0] ^= 1;
    let bad_magic_digest = lifecycle_digest(sealed_domain, &bad_magic);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &bad_magic_digest,
            &bad_magic,
        )
        .unwrap_err(),
        ManifestLifecycleError::InvalidLifecycleMagic
    );
    let mut bad_version = bytes.to_vec();
    bad_version[9] = 2;
    let bad_version_digest = lifecycle_digest(sealed_domain, &bad_version);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &bad_version_digest,
            &bad_version,
        )
        .unwrap_err(),
        ManifestLifecycleError::UnknownLifecycleCodecVersion(2)
    );
    let mut bad_proof_kind = bytes.to_vec();
    let proof_kind_offset = bad_proof_kind.len() - 33;
    bad_proof_kind[proof_kind_offset] = 99;
    let bad_proof_digest = lifecycle_digest(sealed_domain, &bad_proof_kind);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &bad_proof_digest,
            &bad_proof_kind,
        )
        .unwrap_err(),
        ManifestLifecycleError::UnknownProofKind(99)
    );
    let mut noncanonical_realm_proof = bytes.to_vec();
    *noncanonical_realm_proof.last_mut().unwrap() = 1;
    let noncanonical_realm_digest =
        lifecycle_digest(sealed_domain, &noncanonical_realm_proof);
    assert_eq!(
        decode(
            sealed.revision().as_i64(),
            sealed.status() as i8,
            sealed.prepared().digest().as_bytes(),
            &noncanonical_realm_digest,
            &noncanonical_realm_proof,
        )
        .unwrap_err(),
        ManifestLifecycleError::NonCanonicalRealmProof
    );
}

#[test]
fn committed_codec_rejects_unknown_publication_kind() {
    let committed = committed_realm(20);
    let mut bytes = committed.encode_canonical().to_vec();
    *bytes.last_mut().unwrap() = 99;
    let digest = lifecycle_digest(
        b"psy.rollback.committed-authority-manifest.v1\0",
        &bytes,
    );
    assert_eq!(
        CommittedAuthorityManifest::decode_persisted(
            *committed.sealed().prepared().identity(),
            committed.revision().as_i64(),
            committed.status() as i8,
            committed.sealed().prepared().digest().as_bytes(),
            &digest,
            &bytes,
        )
        .unwrap_err(),
        ManifestLifecycleError::UnknownHeadPublicationKind(99)
    );
}

#[test]
fn persisted_lifecycle_dispatches_all_three_statuses_strictly() {
    let prepared = realm_prepared(21);
    let decoded = PersistedAuthorityManifest::decode_persisted(
        *prepared.identity(),
        prepared.revision().as_i64(),
        prepared.status() as i8,
        prepared.digest().as_bytes(),
        prepared.digest().as_bytes(),
        prepared.encode_canonical(),
    )
    .unwrap();
    assert!(matches!(decoded, PersistedAuthorityManifest::Prepared(_)));
    assert_eq!(decoded.prepared(), &prepared);

    let sealed = sealed_realm(22);
    let decoded = PersistedAuthorityManifest::decode_persisted(
        *sealed.prepared().identity(),
        sealed.revision().as_i64(),
        sealed.status() as i8,
        sealed.prepared().digest().as_bytes(),
        sealed.lifecycle_digest().as_bytes(),
        sealed.encode_canonical(),
    )
    .unwrap();
    assert!(matches!(decoded, PersistedAuthorityManifest::Sealed(_)));

    let committed = committed_realm(23);
    let decoded = PersistedAuthorityManifest::decode_persisted(
        *committed.sealed().prepared().identity(),
        committed.revision().as_i64(),
        committed.status() as i8,
        committed.sealed().prepared().digest().as_bytes(),
        committed.lifecycle_digest().as_bytes(),
        committed.encode_canonical(),
    )
    .unwrap();
    assert!(matches!(
        decoded,
        PersistedAuthorityManifest::Committed(_)
    ));
}

#[test]
fn prepared_lifecycle_digest_must_equal_immutable_manifest_digest() {
    let prepared = realm_prepared(24);
    let mut wrong = *prepared.digest().as_bytes();
    wrong[0] ^= 1;
    assert_eq!(
        PersistedAuthorityManifest::decode_persisted(
            *prepared.identity(),
            prepared.revision().as_i64(),
            prepared.status() as i8,
            prepared.digest().as_bytes(),
            &wrong,
            prepared.encode_canonical(),
        )
        .unwrap_err(),
        ManifestLifecycleError::PreparedLifecycleDigestMismatch
    );
}
