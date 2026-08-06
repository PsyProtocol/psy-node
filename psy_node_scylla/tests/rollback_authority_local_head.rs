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
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
        AuthorityStorageNamespaceId, SealedAuthorityLocalHeadCas,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        ManifestArtifactSetCommitment, SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        SealedAuthorityManifest,
    },
    manifest_record::PreparedAuthorityManifestRecord,
    timestamp::CommitWriteTimestampUs,
};
use psy_node_scylla::rollback::{
    decode_authority_local_head_persisted_cells,
    AuthorityLocalHeadBindValue, AuthorityLocalHeadBootstrapBinding,
    AuthorityLocalHeadCasBinding, AuthorityLocalHeadPrototypeError,
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
        ChainEpoch::new(5),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn fixture() -> (
    AuthorityLocalHeadBootstrap<PHash>,
    SealedAuthorityLocalHeadCas<PHash>,
) {
    let key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        },
    );
    let summary = vec![0xA5; 24];
    let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
        &summary,
        [0x55; 32],
        1,
        1,
        0,
        1,
    )
    .unwrap();
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(40, 1),
        chain(41, 2),
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(39),
            checkpoint: AuthorityStateCheckpointId::new(41),
            old_root: AuthorityStateRoot::from_local_state_root(hash(3)),
            new_root: AuthorityStateRoot::from_local_state_root(hash(4)),
        },
        AuthorityHeadPayload::try_new(vec![0x66; 16]).unwrap(),
        artifacts,
    )
    .unwrap();
    let reservation = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(500).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    )
    .candidate()
    .seal_reservation(
        key,
        intent.digest(),
        AuthorityClockSampleUs::try_from_i128(501).unwrap(),
    )
    .unwrap();
    let prepared_intent = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    let prepared =
        PreparedAuthorityManifestRecord::seal(&prepared_intent, summary).unwrap();
    let sealed = SealedAuthorityManifest::verify_and_seal(
        prepared.clone(),
        AuthorityPostWriteObservation::new(
            AuthorityHeadView::candidate(&prepared),
            prepared.intent().artifacts().mutation_digest(),
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                prepared.intent().head_payload().as_bytes(),
            ),
            AuthorityProofObservation::NotApplicableForRealm,
        ),
    )
    .unwrap();
    let bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::expected(&prepared),
        CommitWriteTimestampUs::try_from_i128(500).unwrap(),
        prepared.digest(),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(3).unwrap(),
            AuthorityStorageNamespaceId::from_verified_namespace_id([0x77; 32]),
        ),
    );
    let cas = SealedAuthorityLocalHeadCas::seal_normal_advance(
        bootstrap.candidate().clone(),
        &sealed,
    )
    .unwrap();
    (bootstrap, cas)
}

#[test]
fn bootstrap_and_cas_bind_order_are_stable_and_complete() {
    let (bootstrap, cas) = fixture();
    let bootstrap_values =
        AuthorityLocalHeadBootstrapBinding::from_bootstrap(&bootstrap).values();
    assert_eq!(bootstrap_values.len(), 6);
    assert_eq!(bootstrap_values[0], AuthorityLocalHeadBindValue::BigInt(1337));
    assert_eq!(bootstrap_values[1], AuthorityLocalHeadBindValue::TinyInt(2));
    assert_eq!(bootstrap_values[2], AuthorityLocalHeadBindValue::BigInt(7));
    assert_eq!(bootstrap_values[3], AuthorityLocalHeadBindValue::BigInt(2));
    assert_eq!(bootstrap_values[4], AuthorityLocalHeadBindValue::BigInt(0));
    assert_eq!(
        bootstrap_values[5],
        AuthorityLocalHeadBindValue::Blob(bootstrap.candidate_payload().to_vec())
    );

    let cas_values = AuthorityLocalHeadCasBinding::from_sealed(&cas).values();
    assert_eq!(cas_values.len(), 8);
    assert_eq!(cas_values[0], AuthorityLocalHeadBindValue::BigInt(1));
    assert_eq!(
        cas_values[1],
        AuthorityLocalHeadBindValue::Blob(cas.candidate_payload().to_vec())
    );
    assert_eq!(cas_values[2], AuthorityLocalHeadBindValue::BigInt(1337));
    assert_eq!(cas_values[3], AuthorityLocalHeadBindValue::TinyInt(2));
    assert_eq!(cas_values[4], AuthorityLocalHeadBindValue::BigInt(7));
    assert_eq!(cas_values[5], AuthorityLocalHeadBindValue::BigInt(2));
    assert_eq!(cas_values[6], AuthorityLocalHeadBindValue::BigInt(0));
    assert_eq!(
        cas_values[7],
        AuthorityLocalHeadBindValue::Blob(cas.expected_payload().to_vec())
    );
}

#[test]
fn persisted_reader_rejects_wrong_partition_and_missing_cells() {
    let (bootstrap, _) = fixture();
    let key = bootstrap.key();
    let payload = bootstrap.candidate_payload();
    let decoded = decode_authority_local_head_persisted_cells::<PHash>(
        key,
        1337,
        2,
        7,
        2,
        Some(0),
        Some(&payload),
    )
    .unwrap();
    assert_eq!(decoded, *bootstrap.candidate());

    assert_eq!(
        decode_authority_local_head_persisted_cells::<PHash>(
            key,
            1337,
            2,
            8,
            2,
            Some(0),
            Some(&payload),
        )
        .unwrap_err(),
        AuthorityLocalHeadPrototypeError::SelectedPartitionMismatch
    );
    assert_eq!(
        decode_authority_local_head_persisted_cells::<PHash>(
            key, 1337, 2, 7, 2, None, Some(&payload),
        )
        .unwrap_err(),
        AuthorityLocalHeadPrototypeError::MissingRevision
    );
    assert_eq!(
        decode_authority_local_head_persisted_cells::<PHash>(
            key,
            1337,
            2,
            7,
            2,
            Some(0),
            None,
        )
        .unwrap_err(),
        AuthorityLocalHeadPrototypeError::MissingHeadPayload
    );
}
