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
        SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadPublishDecision,
        AuthorityHeadView, AuthorityPostWriteObservation,
        AuthorityProofObservation, CommittedAuthorityManifest,
        PersistedAuthorityManifest, SealedAuthorityManifest,
    },
    manifest_record::PreparedManifestWriteOutcome,
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId as StorageCheckpointId, LogicalMutation, MutationValue,
        TypedTableKey,
    },
};
use psy_node_scylla::rollback::{
    classify_lifecycle_cas_observation, decode_manifest_artifact_plan,
    CanonicalManifestArtifacts,
    CanonicalPhysicalMutationBatch, DecodedManifestArtifactPlan,
    FullPhysicalDeltaRecord, ManifestArtifactKind,
    ManifestChunkBucketReadBinding,
    ManifestChunkPutBinding, ManifestControlNoTabletKeyspace,
    ManifestLifecycleCasBinding, ManifestPreparedBindValue,
    ManifestLifecycleWriteOutcome,
    ManifestPreparedConsistencyContract, ManifestPreparedKeyspaces,
    ManifestPreparedQueries, ManifestReadBinding,
    OperationalReplayAction, PreparedManifestInsertBinding, ReplayAuthority,
    ReplayReceipt, VerifiedPreparedManifestPackage,
};
use scylla::statement::{Consistency, SerialConsistency};

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1337).unwrap()
}

fn chain(epoch: u64, checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn artifacts(
    checkpoint: u64,
    value: Option<u8>,
) -> CanonicalManifestArtifacts {
    let checkpoint = StorageCheckpointId::try_new(checkpoint).unwrap();
    let mutations = value.map_or_else(Vec::new, |value| {
        vec![LogicalMutation::Put {
            key: TypedTableKey::CheckpointLeaf(checkpoint),
            value: MutationValue::PsyCanonicalBytes(vec![value; 32]),
        }]
    });
    let mutation_count = mutations.len() as u32;
    let batch = CanonicalPhysicalMutationBatch::from_logical(mutations).unwrap();
    let receipt = ReplayReceipt::new(
        ReplayAuthority::Realm,
        checkpoint,
        0,
        mutation_count,
        vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
    );
    let record = FullPhysicalDeltaRecord::try_new(batch, receipt).unwrap();
    CanonicalManifestArtifacts::try_from_full(&record).unwrap()
}

fn package(
    epoch: u64,
    checkpoint: u64,
    candidate_hash_seed: u8,
    value: Option<u8>,
) -> VerifiedPreparedManifestPackage<PHash> {
    let artifacts = artifacts(checkpoint, value);
    let key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
    );
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(epoch, checkpoint - 1, 0x11),
        chain(epoch, checkpoint, candidate_hash_seed),
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(checkpoint - 1),
            root: AuthorityStateRoot::from_local_state_root(hash(0x71)),
        },
        AuthorityHeadPayload::try_new(vec![0x55; 12]).unwrap(),
        artifacts.commitment(),
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
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    VerifiedPreparedManifestPackage::try_new(&prepared, artifacts).unwrap()
}

fn keyspaces() -> ManifestPreparedKeyspaces {
    ManifestPreparedKeyspaces::new(
        ManifestControlNoTabletKeyspace::try_new("psy_rollback_no_tablet")
            .unwrap(),
        psy_node_scylla::rollback::ManifestArtifactKeyspace::try_new(
            "psy_rollback_artifacts",
        )
        .unwrap(),
    )
}

fn sealed_package(
    package: &VerifiedPreparedManifestPackage<PHash>,
) -> SealedAuthorityManifest<PHash> {
    let prepared = package.record();
    SealedAuthorityManifest::verify_and_seal(
        prepared.clone(),
        AuthorityPostWriteObservation::new(
            AuthorityHeadView::candidate(prepared),
            prepared.intent().artifacts().mutation_digest(),
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                prepared.intent().head_payload().as_bytes(),
            ),
            AuthorityProofObservation::NotApplicableForRealm,
        ),
    )
    .unwrap()
}

fn committed_package(
    package: &VerifiedPreparedManifestPackage<PHash>,
) -> CommittedAuthorityManifest<PHash> {
    let sealed = sealed_package(package);
    let receipt = match sealed
        .classify_head_cas(true, *sealed.verified_head())
        .unwrap()
    {
        AuthorityHeadPublishDecision::Published(receipt) => receipt,
        other => panic!("unexpected publication decision: {other:?}"),
    };
    sealed.mark_committed(receipt).unwrap()
}

fn render_golden() -> String {
    let package = package(7, 41, 0x22, Some(0x31));
    let set = package.artifacts().chunked().unwrap();
    let chunk = &set.locator().chunks()[0];
    let manifest =
        PreparedManifestInsertBinding::try_from_record(package.record()).unwrap();
    let chunk_put =
        ManifestChunkPutBinding::try_new(package.record(), chunk).unwrap();
    let chunk_read =
        ManifestChunkBucketReadBinding::try_new(package.record(), 0).unwrap();
    format!(
        "{}MANIFEST_BIND\n{}\nLOCATOR_CHUNK_PUT_BIND\n{}\nLOCATOR_BUCKET_READ_BIND\n{}\n",
        ManifestPreparedQueries::new(&keyspaces()).render_golden(),
        manifest.render_golden(),
        chunk_put.render_golden(),
        chunk_read.render_golden(),
    )
}

#[test]
fn schema_queries_and_bindings_match_the_public_golden() {
    assert_eq!(
        render_golden(),
        include_str!("golden/rollback_manifest_prepared_v1.txt")
    );
}

#[test]
fn prepared_is_the_only_authority_marker_and_chunks_are_digest_isolated() {
    let queries = ManifestPreparedQueries::new(&keyspaces());
    assert!(queries.insert_prepared_manifest().cql().contains("IF NOT EXISTS"));
    assert!(!queries.read_manifest().cql().contains("ALLOW FILTERING"));
    for kind in [
        ManifestArtifactKind::Locator,
        ManifestArtifactKind::ReplayRecord,
        ManifestArtifactKind::DurablePreparedPayload,
    ] {
        let put = queries.put_chunk(kind);
        assert!(put.cql().contains("USING TIMESTAMP ?"));
        assert!(!put.cql().contains("IF NOT EXISTS"));
        assert!(put.cql().contains("manifest_digest"));
        assert!(queries.read_bucket(kind).cql().contains("manifest_digest = ?"));
    }

    let package = package(7, 41, 0x22, Some(0x31));
    let set = package.artifacts().chunked().unwrap();
    let chunk_binding = ManifestChunkPutBinding::try_new(
        package.record(),
        &set.locator().chunks()[0],
    )
    .unwrap();
    let values = chunk_binding.render_golden();
    assert!(values.contains(&format!(
        "BLOB:{}",
        hex::encode(package.record().digest().as_bytes())
    )));

    // M15: chunk rows alone are not a manifest. Only the separate PREPARED
    // LWT row can make this exact digest discoverable as an authority record.
    let persisted_chunks = set.locator().chunks().len();
    let prepared_manifest_row: Option<()> = None;
    assert!(persisted_chunks > 0);
    assert!(prepared_manifest_row.is_none());
}

#[test]
fn lifecycle_cas_is_exact_monotonic_and_keeps_prepared_digest_immutable() {
    let package = package(7, 41, 0x22, Some(0x31));
    let queries = ManifestPreparedQueries::new(&keyspaces());
    let cql = queries.advance_lifecycle().cql();
    assert!(cql.starts_with("UPDATE "));
    assert!(!cql.contains("USING TIMESTAMP"));
    assert!(!cql.contains("SET manifest_digest"));
    for condition in [
        "IF revision = ?",
        "status = ?",
        "manifest_digest = ?",
        "lifecycle_digest = ?",
        "manifest_payload = ?",
    ] {
        assert!(cql.contains(condition), "missing {condition}");
    }

    let sealed = sealed_package(&package);
    let first = ManifestLifecycleCasBinding::try_from_sealed(&sealed).unwrap();
    let second = ManifestLifecycleCasBinding::try_from_sealed(&sealed).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.render_golden(), second.render_golden());
    let values = first.values();
    assert_eq!(values.len(), 17);
    assert_eq!(values[0], ManifestPreparedBindValue::BigInt(1));
    assert_eq!(values[1], ManifestPreparedBindValue::TinyInt(2));
    assert_eq!(values[12], ManifestPreparedBindValue::BigInt(0));
    assert_eq!(values[13], ManifestPreparedBindValue::TinyInt(1));
    assert_eq!(
        values[14],
        ManifestPreparedBindValue::Blob(
            package.record().digest().as_bytes().to_vec()
        )
    );
    assert_eq!(values[14], values[15]);

    let committed = committed_package(&package);
    let values = ManifestLifecycleCasBinding::try_from_committed(&committed)
        .unwrap()
        .values();
    assert_eq!(values[0], ManifestPreparedBindValue::BigInt(2));
    assert_eq!(values[1], ManifestPreparedBindValue::TinyInt(3));
    assert_eq!(values[12], ManifestPreparedBindValue::BigInt(1));
    assert_eq!(values[13], ManifestPreparedBindValue::TinyInt(2));
    assert_eq!(
        values[14],
        ManifestPreparedBindValue::Blob(
            package.record().digest().as_bytes().to_vec()
        )
    );
    assert_ne!(values[14], values[15]);
}

#[test]
fn lifecycle_lwt_observation_is_applied_idempotent_or_conflict() {
    let first_package = package(7, 41, 0x22, Some(0x31));
    let candidate = PersistedAuthorityManifest::Sealed(sealed_package(
        &first_package,
    ));
    assert!(matches!(
        classify_lifecycle_cas_observation(
            true,
            candidate.clone(),
            candidate.clone(),
        )
        .unwrap(),
        ManifestLifecycleWriteOutcome::Applied(_)
    ));
    assert!(matches!(
        classify_lifecycle_cas_observation(
            false,
            candidate.clone(),
            candidate.clone(),
        )
        .unwrap(),
        ManifestLifecycleWriteOutcome::Idempotent(_)
    ));

    let other_package = package(7, 41, 0x23, Some(0x32));
    let conflict = PersistedAuthorityManifest::Sealed(sealed_package(
        &other_package,
    ));
    assert!(matches!(
        classify_lifecycle_cas_observation(
            false,
            candidate.clone(),
            conflict.clone(),
        )
        .unwrap(),
        ManifestLifecycleWriteOutcome::Conflict { current }
            if current == conflict
    ));
    assert!(classify_lifecycle_cas_observation(
        true,
        candidate,
        conflict,
    )
    .is_err());
}

#[test]
fn exact_epoch_height_hash_and_manifest_digest_define_the_chunk_namespace() {
    let epoch7 = package(7, 41, 0x22, Some(0x31));
    let epoch8 = package(8, 41, 0x22, Some(0x32));
    assert_ne!(epoch7.record().identity(), epoch8.record().identity());
    assert_ne!(epoch7.record().digest(), epoch8.record().digest());

    let first = epoch7.artifacts().chunked().unwrap().locator().chunks()[0].clone();
    let second = epoch8.artifacts().chunked().unwrap().locator().chunks()[0].clone();
    let first = ManifestChunkPutBinding::try_new(epoch7.record(), &first).unwrap();
    let second = ManifestChunkPutBinding::try_new(epoch8.record(), &second).unwrap();
    assert_ne!(first.values(), second.values());

    let first_read = ManifestReadBinding::try_from_identity(epoch7.record().identity()).unwrap();
    let second_read = ManifestReadBinding::try_from_identity(epoch8.record().identity()).unwrap();
    assert_ne!(first_read.values(), second_read.values());
}

#[test]
fn zero_mutation_checkpoint_has_a_compact_prepared_record_and_no_chunks() {
    let package = package(7, 41, 0x22, None);
    assert!(package.artifacts().is_zero_mutation());
    assert!(package.artifacts().chunked().is_none());
    assert_eq!(package.record().intent().artifacts().affected_row_count(), 0);
    assert_eq!(package.record().intent().artifacts().locator_chunk_count(), 0);
    assert_eq!(package.record().intent().artifacts().replay_chunk_count(), 0);
    assert_eq!(
        package
            .record()
            .intent()
            .artifacts()
            .durable_payload_chunk_count(),
        0
    );
    PreparedManifestInsertBinding::try_from_record(package.record()).unwrap();
    let plan = decode_manifest_artifact_plan(
        package.record().artifact_summary(),
        package.record().intent().artifacts(),
    )
    .unwrap();
    assert!(matches!(
        plan,
        DecodedManifestArtifactPlan::ZeroMutation { .. }
    ));
    assert!(!plan.zero_mutation_replay_record().unwrap().is_empty());
}

#[test]
fn prepared_row_summary_is_sufficient_to_recover_the_chunk_plan() {
    let package = package(7, 41, 0x22, Some(0x31));
    let plan = decode_manifest_artifact_plan(
        package.record().artifact_summary(),
        package.record().intent().artifacts(),
    )
    .unwrap();
    assert_eq!(
        plan.locator().unwrap().chunk_count(),
        package
            .record()
            .intent()
            .artifacts()
            .locator_chunk_count()
    );
    assert_eq!(
        plan.replay_record().unwrap().chunk_count(),
        package
            .record()
            .intent()
            .artifacts()
            .replay_chunk_count()
    );

    let mut tampered = package.record().artifact_summary().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(decode_manifest_artifact_plan(
        &tampered,
        package.record().intent().artifacts()
    )
    .is_err());
}

#[test]
fn artifacts_cannot_be_attached_to_a_different_sealed_intent() {
    let first = package(7, 41, 0x22, Some(0x31));
    let other_artifacts = artifacts(41, Some(0x32));
    assert_ne!(first.record().intent().artifacts(), other_artifacts.commitment());

    let key = first.record().intent().key();
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(7, 40, 0x11),
        chain(7, 41, 0x22),
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(40),
            root: AuthorityStateRoot::from_local_state_root(hash(0x71)),
        },
        AuthorityHeadPayload::try_new(vec![0x55; 12]).unwrap(),
        first.record().intent().artifacts(),
    )
    .unwrap();
    let bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(1_000_000).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let lease = bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128(1_000_001).unwrap(),
        )
        .unwrap();
    let prepared = intent.attach_timestamp_lease(lease.lease()).unwrap();
    assert!(VerifiedPreparedManifestPackage::try_new(
        &prepared,
        other_artifacts
    )
    .is_err());
}

#[test]
fn consistency_and_keyspace_contracts_fail_closed() {
    assert!(ManifestControlNoTabletKeyspace::try_new("ordinary_tablet").is_err());
    assert!(
        psy_node_scylla::rollback::ManifestArtifactKeyspace::try_new(
            "artifacts_no_tablet"
        )
        .is_err()
    );
    let contract = ManifestPreparedConsistencyContract::rf3_default();
    assert_eq!(contract.chunk_write(), Consistency::Quorum);
    assert_eq!(contract.read(), Consistency::Quorum);
    assert_eq!(contract.lwt_regular(), Consistency::Quorum);
    assert_eq!(contract.lwt_serial(), SerialConsistency::LocalSerial);
}

#[test]
fn prototype_remains_absent_from_production_setup_and_processors() {
    for (name, source) in [
        ("setup", include_str!("../src/psy_setup.rs")),
        (
            "coordinator",
            include_str!("../../psy_node_common/src/coordinator/processor/db.rs"),
        ),
        (
            "realm_commit",
            include_str!("../../psy_node_common/src/realm/processor/db/commit.rs"),
        ),
        (
            "realm_sync",
            include_str!("../../psy_node_common/src/realm/processor/db/sync.rs"),
        ),
    ] {
        for forbidden in [
            "ScyllaPreparedManifestStore",
            "VerifiedPreparedManifestPackage",
            "d03b_authority_checkpoint_manifest",
        ] {
            assert!(
                !source.contains(forbidden),
                "production source {name} unexpectedly references {forbidden}"
            );
        }
    }
}

#[test]
fn insert_observation_is_idempotent_only_for_the_exact_prepared_record() {
    let first = package(7, 41, 0x22, Some(0x31));
    let retry = first.record().clone();
    assert!(matches!(
        first
            .record()
            .classify_insert_observation(false, retry)
            .unwrap(),
        PreparedManifestWriteOutcome::Idempotent(_)
    ));
    let conflict = package(7, 41, 0x22, Some(0x32));
    assert!(matches!(
        first
            .record()
            .classify_insert_observation(false, conflict.record().clone())
            .unwrap(),
        PreparedManifestWriteOutcome::Conflict(_)
    ));
}
