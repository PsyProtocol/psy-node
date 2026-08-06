use psy_node_core::store::typed::{
    CheckpointId, LogicalMutation, MerkleNode, MutationValue, NodeIndex,
    TypedTableKey,
};
use psy_node_scylla::rollback::{
    CanonicalManifestArtifact, CanonicalManifestArtifactSet,
    CanonicalPhysicalMutationBatch, DerivedSupplementBatch,
    DurablePreparedPayloadReference, FullPhysicalDeltaRecord,
    ManifestArtifactDescriptor, OperationalReplayAction, PreparedPayload,
    PreparedPayloadKind, PreparedPayloadSource,
    PreparedReferencePlusSupplementRecord, PreparedSemanticMutation,
    ReplayAuthority, ReplayReceipt, MANIFEST_ARTIFACT_ENCODING_VERSION,
    MANIFEST_ARTIFACT_MAX_CHUNK_BYTES,
};

fn put(key: TypedTableKey, value: u8) -> LogicalMutation {
    LogicalMutation::Put {
        key,
        value: MutationValue::PsyCanonicalBytes(vec![value; 32]),
    }
}

fn fixture_mutations(checkpoint: CheckpointId) -> Vec<LogicalMutation> {
    vec![
        put(TypedTableKey::CheckpointLeaf(checkpoint), 0x31),
        put(
            TypedTableKey::GlobalUserMerkle {
                node: MerkleNode::new(3, NodeIndex::new(4)),
                checkpoint,
            },
            0x32,
        ),
    ]
}

fn receipt(checkpoint: CheckpointId) -> ReplayReceipt {
    ReplayReceipt::new(
        ReplayAuthority::Coordinator,
        checkpoint,
        1,
        1,
        vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
    )
}

fn full_set() -> CanonicalManifestArtifactSet {
    let checkpoint = CheckpointId::try_new(8).unwrap();
    let batch =
        CanonicalPhysicalMutationBatch::from_logical(fixture_mutations(checkpoint))
            .unwrap();
    let record = FullPhysicalDeltaRecord::try_new(batch, receipt(checkpoint)).unwrap();
    CanonicalManifestArtifactSet::try_from_full(&record).unwrap()
}

fn compact_set() -> CanonicalManifestArtifactSet {
    let checkpoint = CheckpointId::try_new(8).unwrap();
    let payload = PreparedPayload::try_v1(
        PreparedPayloadKind::Coordinator,
        vec![PreparedSemanticMutation::CheckpointLeaf {
            checkpoint,
            value: vec![0x31; 32],
        }],
    )
    .unwrap();
    let payload_bytes = payload.encode_canonical();
    let reference = DurablePreparedPayloadReference::try_from_source(
        payload.kind(),
        1,
        1,
        PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
    )
    .unwrap();
    let supplements = DerivedSupplementBatch::from_logical(vec![put(
        TypedTableKey::GlobalUserMerkle {
            node: MerkleNode::new(3, NodeIndex::new(4)),
            checkpoint,
        },
        0x32,
    )])
    .unwrap();
    let full =
        CanonicalPhysicalMutationBatch::from_logical(fixture_mutations(checkpoint))
            .unwrap();
    let record = PreparedReferencePlusSupplementRecord::try_v1(
        reference,
        supplements,
        receipt(checkpoint),
        &payload_bytes,
        &full,
    )
    .unwrap();
    CanonicalManifestArtifactSet::try_from_compact(&record, &payload_bytes).unwrap()
}

fn descriptor_line(
    name: &str,
    artifact: &CanonicalManifestArtifact,
) -> String {
    let descriptor: ManifestArtifactDescriptor = artifact.descriptor();
    format!(
        "{name}=kind:{} chunks:{} items:{} bytes:{} payload:{} chunk_set:{}\n",
        descriptor.kind() as u8,
        descriptor.chunk_count(),
        descriptor.item_count(),
        descriptor.encoded_bytes(),
        hex::encode(descriptor.payload_digest().as_bytes()),
        hex::encode(descriptor.chunk_set_digest().as_bytes()),
    )
}

fn render_golden() -> String {
    let full = full_set();
    let compact = compact_set();
    let mut output = format!(
        "schema={} max_chunk={}\nfull_kind={} mutation={} commitment={}\n",
        MANIFEST_ARTIFACT_ENCODING_VERSION,
        MANIFEST_ARTIFACT_MAX_CHUNK_BYTES,
        full.replay_record_kind() as u8,
        hex::encode(full.mutation_digest()),
        hex::encode(full.commitment().digest()),
    );
    output.push_str(&descriptor_line("full_locator", full.locator()));
    output.push_str(&descriptor_line("full_replay", full.replay_record()));
    output.push_str(&format!(
        "compact_kind={} mutation={} commitment={}\n",
        compact.replay_record_kind() as u8,
        hex::encode(compact.mutation_digest()),
        hex::encode(compact.commitment().digest()),
    ));
    output.push_str(&descriptor_line("compact_locator", compact.locator()));
    output.push_str(&descriptor_line("compact_replay", compact.replay_record()));
    output.push_str(&descriptor_line(
        "compact_payload",
        compact.durable_prepared_payload().unwrap(),
    ));
    output
}

#[test]
fn public_artifact_contract_matches_golden() {
    assert_eq!(
        render_golden(),
        include_str!("golden/rollback_manifest_artifact_v1.txt")
    );
}

#[test]
fn public_full_and_compact_artifacts_bind_the_same_physical_mutations() {
    let full = full_set();
    let compact = compact_set();
    assert_eq!(full.mutation_digest(), compact.mutation_digest());
    assert_ne!(full.commitment(), compact.commitment());
    assert!(full.durable_prepared_payload().is_none());
    assert!(compact.durable_prepared_payload().is_some());
    full.verify_integrity().unwrap();
    compact.verify_integrity().unwrap();
}

#[test]
fn prototype_is_not_wired_into_production_setup_or_processors() {
    for (name, source) in [
        ("setup", include_str!("../src/psy_setup.rs")),
        (
            "coordinator",
            include_str!(
                "../../psy_node_common/src/coordinator/processor/db.rs"
            ),
        ),
        (
            "realm_commit",
            include_str!(
                "../../psy_node_common/src/realm/processor/db/commit.rs"
            ),
        ),
        (
            "realm_sync",
            include_str!(
                "../../psy_node_common/src/realm/processor/db/sync.rs"
            ),
        ),
    ] {
        for forbidden in [
            "CanonicalManifestArtifactSet",
            "SealedAuthorityCommitIntent",
            "PreparedAuthorityManifestIntent",
        ] {
            assert!(
                !source.contains(forbidden),
                "production source {name} unexpectedly references {forbidden}"
            );
        }
    }
}
