use std::time::Instant;

use psy_node_core::store::typed::{
    CheckpointId, CheckpointLeafKey, CheckpointRootKey,
    CheckpointedObjectKey, ImtCursorTransition, ImtEncodedKey, LatestInfoSlot,
    LeafIndex, LogicalMutation, MerkleNode, MutationOperation, MutationValue,
    NodeIndex, RealmId, StructuredValueSchema, TreeId, TreeSubId, TypedTableKey,
    U64SingletonSlot, UniquePendingId, UserId, ValueDigestAlgorithm,
};
use psy_node_scylla::rollback::*;
use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn put(key: TypedTableKey, value: impl Into<Vec<u8>>) -> LogicalMutation {
    LogicalMutation::Put { key, value: MutationValue::PsyCanonicalBytes(value.into()) }
}

#[derive(Clone)]
struct FixtureSpec {
    authority: ReplayAuthority,
    checkpoint: CheckpointId,
    payload: PreparedPayload,
    supplements: Vec<LogicalMutation>,
    full: Vec<LogicalMutation>,
    state_mutations: usize,
    metadata_mutations: usize,
    operational_actions: Vec<OperationalReplayAction>,
}

struct MaterializedFixture {
    payload_bytes: Vec<u8>,
    full: CanonicalPhysicalMutationBatch,
    supplements: DerivedSupplementBatch,
    full_record: FullPhysicalDeltaRecord,
    compact_record: PreparedReferencePlusSupplementRecord,
    state_mutations: usize,
    metadata_mutations: usize,
}

fn materialize(spec: FixtureSpec) -> Result<MaterializedFixture, ReplayPrototypeError> {
    let payload_bytes = spec.payload.encode_canonical();
    let full = CanonicalPhysicalMutationBatch::from_logical(spec.full)?;
    let supplements = DerivedSupplementBatch::from_logical(spec.supplements)?;
    let reference = DurablePreparedPayloadReference::try_from_source(
        spec.payload.kind(),
        1,
        1,
        PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
    )?;
    let receipt = ReplayReceipt::new(
        spec.authority,
        spec.checkpoint,
        spec.state_mutations as u32,
        spec.metadata_mutations as u32,
        spec.operational_actions,
    );
    let compact_record =
        PreparedReferencePlusSupplementRecord::try_v1(reference, supplements.clone(), receipt.clone(), &payload_bytes, &full)?;
    let full_record = FullPhysicalDeltaRecord::try_new(full.clone(), receipt)?;
    Ok(MaterializedFixture {
        payload_bytes,
        full,
        supplements,
        full_record,
        compact_record,
        state_mutations: spec.state_mutations,
        metadata_mutations: spec.metadata_mutations,
    })
}

fn coordinator_spec() -> FixtureSpec {
    let cp = checkpoint(42);
    let root = CheckpointRootKey::new(vec![0x42; 32]);
    let direct = vec![
        PreparedSemanticMutation::CheckpointLeaf { checkpoint: cp, value: vec![0x11; 96] },
        PreparedSemanticMutation::L2BlockState { checkpoint: cp, value: vec![0x12; 80] },
        PreparedSemanticMutation::CheckpointStateRoots { checkpoint: cp, value: vec![0x13; 128] },
        PreparedSemanticMutation::GlobalUserMerkle {
            checkpoint: cp,
            node: MerkleNode::new(8, NodeIndex::new(3)),
            value: vec![0x14; 32],
        },
    ];
    let supplements = vec![
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(4, NodeIndex::new(2)), checkpoint: cp },
            vec![0x15; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root, checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x12; 80]),
        latest_checkpoint_restore(cp),
        put(TypedTableKey::CheckpointZkProof(cp), vec![0x16; 160]),
    ];
    let full = vec![
        put(TypedTableKey::CheckpointLeaf(cp), vec![0x11; 96]),
        put(TypedTableKey::L2BlockState(cp), vec![0x12; 80]),
        put(TypedTableKey::CheckpointStateRoots(cp), vec![0x13; 128]),
        put(
            TypedTableKey::GlobalUserMerkle { checkpoint: cp, node: MerkleNode::new(8, NodeIndex::new(3)) },
            vec![0x14; 32],
        ),
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(4, NodeIndex::new(2)), checkpoint: cp },
            vec![0x15; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root: CheckpointRootKey::new(vec![0x42; 32]), checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x12; 80]),
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            value: MutationValue::CqlU64(cp.get()),
        },
        put(TypedTableKey::CheckpointZkProof(cp), vec![0x16; 160]),
    ];
    FixtureSpec {
        authority: ReplayAuthority::Coordinator,
        checkpoint: cp,
        payload: PreparedPayload::try_v1(PreparedPayloadKind::Coordinator, direct).unwrap(),
        supplements,
        full,
        state_mutations: 1,
        metadata_mutations: 9,
        operational_actions: vec![
            OperationalReplayAction::RotatePendingCheckpointNamespace,
            OperationalReplayAction::RotatePendingProcNamespace,
        ],
    }
}

fn realm_spec() -> FixtureSpec {
    let cp = checkpoint(43);
    let tree = TreeId::new(9);
    let tree_sub = TreeSubId::new(2);
    let encoded_key = ImtEncodedKey::new([0x37; 32]);
    let direct = vec![
        PreparedSemanticMutation::UserLeaf { user: UserId::new(7), checkpoint: cp, value: vec![0x21; 128] },
        PreparedSemanticMutation::GlobalUserMerkle {
            checkpoint: cp,
            node: MerkleNode::new(7, NodeIndex::new(5)),
            value: vec![0x22; 32],
        },
        PreparedSemanticMutation::ImtLeaf {
            tree,
            tree_sub,
            leaf: LeafIndex::new(3),
            checkpoint: cp,
            canonical_row: vec![0x23; 161],
        },
        PreparedSemanticMutation::CheckpointLeaf { checkpoint: cp, value: vec![0x24; 96] },
        PreparedSemanticMutation::L2BlockState { checkpoint: cp, value: vec![0x25; 80] },
        PreparedSemanticMutation::CheckpointStateRoots { checkpoint: cp, value: vec![0x26; 128] },
    ];
    let mut supplements =
        imt_leaf_supplements(tree, tree_sub, encoded_key.clone(), cp, 3, 4)
            .unwrap();
    supplements.extend([
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(5, NodeIndex::new(1)), checkpoint: cp },
            vec![0x27; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root: CheckpointRootKey::new(vec![0x43; 32]), checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x25; 80]),
        latest_checkpoint_restore(cp),
    ]);
    let mut full = vec![
        put(TypedTableKey::UserLeaf { user: UserId::new(7), checkpoint: cp }, vec![0x21; 128]),
        put(
            TypedTableKey::GlobalUserMerkle { checkpoint: cp, node: MerkleNode::new(7, NodeIndex::new(5)) },
            vec![0x22; 32],
        ),
        LogicalMutation::Put {
            key: TypedTableKey::ImtLeaf { tree, tree_sub, leaf: LeafIndex::new(3), checkpoint: cp },
            value: MutationValue::Structured {
                schema: StructuredValueSchema::ImtLeafRowV1,
                canonical_bytes: vec![0x23; 161],
            },
        },
        put(TypedTableKey::CheckpointLeaf(cp), vec![0x24; 96]),
        put(TypedTableKey::L2BlockState(cp), vec![0x25; 80]),
        put(TypedTableKey::CheckpointStateRoots(cp), vec![0x26; 128]),
    ];
    full.extend(imt_leaf_supplements(tree, tree_sub, encoded_key, cp, 3, 4).unwrap());
    full.extend([
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(5, NodeIndex::new(1)), checkpoint: cp },
            vec![0x27; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root: CheckpointRootKey::new(vec![0x43; 32]), checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x25; 80]),
        latest_checkpoint_restore(cp),
    ]);
    FixtureSpec {
        authority: ReplayAuthority::Realm,
        checkpoint: cp,
        payload: PreparedPayload::try_v1(PreparedPayloadKind::Realm, direct).unwrap(),
        supplements,
        full,
        state_mutations: 5,
        metadata_mutations: 8,
        operational_actions: vec![
            OperationalReplayAction::RotatePendingCheckpointNamespace,
            OperationalReplayAction::RotatePendingProcNamespace,
            OperationalReplayAction::RotateRewardTagNamespace,
        ],
    }
}

fn empty_realm_spec() -> FixtureSpec {
    let cp = checkpoint(44);
    let direct = vec![
        PreparedSemanticMutation::CheckpointLeaf { checkpoint: cp, value: vec![0x31; 96] },
        PreparedSemanticMutation::L2BlockState { checkpoint: cp, value: vec![0x32; 80] },
        PreparedSemanticMutation::CheckpointStateRoots { checkpoint: cp, value: vec![0x33; 128] },
    ];
    let supplements = vec![
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(4, NodeIndex::new(4)), checkpoint: cp },
            vec![0x34; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root: CheckpointRootKey::new(vec![0x44; 32]), checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x32; 80]),
        latest_checkpoint_restore(cp),
    ];
    let full = vec![
        put(TypedTableKey::CheckpointLeaf(cp), vec![0x31; 96]),
        put(TypedTableKey::L2BlockState(cp), vec![0x32; 80]),
        put(TypedTableKey::CheckpointStateRoots(cp), vec![0x33; 128]),
        put(
            TypedTableKey::GlobalCheckpointMerkle { node: MerkleNode::new(4, NodeIndex::new(4)), checkpoint: cp },
            vec![0x34; 32],
        ),
        LogicalMutation::CheckpointRootMapping { root: CheckpointRootKey::new(vec![0x44; 32]), checkpoint: cp },
        put(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState), vec![0x32; 80]),
        latest_checkpoint_restore(cp),
    ];
    FixtureSpec {
        authority: ReplayAuthority::Realm,
        checkpoint: cp,
        payload: PreparedPayload::try_v1(PreparedPayloadKind::Realm, direct).unwrap(),
        supplements,
        full,
        state_mutations: 0,
        metadata_mutations: 8,
        operational_actions: vec![],
    }
}

#[test]
fn canonical_bytes_digest_and_input_order_are_stable() {
    let one = materialize(coordinator_spec()).unwrap();
    let two = materialize(coordinator_spec()).unwrap();
    assert_eq!(one.payload_bytes, two.payload_bytes);
    assert_eq!(one.full.encode_canonical(), two.full.encode_canonical());
    assert_eq!(one.full.digest(), two.full.digest());
    assert_eq!(one.full_record.encode_canonical(), two.full_record.encode_canonical());
    assert_eq!(one.compact_record.encode_canonical(), two.compact_record.encode_canonical());

    let mut reordered = coordinator_spec();
    let mut prepared = reordered.payload.mutations().to_vec();
    prepared.reverse();
    reordered.payload = PreparedPayload::try_v1(PreparedPayloadKind::Coordinator, prepared).unwrap();
    reordered.supplements.reverse();
    reordered.full.reverse();
    let reordered = materialize(reordered).unwrap();
    assert_eq!(one.full.encode_canonical(), reordered.full.encode_canonical());
    assert_eq!(one.full.digest(), reordered.full.digest());
    assert_eq!(one.compact_record.encode_canonical(), reordered.compact_record.encode_canonical());
}

#[test]
fn coordinator_realm_and_empty_realm_full_compact_are_equivalent() {
    for spec in [coordinator_spec(), realm_spec(), empty_realm_spec()] {
        let fixture = materialize(spec).unwrap();
        let expanded = fixture.compact_record.expand(&fixture.payload_bytes).unwrap();
        assert_eq!(expanded.digest(), fixture.full.digest());
        assert_eq!(expanded.encode_canonical(), fixture.full.encode_canonical());
    }
    let empty = materialize(empty_realm_spec()).unwrap();
    assert_eq!(empty.state_mutations, 0);
    assert!(empty.metadata_mutations > 0);
    assert_eq!(empty.compact_record.receipt().state_mutation_count(), 0);
    assert_eq!(empty.compact_record.receipt().metadata_mutation_count(), 8);
    assert!(empty.compact_record.receipt().operational_actions().is_empty());
    assert!(empty
        .full
        .mutations()
        .iter()
        .all(|mutation| !matches!(mutation.mutation().physical_table(), ScyllaPhysicalTableId::UserLeaf | ScyllaPhysicalTableId::ImtLeaf)));
}

#[test]
fn persisted_compact_records_strictly_decode_and_expand_after_restart() {
    for fixture in [
        materialize(coordinator_spec()).unwrap(),
        materialize(realm_spec()).unwrap(),
        materialize(empty_realm_spec()).unwrap(),
    ] {
        let compact_bytes = fixture.compact_record.encode_canonical();
        let recovered = PreparedReferencePlusSupplementRecord::decode_canonical(&compact_bytes).unwrap();
        assert_eq!(recovered.encode_canonical(), compact_bytes);
        assert_eq!(recovered, fixture.compact_record);

        let supplement_bytes = fixture.supplements.batch().encode_canonical();
        let recovered_supplements = CanonicalPhysicalMutationBatch::decode_canonical(supplement_bytes).unwrap();
        assert_eq!(recovered_supplements, *fixture.supplements.batch());

        let expanded = recovered.expand(&fixture.payload_bytes).unwrap();
        assert_eq!(expanded.encode_canonical(), fixture.full.encode_canonical());
        assert_eq!(expanded.digest(), fixture.full.digest());
    }
}

#[test]
fn persisted_compact_decoder_rejects_envelope_locator_and_mutation_tampering() {
    let fixture = materialize(coordinator_spec()).unwrap();
    let canonical = fixture.compact_record.encode_canonical();

    for cut in 0..canonical.len() {
        assert!(PreparedReferencePlusSupplementRecord::decode_canonical(&canonical[..cut]).is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        PreparedReferencePlusSupplementRecord::decode_canonical(&trailing).unwrap_err(),
        ReplayPrototypeError::InvalidCanonicalPayload("trailing compact replay bytes")
    );

    for (offset, replacement, expected) in [
        (0, b'X', ReplayPrototypeError::InvalidCanonicalPayload("bad compact replay magic")),
        (5, 2, ReplayPrototypeError::UnknownReplaySchemaVersion),
        (6, 1, ReplayPrototypeError::UnexpectedReplayRecordKind),
        (8, 2, ReplayPrototypeError::UnknownReplayAdapterVersion(2)),
        (9, 9, ReplayPrototypeError::UnknownReplayAuthority(9)),
        (9, 2, ReplayPrototypeError::ReceiptPayloadAuthorityMismatch),
        (28, 9, ReplayPrototypeError::UnknownOperationalReplayAction(9)),
    ] {
        let mut tampered = canonical.clone();
        tampered[offset] = replacement;
        assert_eq!(PreparedReferencePlusSupplementRecord::decode_canonical(&tampered).unwrap_err(), expected);
    }

    let mut batch = fixture.supplements.batch().encode_canonical().to_vec();
    let mut impossible_count = batch.clone();
    impossible_count[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        CanonicalPhysicalMutationBatch::decode_canonical(&impossible_count).unwrap_err(),
        ReplayPrototypeError::InvalidCanonicalPayload("physical batch count exceeds encoded bytes")
    );
    let mutation_start = batch.windows(4).position(|window| window == b"PSRM").unwrap();
    let locator_len = u32::from_be_bytes(batch[mutation_start + 6..mutation_start + 10].try_into().unwrap()) as usize;
    let locator_start = mutation_start + 10;
    let operation_offset = locator_start + locator_len;

    let mut unknown_physical = batch.clone();
    unknown_physical[locator_start + 6..locator_start + 8].copy_from_slice(&99_u16.to_be_bytes());
    assert!(matches!(
        CanonicalPhysicalMutationBatch::decode_canonical(&unknown_physical),
        Err(ReplayPrototypeError::MutationDecode(MutationDecodeError::InvalidLocator(
            "unknown physical table id"
        )))
    ));

    batch[operation_offset] = 0xff;
    assert!(matches!(
        CanonicalPhysicalMutationBatch::decode_canonical(&batch),
        Err(ReplayPrototypeError::MutationDecode(MutationDecodeError::InvalidEncoding(
            "unknown mutation operation"
        )))
    ));
}

#[test]
fn missing_supplement_and_payload_tampering_fail_closed() {
    let spec = realm_spec();
    let expected = CanonicalPhysicalMutationBatch::from_logical(spec.full.clone()).unwrap();
    for missing in 0..spec.supplements.len() {
        let mut incomplete = spec.supplements.clone();
        incomplete.remove(missing);
        let payload_bytes = spec.payload.encode_canonical();
        let reference = DurablePreparedPayloadReference::try_from_source(
            PreparedPayloadKind::Realm,
            1,
            1,
            PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
        )
        .unwrap();
        assert_eq!(
            PreparedReferencePlusSupplementRecord::try_v1(
                reference,
                DerivedSupplementBatch::from_logical(incomplete).unwrap(),
                ReplayReceipt::new(ReplayAuthority::Realm, checkpoint(43), 5, 8, vec![]),
                &payload_bytes,
                &expected,
            )
            .unwrap_err(),
            ReplayPrototypeError::ExpandedMutationDigestMismatch
        );
    }

    let fixture = materialize(realm_spec()).unwrap();
    let mut tampered = fixture.payload_bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        fixture.compact_record.expand(&tampered).unwrap_err(),
        ReplayPrototypeError::PreparedPayloadDigestMismatch
    );
}

#[test]
fn key_value_and_operation_changes_are_detected() {
    let original = CanonicalPhysicalMutationBatch::from_logical(vec![put(TypedTableKey::CheckpointLeaf(checkpoint(5)), vec![1, 2])]).unwrap();
    let changed_key = CanonicalPhysicalMutationBatch::from_logical(vec![put(TypedTableKey::CheckpointLeaf(checkpoint(6)), vec![1, 2])]).unwrap();
    let changed_value = CanonicalPhysicalMutationBatch::from_logical(vec![put(TypedTableKey::CheckpointLeaf(checkpoint(5)), vec![1, 3])]).unwrap();
    assert_ne!(original.digest(), changed_key.digest());
    assert_ne!(original.digest(), changed_value.digest());
    assert!(matches!(
        CanonicalPhysicalMutationBatch::from_logical(vec![LogicalMutation::Delete {
            key: TypedTableKey::CheckpointLeaf(checkpoint(5))
        }]),
        Err(ReplayPrototypeError::MutationBuild(MutationBuildError::DeleteNotEnabled))
    ));
}

#[test]
fn unknown_payload_codec_writer_schema_record_and_adapter_versions_are_rejected() {
    assert!(matches!(PreparedPayloadKind::try_from(9), Err(ReplayPrototypeError::UnknownPreparedPayloadKind(9))));
    assert!(matches!(ReplayRecordKind::try_from(9), Err(ReplayPrototypeError::UnknownReplayRecordKind(9))));
    assert!(matches!(resolve_replay_adapter(1, 2, 1, 1), Err(ReplayPrototypeError::UnknownPayloadCodec(2))));
    assert!(matches!(resolve_replay_adapter(1, 1, 2, 1), Err(ReplayPrototypeError::UnknownWriterVersion(2))));
    assert!(matches!(
        resolve_replay_adapter(1, 1, 1, 2),
        Err(ReplayPrototypeError::UnknownReplayAdapterVersion(2))
    ));

    let payload = PreparedPayload::try_v1(
        PreparedPayloadKind::Coordinator,
        vec![PreparedSemanticMutation::CheckpointLeaf { checkpoint: checkpoint(1), value: vec![1] }],
    )
    .unwrap();
    let mut bytes = payload.encode_canonical();
    bytes[17] = 99;
    assert_eq!(PreparedPayload::decode_canonical(&bytes).unwrap_err(), ReplayPrototypeError::UnknownPreparedSchemaTag(99));
    assert_eq!(
        PreparedPayload::try_v1(
            PreparedPayloadKind::Coordinator,
            vec![PreparedSemanticMutation::UserLeaf {
                user: UserId::new(1),
                checkpoint: checkpoint(1),
                value: vec![1],
            }],
        )
        .unwrap_err(),
        ReplayPrototypeError::PayloadMutationNotAllowedForAuthority
    );
}

#[test]
fn current_prepared_struct_boundaries_are_accounted_for() {
    use parth_core::data::hash::hash256::Hash256;
    use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

    let current_realm = PsyPreparedRealmBlockStateUpdates::<Hash256> {
        realm_id: 4,
        realm_sub_id: 1,
        unique_pending_id: 77,
        proc_checkpoint_unique_id: 88,
        old_realm_root: Hash256([1; 32]),
        new_realm_root: Hash256([2; 32]),
        update_global_user_tree_nodes_ffs: vec![0x22; 49],
        update_user_contract_tree_nodes_ffs: vec![0x23; 57],
        update_contract_state_tree_nodes_ffs: vec![0x24; 65],
        update_user_leaves_ffs: vec![0x25; 136],
        update_contract_state_imt_leaves_ffs: vec![0x26; 161],
    };
    assert_eq!(current_realm.update_contract_state_imt_leaves_ffs.len(), 161);
    assert!(!current_realm.update_global_user_tree_nodes_ffs.is_empty());

    // Bare Realm prepared data has no checkpoint field. The prototype gets
    // checkpoint metadata from a separately versioned receipt/supplement.
    let projected = PreparedPayload::try_v1(
        PreparedPayloadKind::Realm,
        vec![PreparedSemanticMutation::ImtLeaf {
            tree: TreeId::new(9),
            tree_sub: TreeSubId::new(2),
            leaf: LeafIndex::new(3),
            checkpoint: checkpoint(43),
            canonical_row: current_realm.update_contract_state_imt_leaves_ffs.clone(),
        }],
    )
    .unwrap();
    assert_eq!(projected.mutations().len(), 1);

    let coordinator_type = include_str!("../../psy_data/src/prepared_block/coordinator.rs");
    let coordinator_writer = include_str!("../../psy_node_common/src/coordinator/processor/db.rs");
    for required in [
        "checkpoint_tree_update_proof",
        "update_global_contract_tree_nodes_ffs",
        "new_public_key_hash_to_user_id_rows_ffs",
    ] {
        assert!(coordinator_type.contains(required));
    }
    assert!(coordinator_writer.contains("zk_proof: Vec<u8>"));
    assert!(coordinator_writer.contains("checkpoint_tree_set_leaf_hash"));
}

#[test]
fn non_durable_sources_and_digest_only_values_are_rejected() {
    for source in [
        PreparedPayloadSource::LocalGathererFile("/tmp/gatherer.bin"),
        PreparedPayloadSource::RedisKey("pending:7"),
        PreparedPayloadSource::TemporaryPendingFile("/tmp/pending-7"),
    ] {
        assert!(matches!(
            DurablePreparedPayloadReference::try_from_source(PreparedPayloadKind::Coordinator, 1, 1, source),
            Err(ReplayPrototypeError::NonDurablePayloadSource(_))
        ));
    }
    let digest_only = LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(checkpoint(2)),
        value: MutationValue::Digest { algorithm: ValueDigestAlgorithm::Sha256, digest: [7; 32] },
    };
    assert_eq!(
        CanonicalPhysicalMutationBatch::from_logical(vec![digest_only]).unwrap_err(),
        ReplayPrototypeError::DigestOnlyValueNotExecutable
    );
}

#[test]
fn blocked_and_retired_domains_cannot_be_replay_ready() {
    let blocked = [
        TypedTableKey::CheckpointedObject(CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint(1))),
        TypedTableKey::CheckpointToPending(checkpoint(1)),
        TypedTableKey::RealmRewardNode { realm: RealmId::new(1), pending: UniquePendingId::try_new(1).unwrap() },
    ];
    for key in blocked {
        assert!(matches!(
            CanonicalPhysicalMutationBatch::from_logical(vec![put(key, vec![1])]),
            Err(ReplayPrototypeError::MutationBuild(MutationBuildError::Readiness(
                RegistryReadinessError::Blocked(_)
            )))
        ));
    }
    assert!(matches!(
        CanonicalPhysicalMutationBatch::from_logical(vec![LogicalMutation::CheckpointLeafMapping {
            leaf: CheckpointLeafKey::new(vec![1; 32]),
            checkpoint: checkpoint(1),
        }]),
        Err(ReplayPrototypeError::MutationBuild(MutationBuildError::Readiness(
            RegistryReadinessError::RetireCandidate
        )))
    ));
}

#[test]
fn root_pair_imt_supplements_and_singleton_restore_are_explicit() {
    let pair = expand_logical_mutation(LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(vec![1; 32]),
        checkpoint: checkpoint(7),
    })
    .unwrap();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].mutation().physical_table(), ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1);
    assert_eq!(pair[1].mutation().physical_table(), ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2);
    assert_ne!(pair[0].locator_bytes(), pair[1].locator_bytes());

    let realm = materialize(realm_spec()).unwrap();
    let physical: Vec<_> = realm.full.mutations().iter().map(|mutation| mutation.mutation().physical_table()).collect();
    for required in [
        ScyllaPhysicalTableId::ImtLeaf,
        ScyllaPhysicalTableId::ImtKeyIndex,
        ScyllaPhysicalTableId::ImtNextAppendIndex,
        ScyllaPhysicalTableId::LatestInfo,
        ScyllaPhysicalTableId::U64Singleton,
    ] {
        assert!(physical.contains(&required), "missing {required:?}");
    }
    let cursor = realm
        .full
        .mutations()
        .iter()
        .find(|mutation| {
            mutation.mutation().physical_table()
                == ScyllaPhysicalTableId::ImtNextAppendIndex
        })
        .unwrap();
    let MutationOperation::Put(MutationValue::Structured {
        schema: StructuredValueSchema::ImtCursorTransitionV1,
        canonical_bytes,
    }) = cursor.mutation().operation()
    else {
        panic!("IMT cursor must carry a durable transition")
    };
    let transition = ImtCursorTransition::decode_canonical(canonical_bytes).unwrap();
    assert_eq!(transition.checkpoint(), checkpoint(43));
    assert_eq!((transition.before(), transition.after()), (3, 4));
}

#[test]
fn imt_cursor_before_image_is_digest_bound_and_checkpoint_checked() {
    let key = TypedTableKey::ImtCursor {
        tree: TreeId::new(9),
        tree_sub: TreeSubId::new(2),
    };
    let one = CanonicalPhysicalMutationBatch::from_logical(vec![
        LogicalMutation::Put {
            key: key.clone(),
            value: MutationValue::imt_cursor_transition(
                ImtCursorTransition::try_new(checkpoint(43), 3, 4).unwrap(),
            ),
        },
    ])
    .unwrap();
    let changed_before = CanonicalPhysicalMutationBatch::from_logical(vec![
        LogicalMutation::Put {
            key,
            value: MutationValue::imt_cursor_transition(
                ImtCursorTransition::try_new(checkpoint(43), 2, 4).unwrap(),
            ),
        },
    ])
    .unwrap();
    assert_ne!(one.digest(), changed_before.digest());

    let coordinator_receipt = ReplayReceipt::new(
        ReplayAuthority::Coordinator,
        checkpoint(43),
        0,
        1,
        vec![],
    );
    assert_eq!(
        FullPhysicalDeltaRecord::try_new(
            one.clone(),
            coordinator_receipt
        )
        .unwrap_err(),
        ReplayPrototypeError::ImtCursorAuthorityMismatch
    );

    let receipt = ReplayReceipt::new(
        ReplayAuthority::Realm,
        checkpoint(44),
        0,
        1,
        vec![],
    );
    assert_eq!(
        FullPhysicalDeltaRecord::try_new(one, receipt).unwrap_err(),
        ReplayPrototypeError::ImtCursorCheckpointMismatch {
            receipt: checkpoint(44),
            transition: checkpoint(43),
        }
    );
}

#[test]
fn persisted_imt_cursor_transition_corruption_fails_closed() {
    let fixture = materialize(realm_spec()).unwrap();
    let transition = ImtCursorTransition::try_new(checkpoint(43), 3, 4)
        .unwrap()
        .encode_canonical();
    let canonical = fixture.compact_record.encode_canonical();
    let offset = canonical
        .windows(transition.len())
        .position(|window| window == transition)
        .expect("cursor transition must be embedded in the replay record");

    let mut wrong_checkpoint = canonical.clone();
    wrong_checkpoint[offset..offset + 8]
        .copy_from_slice(&checkpoint(44).get().to_be_bytes());
    assert_eq!(
        PreparedReferencePlusSupplementRecord::decode_canonical(
            &wrong_checkpoint
        )
        .unwrap_err(),
        ReplayPrototypeError::ImtCursorCheckpointMismatch {
            receipt: checkpoint(43),
            transition: checkpoint(44),
        }
    );

    let mut rewind = canonical;
    rewind[offset + 8..offset + 16].copy_from_slice(&5_u64.to_be_bytes());
    assert!(matches!(
        PreparedReferencePlusSupplementRecord::decode_canonical(&rewind),
        Err(ReplayPrototypeError::MutationDecode(
            MutationDecodeError::MutationBuild(
                MutationBuildError::InvalidImtCursorTransition(_)
            )
        ))
    ));
}

#[test]
fn duplicate_physical_keys_are_rejected_deterministically() {
    let same = put(TypedTableKey::CheckpointLeaf(checkpoint(9)), vec![1]);
    assert_eq!(
        CanonicalPhysicalMutationBatch::from_logical(vec![same.clone(), same]).unwrap_err(),
        ReplayPrototypeError::DuplicatePhysicalKey
    );
    assert_eq!(
        CanonicalPhysicalMutationBatch::from_logical(vec![
            put(TypedTableKey::CheckpointLeaf(checkpoint(9)), vec![1]),
            put(TypedTableKey::CheckpointLeaf(checkpoint(9)), vec![2]),
        ])
        .unwrap_err(),
        ReplayPrototypeError::DuplicatePhysicalKey
    );
}

#[test]
fn physical_coverage_is_exact_and_registry_consistent() {
    validate_replay_coverage().unwrap();
    let matrix = replay_coverage_matrix();
    assert_eq!(matrix.len(), 35);
    assert_eq!(
        matrix.iter().map(|row| row.physical_table.stable_id()).collect::<Vec<_>>(),
        (1_u16..=35).collect::<Vec<_>>()
    );
    let blocked = matrix.iter().filter(|row| matches!(row.action, ReplayCoverageAction::BlockedSchema(_))).count();
    let retired = matrix.iter().filter(|row| row.action == ReplayCoverageAction::RetireUnused).count();
    assert_eq!((blocked, retired), (3, 3));
    assert_eq!(psy_node_core::store::typed::PsyLogicalTableId::iter().count(), 32);
    assert_eq!(ScyllaPhysicalTableId::iter().count(), 35);
    assert_eq!(ScyllaKeyDomain::iter().count(), 39);
}

#[test]
fn production_capabilities_and_callers_remain_unchanged() {
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
    for (name, source) in [
        ("setup", include_str!("../src/psy_setup.rs")),
        ("core_db", include_str!("../src/core_db.rs")),
        ("coordinator", include_str!("../../psy_node_common/src/coordinator/processor/db.rs")),
        ("realm_commit", include_str!("../../psy_node_common/src/realm/processor/db/commit.rs")),
        ("realm_sync", include_str!("../../psy_node_common/src/realm/processor/db/sync.rs")),
    ] {
        for forbidden in ["PreparedReferencePlusSupplementRecord", "resolve_replay_adapter", "replay_coverage_matrix"] {
            assert!(!source.contains(forbidden), "production source {name} unexpectedly references {forbidden}");
        }
    }
}

fn golden_snapshot() -> String {
    let coordinator = materialize(coordinator_spec()).unwrap();
    let realm = materialize(realm_spec()).unwrap();
    let empty = materialize(empty_realm_spec()).unwrap();
    let direct = replay_coverage_matrix()
        .iter()
        .filter(|row| row.action == ReplayCoverageAction::PreparedPayloadDirect)
        .count();
    let supplements = replay_coverage_matrix()
        .iter()
        .filter(|row| row.action == ReplayCoverageAction::DerivedSupplement)
        .count();
    let record_hash = |bytes: Vec<u8>| hex::encode(Sha256::digest(bytes));
    format!(
        "schema=1\ncoverage=35 direct={direct} supplement={supplements}\ncoordinator_digest={}\ncoordinator_metrics={:?}\ncoordinator_full_record={} compact_record={} payload={} supplement={}\ncoordinator_full_record_sha256={}\ncoordinator_compact_record_sha256={}\nrealm_digest={}\nrealm_metrics={:?}\nrealm_full_record={} compact_record={} payload={} supplement={}\nrealm_full_record_sha256={}\nrealm_compact_record_sha256={}\nempty_realm_digest={} state={} metadata={}\n",
        hex::encode(coordinator.full.digest().as_bytes()),
        coordinator.full.metrics(),
        coordinator.full_record.encode_canonical().len(),
        coordinator.compact_record.encode_canonical().len(),
        coordinator.payload_bytes.len(),
        coordinator.supplements.batch().encode_canonical().len(),
        record_hash(coordinator.full_record.encode_canonical()),
        record_hash(coordinator.compact_record.encode_canonical()),
        hex::encode(realm.full.digest().as_bytes()),
        realm.full.metrics(),
        realm.full_record.encode_canonical().len(),
        realm.compact_record.encode_canonical().len(),
        realm.payload_bytes.len(),
        realm.supplements.batch().encode_canonical().len(),
        record_hash(realm.full_record.encode_canonical()),
        record_hash(realm.compact_record.encode_canonical()),
        hex::encode(empty.full.digest().as_bytes()),
        empty.state_mutations,
        empty.metadata_mutations,
    )
}

#[test]
fn canonical_golden_is_stable() {
    assert_eq!(golden_snapshot(), include_str!("golden/rollback_replay_prototype_v1.txt"));
}

#[test]
fn report_directional_expansion_cpu_and_algorithmic_metrics() {
    let fixture = materialize(realm_spec()).unwrap();
    let iterations = 2_000;
    let started = Instant::now();
    for _ in 0..iterations {
        let expanded = fixture.compact_record.expand(&fixture.payload_bytes).unwrap();
        assert_eq!(expanded.digest(), fixture.full.digest());
    }
    let elapsed = started.elapsed();
    println!(
        "G0-05 directional-only: iterations={iterations} elapsed_us={} ns_per_expand={} full_record={} compact_record={} payload={} supplements={}",
        elapsed.as_micros(),
        elapsed.as_nanos() / iterations,
        fixture.full_record.encode_canonical().len(),
        fixture.compact_record.encode_canonical().len(),
        fixture.payload_bytes.len(),
        fixture.supplements.batch().encode_canonical().len(),
    );
}
