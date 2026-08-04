use std::collections::{BTreeSet, HashSet};

use psy_node_core::store::typed::{
    CheckpointId, CheckpointLeafKey, CheckpointRootKey, CheckpointedObjectKey, ContractId, ImtEncodedKey, LeafIndex, LogicalMutation,
    LatestInfoSlot, MerkleNode, MutationOperation, MutationValue, MutationValueKind, NodeIndex, ProcCheckpointUniqueId, PsyLogicalTableId,
    PublicKeyHash, RealmId, StructuredValueSchema, TreeId, TreeSubId, TypedTableKey, U64CounterSlot, U64SingletonSlot, UniquePendingId,
    UserId,
};
use psy_node_scylla::rollback::*;
use strum::IntoEnumIterator;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn pending(value: u64) -> UniquePendingId {
    UniquePendingId::try_new(value).unwrap()
}

fn setup_call_fragment(spec: &LogicalSetupSpec, prepare_only: bool) -> String {
    let prepare_suffix = if prepare_only { "_prepare_only" } else { "" };
    match spec.initializer {
        SetupInitializer::Standard(family) => {
            let rust_alias = match family {
                ScyllaSchemaFamily::Kiv => "ExKivTableIdentifier",
                ScyllaSchemaFamily::ObjectSingle => "ExSingleIdTableIdentifier",
                ScyllaSchemaFamily::U64 => "ExU64TableIdentifier",
                ScyllaSchemaFamily::HashToMany => "ExHashToManyIdsTableIdentifier",
                ScyllaSchemaFamily::MerkleSingle => "ExSingleIdMerkleTableIdentifier",
                ScyllaSchemaFamily::MerkleDouble => "ExDoubleIdMerkleTableIdentifier",
                ScyllaSchemaFamily::TagTree => "ExTagTreeTableIdentifier",
                ScyllaSchemaFamily::ImtLeaf => "ExIMTLeafTableIdentifier",
                ScyllaSchemaFamily::ImtKeyIndex => "ExIMTKeyIndexTableIdentifier",
                ScyllaSchemaFamily::ImtCursor => "ExIMTNextAppendIndexTableIdentifier",
                ScyllaSchemaFamily::Blob
                | ScyllaSchemaFamily::Counter
                | ScyllaSchemaFamily::U64ToU128
                | ScyllaSchemaFamily::U128ToU64
                | ScyllaSchemaFamily::MerkleZero => panic!("schema family {family:?} has a dedicated setup initializer"),
            };
            format!(
                "store.init_std_table{prepare_suffix}::<{rust_alias}>(\"{}\", get_rk({}))",
                spec.table_name, spec.routing_key
            )
        }
        SetupInitializer::NoTabletCounter => format!(
            "store.init_no_tablet_table{prepare_suffix}::<ExU64CounterTableIdentifier>(\"{}\", get_rk({}))",
            spec.table_name, spec.routing_key
        ),
        SetupInitializer::BlobBidirectional => format!(
            "store.init_std_table{prepare_suffix}::<ExBiDirectionalMappingTableIdentifier>(\"{}\", get_rk({}))",
            spec.table_name, spec.routing_key
        ),
        SetupInitializer::U64U128Bidirectional => format!(
            "store.init_std_table{prepare_suffix}::<ExBiDirectionalU64U128MappingTableIdentifier>(\"{}\", get_rk({}))",
            spec.table_name, spec.routing_key
        ),
        SetupInitializer::ZeroMerkle => format!(
            "store.init_zero_id_merkle_table{prepare_suffix}(\"{}\", get_rk({}),",
            spec.table_name, spec.routing_key
        ),
    }
}

#[test]
fn logical_and_physical_registry_is_total() {
    let logical: Vec<_> = PsyLogicalTableId::iter().collect();
    let physical: Vec<_> = ScyllaPhysicalTableId::iter().collect();
    assert_eq!(logical.len(), 32);
    assert_eq!(physical.len(), 35);
    assert_eq!(physical.iter().map(|id| id.stable_id()).collect::<Vec<_>>(), (1..=35).collect::<Vec<_>>());

    let expanded: Vec<_> = logical.iter().flat_map(|id| physical_tables(*id).iter().copied()).collect();
    assert_eq!(expanded.len(), 35);
    assert_eq!(expanded.iter().copied().collect::<BTreeSet<_>>(), physical.iter().copied().collect());

    for physical_id in physical {
        let descriptor = physical_descriptor(physical_id);
        assert_eq!(descriptor.id, physical_id);
        assert!(physical_tables(descriptor.logical_owner).contains(&physical_id));
        assert!(!descriptor.physical_name.is_empty());
        assert!(!descriptor.cql_primary_key().partition.is_empty());
        assert!(!descriptor.rust_implementation().is_empty());
        match descriptor.access {
            AccessPattern::ReaderWriter => {
                assert!(!descriptor.reader_symbols.is_empty(), "{:?} lacks reader evidence", descriptor.id);
                assert!(!descriptor.writer_symbols.is_empty(), "{:?} lacks writer evidence", descriptor.id);
            }
            AccessPattern::WriterOnly => {
                assert!(descriptor.reader_symbols.is_empty());
                assert!(!descriptor.writer_symbols.is_empty());
            }
            AccessPattern::Unused => {
                assert!(descriptor.reader_symbols.is_empty());
                assert!(descriptor.writer_symbols.is_empty());
            }
        }
    }
}

#[test]
fn routing_names_and_setup_catalog_are_stable() {
    let setup_source = include_str!("../src/psy_setup.rs");
    let setup_active = setup_source
        .split("pub async fn setup_psy_scylla_database_store")
        .nth(1)
        .expect("production setup function must exist")
        .split("/**")
        .next()
        .expect("active setup block must precede the legacy comment");
    let prepare_active = setup_source
        .split("pub async fn prepare_psy_scylla_database_store")
        .nth(1)
        .expect("production prepare-only function must exist");

    let setup = setup_catalog();
    assert_eq!(setup.len(), 32);
    assert_eq!(setup_active.matches("store.init_").count(), 32);
    assert_eq!(prepare_active.matches("store.init_").count(), 32);
    assert_eq!(setup.iter().map(|spec| spec.routing_key).collect::<Vec<_>>(), (1..=32).collect::<Vec<_>>());
    assert_eq!(
        setup.iter().map(|spec| spec.logical_id).collect::<Vec<_>>(),
        PsyLogicalTableId::iter().collect::<Vec<_>>()
    );
    for spec in &setup {
        assert_eq!(
            setup_active.matches(&setup_call_fragment(spec, false)).count(),
            1,
            "setup source must contain exactly one typed initializer binding for {:?}",
            spec.logical_id
        );
        assert_eq!(
            prepare_active.matches(&setup_call_fragment(spec, true)).count(),
            1,
            "prepare-only source must contain exactly one typed initializer binding for {:?}",
            spec.logical_id
        );
        assert_eq!(spec.table_name, spec.logical_id.table_name());
        assert_eq!(spec.routing_key, spec.logical_id.routing_key());
        for physical in physical_tables(spec.logical_id) {
            let descriptor = physical_descriptor(*physical);
            assert_eq!(descriptor.routing_key, spec.routing_key);
            assert_eq!(descriptor.keyspace, spec.keyspace);
            assert!(descriptor.physical_name.starts_with(spec.table_name));

            match spec.initializer {
                SetupInitializer::Standard(family) => assert_eq!(descriptor.schema_family, family),
                SetupInitializer::NoTabletCounter => assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::Counter),
                SetupInitializer::BlobBidirectional => assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::Blob),
                SetupInitializer::U64U128Bidirectional => assert!(matches!(
                    descriptor.schema_family,
                    ScyllaSchemaFamily::U64ToU128 | ScyllaSchemaFamily::U128ToU64
                )),
                SetupInitializer::ZeroMerkle => assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::MerkleZero),
            }
        }
    }

    let physical_names: HashSet<_> = physical_registry().into_iter().map(|descriptor| descriptor.physical_name).collect();
    assert_eq!(physical_names.len(), 35);
    assert!(physical_names.iter().all(|name| !name.contains("bridge_deposit")));

    for alias in [
        "type ExBiDirectionalMappingTableIdentifier = ScyllaBiDirectionalBlobToBlobTablePreparedStatements;",
        "type ExBiDirectionalU64U128MappingTableIdentifier = ScyllaBidirectionalU64U128MappingPreparedStatements;",
        "type ExU64TableIdentifier = ScyllaU64ToU64TablePreparedStatements;",
        "type ExSingleIdTableIdentifier = ScyllaGenericObjectSingleIdTablePreparedStatements;",
        "type ExKivTableIdentifier = ScyllaGenericKeyIdValueTablePreparedStatements;",
        "type ExSingleIdMerkleTableIdentifier = ScyllaMerkleNodesPreparedStatements;",
        "type ExDoubleIdMerkleTableIdentifier = ScyllaDoubleMerkleNodesPreparedStatements;",
        "type ExTagTreeTableIdentifier = ScyllaTagTreeNodesPreparedStatements;",
        "type ExHashToManyIdsTableIdentifier = ScyllaHashToManyIdsTablePreparedStatements;",
        "type ExU64CounterTableIdentifier = ScyllaU64ToU64CounterTablePreparedStatements;",
        "type ExIMTLeafTableIdentifier = ScyllaIMTLeafPreparedStatements;",
        "type ExIMTKeyIndexTableIdentifier = ScyllaIMTKeyIndexPreparedStatements;",
        "type ExIMTNextAppendIndexTableIdentifier = ScyllaIMTNextAppendIndexPreparedStatements;",
    ] {
        assert_eq!(setup_source.matches(alias).count(), 1, "setup adapter alias drifted: {alias}");
    }
}

#[test]
fn bidirectional_expansion_and_keyspace_assignment_are_exact() {
    let pairs: Vec<_> = PsyLogicalTableId::iter().filter(|logical| physical_tables(*logical).len() == 2).collect();
    assert_eq!(
        pairs,
        vec![
            PsyLogicalTableId::CheckpointRootToCheckpointId,
            PsyLogicalTableId::CheckpointLeafToCheckpointId,
            PsyLogicalTableId::PendingIdToPendingProcId,
        ]
    );

    assert_eq!(
        physical_tables(PsyLogicalTableId::CheckpointRootToCheckpointId),
        &[ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1, ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2]
    );
    assert_eq!(
        physical_tables(PsyLogicalTableId::CheckpointLeafToCheckpointId),
        &[ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1, ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK2]
    );
    assert_eq!(
        physical_tables(PsyLogicalTableId::PendingIdToPendingProcId),
        &[
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
        ]
    );

    let no_tablet: Vec<_> = physical_registry()
        .into_iter()
        .filter(|descriptor| descriptor.keyspace == ScyllaKeyspaceKind::NoTablet)
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(no_tablet, vec![ScyllaPhysicalTableId::U64CounterSingleton]);
    assert_eq!(physical_descriptor(ScyllaPhysicalTableId::U64CounterSingleton).routing_key, 12);
}

#[test]
fn unused_writer_only_and_checkpoint_kiv_sets_are_exact() {
    let unused: BTreeSet<_> = physical_registry()
        .into_iter()
        .filter(|descriptor| descriptor.classification == StorageClassification::Unused)
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(
        unused,
        BTreeSet::from([
            ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1,
            ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK2,
            ScyllaPhysicalTableId::CheckpointIdToRealmRoot,
        ])
    );

    let writer_only: Vec<_> = physical_registry()
        .into_iter()
        .filter(|descriptor| descriptor.access == AccessPattern::WriterOnly)
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(writer_only, vec![ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64]);
    assert!(physical_descriptor(writer_only[0]).reader_symbols.is_empty());
    assert!(!physical_descriptor(writer_only[0]).writer_symbols.is_empty());

    let checkpoint_kiv: BTreeSet<_> = physical_registry()
        .into_iter()
        .filter(|descriptor| {
            descriptor.schema_family == ScyllaSchemaFamily::Kiv
                && descriptor.classification != StorageClassification::Unused
                && descriptor.delete_candidates.contains(&DeleteStrategy::VersionPartition)
        })
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(
        checkpoint_kiv,
        BTreeSet::from([
            ScyllaPhysicalTableId::CheckpointLeaf,
            ScyllaPhysicalTableId::L2BlockState,
            ScyllaPhysicalTableId::CheckpointStateRoots,
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
        ])
    );
}

#[test]
fn merkle_imt_and_tag_axes_match_the_actual_schema() {
    let merkle_checkpoint_clustering: Vec<_> = physical_registry()
        .into_iter()
        .filter(|descriptor| {
            matches!(
                descriptor.schema_family,
                ScyllaSchemaFamily::MerkleZero | ScyllaSchemaFamily::MerkleSingle | ScyllaSchemaFamily::MerkleDouble
            ) && descriptor.version_axis == VersionAxis::CheckpointClustering
        })
        .collect();
    assert_eq!(merkle_checkpoint_clustering.len(), 7);
    assert_eq!(merkle_checkpoint_clustering.iter().filter(|d| d.schema_family == ScyllaSchemaFamily::MerkleZero).count(), 4);
    assert_eq!(merkle_checkpoint_clustering.iter().filter(|d| d.schema_family == ScyllaSchemaFamily::MerkleSingle).count(), 2);
    assert_eq!(merkle_checkpoint_clustering.iter().filter(|d| d.schema_family == ScyllaSchemaFamily::MerkleDouble).count(), 1);
    for descriptor in merkle_checkpoint_clustering {
        assert_eq!(descriptor.cql_primary_key().clustering.last().copied(), Some("checkpoint_id BIGINT DESC"));
    }

    let leaf = physical_descriptor(ScyllaPhysicalTableId::ImtLeaf);
    assert_eq!(leaf.version_axis, VersionAxis::CheckpointClustering);
    assert_eq!(leaf.cql_primary_key().clustering, &["checkpoint_id BIGINT DESC"]);
    let index = physical_descriptor(ScyllaPhysicalTableId::ImtKeyIndex);
    assert_eq!(index.version_axis, VersionAxis::ImtBirthOrdinaryColumn);
    assert!(!index.cql_primary_key().cql.contains("birth_checkpoint"));
    assert_eq!(index.manifest_requirement, ManifestRequirement::DerivedSupplement);
    let cursor = physical_descriptor(ScyllaPhysicalTableId::ImtNextAppendIndex);
    assert_eq!(cursor.version_axis, VersionAxis::MutableCursor);
    assert_eq!(cursor.rollback_policy, RollbackPolicy::RestoreSingleton);
    assert_eq!(cursor.manifest_requirement, ManifestRequirement::CursorBeforeAfter);

    let tag = physical_descriptor(ScyllaPhysicalTableId::GutaRewardTagTree);
    assert_eq!(tag.version_axis, VersionAxis::UniquePendingPartition);
    assert_eq!(tag.recovery_action, RecoveryAction::RotateNamespace);
}

#[test]
fn confirmed_schema_blockers_fail_closed() {
    let blocked: Vec<_> = physical_registry()
        .into_iter()
        .filter_map(|descriptor| match descriptor.readiness {
            RegistryReadiness::Blocked(blocker) => Some((descriptor.id, blocker)),
            RegistryReadiness::Ready | RegistryReadiness::RetireCandidate => None,
        })
        .collect();
    assert_eq!(
        blocked,
        vec![
            (ScyllaPhysicalTableId::CheckpointedObject, RegistryBlocker::MixedCheckpointPendingAxis),
            (ScyllaPhysicalTableId::CheckpointIdToPendingId, RegistryBlocker::ReusableCheckpointHeightKey),
            (ScyllaPhysicalTableId::RealmRewardsTreeNodeKey, RegistryBlocker::PendingSuffixReadThrough),
        ]
    );
    for (physical, blocker) in blocked {
        assert_eq!(
            physical_descriptor(physical).require_rollback_ready(),
            Err(RegistryReadinessError::Blocked(blocker))
        );
    }

    let checkpoint_domain = describe_existing_key(&TypedTableKey::CheckpointedObject(
        CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint(2)),
    ));
    let pending_domain = describe_existing_key(&TypedTableKey::CheckpointedObject(
        CheckpointedObjectKey::RewardsProofAtPending(pending(2)),
    ));
    assert_ne!(checkpoint_domain.key_domain(), pending_domain.key_domain());
    assert_ne!(checkpoint_domain.locator_bytes(), pending_domain.locator_bytes());
    assert_eq!(checkpoint_domain.cql_fingerprint(), pending_domain.cql_fingerprint());
    assert_ne!(
        describe_existing_key(&TypedTableKey::CheckpointLeaf(checkpoint(2))).cql_fingerprint(),
        describe_existing_key(&TypedTableKey::L2BlockState(checkpoint(2))).cql_fingerprint(),
        "physical row fingerprints must not collide across tables with the same schema and key value"
    );
    assert_eq!(
        resolve_key_for_rollback(checkpoint_domain.typed_key()),
        Err(RegistryReadinessError::Blocked(RegistryBlocker::MixedCheckpointPendingAxis))
    );

    assert!(physical_descriptor(ScyllaPhysicalTableId::RealmRewardsTreeNodeKey).reader_symbols[0].contains("<= pending"));
}

#[test]
fn pair_mutations_expand_deterministically_and_asymmetrically() {
    let root = CheckpointRootKey::new(vec![0, 1, 2, 3]);
    let intent = LogicalMutation::CheckpointRootMapping { root: root.clone(), checkpoint: checkpoint(42) };
    let first = expand_logical_mutation(intent.clone()).unwrap();
    let second = expand_logical_mutation(intent).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(
        first.iter().map(|mutation| mutation.mutation().physical_table()).collect::<Vec<_>>(),
        vec![ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1, ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2]
    );
    assert_ne!(first[0].locator_bytes(), first[1].locator_bytes());
    assert_eq!(first[0].mutation().key(), &TypedTableKey::CheckpointRootByHash(root.clone()));
    assert_eq!(
        first[0].mutation().operation(),
        &MutationOperation::Put(MutationValue::PsyCanonicalBytes(42_u64.to_le_bytes().to_vec()))
    );
    assert_eq!(first[1].mutation().key(), &TypedTableKey::CheckpointRootByCheckpoint(checkpoint(42)));
    assert_eq!(
        first[1].mutation().operation(),
        &MutationOperation::Put(MutationValue::PsyCanonicalBytes(root.as_bytes().to_vec()))
    );
    assert_eq!(physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1).delete_candidates, &[DeleteStrategy::Point, DeleteStrategy::SnapshotOnly]);
    assert_eq!(
        physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1).manifest_requirement,
        ManifestRequirement::PairPhysicalDirection
    );
    assert_eq!(physical_descriptor(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2).delete_candidates, &[DeleteStrategy::VersionPartition, DeleteStrategy::SnapshotOnly]);

    let proc_id = ProcCheckpointUniqueId::from_bytes([0x11; 16]);
    let pending_pair = expand_logical_mutation(LogicalMutation::PendingProcMapping { pending: pending(7), proc_id }).unwrap();
    assert_eq!(pending_pair.len(), 2);
    assert_eq!(
        pending_pair.iter().map(|mutation| mutation.mutation().physical_table()).collect::<Vec<_>>(),
        vec![
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
        ]
    );
    assert_eq!(pending_pair[0].mutation().key(), &TypedTableKey::PendingToProc(pending(7)));
    assert_eq!(pending_pair[0].mutation().operation(), &MutationOperation::Put(MutationValue::CqlU128(proc_id.as_u128())));
    assert_eq!(pending_pair[1].mutation().key(), &TypedTableKey::ProcToPending(proc_id));
    assert_eq!(pending_pair[1].mutation().operation(), &MutationOperation::Put(MutationValue::CqlU64(7)));

    let retired = expand_logical_mutation(LogicalMutation::CheckpointLeafMapping {
        leaf: CheckpointLeafKey::new(vec![9]),
        checkpoint: checkpoint(1),
    });
    assert_eq!(retired, Err(MutationBuildError::Readiness(RegistryReadinessError::RetireCandidate)));

    let partial = expand_logical_mutation(LogicalMutation::Put {
        key: TypedTableKey::CheckpointRootByHash(root),
        value: MutationValue::PsyCanonicalBytes(vec![1]),
    });
    assert_eq!(partial, Err(MutationBuildError::PairDirectionRequiresLogicalIntent));
}

#[test]
fn mutation_value_kind_is_checked_per_key_domain() {
    let mismatch_cases = [
        (
            TypedTableKey::CheckpointLeaf(checkpoint(1)),
            MutationValue::CqlU128(1),
            ScyllaKeyDomain::CheckpointLeaf,
            MutationValueKind::CqlU128,
        ),
        (
            TypedTableKey::PendingToCheckpoint(pending(1)),
            MutationValue::PsyCanonicalBytes(vec![1]),
            ScyllaKeyDomain::PendingToCheckpoint,
            MutationValueKind::PsyCanonicalBytes,
        ),
        (
            TypedTableKey::UserLeaf { user: UserId::new(1), checkpoint: checkpoint(1) },
            MutationValue::CqlU64(1),
            ScyllaKeyDomain::UserLeaf,
            MutationValueKind::CqlU64,
        ),
        (
            TypedTableKey::PublicKeyToUser { public_key_hash: PublicKeyHash::new(vec![1]), user: UserId::new(1) },
            MutationValue::PsyCanonicalBytes(vec![1]),
            ScyllaKeyDomain::PublicKeyToUser,
            MutationValueKind::PsyCanonicalBytes,
        ),
        (
            TypedTableKey::RewardTagMerkle { pending: pending(1), node: MerkleNode::new(0, NodeIndex::new(0)) },
            MutationValue::CqlU64(1),
            ScyllaKeyDomain::RewardTagMerkle,
            MutationValueKind::CqlU64,
        ),
        (
            TypedTableKey::ImtLeaf {
                tree: TreeId::new(1),
                tree_sub: TreeSubId::new(2),
                leaf: LeafIndex::new(3),
                checkpoint: checkpoint(4),
            },
            MutationValue::Structured { schema: StructuredValueSchema::ImtKeyIndexRowV1, canonical_bytes: vec![1] },
            ScyllaKeyDomain::ImtLeaf,
            MutationValueKind::Structured(StructuredValueSchema::ImtKeyIndexRowV1),
        ),
    ];
    for (key, value, domain, actual) in mismatch_cases {
        assert_eq!(
            expand_logical_mutation(LogicalMutation::Put { key, value }),
            Err(MutationBuildError::ValueEncodingMismatch { domain, actual })
        );
    }

    let mut imt_key = [0_u8; 32];
    imt_key[0] = 0x80;
    let valid_cases = [
        (
            TypedTableKey::PublicKeyToUser { public_key_hash: PublicKeyHash::new(vec![1]), user: UserId::new(1) },
            MutationValue::KeyOnly,
        ),
        (
            TypedTableKey::RewardTagMerkle { pending: pending(1), node: MerkleNode::new(0, NodeIndex::new(0)) },
            MutationValue::Structured { schema: StructuredValueSchema::TagTreeNodeV1, canonical_bytes: vec![1, 2] },
        ),
        (
            TypedTableKey::ImtLeaf {
                tree: TreeId::new(1),
                tree_sub: TreeSubId::new(2),
                leaf: LeafIndex::new(3),
                checkpoint: checkpoint(4),
            },
            MutationValue::Structured { schema: StructuredValueSchema::ImtLeafRowV1, canonical_bytes: vec![3, 4] },
        ),
        (
            TypedTableKey::ImtKeyIndex {
                tree: TreeId::new(1),
                tree_sub: TreeSubId::new(2),
                encoded_key: ImtEncodedKey::new(imt_key),
            },
            MutationValue::Structured { schema: StructuredValueSchema::ImtKeyIndexRowV1, canonical_bytes: vec![5, 6] },
        ),
        (TypedTableKey::ImtCursor { tree: TreeId::new(1), tree_sub: TreeSubId::new(2) }, MutationValue::CqlU64(7)),
    ];
    for (key, value) in valid_cases {
        assert_eq!(expand_logical_mutation(LogicalMutation::Put { key, value }).unwrap().len(), 1);
    }
}

#[test]
fn delete_is_reserved_until_the_adapter_and_strategy_are_enabled() {
    for key in all_key_domain_samples() {
        assert_eq!(
            expand_logical_mutation(LogicalMutation::Delete { key }),
            Err(MutationBuildError::DeleteNotEnabled)
        );
    }
}

#[test]
fn all_three_confirmed_blockers_reject_put_mutations() {
    let cases = [
        (
            TypedTableKey::CheckpointedObject(CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint(1))),
            RegistryBlocker::MixedCheckpointPendingAxis,
        ),
        (TypedTableKey::CheckpointToPending(checkpoint(1)), RegistryBlocker::ReusableCheckpointHeightKey),
        (
            TypedTableKey::RealmRewardNode { realm: RealmId::new(1), pending: pending(1) },
            RegistryBlocker::PendingSuffixReadThrough,
        ),
    ];
    for (key, blocker) in cases {
        assert_eq!(
            expand_logical_mutation(LogicalMutation::Put {
                key,
                value: MutationValue::PsyCanonicalBytes(vec![1]),
            }),
            Err(MutationBuildError::Readiness(RegistryReadinessError::Blocked(blocker)))
        );
    }
}

fn key_family_samples() -> Vec<(&'static str, TypedTableKey)> {
    let cp = checkpoint(7);
    let node = MerkleNode::new(3, NodeIndex::new(11));
    let mut encoded_imt = [0_u8; 32];
    encoded_imt[0] = 0x80;
    encoded_imt[31] = 0x55;
    vec![
        ("kiv", TypedTableKey::CheckpointLeaf(cp)),
        ("blob", TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(vec![0, 0xaa]))),
        ("object_single", TypedTableKey::UserLeaf { user: UserId::new(5), checkpoint: cp }),
        ("u64", TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint)),
        ("counter", TypedTableKey::U64Counter(U64CounterSlot::UniquePending)),
        ("u64_to_u128", TypedTableKey::PendingToProc(pending(9))),
        ("u128_to_u64", TypedTableKey::ProcToPending(ProcCheckpointUniqueId::from_u128(0x00112233445566778899aabbccddeeff))),
        ("hash_to_many", TypedTableKey::PublicKeyToUser { public_key_hash: PublicKeyHash::new(vec![0, 1, 2]), user: UserId::new(5) }),
        ("merkle_zero", TypedTableKey::GlobalUserMerkle { node, checkpoint: cp }),
        ("merkle_single", TypedTableKey::UserContractMerkle { user: UserId::new(5), node, checkpoint: cp }),
        ("merkle_double", TypedTableKey::ContractStateMerkle { user: UserId::new(5), contract: ContractId::new(6), node, checkpoint: cp }),
        ("tag", TypedTableKey::RewardTagMerkle { pending: pending(9), node }),
        ("imt_leaf", TypedTableKey::ImtLeaf { tree: TreeId::new(5), tree_sub: TreeSubId::new(6), leaf: LeafIndex::new(7), checkpoint: cp }),
        ("imt_key_index", TypedTableKey::ImtKeyIndex { tree: TreeId::new(5), tree_sub: TreeSubId::new(6), encoded_key: ImtEncodedKey::new(encoded_imt) }),
        ("imt_cursor", TypedTableKey::ImtCursor { tree: TreeId::new(5), tree_sub: TreeSubId::new(6) }),
    ]
}

fn all_key_domain_samples() -> Vec<TypedTableKey> {
    let cp = checkpoint(7);
    let pending = pending(9);
    let proc_id = ProcCheckpointUniqueId::from_u128(0x00112233445566778899aabbccddeeff);
    let node = MerkleNode::new(3, NodeIndex::new(11));
    let mut encoded_imt = [0_u8; 32];
    encoded_imt[0] = 0x80;
    encoded_imt[31] = 0x55;
    vec![
        TypedTableKey::CheckpointLeaf(cp),
        TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(vec![0xaa])),
        TypedTableKey::CheckpointRootByCheckpoint(cp),
        TypedTableKey::CheckpointLeafByHash(CheckpointLeafKey::new(vec![0xbb])),
        TypedTableKey::CheckpointLeafByCheckpoint(cp),
        TypedTableKey::L2BlockState(cp),
        TypedTableKey::UnusedCheckpointRealmRoot(cp),
        TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
        TypedTableKey::CheckpointedObject(CheckpointedObjectKey::GlobalUserProofAtCheckpoint(cp)),
        TypedTableKey::CheckpointedObject(CheckpointedObjectKey::RewardsProofAtCheckpoint(cp)),
        TypedTableKey::CheckpointedObject(CheckpointedObjectKey::RewardsProofAtPending(pending)),
        TypedTableKey::CheckpointedObject(CheckpointedObjectKey::ContractStateProofAtCheckpoint(cp)),
        TypedTableKey::CheckpointStateRoots(cp),
        TypedTableKey::UserLeaf { user: UserId::new(5), checkpoint: cp },
        TypedTableKey::UserPublicKey { user: UserId::new(5), checkpoint: cp },
        TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
        TypedTableKey::U64Counter(U64CounterSlot::UniquePending),
        TypedTableKey::ContractStateTreeHeight { contract: ContractId::new(6), checkpoint: cp },
        TypedTableKey::CheckpointToPending(cp),
        TypedTableKey::PendingToCheckpoint(pending),
        TypedTableKey::PendingToProc(pending),
        TypedTableKey::ProcToPending(proc_id),
        TypedTableKey::RealmRewardNode { realm: RealmId::new(4), pending },
        TypedTableKey::PublicKeyToUser { public_key_hash: PublicKeyHash::new(vec![1, 2]), user: UserId::new(5) },
        TypedTableKey::GlobalUserMerkle { node, checkpoint: cp },
        TypedTableKey::UserContractMerkle { user: UserId::new(5), node, checkpoint: cp },
        TypedTableKey::ContractStateMerkle { user: UserId::new(5), contract: ContractId::new(6), node, checkpoint: cp },
        TypedTableKey::GlobalCheckpointMerkle { node, checkpoint: cp },
        TypedTableKey::RewardTagMerkle { pending, node },
        TypedTableKey::UserRegistrationMerkle { node, checkpoint: cp },
        TypedTableKey::GlobalContractMerkle { node, checkpoint: cp },
        TypedTableKey::ContractFunctionMerkle { contract: ContractId::new(6), node, checkpoint: cp },
        TypedTableKey::ContractLeaf { contract: ContractId::new(6), checkpoint: cp },
        TypedTableKey::ContractCodeDefinition { contract: ContractId::new(6), checkpoint: cp },
        TypedTableKey::CheckpointZkProof(cp),
        TypedTableKey::ImtLeaf {
            tree: TreeId::new(5),
            tree_sub: TreeSubId::new(6),
            leaf: LeafIndex::new(7),
            checkpoint: cp,
        },
        TypedTableKey::ImtKeyIndex {
            tree: TreeId::new(5),
            tree_sub: TreeSubId::new(6),
            encoded_key: ImtEncodedKey::new(encoded_imt),
        },
        TypedTableKey::ImtCursor { tree: TreeId::new(5), tree_sub: TreeSubId::new(6) },
    ]
}

#[test]
fn key_domain_registry_is_total_and_matches_typed_resolver() {
    let domains: Vec<_> = ScyllaKeyDomain::iter().collect();
    assert_eq!(domains.len(), 38);
    assert_eq!(domains.iter().map(|id| id.stable_id()).collect::<Vec<_>>(), (1..=38).collect::<Vec<_>>());

    let samples = all_key_domain_samples();
    assert_eq!(samples.len(), 38);
    let resolved_domains: BTreeSet<_> = samples
        .iter()
        .map(|key| {
            let resolved = describe_existing_key(key);
            let descriptor = key_domain_descriptor(resolved.key_domain());
            assert_eq!(descriptor.physical_table, resolved.physical_table());
            assert_eq!(descriptor.logical_owner, resolved.logical_table());
            assert!(!descriptor.allowed_put_values.is_empty());
            assert!(descriptor.allowed_put_values.contains(&MutationValueKind::Digest));
            resolved.key_domain()
        })
        .collect();
    assert_eq!(resolved_domains, domains.into_iter().collect());

    let mixed = key_domain_descriptor(ScyllaKeyDomain::CheckpointedRewardsProofAtPending);
    assert_eq!(mixed.classification, KeyDomainClassification::Operational);
    assert_eq!(mixed.version_axis, VersionAxis::UniquePendingClustering);
    assert_eq!(mixed.prepared_coverage.realm, DomainPreparedUpdateCoverage::None);
    assert_eq!(mixed.recovery_action, RecoveryAction::RotateNamespace);

    let contract_height = key_domain_descriptor(ScyllaKeyDomain::ContractStateTreeHeight);
    assert_eq!(contract_height.prepared_coverage.coordinator, DomainPreparedUpdateCoverage::Indirect);
    assert_eq!(contract_height.prepared_coverage.realm, DomainPreparedUpdateCoverage::None);
}

#[test]
fn typed_key_codec_golden_v1() {
    let actual = key_family_samples()
        .into_iter()
        .map(|(name, key)| format!("{name}|{}", hex::encode(describe_existing_key(&key).locator_bytes())))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_eq!(actual, include_str!("golden/typed_key_v1.txt"));

    let checkpoint_key = describe_existing_key(&TypedTableKey::CheckpointLeaf(checkpoint(1)));
    let pending_key = describe_existing_key(&TypedTableKey::PendingToCheckpoint(pending(1)));
    assert_ne!(checkpoint_key.locator_bytes(), pending_key.locator_bytes());
}

#[test]
fn registry_golden_v1() {
    let actual = registry_snapshot_v1();
    assert_eq!(actual, include_str!("golden/rollback_registry_v1.txt"));
}

#[test]
fn key_domain_golden_v1() {
    let actual = key_domain_snapshot_v1();
    assert_eq!(actual, include_str!("golden/key_domain_registry_v1.txt"));
}

#[test]
fn mutation_encoding_is_deterministic() {
    let intent = LogicalMutation::Put {
        key: TypedTableKey::UserLeaf { user: UserId::new(1), checkpoint: checkpoint(2) },
        value: MutationValue::PsyCanonicalBytes(vec![3, 4, 5]),
    };
    let first = expand_logical_mutation(intent.clone()).unwrap();
    let second = expand_logical_mutation(intent).unwrap();
    assert_eq!(first[0].encode_canonical(), second[0].encode_canonical());
}

#[test]
fn descriptor_enums_are_matched_without_fallback_semantics() {
    fn readiness_tag(value: RegistryReadiness) -> u8 {
        match value {
            RegistryReadiness::Ready => 1,
            RegistryReadiness::Blocked(_) => 2,
            RegistryReadiness::RetireCandidate => 3,
        }
    }
    fn action_tag(value: RecoveryAction) -> u8 {
        match value {
            RecoveryAction::ArchiveAndSnapshot => 1,
            RecoveryAction::ArchiveAndRebuild => 2,
            RecoveryAction::RestoreFromTargetManifest => 3,
            RecoveryAction::PreserveOperational => 4,
            RecoveryAction::RotateNamespace => 5,
            RecoveryAction::RebuildFromAuthoritative => 6,
            RecoveryAction::Retire => 7,
            RecoveryAction::BlockedUntilMigration => 8,
        }
    }
    for descriptor in physical_registry() {
        assert!(readiness_tag(descriptor.readiness) > 0);
        assert!(action_tag(descriptor.recovery_action) > 0);
    }
}

#[test]
fn typed_primary_key_examples_cover_special_semantics() {
    let realm = describe_existing_key(&TypedTableKey::RealmRewardNode {
        realm: RealmId::new(4),
        pending: pending(10),
    });
    assert_eq!(realm.physical_table(), ScyllaPhysicalTableId::RealmRewardsTreeNodeKey);
    assert_eq!(realm.key_domain(), ScyllaKeyDomain::RealmRewardNode);

    let latest_checkpoint_tree_root = describe_existing_key(&TypedTableKey::LatestInfo(LatestInfoSlot::LatestCheckpointTreeRoot));
    assert_eq!(latest_checkpoint_tree_root.physical_table(), ScyllaPhysicalTableId::LatestInfo);
    assert_ne!(
        latest_checkpoint_tree_root.locator_bytes(),
        describe_existing_key(&TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)).locator_bytes()
    );

    assert_eq!(
        PRODUCTION_CQL_CAPABILITIES,
        ProductionCqlCapabilities { explicit_write_timestamp: false, delete_adapter: false }
    );
}
