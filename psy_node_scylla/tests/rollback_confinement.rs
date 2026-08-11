use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Path, PathBuf}};

use psy_node_core::store::{
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId, CheckpointLeafKey, CheckpointRootKey,
        CheckpointedObjectKey, LogicalMutation, MerkleNode, MutationValue,
        NodeIndex, TypedTableKey, U64SingletonSlot,
    },
};
use psy_node_scylla::rollback::*;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
}

fn checkpoint_leaf_intent(checkpoint_id: u64, value: &[u8]) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(checkpoint(checkpoint_id)),
        value: MutationValue::PsyCanonicalBytes(value.to_vec()),
    }
}

fn global_user_intent(level: u8, index: u64, checkpoint_id: u64, value: [u8; 32]) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::GlobalUserMerkle {
            node: MerkleNode::new(level, NodeIndex::new(index)),
            checkpoint: checkpoint(checkpoint_id),
        },
        value: MutationValue::PsyCanonicalBytes(value.to_vec()),
    }
}

#[tokio::test]
async fn representative_writes_cross_only_the_typed_store_boundary() {
    let store = RollbackableStorePrototype::recording();
    let leaf = seal_commit_put(checkpoint_leaf_intent(9, &[1, 2, 3]), timestamp(1_000)).unwrap();
    let merkle = seal_commit_put(global_user_intent(7, 11, 9, [5; 32]), timestamp(1_001)).unwrap();
    let singleton = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            value: MutationValue::CqlU64(9),
        },
        timestamp(1_002),
    )
    .unwrap();
    let checkpoint_root = seal_commit_put_batch(
        LogicalMutation::CheckpointRootMapping {
            root: CheckpointRootKey::new(vec![0x44; 32]),
            checkpoint: checkpoint(9),
        },
        timestamp(1_003),
    )
    .unwrap();

    let leaf_receipt = store.put_checkpoint_leaf(&leaf).await.unwrap();
    let merkle_receipt = store.put_global_user_merkle(&merkle).await.unwrap();
    let singleton_receipt = store.put_latest_checkpoint(&singleton).await.unwrap();
    let checkpoint_root_receipts = store
        .put_checkpoint_root_pair(&checkpoint_root)
        .await
        .unwrap();
    assert_eq!(leaf_receipt.physical_table(), ScyllaPhysicalTableId::CheckpointLeaf);
    assert_eq!(leaf_receipt.query_id(), ConfinedWriteQueryId::TimestampPrototype(TimestampPrototypeQueryId::CheckpointLeafPut));
    assert_eq!(leaf_receipt.canonical_mutation(), leaf.canonical_bytes());
    assert_eq!(merkle_receipt.physical_table(), ScyllaPhysicalTableId::GlobalUserTree);
    assert_eq!(merkle_receipt.query_id(), ConfinedWriteQueryId::TimestampPrototype(TimestampPrototypeQueryId::GlobalUserMerklePut));
    assert_eq!(merkle_receipt.canonical_mutation(), merkle.canonical_bytes());
    assert_eq!(singleton_receipt.physical_table(), ScyllaPhysicalTableId::U64Singleton);
    assert_eq!(
        singleton_receipt.query_id(),
        ConfinedWriteQueryId::MutableSingleton(MutableSingletonQueryKind::LatestCheckpointPut)
    );
    assert_eq!(singleton_receipt.canonical_mutation(), singleton.canonical_bytes());
    assert_eq!(checkpoint_root_receipts.len(), 2);
    assert_eq!(
        checkpoint_root_receipts[0].physical_table(),
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
    );
    assert_eq!(
        checkpoint_root_receipts[1].physical_table(),
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2
    );
    for receipt in &checkpoint_root_receipts {
        assert_eq!(
            receipt.query_id(),
            ConfinedWriteQueryId::CheckpointRootPair(
                CheckpointRootPairQueryKind::Put
            )
        );
    }

    let calls = store.recorded_calls().unwrap();
    assert_eq!(
        calls,
        vec![
            leaf_receipt,
            merkle_receipt,
            singleton_receipt,
            checkpoint_root_receipts[0].clone(),
            checkpoint_root_receipts[1].clone(),
        ]
    );
}

#[tokio::test]
async fn typed_store_rejects_a_ready_mutation_for_the_wrong_representative_adapter() {
    let store = RollbackableStorePrototype::recording();
    let merkle = seal_commit_put(global_user_intent(1, 2, 3, [8; 32]), timestamp(2_000)).unwrap();
    assert!(matches!(
        store.put_checkpoint_leaf(&merkle).await,
        Err(RollbackableStorePrototypeError::TypedPlan(
            TimestampPrototypePlanError::WrongPhysicalTable {
                expected: ScyllaPhysicalTableId::CheckpointLeaf,
                actual: ScyllaPhysicalTableId::GlobalUserTree,
            }
        ))
    ));
    assert!(store.recorded_calls().unwrap().is_empty());

    assert_eq!(
        store.read_global_user_merkle_exact(&merkle).await,
        Err(RollbackableStorePrototypeError::ExactReadRequiresScylla)
    );

    let checkpoint_root = seal_commit_put_batch(
        LogicalMutation::CheckpointRootMapping {
            root: CheckpointRootKey::new(vec![0x45; 32]),
            checkpoint: checkpoint(3),
        },
        timestamp(2_001),
    )
    .unwrap();
    assert_eq!(
        store
            .read_checkpoint_root_pair_exact(&checkpoint_root)
            .await,
        Err(RollbackableStorePrototypeError::ExactReadRequiresScylla)
    );
}

#[test]
fn blocked_retired_and_commitment_only_domains_cannot_reach_the_store() {
    let blocked = LogicalMutation::Put {
        key: TypedTableKey::CheckpointedObject(CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint(2))),
        value: MutationValue::PsyCanonicalBytes(vec![1]),
    };
    assert!(matches!(
        seal_commit_put(blocked, timestamp(10)),
        Err(TimestampedMutationError::MutationBuild(MutationBuildError::Readiness(
            RegistryReadinessError::Blocked(RegistryBlocker::MixedCheckpointPendingAxis)
        )))
    ));

    let retired = LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeafByHash(CheckpointLeafKey::new(vec![2; 32])),
        value: MutationValue::PsyCanonicalBytes(checkpoint(2).get().to_le_bytes().to_vec()),
    };
    assert!(matches!(
        seal_commit_put(retired, timestamp(11)),
        Err(TimestampedMutationError::MutationBuild(MutationBuildError::Readiness(
            RegistryReadinessError::RetireCandidate
        )))
    ));

    let digest_only = LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(checkpoint(2)),
        value: MutationValue::Digest {
            algorithm: psy_node_core::store::typed::ValueDigestAlgorithm::Sha256,
            digest: [9; 32],
        },
    };
    assert!(matches!(
        seal_commit_put(digest_only, timestamp(12)),
        Err(TimestampedMutationError::CommitmentOnlyPayload)
    ));
}

#[test]
fn readiness_has_no_unknown_or_default_write_path() {
    fn admitted(readiness: RegistryReadiness) -> bool {
        match readiness {
            RegistryReadiness::Ready => true,
            RegistryReadiness::Blocked(_) | RegistryReadiness::RetireCandidate => false,
        }
    }

    for descriptor in physical_registry() {
        assert_eq!(admitted(descriptor.readiness), descriptor.require_rollback_ready().is_ok());
    }
    for descriptor in key_domain_registry() {
        assert_eq!(admitted(descriptor.readiness), descriptor.require_rollback_ready().is_ok());
    }
}

fn collect_rust_sources(root: &Path, current: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(current).unwrap_or_else(|error| panic!("cannot read {}: {error}", current.display())) {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rust_sources(root, &path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path.strip_prefix(root).unwrap().to_path_buf());
        }
    }
}

fn detected_workspace_access() -> BTreeMap<String, RawScyllaAccessCounts> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_root.parent().unwrap();
    let mut sources = Vec::new();
    collect_rust_sources(workspace, workspace, &mut sources);
    let mut detected = BTreeMap::new();
    for relative in sources {
        let path = relative.to_string_lossy().replace('\\', "/");
        let source = fs::read_to_string(workspace.join(&relative)).unwrap();
        let counts = inspect_raw_scylla_source(&path, &source);
        if !counts.is_empty() {
            require_raw_scylla_access_allowlisted(&path, &source)
                .unwrap_or_else(|violation| panic!("unallowlisted raw Scylla access: {violation:?}"));
            detected.insert(path, counts);
        }
    }
    detected
}

#[test]
fn raw_scylla_access_is_exactly_allowlisted() {
    let detected = detected_workspace_access();
    let allowlisted = RAW_SCYLLA_ACCESS_ALLOWLIST.iter().map(|entry| entry.path.to_owned()).collect::<BTreeSet<_>>();
    assert_eq!(allowlisted.len(), RAW_SCYLLA_ACCESS_ALLOWLIST.len(), "allowlist paths must be unique");
    assert!(allowlisted.iter().all(|path| !path.contains('*') && !path.ends_with('/')));
    assert_eq!(detected.keys().cloned().collect::<BTreeSet<_>>(), allowlisted);
}

#[test]
fn direct_cql_fixture_outside_allowlist_fails_closed() {
    let source = r#"
        use scylla::client::session::Session;
        async fn bypass(session: &Session) {
            session.query_unpaged("DELETE FROM authority_state WHERE id = ?", (7_i64,)).await;
        }
    "#;
    let violation = require_raw_scylla_access_allowlisted("psy_node_common/src/business/bypass.rs", source).unwrap_err();
    assert_eq!(violation.path, "psy_node_common/src/business/bypass.rs");
    assert!(violation.counts.session_type > 0);
    assert!(violation.counts.query_call > 0);
    assert!(violation.counts.direct_cql > 0);
}

#[test]
fn inferred_public_session_field_fixture_outside_allowlist_fails_closed() {
    let source = r#"
        use psy_node_scylla::core::ScyllaCoreStore;
        fn bypass(store: ScyllaCoreStore<Hash, Hasher>) {
            let leaked = store.session.clone();
        }
    "#;
    let violation = require_raw_scylla_access_allowlisted("psy_node_common/src/business/leak.rs", source).unwrap_err();
    assert_eq!(violation.counts.session_field_access, 1);
}

#[test]
fn prototype_is_not_wired_into_production_or_promoted_to_full_capability() {
    assert_eq!(
        PRODUCTION_CQL_CAPABILITIES,
        ProductionCqlCapabilities {
            explicit_write_timestamp: false,
            delete_adapter: false,
        }
    );
    for production_source in [include_str!("../src/psy_setup.rs"), include_str!("../src/core_db.rs")] {
        assert!(!production_source.contains("RollbackableStorePrototype"));
        assert!(!production_source.contains(
            "ScyllaRepresentativeRealmNormalCommitExecutor"
        ));
    }
}

#[test]
fn lexical_inventory_is_stable_and_nontrivial() {
    let detected = detected_workspace_access();
    let total = detected.values().fold(RawScyllaAccessCounts::default(), |mut total, row| {
        total.session_type += row.session_type;
        total.session_builder += row.session_builder;
        total.session_field_access += row.session_field_access;
        total.prepared_statement += row.prepared_statement;
        total.prepare_call += row.prepare_call;
        total.execute_call += row.execute_call;
        total.query_call += row.query_call;
        total.direct_cql += row.direct_cql;
        total
    });
    assert_eq!(detected.len(), 145);
    assert_eq!(
        total,
        RawScyllaAccessCounts {
            session_type: 988,
            session_builder: 65,
            session_field_access: 302,
            prepared_statement: 417,
            prepare_call: 187,
            execute_call: 381,
            query_call: 317,
            direct_cql: 686,
        }
    );
}

#[test]
fn raw_scylla_access_inventory_matches_golden() {
    let detected = detected_workspace_access();
    let mut rendered = String::from(
        "path|scope|session|session_builder|session_field_access|prepared_statement|prepare_call|execute_call|query_call|direct_cql\n",
    );
    for (path, counts) in detected {
        let scope = raw_scylla_access_allowance(&path).unwrap().scope;
        rendered.push_str(&format!(
            "{path}|{scope:?}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            counts.session_type,
            counts.session_builder,
            counts.session_field_access,
            counts.prepared_statement,
            counts.prepare_call,
            counts.execute_call,
            counts.query_call,
            counts.direct_cql,
        ));
    }
    let expected = include_str!("golden/raw_scylla_access_inventory_v1.txt");
    let actual_lines = rendered.lines().collect::<Vec<_>>();
    let expected_lines = expected.lines().collect::<Vec<_>>();
    assert_eq!(actual_lines.len(), expected_lines.len(), "raw-access golden line count");
    for (line_number, (actual, expected)) in actual_lines.iter().zip(&expected_lines).enumerate() {
        assert_eq!(actual, expected, "raw-access golden mismatch at line {}", line_number + 1);
    }
}
