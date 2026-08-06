use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs},
    typed::{
        CheckpointId, LogicalMutation, MutationValue, PublicKeyHash, TypedTableKey, UserId,
    },
};
use psy_node_scylla::rollback::*;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
}

fn fence(write: i64, value: i64) -> DeleteFenceTimestampUs {
    DeleteFenceTimestampUs::try_after(timestamp(write), value as i128).unwrap()
}

fn intent(hash: &[u8], user: u64) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::PublicKeyToUser {
            public_key_hash: PublicKeyHash::new(hash.to_vec()),
            user: UserId::new(user),
        },
        value: MutationValue::KeyOnly,
    }
}

fn sealed(hash: &[u8], user: u64, ts: i64) -> SealedTimestampedPut {
    seal_commit_put(intent(hash, user), timestamp(ts)).unwrap()
}

#[test]
fn registry_declares_a_key_only_derived_birth_projection() {
    let descriptor = physical_descriptor(ScyllaPhysicalTableId::PublicKeyHashToUserIds);
    assert_eq!(descriptor.schema_family, ScyllaSchemaFamily::HashToMany);
    assert_eq!(descriptor.classification, StorageClassification::Derived);
    assert_eq!(descriptor.version_axis, VersionAxis::ContentBirth);
    assert_eq!(descriptor.rollback_policy, RollbackPolicy::DerivedBirth);
    assert_eq!(descriptor.delete_candidates, &[DeleteStrategy::Point, DeleteStrategy::SnapshotOnly]);
    assert_eq!(descriptor.manifest_requirement, ManifestRequirement::DerivedSupplement);
    assert_eq!(descriptor.readiness, RegistryReadiness::Ready);
    let allowed = key_domain_descriptor(ScyllaKeyDomain::PublicKeyToUser).allowed_put_values;
    assert!(allowed.contains(&psy_node_core::store::typed::MutationValueKind::KeyOnly));
    assert!(allowed.contains(&psy_node_core::store::typed::MutationValueKind::Digest));
}

#[test]
fn query_catalog_uses_the_real_schema_and_matches_golden() {
    let queries =
        PublicKeyProjectionQueries::new(&CqlKeyspaceName::try_new("psy_d02t5").unwrap());
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_public_key_projection_v1.txt")
    );
    assert!(queries.put().cql().contains("USING TIMESTAMP ?"));
    assert!(queries
        .point_delete()
        .cql()
        .contains("WHERE hash_id = ? AND value_u64 = ?"));
    for query in [queries.put(), queries.point_delete()] {
        assert_eq!(query.cql().matches('?').count(), query.bind_shape().len());
    }
}

#[test]
fn key_only_put_binds_complete_physical_key_timestamp_and_birth() {
    let hash = [0x21; 32];
    let sealed = sealed(&hash, u64::MAX, 1_000);
    let binding =
        PublicKeyProjectionPutBinding::try_from_sealed(&sealed, checkpoint(7)).unwrap();
    assert_eq!(binding.public_key_hash(), &hash);
    assert_eq!(binding.user(), UserId::new(u64::MAX));
    assert_eq!(binding.birth_checkpoint(), checkpoint(7));
    assert_eq!(binding.write_timestamp_us(), 1_000);
    assert_eq!(binding.timestamped_intent_digest(), sealed.intent_digest());
    assert_eq!(
        binding.bind_values(),
        vec![
            PrototypeBindValue::Blob(hash.to_vec()),
            PrototypeBindValue::BigInt(-1),
            PrototypeBindValue::BigInt(1_000),
        ]
    );
}

#[test]
fn hash_length_value_kind_and_wrong_family_fail_closed() {
    assert!(matches!(
        PublicKeyProjectionPutBinding::try_from_sealed(
            &sealed(&[1; 31], 1, 100),
            checkpoint(1),
        ),
        Err(PublicKeyProjectionPlanError::InvalidHashLength { actual: 31 })
    ));
    assert!(seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::PublicKeyToUser {
                public_key_hash: PublicKeyHash::new(vec![1; 32]),
                user: UserId::new(1),
            },
            value: MutationValue::CqlU64(1),
        },
        timestamp(100),
    )
    .is_err());
    assert!(matches!(
        seal_commit_put(
            LogicalMutation::Put {
                key: TypedTableKey::PublicKeyToUser {
                    public_key_hash: PublicKeyHash::new(vec![1; 32]),
                    user: UserId::new(1),
                },
                value: MutationValue::Digest {
                    algorithm: psy_node_core::store::typed::ValueDigestAlgorithm::Sha256,
                    digest: [9; 32],
                },
            },
            timestamp(100),
        ),
        Err(TimestampedMutationError::CommitmentOnlyPayload)
    ));

    let checkpoint_leaf = seal_commit_put(
        LogicalMutation::Put {
            key: TypedTableKey::CheckpointLeaf(checkpoint(1)),
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        },
        timestamp(100),
    )
    .unwrap();
    assert!(matches!(
        PublicKeyProjectionPutBinding::try_from_sealed(&checkpoint_leaf, checkpoint(1)),
        Err(PublicKeyProjectionPlanError::WrongPhysicalTable(_))
    ));
}

#[test]
fn birth_checkpoint_is_part_of_retry_identity() {
    let sealed = sealed(&[2; 32], 9, 100);
    let binding =
        PublicKeyProjectionPutBinding::try_from_sealed(&sealed, checkpoint(10)).unwrap();
    let retry =
        PublicKeyProjectionPutBinding::try_from_sealed(&sealed, checkpoint(10)).unwrap();
    let different_birth =
        PublicKeyProjectionPutBinding::try_from_sealed(&sealed, checkpoint(11)).unwrap();
    assert_eq!(binding, retry);
    assert_ne!(binding.birth_digest(), different_birth.birth_digest());
    assert!(binding.ensure_exact_retry(&sealed, checkpoint(10)).is_ok());
    assert!(matches!(
        binding.ensure_exact_retry(&sealed, checkpoint(11)),
        Err(PublicKeyProjectionPlanError::RetryChanged)
    ));
}

#[test]
fn homogeneous_batch_is_stable_and_rejects_empty_mixed_or_duplicate_input() {
    let a = sealed(&[1; 32], 1, 100);
    let b = sealed(&[2; 32], 2, 100);
    let batch = PublicKeyProjectionPutBatch::try_from_sealed(
        &[a.clone(), b.clone()],
        checkpoint(8),
    )
    .unwrap();
    let retry = PublicKeyProjectionPutBatch::try_from_sealed(&[a.clone(), b], checkpoint(8))
        .unwrap();
    assert_eq!(batch, retry);
    assert_eq!(batch.members().len(), 2);
    assert_eq!(batch.birth_checkpoint(), checkpoint(8));
    assert_eq!(batch.write_timestamp_us(), 100);
    assert!(matches!(
        PublicKeyProjectionPutBatch::try_from_sealed(&[], checkpoint(8)),
        Err(PublicKeyProjectionPlanError::EmptyBatch)
    ));
    assert!(matches!(
        PublicKeyProjectionPutBatch::try_from_sealed(
            &[a.clone(), sealed(&[3; 32], 3, 101)],
            checkpoint(8),
        ),
        Err(PublicKeyProjectionPlanError::MixedWriteTimestamps { .. })
    ));
    assert!(matches!(
        PublicKeyProjectionPutBatch::try_from_sealed(&[a.clone(), a], checkpoint(8)),
        Err(PublicKeyProjectionPlanError::DuplicatePhysicalKey)
    ));
}

#[test]
fn point_delete_requires_manifest_birth_after_target_and_fence_after_write() {
    let binding = PublicKeyProjectionPutBinding::try_from_sealed(
        &sealed(&[4; 32], 17, 1_000),
        checkpoint(101),
    )
    .unwrap();
    let plan = PublicKeyProjectionPointDeletePlan::try_from_orphaned_birth(
        &binding,
        checkpoint(100),
        fence(1_000, 2_000),
    )
    .unwrap();
    assert_eq!(plan.birth_checkpoint(), checkpoint(101));
    assert_eq!(plan.target_checkpoint(), checkpoint(100));
    assert_eq!(
        plan.bind_values(),
        vec![
            PrototypeBindValue::BigInt(2_000),
            PrototypeBindValue::Blob(vec![4; 32]),
            PrototypeBindValue::BigInt(17),
        ]
    );
    assert!(matches!(
        PublicKeyProjectionPointDeletePlan::try_from_orphaned_birth(
            &binding,
            checkpoint(101),
            fence(1_000, 2_000),
        ),
        Err(PublicKeyProjectionPlanError::BirthNotAfterTarget { .. })
    ));

    let stale_fence = DeleteFenceTimestampUs::try_after(timestamp(999), 1_000).unwrap();
    assert!(matches!(
        PublicKeyProjectionPointDeletePlan::try_from_orphaned_birth(
            &binding,
            checkpoint(100),
            stale_fence,
        ),
        Err(PublicKeyProjectionPlanError::FenceNotAfterWrite { .. })
    ));
}

#[test]
fn d02t5_is_isolated_and_does_not_promote_production_capability() {
    let adapter = include_str!("../src/rollback/public_key_projection.rs");
    let legacy = include_str!("../src/tables/hash_to_many_ids.rs");
    let setup = include_str!("../src/psy_setup.rs");
    let core_db = include_str!("../src/core_db.rs");
    assert!(adapter.contains("BatchType::Unlogged"));
    assert!(adapter.contains("PublicKeyProjectionPutBinding::driver_values"));
    assert!(!legacy.contains("USING TIMESTAMP"));
    assert!(!legacy.contains("DELETE FROM"));
    assert!(!setup.contains("PublicKeyProjectionAdapter"));
    assert!(!core_db.contains("PublicKeyProjectionAdapter"));
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
}
