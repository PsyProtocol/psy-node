use psy_node_core::store::typed::CheckpointId;
use psy_node_scylla::rollback::*;
use scylla::statement::{Consistency, SerialConsistency};

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).unwrap()
}

fn authority(id: u64) -> StorageAuthority {
    StorageAuthority::try_new("g003-unit", StorageAuthorityKind::Realm, id).unwrap()
}

fn dataset(seed: u64) -> RepresentativeDataset {
    RepresentativeDataset::artificial(seed, checkpoint(100), 3, 5, 2).unwrap()
}

fn descriptor(seed: u64, generation: u64) -> RecoveryNamespaceDescriptor {
    let data = dataset(seed);
    RecoveryNamespaceDescriptor::from_dataset(
        authority(7),
        checkpoint(100),
        NamespaceCheckpointHash::new([seed as u8; 32]),
        BindingGeneration::try_new(generation).unwrap(),
        &data,
    )
    .unwrap()
}

#[test]
fn namespace_identity_is_deterministic_and_owns_both_keyspaces() {
    let first = descriptor(1, 4);
    let retry = descriptor(1, 4);
    assert_eq!(first, retry);
    assert_eq!(first.namespace().standard().as_str(), retry.namespace().standard().as_str());
    assert_eq!(first.namespace().no_tablet().as_str(), retry.namespace().no_tablet().as_str());
    assert!(first.namespace().standard().as_str().starts_with("psy_rb_"));
    assert_eq!(
        first.namespace().no_tablet().as_str(),
        format!("{}_nt", first.namespace().standard().as_str())
    );

    assert_ne!(first.namespace().id(), descriptor(1, 5).namespace().id());
    assert_ne!(first.namespace().id(), descriptor(2, 4).namespace().id());
    let other_authority_data = dataset(1);
    let other_authority = RecoveryNamespaceDescriptor::from_dataset(
        authority(8),
        checkpoint(100),
        NamespaceCheckpointHash::new([1; 32]),
        BindingGeneration::try_new(4).unwrap(),
        &other_authority_data,
    )
    .unwrap();
    assert_ne!(first.namespace().id(), other_authority.namespace().id());
}

#[test]
fn arbitrary_or_mixed_keyspace_names_fail_closed() {
    for invalid in ["", "9psy", "psy-rb", "psy.rb", "psy; DROP KEYSPACE x"] {
        assert!(CqlKeyspaceName::try_new(invalid).is_err());
    }

    let old = descriptor(1, 0);
    let new = descriptor(2, 0);
    assert!(matches!(
        AuthorityStorageNamespace::validate_persisted_pair(
            old.namespace().id(),
            old.namespace().standard().as_str(),
            new.namespace().no_tablet().as_str(),
        ),
        Err(NamespaceModelError::MixedNamespacePair { .. })
    ));

}

#[test]
fn representative_digest_root_and_counts_are_canonical() {
    let original = dataset(9);
    let mut leaves = original.checkpoint_leaves().to_vec();
    let mut merkle = original.global_user_merkle().to_vec();
    let mut counters = original.no_tablet_counters().to_vec();
    leaves.reverse();
    merkle.reverse();
    counters.reverse();
    let reordered = RepresentativeDataset::try_new(leaves, merkle, counters).unwrap();
    assert_eq!(original, reordered);
    assert_eq!(original.counts(), RepresentativeRowCounts::try_new(3, 5, 2).unwrap());
    assert_eq!(original.counts().total(), 10);
    assert_ne!(original.digest(), dataset(10).digest());
    assert_ne!(original.state_root(), dataset(10).state_root());

    assert!(RepresentativeRowCounts::try_new(0, 1, 1).is_err());
    assert!(RepresentativeRowCounts::try_new(1, 0, 1).is_err());
    assert!(RepresentativeRowCounts::try_new(1, 1, 0).is_err());
}

#[test]
fn control_queries_encode_immutable_catalog_and_exact_binding_cas() {
    let control = CqlKeyspaceName::try_new("psy_g003_control").unwrap();
    let queries = NamespaceControlQueries::new(&control);

    assert!(queries.insert_catalog_if_absent().ends_with("IF NOT EXISTS"));
    assert!(queries.insert_binding_if_absent().ends_with("IF NOT EXISTS"));
    assert!(queries.create_catalog().contains("status tinyint"));
    assert!(queries.create_catalog().contains("verified_at_unix_ms bigint"));
    assert!(queries.create_binding().contains("namespace_id blob"));

    let cas = queries.cutover_binding();
    for exact_condition in [
        "IF binding_generation = ?",
        "namespace_id = ?",
        "standard_namespace = ?",
        "no_tablet_namespace = ?",
        "checkpoint_id = ?",
        "checkpoint_hash = ?",
        "state_root = ?",
        "dataset_digest = ?",
    ] {
        assert!(cas.contains(exact_condition), "missing exact CAS predicate {exact_condition:?}");
    }
    assert_eq!(cas.matches("IF ").count(), 1);
    assert_eq!(cas.matches('?').count(), 20);

    let rendered = queries.render_golden();
    assert_eq!(rendered, NamespaceControlQueries::new(&control).render_golden());
    assert!(!rendered.contains("ALLOW FILTERING"));
}

#[test]
fn lwt_contract_is_explicit_quorum_and_local_serial() {
    let contract = NamespaceLwtContract::rf3_default();
    assert_eq!(contract.regular(), Consistency::Quorum);
    assert_eq!(contract.serial(), SerialConsistency::LocalSerial);
}

#[test]
fn prototype_is_not_advertised_as_a_production_capability() {
    assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
    assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);

    let production_sources = [
        include_str!("../src/psy_setup.rs"),
        include_str!("../src/core.rs"),
        include_str!("../../psy_node_common/src/coordinator/processor/db.rs"),
        include_str!("../../psy_node_common/src/realm/processor/db/mod.rs"),
    ];
    for source in production_sources {
        assert!(!source.contains("NamespaceControlAdapter"));
        assert!(!source.contains("RepresentativeNamespaceStore"));
        assert!(!source.contains("BoundAuthorityStore"));
        assert!(!source.contains("g003_recovery_namespace_catalog"));
    }
}
