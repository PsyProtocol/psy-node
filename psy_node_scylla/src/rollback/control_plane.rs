//! One composition owning every rollback control-plane store.
//!
//! Deliberately separate from `ScyllaUnifiedPsyStore`.  That store is the 32
//! logical state tables and is also prepared by Edge nodes, which never commit
//! and so have nothing to record; mixing the control plane in would hand a
//! commit capability to a node that must not have one.
//!
//! Everything here lives in `<keyspace>_no_tablet`.  LWT is only linearizable on
//! a keyspace with tablets disabled, and every control write is an LWT.
//!
//! design-r1 §0.2 D3 makes this composition mandatory rather than optional: a
//! Coordinator that cannot record a commit must not be able to make one.  The
//! spike's failure mode was a manifest path that could be switched off, so
//! there is no constructor here that yields a store with pieces missing.

use std::sync::Arc;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, protocol::core_types::QHashBase};
use scylla::client::session::Session;

use crate::core::ScyllaCoreStore;

use super::{
    CanonicalHeadNoTabletKeyspace, CommitSourceNoTabletKeyspace, CqlKeyspaceName,
    ManifestArtifactNoTabletKeyspace, ManifestNoTabletKeyspace, RollbackFloorNoTabletKeyspace,
    ScyllaAuthorityManifestStore, ScyllaCanonicalHeadStore, ScyllaCoordinatorCommitSourceStore,
    ScyllaCoordinatorRollbackFloorStore, ScyllaManifestArtifactStore,
};

/// Every table this control plane owns, for inventory assertions.
pub const COORDINATOR_ROLLBACK_CONTROL_TABLES: &[&str] = &[
    super::COORDINATOR_CANONICAL_HEAD_TABLE,
    super::COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
    super::COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE,
    super::COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE,
    super::AUTHORITY_MANIFEST_TABLE,
    super::AUTHORITY_MANIFEST_ARTIFACT_TABLE,
    super::COORDINATOR_ROLLBACK_FLOOR_TABLE,
    super::COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE,
];

/// The validated keyspace pair a control plane binds to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackControlKeyspaces {
    state: CqlKeyspaceName,
    canonical_head: CanonicalHeadNoTabletKeyspace,
    commit_source: CommitSourceNoTabletKeyspace,
    manifest: ManifestNoTabletKeyspace,
    manifest_artifact: ManifestArtifactNoTabletKeyspace,
    floor: RollbackFloorNoTabletKeyspace,
}

impl RollbackControlKeyspaces {
    /// Derive both keyspaces from a core store, so the control plane can never
    /// point at a different cluster or keyspace than the state it describes.
    pub fn from_core_store<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        store: &ScyllaCoreStore<Hash, Hasher>,
    ) -> anyhow::Result<Self> {
        Self::try_new(&store.keyspace, &store.no_tablet_keyspace)
    }

    pub fn try_new(state: &str, no_tablet: &str) -> anyhow::Result<Self> {
        Ok(Self {
            state: CqlKeyspaceName::try_new(state)?,
            canonical_head: CanonicalHeadNoTabletKeyspace::try_new(no_tablet)?,
            commit_source: CommitSourceNoTabletKeyspace::try_new(no_tablet)?,
            manifest: ManifestNoTabletKeyspace::try_new(no_tablet)?,
            manifest_artifact: ManifestArtifactNoTabletKeyspace::try_new(no_tablet)?,
            floor: RollbackFloorNoTabletKeyspace::try_new(no_tablet)?,
        })
    }

    pub fn state(&self) -> &CqlKeyspaceName {
        &self.state
    }
}

/// All rollback control stores for one Coordinator authority.
pub struct CoordinatorRollbackControlPlane {
    canonical_head: ScyllaCanonicalHeadStore,
    commit_source: ScyllaCoordinatorCommitSourceStore,
    manifest: ScyllaAuthorityManifestStore,
    manifest_artifact: ScyllaManifestArtifactStore,
    floor: ScyllaCoordinatorRollbackFloorStore,
}

impl CoordinatorRollbackControlPlane {
    /// Idempotent DDL for every control table.
    ///
    /// Safe against an existing deployment: all statements are
    /// `CREATE TABLE IF NOT EXISTS` in a keyspace the node already creates.
    pub async fn create_tables(
        session: &Session,
        keyspaces: &RollbackControlKeyspaces,
    ) -> anyhow::Result<()> {
        ScyllaCanonicalHeadStore::create_schema(session, &keyspaces.canonical_head).await?;
        ScyllaCoordinatorCommitSourceStore::create_tables(session, &keyspaces.commit_source)
            .await?;
        ScyllaAuthorityManifestStore::create_tables(session, &keyspaces.manifest).await?;
        ScyllaManifestArtifactStore::create_tables(session, &keyspaces.manifest_artifact).await?;
        ScyllaCoordinatorRollbackFloorStore::create_tables(
            session,
            &keyspaces.floor,
            &keyspaces.state,
        )
        .await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspaces: &RollbackControlKeyspaces,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            canonical_head: ScyllaCanonicalHeadStore::prepare(
                session.clone(),
                keyspaces.canonical_head.clone(),
            )
            .await?,
            commit_source: ScyllaCoordinatorCommitSourceStore::prepare(
                session.clone(),
                &keyspaces.commit_source,
            )
            .await?,
            manifest: ScyllaAuthorityManifestStore::prepare(session.clone(), &keyspaces.manifest)
                .await?,
            manifest_artifact: ScyllaManifestArtifactStore::prepare(
                session.clone(),
                &keyspaces.manifest_artifact,
            )
            .await?,
            floor: ScyllaCoordinatorRollbackFloorStore::prepare(
                session,
                &keyspaces.floor,
                &keyspaces.state,
            )
            .await?,
        })
    }

    /// Create then prepare, for a Coordinator bringing a keyspace up.
    pub async fn setup<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        store: &ScyllaCoreStore<Hash, Hasher>,
    ) -> anyhow::Result<Self> {
        let keyspaces = RollbackControlKeyspaces::from_core_store(store)?;
        Self::create_tables(&store.session, &keyspaces).await?;
        Self::prepare(store.session.clone(), &keyspaces).await
    }

    pub fn canonical_head(&self) -> &ScyllaCanonicalHeadStore {
        &self.canonical_head
    }

    pub fn commit_source(&self) -> &ScyllaCoordinatorCommitSourceStore {
        &self.commit_source
    }

    pub fn manifest(&self) -> &ScyllaAuthorityManifestStore {
        &self.manifest
    }

    pub fn manifest_artifact(&self) -> &ScyllaManifestArtifactStore {
        &self.manifest_artifact
    }

    pub fn floor(&self) -> &ScyllaCoordinatorRollbackFloorStore {
        &self.floor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_control_table_is_listed_once() {
        let mut sorted = COORDINATOR_ROLLBACK_CONTROL_TABLES.to_vec();
        sorted.sort_unstable();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted, deduped, "a control table is listed twice");
        assert_eq!(COORDINATOR_ROLLBACK_CONTROL_TABLES.len(), 8);
    }

    #[test]
    fn control_tables_never_collide_with_a_real_state_table() {
        // The control plane shares a cluster with the 35 physical state tables,
        // and u64_counter_singleton_table already lives in the same no-tablet
        // keyspace.  A name collision would stay silent until two writers met
        // on one row, so this checks against the registry rather than against a
        // naming convention.
        use strum::IntoEnumIterator;
        let state_names: Vec<&str> = super::super::ScyllaPhysicalTableId::iter()
            .map(|id| super::super::physical_descriptor(id).physical_name)
            .collect();
        assert_eq!(state_names.len(), 35, "the physical inventory moved");
        for control in COORDINATOR_ROLLBACK_CONTROL_TABLES {
            assert!(
                !state_names.contains(control),
                "{control} collides with a physical state table"
            );
        }
    }

    #[test]
    fn keyspaces_are_derived_together_so_they_cannot_diverge() {
        let keyspaces = RollbackControlKeyspaces::try_new("psy", "psy_no_tablet").unwrap();
        assert_eq!(keyspaces.state().as_str(), "psy");
        // Every control store must land in the same no-tablet keyspace.
        assert_eq!(keyspaces.commit_source.as_str(), "psy_no_tablet");
        assert_eq!(keyspaces.manifest.as_str(), "psy_no_tablet");
        assert_eq!(keyspaces.manifest_artifact.as_str(), "psy_no_tablet");
        assert_eq!(keyspaces.floor.as_str(), "psy_no_tablet");
        assert_eq!(keyspaces.canonical_head.as_str(), "psy_no_tablet");
    }

    #[test]
    fn a_tablet_enabled_keyspace_is_refused_for_control_tables() {
        assert!(RollbackControlKeyspaces::try_new("psy", "psy").is_err());
    }
}
