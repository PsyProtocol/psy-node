//! Capabilities a Coordinator needs to record a commit.
//!
//! Defined here rather than beside the Scylla adapters because
//! `psy_node_common` builds the processor and must not depend on a storage
//! driver.  design-r1 §0.2 D3 makes these mandatory: a Coordinator that cannot
//! record a commit must not be able to make one, so `create_coordinator_processor`
//! takes them by value rather than as an option.

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;

use super::{
    manifest_lifecycle::{CommittedAuthorityManifest, SealedAuthorityManifest},
    manifest_record::{
        AuthorityManifestIdentity, AuthorityManifestStatus, ManifestRevision,
        PreparedAuthorityManifestRecord,
    },
};

/// Which artifact of a manifest a chunk belongs to.
///
/// R1 has no replay artifact: replay existed for the snapshot fallback, and
/// design-r1 §0.0 removed snapshot rollback from scope.  The discriminant space
/// leaves room for it rather than renumbering later.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManifestArtifactKind {
    /// Physical keys of every row the commit wrote.
    Locator = 1,
    /// Before/after images for the overwrite-in-place tables that cannot be
    /// recomputed from target state (design-r1 §2.2.1).
    DurablePayload = 2,
}

/// One persisted lifecycle row, still in canonical byte form.
///
/// Decoding needs the identity the caller selected, so a store returns bytes
/// and lets the typed models decode against that identity.  A store that
/// decoded on its own would be choosing which identity to trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedManifestRow {
    pub checkpoint_id: u64,
    pub revision: ManifestRevision,
    pub status: AuthorityManifestStatus,
    pub digest: Vec<u8>,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait AuthorityManifestStore<Hash: Q256BitHash>: Send + Sync {
    /// Append PREPARED.  It must exist before any hot-table write, so a crash
    /// can never leave physical rows that no manifest names.
    async fn append_prepared(
        &self,
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> anyhow::Result<()>;

    async fn append_sealed(&self, sealed: &SealedAuthorityManifest<Hash>) -> anyhow::Result<()>;

    async fn append_committed(
        &self,
        committed: &CommittedAuthorityManifest<Hash>,
    ) -> anyhow::Result<()>;

    async fn read_manifest_row(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        revision: ManifestRevision,
    ) -> anyhow::Result<Option<PersistedManifestRow>>;

    /// Every lifecycle row in `(from_checkpoint, to_checkpoint]`, the read the
    /// rollback planner performs over the discarded suffix.
    async fn read_manifest_suffix(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        from_checkpoint: u64,
        to_checkpoint: u64,
    ) -> anyhow::Result<Vec<PersistedManifestRow>>;
}

#[async_trait]
pub trait ManifestArtifactStore<Hash: Q256BitHash>: Send + Sync {
    /// Chunks are written before the manifest record that names them, so a
    /// crash in between leaves chunks no manifest points at.
    async fn persist_artifact_chunks(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        chunks: &[Vec<u8>],
    ) -> anyhow::Result<()>;

    /// `committed_chunk_count` comes from the manifest's artifact set
    /// commitment, never from the store: trusting what the store happens to
    /// hold would let a lost chunk read as a shorter mutation set.
    async fn read_artifact_chunks(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        committed_chunk_count: u32,
    ) -> anyhow::Result<Vec<Vec<u8>>>;
}

/// Everything a Coordinator needs to record a commit, as one value.
///
/// There is no `Default`, no `Option` field and no partial constructor.  A
/// Coordinator processor takes this by value, so "recording is off" is not a
/// state the type system permits (design-r1 §0.2 D3).
pub struct CoordinatorCommitRecording<Hash: Q256BitHash> {
    canonical_head: std::sync::Arc<dyn super::canonical_head::CoordinatorCanonicalHeadStore<Hash>>,
    commit_source: std::sync::Arc<
        dyn super::coordinator_commit_source::CoordinatorCommitSourceStore<Hash>,
    >,
    manifest: std::sync::Arc<dyn AuthorityManifestStore<Hash>>,
    manifest_artifact: std::sync::Arc<dyn ManifestArtifactStore<Hash>>,
    floor: std::sync::Arc<
        dyn super::coordinator_commit_source::CoordinatorRollbackFloorStore<Hash>,
    >,
}

impl<Hash: Q256BitHash> Clone for CoordinatorCommitRecording<Hash> {
    fn clone(&self) -> Self {
        Self {
            canonical_head: self.canonical_head.clone(),
            commit_source: self.commit_source.clone(),
            manifest: self.manifest.clone(),
            manifest_artifact: self.manifest_artifact.clone(),
            floor: self.floor.clone(),
        }
    }
}

impl<Hash: Q256BitHash> CoordinatorCommitRecording<Hash> {
    pub fn new(
        canonical_head: std::sync::Arc<
            dyn super::canonical_head::CoordinatorCanonicalHeadStore<Hash>,
        >,
        commit_source: std::sync::Arc<
            dyn super::coordinator_commit_source::CoordinatorCommitSourceStore<Hash>,
        >,
        manifest: std::sync::Arc<dyn AuthorityManifestStore<Hash>>,
        manifest_artifact: std::sync::Arc<dyn ManifestArtifactStore<Hash>>,
        floor: std::sync::Arc<
            dyn super::coordinator_commit_source::CoordinatorRollbackFloorStore<Hash>,
        >,
    ) -> Self {
        Self {
            canonical_head,
            commit_source,
            manifest,
            manifest_artifact,
            floor,
        }
    }

    pub fn canonical_head(
        &self,
    ) -> &dyn super::canonical_head::CoordinatorCanonicalHeadStore<Hash> {
        self.canonical_head.as_ref()
    }

    pub fn commit_source(
        &self,
    ) -> &dyn super::coordinator_commit_source::CoordinatorCommitSourceStore<Hash> {
        self.commit_source.as_ref()
    }

    pub fn manifest(&self) -> &dyn AuthorityManifestStore<Hash> {
        self.manifest.as_ref()
    }

    pub fn manifest_artifact(&self) -> &dyn ManifestArtifactStore<Hash> {
        self.manifest_artifact.as_ref()
    }

    pub fn floor(
        &self,
    ) -> &dyn super::coordinator_commit_source::CoordinatorRollbackFloorStore<Hash> {
        self.floor.as_ref()
    }
}
