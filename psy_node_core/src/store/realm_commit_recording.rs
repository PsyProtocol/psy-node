//! The Realm's half of commit recording (design-r1 §6.3).
//!
//! Deliberately a subset of the Coordinator's.  §6 gives the chain one authority
//! over its head: every barrier is an LWT on the Coordinator's control row and
//! the Realms read it, so a Realm has no canonical head of its own to publish and
//! no rollback floor to establish.  Handing it those capabilities would create a
//! second place a head could be declared, which I10 exists to forbid.
//!
//! What it does need is its own manifest and its own timestamp allocator, and it
//! already has somewhere to put them: `authority_manifest` is partitioned by
//! `authority_scope` and `authority_commit_timestamp` by authority kind and realm
//! id, so a Realm's records sit beside the Coordinator's without colliding at the
//! same height.
//!
//! Bundled the same way as the Coordinator's for the same reason (§0.2 D3):
//! there is no constructor that yields some of it, so a Realm processor cannot be
//! built that writes state without recording it.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;

use super::authority_commit::AuthorityCommitTimestampStore;
use super::commit_planner::RealmCommitPlanner;
use super::commit_window::{CommitWindow, CommitWindowClock, CommitWindowError, CommitWindowGuard};
use super::manifest_store::{AuthorityManifestStore, ManifestArtifactStore};
use super::timestamp::CommitWriteTimestampUs;
use super::verification_journal::CommitVerificationJournal;

/// Everything a Realm processor needs to record what it commits.
pub struct RealmCommitRecording<Hash: Q256BitHash> {
    timestamp: Arc<dyn AuthorityCommitTimestampStore>,
    planner: Arc<dyn RealmCommitPlanner>,
    manifest: Arc<dyn AuthorityManifestStore<Hash>>,
    manifest_artifact: Arc<dyn ManifestArtifactStore<Hash>>,
    commit_window: Arc<CommitWindowClock>,
    journal: Option<Arc<dyn CommitVerificationJournal>>,
}

impl<Hash: Q256BitHash> Clone for RealmCommitRecording<Hash> {
    fn clone(&self) -> Self {
        Self {
            timestamp: self.timestamp.clone(),
            planner: self.planner.clone(),
            manifest: self.manifest.clone(),
            manifest_artifact: self.manifest_artifact.clone(),
            commit_window: self.commit_window.clone(),
            journal: self.journal.clone(),
        }
    }
}

impl<Hash: Q256BitHash> RealmCommitRecording<Hash> {
    pub fn new(
        timestamp: Arc<dyn AuthorityCommitTimestampStore>,
        planner: Arc<dyn RealmCommitPlanner>,
        manifest: Arc<dyn AuthorityManifestStore<Hash>>,
        manifest_artifact: Arc<dyn ManifestArtifactStore<Hash>>,
        commit_window: Arc<CommitWindowClock>,
        journal: Option<Arc<dyn CommitVerificationJournal>>,
    ) -> Self {
        Self {
            timestamp,
            planner,
            manifest,
            manifest_artifact,
            commit_window,
            journal,
        }
    }

    pub fn timestamp(&self) -> &dyn AuthorityCommitTimestampStore {
        self.timestamp.as_ref()
    }

    pub fn planner(&self) -> &dyn RealmCommitPlanner {
        self.planner.as_ref()
    }

    pub fn manifest(&self) -> &dyn AuthorityManifestStore<Hash> {
        self.manifest.as_ref()
    }

    pub fn manifest_artifact(&self) -> &dyn ManifestArtifactStore<Hash> {
        self.manifest_artifact.as_ref()
    }

    pub fn journal(&self) -> Option<&dyn CommitVerificationJournal> {
        self.journal.as_deref()
    }

    /// Open the commit window for one checkpoint.
    ///
    /// The Realm has its own store and therefore its own session and its own
    /// clock; the Coordinator's window says nothing about a Realm's writes.
    pub fn open_commit_window(
        &self,
        checkpoint_id: u64,
        timestamp: CommitWriteTimestampUs,
    ) -> Result<CommitWindowGuard, CommitWindowError> {
        self.commit_window
            .open(CommitWindow::new(checkpoint_id, timestamp))
    }

    pub fn require_commit_window(
        &self,
        checkpoint_id: u64,
    ) -> Result<CommitWriteTimestampUs, CommitWindowError> {
        self.commit_window.require_checkpoint(checkpoint_id)
    }

    /// Stop admitting commits, because this node is a participant in a rollback
    /// that has reached its freeze phase.
    ///
    /// The Coordinator and every Realm reach their commit path through one of
    /// these, so this is the whole of a node's freeze.
    pub fn freeze_for_rollback(&self) {
        self.commit_window.freeze_for_rollback();
    }

    /// Admit commits again, once the rollback has finished or been abandoned.
    pub fn thaw_after_rollback(&self) {
        self.commit_window.thaw_after_rollback();
    }

    /// Frozen and drained, which is what a freeze receipt claims.
    pub fn is_quiesced_for_rollback(&self) -> bool {
        self.commit_window.is_quiesced()
    }
}
