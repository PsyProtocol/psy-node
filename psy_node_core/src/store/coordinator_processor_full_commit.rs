//! Minimal storage boundary for one branch-exact Coordinator commit.
//!
//! The Processor performs the proof and the local checkpoint-tree backup. The
//! backend owns the explicit-timestamp state writes and the durable head-last
//! publication sequence. Keeping those as two calls makes the required order
//! visible without exposing backend manifests or completion receipts.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;

use super::{
    authority_commit::AuthorityClockSampleUs,
    canonical_head::{SealedCanonicalHeadCas, StoredCanonicalHead},
    coordinator_commit_source::{
        CoordinatorCheckpointBackupEvidence, CoordinatorCommitSource,
    },
    timestamp::DeleteFenceTimestampUs,
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};

#[async_trait]
pub trait CoordinatorProcessorFullCommitStore<Hash>: Send + Sync
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    /// Persist/reconcile the immutable source, narrow mapping writes, every
    /// typed Coordinator state row, and the full manifest. This does not mark
    /// the source committed and cannot publish the canonical head.
    async fn persist_full_write(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        pending: UniquePendingId,
        proc_id: ProcCheckpointUniqueId,
        clock: AuthorityClockSampleUs,
        post_rollback_fence: Option<DeleteFenceTimestampUs>,
    ) -> Result<(), CoordinatorProcessorFullCommitError>;

    /// Consume exact local backup evidence, persist completion, then publish
    /// COMMITTED and the canonical head in that order. The writer lifecycle is
    /// finalized only after the exact candidate head is durable.
    async fn publish_after_backup(
        &self,
        source: &CoordinatorCommitSource<Hash>,
        backup: CoordinatorCheckpointBackupEvidence<Hash>,
        head: &SealedCanonicalHeadCas<Hash>,
        post_rollback_fence: Option<DeleteFenceTimestampUs>,
    ) -> Result<StoredCanonicalHead<Hash>, CoordinatorProcessorFullCommitError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorProcessorFullCommitError {
    IdentityMismatch,
    AwaitingVerifiedWrites,
    Backend(String),
}

impl fmt::Display for CoordinatorProcessorFullCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorProcessorFullCommitError {}
