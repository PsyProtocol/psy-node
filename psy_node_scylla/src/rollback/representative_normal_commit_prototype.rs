//! One recovery loop composing representative Realm state with D-04b metadata.
//!
//! Each call to [`ScyllaRepresentativeRealmNormalCommitExecutor::step`]
//! derives the next operation from durable manifest/head/timestamp rows.  It
//! never carries an in-memory phase across calls, so a process restart between
//! any two returned steps follows the same path.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    manifest_lifecycle::{
        CommittedAuthorityManifest, SealedAuthorityManifest,
    },
    manifest_record::AuthorityManifestIdentity,
    normal_commit::{
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
    },
};

use super::{
    ManifestPreparedError, NormalCommitMetadataError,
    RepresentativeRealmStateReplayExecutor,
    RepresentativeRealmStateReplayPlan, RepresentativeStateExecutionError,
    RepresentativeStateReplayError, RollbackableStorePrototype,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaNormalCommitMetadataExecutor, ScyllaPreparedManifestStore,
};

/// Result of exactly one recovery step.  A caller must durably re-read and
/// call `step` again rather than assuming the following phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepresentativeNormalCommitStep<Hash> {
    StateVerifiedAndSealed {
        sealed: SealedAuthorityManifest<Hash>,
    },
    HeadPublishedAwaitingCommitted {
        committed: CommittedAuthorityManifest<Hash>,
    },
    HeadCasRetryRequired,
    CommittedPersisted {
        committed: CommittedAuthorityManifest<Hash>,
    },
    TimestampCompleted,
    Done {
        committed: CommittedAuthorityManifest<Hash>,
    },
}

/// Isolated production-shaped executor for the one currently supported Realm
/// state family.  It is intentionally absent from `psy_setup.rs` and all
/// Processor callsites.
pub struct ScyllaRepresentativeRealmNormalCommitExecutor<'a> {
    manifests: &'a ScyllaPreparedManifestStore,
    metadata: ScyllaNormalCommitMetadataExecutor<'a>,
    state: RepresentativeRealmStateReplayExecutor<'a>,
}

impl<'a> ScyllaRepresentativeRealmNormalCommitExecutor<'a> {
    pub const fn new(
        manifests: &'a ScyllaPreparedManifestStore,
        heads: &'a ScyllaAuthorityLocalHeadStore,
        timestamps: &'a ScyllaAuthorityTimestampStore,
        state: &'a RollbackableStorePrototype,
    ) -> Self {
        Self {
            manifests,
            metadata: ScyllaNormalCommitMetadataExecutor::new(
                manifests, heads, timestamps,
            ),
            state: RepresentativeRealmStateReplayExecutor::new(state),
        }
    }

    /// Execute one durable transition selected from a fresh metadata read.
    pub async fn step<Hash: Q256BitHash>(
        &self,
        identity: AuthorityManifestIdentity<Hash>,
    ) -> Result<RepresentativeNormalCommitStep<Hash>, RepresentativeNormalCommitError>
    {
        match self.metadata.plan(identity).await? {
            NormalCommitRecoveryAction::ReapplyExactMutationsAndVerify {
                prepared,
            } => {
                let artifacts = self
                    .manifests
                    .load_verified_artifacts(&prepared)
                    .await?;
                let plan =
                    RepresentativeRealmStateReplayPlan::try_from_verified_artifacts(
                        &prepared, &artifacts,
                    )?;
                self.state.reapply_all(&plan).await?;
                let observation = self.state.verify_exact(&plan).await?;
                let sealed = self
                    .metadata
                    .verify_and_persist_sealed(prepared, observation)
                    .await?;
                Ok(RepresentativeNormalCommitStep::StateVerifiedAndSealed {
                    sealed,
                })
            }
            NormalCommitRecoveryAction::PublishExactHead { publish } => {
                match self.metadata.publish_head(publish).await? {
                    NormalHeadPublishProgress::PersistCommitted {
                        committed,
                    } => Ok(
                        RepresentativeNormalCommitStep::HeadPublishedAwaitingCommitted {
                            committed,
                        },
                    ),
                    NormalHeadPublishProgress::RetryExactSealedIntent => {
                        Ok(RepresentativeNormalCommitStep::HeadCasRetryRequired)
                    }
                }
            }
            NormalCommitRecoveryAction::PersistRecoveredCommitted {
                committed,
            } => {
                self.metadata.persist_committed(&committed).await?;
                Ok(RepresentativeNormalCommitStep::CommittedPersisted {
                    committed,
                })
            }
            NormalCommitRecoveryAction::CompleteTimestampLease {
                completion,
            } => {
                self.metadata.complete_timestamp(completion).await?;
                Ok(RepresentativeNormalCommitStep::TimestampCompleted)
            }
            NormalCommitRecoveryAction::Done { committed } => {
                Ok(RepresentativeNormalCommitStep::Done { committed })
            }
        }
    }

    /// Convenience loop for an uninterrupted process.  Crash tests and
    /// production recovery should prefer `step` at externally controlled
    /// boundaries.  The finite budget prevents an unexpected retry state from
    /// becoming an internal infinite loop.
    pub async fn drive_to_done<Hash: Q256BitHash>(
        &self,
        identity: AuthorityManifestIdentity<Hash>,
        max_steps: usize,
    ) -> Result<CommittedAuthorityManifest<Hash>, RepresentativeNormalCommitError>
    {
        for _ in 0..max_steps {
            if let RepresentativeNormalCommitStep::Done { committed } =
                self.step(identity).await?
            {
                return Ok(committed);
            }
        }
        Err(RepresentativeNormalCommitError::StepBudgetExhausted {
            max_steps,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepresentativeNormalCommitError {
    Metadata(NormalCommitMetadataError),
    Manifest(ManifestPreparedError),
    StatePlan(RepresentativeStateReplayError),
    StateExecution(RepresentativeStateExecutionError),
    StepBudgetExhausted { max_steps: usize },
}

impl From<NormalCommitMetadataError> for RepresentativeNormalCommitError {
    fn from(value: NormalCommitMetadataError) -> Self {
        Self::Metadata(value)
    }
}

impl From<ManifestPreparedError> for RepresentativeNormalCommitError {
    fn from(value: ManifestPreparedError) -> Self {
        Self::Manifest(value)
    }
}

impl From<RepresentativeStateReplayError> for RepresentativeNormalCommitError {
    fn from(value: RepresentativeStateReplayError) -> Self {
        Self::StatePlan(value)
    }
}

impl From<RepresentativeStateExecutionError>
    for RepresentativeNormalCommitError
{
    fn from(value: RepresentativeStateExecutionError) -> Self {
        Self::StateExecution(value)
    }
}

impl fmt::Display for RepresentativeNormalCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RepresentativeNormalCommitError {}
