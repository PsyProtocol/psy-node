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
        AuthorityPostWriteObservation, CommittedAuthorityManifest,
        SealedAuthorityManifest,
    },
    manifest_record::{
        AuthorityManifestIdentity, PreparedAuthorityManifestRecord,
    },
    normal_commit::{
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
    },
    realm_commit_seal::{
        ChangedRealmCommitSealError, ChangedRealmCommitSealEvidence,
    },
    realm_imt_mutation_graph::SealedRealmImtMutationGraph,
    realm_proof_binding::SealedRealmProofBinding,
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
    StateVerifiedAwaitingRealmEvidence {
        state: VerifiedRepresentativeRealmState<Hash>,
    },
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

/// Capability produced only after every representative physical row has
/// been read back exactly. It deliberately contains no proof/graph evidence;
/// callers must supply the two live seals to `seal_changed_realm_state`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRepresentativeRealmState<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    observation: AuthorityPostWriteObservation<Hash>,
}

impl<Hash> VerifiedRepresentativeRealmState<Hash> {
    pub const fn prepared(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.prepared
    }
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
                Ok(
                    RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
                        state: VerifiedRepresentativeRealmState {
                            prepared,
                            observation,
                        },
                    },
                )
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

    /// Consume exact physical read-back plus the live proof and mutation-graph
    /// seals, then re-read head/allocator state and persist the resulting
    /// changed-Realm SEALED manifest.
    pub async fn seal_changed_realm_state<Hash, Hasher>(
        &self,
        state: VerifiedRepresentativeRealmState<Hash>,
        proof: SealedRealmProofBinding<Hash>,
        graph: SealedRealmImtMutationGraph<Hash, Hasher>,
    ) -> Result<RepresentativeNormalCommitStep<Hash>, RepresentativeNormalCommitError>
    where
        Hash: Q256BitHash,
    {
        let VerifiedRepresentativeRealmState {
            prepared,
            observation,
        } = state;
        let evidence = ChangedRealmCommitSealEvidence::try_bind(
            &prepared,
            observation,
            proof,
            graph,
        )?;
        let sealed = self
            .metadata
            .verify_changed_realm_and_persist_sealed(prepared, evidence)
            .await?;
        Ok(RepresentativeNormalCommitStep::StateVerifiedAndSealed {
            sealed,
        })
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
            match self.step(identity).await? {
                RepresentativeNormalCommitStep::Done { committed } => {
                    return Ok(committed)
                }
                RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
                    state,
                } => {
                    return Err(
                        RepresentativeNormalCommitError::RealmEvidenceRequired {
                            prepared_manifest_digest: *state
                                .prepared()
                                .digest()
                                .as_bytes(),
                        },
                    )
                }
                _ => {}
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
    ChangedRealmCommitSeal(ChangedRealmCommitSealError),
    RealmEvidenceRequired { prepared_manifest_digest: [u8; 32] },
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

impl From<ChangedRealmCommitSealError> for RepresentativeNormalCommitError {
    fn from(value: ChangedRealmCommitSealError) -> Self {
        Self::ChangedRealmCommitSeal(value)
    }
}

impl fmt::Display for RepresentativeNormalCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RepresentativeNormalCommitError {}
