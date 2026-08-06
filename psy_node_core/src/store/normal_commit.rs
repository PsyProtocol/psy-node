//! Driver-independent orchestration for one authority normal commit.
//!
//! The module owns no database/session and performs no mutation. It composes
//! the durable timestamp, manifest lifecycle and authority-head types into a
//! fail-closed recovery planner. Production Processor integration must execute
//! the returned typed action and durably re-read before asking for the next.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;

use super::{
    authority_commit::{
        AuthorityCommitModelError, AuthorityIntentObservation,
        AuthorityTimestampLease, ObservedAuthorityTimestampState,
        SealedAuthorityTimestampCompletion,
    },
    authority_local_head::{
        AuthorityLocalHeadModelError, AuthorityLocalHeadWriteOutcome,
        SealedAuthorityLocalHeadCas, StoredAuthorityLocalHead,
    },
    manifest_lifecycle::{
        AuthorityHeadPublishDecision, AuthorityHeadView,
        AuthorityPostWriteObservation, CommittedAuthorityManifest,
        ManifestLifecycleError, PersistedAuthorityManifest,
        SealedAuthorityManifest, SealedManifestRecoveryAction,
    },
    manifest_record::PreparedAuthorityManifestRecord,
};

/// The only next durable operation permitted by the observed manifest, head
/// and allocator rows. Variants contain typed capabilities rather than raw
/// revisions, digests or payload bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalCommitRecoveryAction<Hash> {
    ReapplyExactMutationsAndVerify {
        prepared: PreparedAuthorityManifestRecord<Hash>,
    },
    PublishExactHead {
        publish: SealedNormalHeadPublish<Hash>,
    },
    PersistRecoveredCommitted {
        committed: CommittedAuthorityManifest<Hash>,
    },
    CompleteTimestampLease {
        completion: SealedAuthorityTimestampCompletion,
    },
    Done {
        committed: CommittedAuthorityManifest<Hash>,
    },
}

/// Result of observing the authority-head CAS. A successful or idempotent
/// candidate observation immediately yields a typed COMMITTED candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalHeadPublishProgress<Hash> {
    RetryExactSealedIntent,
    PersistCommitted {
        committed: CommittedAuthorityManifest<Hash>,
    },
}

/// The exact SEALED manifest and authority-head CAS that must be executed as
/// one publish attempt. Neither component can be substituted independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedNormalHeadPublish<Hash> {
    manifest: SealedAuthorityManifest<Hash>,
    head_cas: SealedAuthorityLocalHeadCas<Hash>,
}

impl<Hash> SealedNormalHeadPublish<Hash> {
    pub const fn manifest(&self) -> &SealedAuthorityManifest<Hash> {
        &self.manifest
    }

    pub const fn head_cas(&self) -> &SealedAuthorityLocalHeadCas<Hash> {
        &self.head_cas
    }
}

/// Determine the only safe next step after startup or a lost response.
pub fn plan_normal_commit_recovery<Hash: Q256BitHash>(
    manifest: &PersistedAuthorityManifest<Hash>,
    current_head: &StoredAuthorityLocalHead<Hash>,
    allocator: ObservedAuthorityTimestampState,
) -> Result<NormalCommitRecoveryAction<Hash>, NormalCommitOrchestrationError> {
    let current_view = *current_head.head();
    match manifest {
        PersistedAuthorityManifest::Prepared(prepared) => {
            require_active_lease(prepared, allocator)?;
            let expected = AuthorityHeadView::expected(prepared);
            if current_view != expected {
                return Err(
                    NormalCommitOrchestrationError::PreparedHeadIsNotExpected,
                );
            }
            Ok(NormalCommitRecoveryAction::ReapplyExactMutationsAndVerify {
                prepared: prepared.clone(),
            })
        }
        PersistedAuthorityManifest::Sealed(sealed) => {
            require_active_lease(sealed.prepared(), allocator)?;
            match sealed.recovery_action(current_view) {
                SealedManifestRecoveryAction::PublishExactCandidate => {
                    let head_cas = SealedAuthorityLocalHeadCas::seal_normal_advance(
                        current_head.clone(),
                        sealed,
                    )?;
                    Ok(NormalCommitRecoveryAction::PublishExactHead {
                        publish: SealedNormalHeadPublish {
                            manifest: sealed.clone(),
                            head_cas,
                        },
                    })
                }
                SealedManifestRecoveryAction::MarkCommitted(receipt) => {
                    Ok(NormalCommitRecoveryAction::PersistRecoveredCommitted {
                        committed: sealed.clone().mark_committed(receipt)?,
                    })
                }
                SealedManifestRecoveryAction::Conflict { .. } => {
                    Err(NormalCommitOrchestrationError::AuthorityHeadConflict)
                }
            }
        }
        PersistedAuthorityManifest::Committed(committed) => {
            committed.recovery_action(current_view)?;
            let prepared = committed.sealed().prepared();
            match observe_allocator(prepared, allocator)? {
                ExactAllocatorObservation::Active(lease) => {
                    let completion = allocator.state().seal_completion(
                        allocator.key(),
                        lease,
                    )?;
                    Ok(NormalCommitRecoveryAction::CompleteTimestampLease {
                        completion,
                    })
                }
                ExactAllocatorObservation::Completed => {
                    Ok(NormalCommitRecoveryAction::Done {
                        committed: committed.clone(),
                    })
                }
            }
        }
    }
}

/// Cross the state-write verification boundary. The allocator must still own
/// the exact PREPARED intent and the head must still be its expected head;
/// otherwise stale work cannot become SEALED.
pub fn seal_verified_normal_commit<Hash: Q256BitHash>(
    prepared: PreparedAuthorityManifestRecord<Hash>,
    observation: AuthorityPostWriteObservation<Hash>,
    current_head: &StoredAuthorityLocalHead<Hash>,
    allocator: ObservedAuthorityTimestampState,
) -> Result<SealedAuthorityManifest<Hash>, NormalCommitOrchestrationError> {
    require_active_lease(&prepared, allocator)?;
    if *current_head.head() != AuthorityHeadView::expected(&prepared) {
        return Err(NormalCommitOrchestrationError::AuthorityHeadChangedBeforeSeal);
    }
    SealedAuthorityManifest::verify_and_seal(prepared, observation)
        .map_err(Into::into)
}

/// Classify a real authority-head CAS without allowing the caller to mint a
/// COMMITTED manifest from arbitrary current state.
pub fn classify_normal_head_publish<Hash: Q256BitHash>(
    publish: SealedNormalHeadPublish<Hash>,
    outcome: AuthorityLocalHeadWriteOutcome<Hash>,
    allocator: ObservedAuthorityTimestampState,
) -> Result<NormalHeadPublishProgress<Hash>, NormalCommitOrchestrationError> {
    require_active_lease(publish.manifest.prepared(), allocator)?;
    let (applied, current_head) = match outcome {
        AuthorityLocalHeadWriteOutcome::Applied(current) => {
            if current != *publish.head_cas.candidate() {
                return Err(NormalCommitOrchestrationError::HeadCasOutcomeMismatch);
            }
            (true, *current.head())
        }
        AuthorityLocalHeadWriteOutcome::Idempotent(current) => {
            if current != *publish.head_cas.candidate() {
                return Err(NormalCommitOrchestrationError::HeadCasOutcomeMismatch);
            }
            (false, *current.head())
        }
        AuthorityLocalHeadWriteOutcome::Conflict(current) => {
            if current != *publish.head_cas.expected() {
                return Err(NormalCommitOrchestrationError::AuthorityHeadConflict);
            }
            (false, *current.head())
        }
    };
    match publish.manifest.classify_head_cas(applied, current_head)? {
        AuthorityHeadPublishDecision::Published(receipt)
        | AuthorityHeadPublishDecision::Idempotent(receipt) => {
            Ok(NormalHeadPublishProgress::PersistCommitted {
                committed: publish.manifest.mark_committed(receipt)?,
            })
        }
        AuthorityHeadPublishDecision::RetryExactSealedIntent => {
            Ok(NormalHeadPublishProgress::RetryExactSealedIntent)
        }
        AuthorityHeadPublishDecision::Conflict { .. } => {
            Err(NormalCommitOrchestrationError::AuthorityHeadConflict)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactAllocatorObservation {
    Active(AuthorityTimestampLease),
    Completed,
}

fn require_active_lease<Hash: Q256BitHash>(
    prepared: &PreparedAuthorityManifestRecord<Hash>,
    allocator: ObservedAuthorityTimestampState,
) -> Result<AuthorityTimestampLease, NormalCommitOrchestrationError> {
    match observe_allocator(prepared, allocator)? {
        ExactAllocatorObservation::Active(lease) => Ok(lease),
        ExactAllocatorObservation::Completed => {
            Err(NormalCommitOrchestrationError::AllocatorCompletedBeforeManifest)
        }
    }
}

fn observe_allocator<Hash: Q256BitHash>(
    prepared: &PreparedAuthorityManifestRecord<Hash>,
    allocator: ObservedAuthorityTimestampState,
) -> Result<ExactAllocatorObservation, NormalCommitOrchestrationError> {
    let key = prepared.identity().timestamp_key();
    if allocator.key() != key {
        return Err(NormalCommitOrchestrationError::AllocatorKeyMismatch);
    }
    let intent = prepared.intent().digest();
    match allocator.observe_intent(intent) {
        AuthorityIntentObservation::Active(lease) => {
            if lease.active_revision() != prepared.allocator_active_revision()
                || lease.timestamp() != prepared.commit_write_timestamp()
            {
                Err(NormalCommitOrchestrationError::AllocatorCoordinatesMismatch)
            } else {
                Ok(ExactAllocatorObservation::Active(lease))
            }
        }
        AuthorityIntentObservation::Completed {
            timestamp,
            revision,
        } => {
            let expected_revision = prepared
                .allocator_active_revision()
                .checked_next()?;
            if timestamp != prepared.commit_write_timestamp()
                || revision != expected_revision
            {
                Err(NormalCommitOrchestrationError::AllocatorCoordinatesMismatch)
            } else {
                Ok(ExactAllocatorObservation::Completed)
            }
        }
        AuthorityIntentObservation::BlockedByActive { .. } => {
            Err(NormalCommitOrchestrationError::AllocatorOwnedByOtherIntent)
        }
        AuthorityIntentObservation::Idle { .. } => {
            Err(NormalCommitOrchestrationError::AllocatorDoesNotOwnIntent)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalCommitOrchestrationError {
    ManifestLifecycle(ManifestLifecycleError),
    AuthorityCommit(AuthorityCommitModelError),
    AuthorityLocalHead(AuthorityLocalHeadModelError),
    PreparedHeadIsNotExpected,
    AuthorityHeadChangedBeforeSeal,
    AuthorityHeadConflict,
    HeadCasOutcomeMismatch,
    AllocatorOwnedByOtherIntent,
    AllocatorDoesNotOwnIntent,
    AllocatorKeyMismatch,
    AllocatorCoordinatesMismatch,
    AllocatorCompletedBeforeManifest,
}

impl From<ManifestLifecycleError> for NormalCommitOrchestrationError {
    fn from(value: ManifestLifecycleError) -> Self {
        Self::ManifestLifecycle(value)
    }
}

impl From<AuthorityCommitModelError> for NormalCommitOrchestrationError {
    fn from(value: AuthorityCommitModelError) -> Self {
        Self::AuthorityCommit(value)
    }
}

impl From<AuthorityLocalHeadModelError> for NormalCommitOrchestrationError {
    fn from(value: AuthorityLocalHeadModelError) -> Self {
        Self::AuthorityLocalHead(value)
    }
}

impl fmt::Display for NormalCommitOrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NormalCommitOrchestrationError {}
