//! Storage-owned durable capture authority for one Realm Processor iteration.
//!
//! This is intentionally isolated from the legacy authority path.  It composes
//! the already-qualified assignment, stream binding, consumer gate, artifact
//! store and explicit-ACK transport behind the high-level core port.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        realm_processor_actor_input::RealmProcessorActorInputDigest,
        realm_processor_durable_capture::{
            RealmProcessorApplicationHandoffObservation,
            RealmProcessorDurableCaptureError,
            RealmProcessorDurableCaptureFactory,
            RealmProcessorDurableCaptureOutcome,
            RealmProcessorDurableCapturePort,
            RealmProcessorDurableCapturedBatch,
            RealmProcessorDurableCapturedGeneration,
            RealmProcessorDurableCapturedItem,
            RealmProcessorExternalDependencyLoader,
            SealedRealmProcessorDurableCaptureRequest,
            SealedRealmProcessorGenerationContinuationRequest,
        },
        realm_processor_deferred_actor_input::{
            RealmProcessorDeferredActorInput,
            RealmProcessorDeferredActorInputOutcome,
            RealmProcessorDeferredActorInputSource,
        },
        realm_processor_external_dependency_input::{
            RealmProcessorExternalDependencyCommitment,
            RealmProcessorQualifiedExternalActorInput,
        },
        realm_processor_continuation_restart::{
            RealmProcessorContinuationRestartFactory,
            RealmProcessorContinuationRestartPort,
            RealmProcessorInboundCarryoverObservation,
            RealmProcessorReadOnlyRestartPreparation,
            RealmProcessorTerminalCarryoverRecoveryFactory,
            RealmProcessorTerminalCarryoverRecoveryOutcome,
            RealmProcessorTerminalCarryoverRecoveryPort,
            RealmProcessorTerminalCarryoverObservation,
            SealedRealmProcessorContinuationRestartRequest,
            SealedRealmProcessorTerminalCarryoverRecoveryRequest,
        },
        realm_processor_application_archive::RealmProcessorApplicationArchivePlan,
        realm_processor_generation_continuation::{
            RealmProcessorApplicationContinuation, RealmProcessorGenerationContinuation,
            RealmProcessorGenerationContinuationPhase,
        },
        realm_processor_semantic_output::RealmProcessorSemanticOutput,
        realm_processor_generation_terminal::{
            RealmProcessorDeferredCarryoverSource,
            RealmProcessorGenerationTerminalKind,
        },
        realm_processor_narrow_writer::{
            RealmProcessorNarrowWriterError, RealmProcessorNarrowWriterObservation,
            SealedRealmProcessorNarrowWriterRequest,
        },
        recoverable_artifact::{
            PendingQueueArtifactOwnerAttemptId,
            PendingQueueArtifactOwnerReasonDigest,
        },
        recoverable_ephemeral::{
            PendingQueueArtifactIdentity, PendingQueueBoundaryObservation,
            PendingQueueCaptureCandidate, PendingQueueCaptureContext,
            PendingQueueGenerationBoundary,
            PendingQueueSourceCursorView,
        },
    },
    store::pending_generation_pipeline::{
        PendingPipelineReadState, PendingPipelineWriteOutcome,
        PendingProcessingState, StoredPendingPipeline,
    },
    store::pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    store::branch_exact_dual_write::BranchExactDualWriteIntent,
    store::branch_pending_mapping::BranchPendingMapping,
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment, PendingQueueSegmentLedgerKey,
    },
    recoverable_publish::{
        PendingQueueEnvelopeBody, PendingQueuePublishEnvelope,
        PendingQueuePublisherKind, RecoverableNatsSourceRoute,
    },
    recoverable_transport::{
        RecoverableNatsCaptureSpec,
        RecoverableNatsConsumerProvisioningOperationId,
    },
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

#[cfg(all(test, feature = "rf3-test-support"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(test, feature = "rf3-test-support"))]
use tokio::sync::Notify;

#[cfg(all(test, feature = "rf3-test-support"))]
static QUALIFICATION_PAUSE_AFTER_RECOVERY_SNAPSHOT_A: AtomicBool =
    AtomicBool::new(false);
#[cfg(all(test, feature = "rf3-test-support"))]
static QUALIFICATION_RECOVERY_SNAPSHOT_A_REACHED: Notify = Notify::const_new();
#[cfg(all(test, feature = "rf3-test-support"))]
static QUALIFICATION_RECOVERY_SNAPSHOT_A_RELEASED: Notify = Notify::const_new();
#[cfg(all(test, feature = "rf3-test-support"))]
static QUALIFICATION_FAIL_AFTER_CARRYOVER_PERSIST: AtomicBool =
    AtomicBool::new(false);

/// Qualification-only deterministic pause used by the RF=3 harness. Release
/// builds expose no hook and no way to inject a caller-selected mutation.
#[cfg(all(test, feature = "rf3-test-support"))]
pub(super) fn qualification_pause_after_recovery_snapshot_a_once() {
    QUALIFICATION_PAUSE_AFTER_RECOVERY_SNAPSHOT_A.store(true, Ordering::SeqCst);
}

#[cfg(all(test, feature = "rf3-test-support"))]
pub(super) async fn qualification_wait_for_recovery_snapshot_a() {
    QUALIFICATION_RECOVERY_SNAPSHOT_A_REACHED.notified().await;
}

#[cfg(all(test, feature = "rf3-test-support"))]
pub(super) fn qualification_release_recovery_snapshot_a() {
    QUALIFICATION_RECOVERY_SNAPSHOT_A_RELEASED.notify_one();
}

/// Inject a process/caller failure after the real carryover LWT path returns.
/// This is deliberately not described as a socket-level response loss.
#[cfg(all(test, feature = "rf3-test-support"))]
pub(super) fn qualification_fail_after_carryover_persist_once() {
    QUALIFICATION_FAIL_AFTER_CARRYOVER_PERSIST.store(true, Ordering::SeqCst);
}

#[cfg(all(test, feature = "rf3-test-support"))]
async fn qualification_pause_after_snapshot_a_if_armed() {
    if QUALIFICATION_PAUSE_AFTER_RECOVERY_SNAPSHOT_A.swap(false, Ordering::SeqCst) {
        QUALIFICATION_RECOVERY_SNAPSHOT_A_REACHED.notify_one();
        QUALIFICATION_RECOVERY_SNAPSHOT_A_RELEASED.notified().await;
    }
}

use super::{
    BranchExactWriterState, ScyllaBranchExactWriterRuntime,
    PendingQueueArtifactStoreError, PendingQueueSidecarReady,
    ScyllaPendingPipelineStore, ScyllaPendingQueueArtifactStore,
    ScyllaPendingQueueSegmentLedgerStore,
};
use super::branch_exact_pending_orchestration::seal_branch_exact_begin;
use super::pending_queue_consumer_gate::{
    PendingQueueConsumerGateError, PendingQueueConsumerGateIdentity,
    ScyllaPendingQueueConsumerGateStore,
};
use super::pending_queue_nats_capture::{
    PendingQueueNatsCaptureOutcome, ScyllaBackedRecoverableNatsSource,
};
use super::pending_queue_stream_provision::ScyllaPendingQueueStreamProvisionStore;
use super::pending_queue_stream_provision::AssignmentBoundRecoverablePendingQueuePublisher;
use super::pending_queue_publish_store::{
    ScyllaPendingQueuePublishStore, ScyllaPendingQueuePublishStoreFactory,
};
use super::pending_queue_semantic_aggregate::{
    PersistedPendingQueueSemanticGenerationReceipt,
    ScyllaPendingQueueSemanticAggregateStore,
    StoredPendingQueueSemanticGeneration,
};
use super::pending_queue_semantic_terminal::verify_semantic_source_terminal;
use super::realm_processor_application_archive::{
    PersistedRealmProcessorApplicationHandoffReceipt,
    PersistedRealmProcessorApplicationArchiveReceipt,
    ScyllaRealmProcessorApplicationArchiveStore,
};
use super::realm_processor_deferred_carryover::ScyllaRealmProcessorDeferredCarryoverStore;
use super::realm_processor_generation_terminal::ScyllaRealmProcessorGenerationTerminalStore;

const OWNER_ATTEMPT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-owner-attempt/v1";
const OWNER_REASON_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-owner-reason/v1";
const CONSUMER_OPERATION_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-consumer-operation/v1";
const CAPTURE_BATCH_LIMIT: usize = 1024;

/// Prepared high-level factory.  It is bound to one exact Realm, writer
/// activation, verified sidecar schema and NATS base namespace.
pub(crate) struct ScyllaRealmProcessorDurableCaptureFactory<Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    nats: Arc<NatsJetStreamClient>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    provision: Arc<ScyllaPendingQueueStreamProvisionStore>,
    artifact: Arc<ScyllaPendingQueueArtifactStore>,
    consumer_gate: Arc<ScyllaPendingQueueConsumerGateStore>,
    publish_factory: Arc<ScyllaPendingQueuePublishStoreFactory>,
    transport_archive: Arc<ScyllaPendingQueueSemanticAggregateStore>,
    application_archive: Arc<ScyllaRealmProcessorApplicationArchiveStore>,
    generation_terminal: Arc<ScyllaRealmProcessorGenerationTerminalStore>,
    deferred_carryover: Arc<ScyllaRealmProcessorDeferredCarryoverStore>,
    external_dependency_loader: Arc<dyn RealmProcessorExternalDependencyLoader>,
    _hash: PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaRealmProcessorDurableCaptureFactory<Hash> {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        writer_activation_digest: [u8; 32],
        ready: &PendingQueueSidecarReady,
        nats: Arc<NatsJetStreamClient>,
        external_dependency_loader: Arc<dyn RealmProcessorExternalDependencyLoader>,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if ready.view().authority() != authority
            || writer_activation_digest == [0; 32]
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let keyspaces = ready.view().verified().stored().keyspaces();
        let control = keyspaces.control().clone();
        let ledger = Arc::new(
            ScyllaPendingQueueSegmentLedgerStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let provision = Arc::new(
            ScyllaPendingQueueStreamProvisionStore::prepare_authorized(
                session.clone(),
                ready,
                ledger.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let pipeline = Arc::new(
            ScyllaPendingPipelineStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let consumer_gate = Arc::new(
            ScyllaPendingQueueConsumerGateStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let artifact = Arc::new(
            ScyllaPendingQueueArtifactStore::prepare(
                session.clone(),
                keyspaces.artifact_keyspaces().map_err(backend)?,
            )
            .await
            .map_err(backend)?,
        );
        let publish_factory = ScyllaPendingQueuePublishStore::prepare_factory(
            session.clone(),
            keyspaces.publish_keyspaces().map_err(backend)?,
        )
        .await
        .map_err(backend)?;
        let transport_archive = Arc::new(
            ScyllaPendingQueueSemanticAggregateStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let application_archive = Arc::new(
            ScyllaRealmProcessorApplicationArchiveStore::prepare(
                session.clone(),
                control.clone(),
                keyspaces.application_data_keyspace().map_err(backend)?,
            )
            .await
            .map_err(backend)?,
        );
        let generation_terminal = Arc::new(
            ScyllaRealmProcessorGenerationTerminalStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let deferred_carryover = Arc::new(
            ScyllaRealmProcessorDeferredCarryoverStore::prepare(session, control)
                .await
                .map_err(backend)?,
        );
        Ok(Self {
            network,
            authority,
            writer_activation_digest,
            queue_readiness_digest: *ready.view().ready_digest(),
            nats,
            pipeline,
            ledger,
            provision,
            artifact,
            consumer_gate,
            publish_factory,
            transport_archive,
            application_archive,
            generation_terminal,
            deferred_carryover,
            external_dependency_loader,
            _hash: PhantomData,
        })
    }

    async fn observe_generation_continuation_exact(
        &self,
    ) -> Result<
        ScyllaRealmProcessorExactContinuation<Hash>,
        RealmProcessorDurableCaptureError,
    > {
        let key = PendingGenerationLedgerKey::new(self.network, self.authority);
        let PendingPipelineReadState::Current(pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(backend)?
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if pipeline.activation_digest().as_bytes() != &self.writer_activation_digest
            || pipeline.blocked_reason().is_some()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let phase = match pipeline.processing_state() {
            PendingProcessingState::Baseline(_) => {
                RealmProcessorGenerationContinuationPhase::AwaitPrimeOrRotate
            }
            PendingProcessingState::Ready => {
                RealmProcessorGenerationContinuationPhase::AwaitQueueClose
            }
            PendingProcessingState::Sealing(_) => {
                RealmProcessorGenerationContinuationPhase::CaptureClosedSource
            }
            PendingProcessingState::WorkCaptured(_)
            | PendingProcessingState::InFlight { .. }
            | PendingProcessingState::EmptyQueueSealed(_)
            | PendingProcessingState::RetiredNoWork { .. }
            | PendingProcessingState::Published { .. } => {
                let context = PendingQueueCaptureContext::try_new(
                    pipeline.key(),
                    pipeline.activation_digest(),
                    pipeline.processing(),
                )
                .map_err(backend)?;
                let ledger_key = PendingQueueSegmentLedgerKey::try_new(
                    pipeline.key(),
                    self.nats.base_namespace(),
                )
                .map_err(backend)?;
                let route = self
                    .ledger
                    .read_assignment_route_exact(&ledger_key, context)
                    .await
                    .map_err(backend)?;
                self.ledger
                    .revalidate_assignment_route(&route)
                    .await
                    .map_err(backend)?;
                let (first, archive, first_pipeline) = self
                    .application_archive
                    .observe_generation_continuation::<Hash>(
                        &self.pipeline,
                        route.assignment(),
                    )
                    .await
                    .map_err(backend)?;
                self.transport_archive
                    .revalidate_realm_application_header(
                        route.assignment(),
                        archive.header(),
                    )
                    .await
                    .map_err(backend)?;
                self.ledger
                    .revalidate_assignment_route(&route)
                    .await
                    .map_err(backend)?;
                let (second, second_archive, second_pipeline) = self
                    .application_archive
                    .observe_generation_continuation::<Hash>(
                        &self.pipeline,
                        route.assignment(),
                    )
                    .await
                    .map_err(backend)?;
                self.transport_archive
                    .revalidate_realm_application_header(
                        route.assignment(),
                        second_archive.header(),
                    )
                    .await
                    .map_err(backend)?;
                self.ledger
                    .revalidate_assignment_route(&route)
                    .await
                    .map_err(backend)?;
                if first != second
                    || pipeline.revision() != first_pipeline.revision()
                    || first_pipeline.revision() != second_pipeline.revision()
                    || pipeline.canonical_payload() != first_pipeline.canonical_payload()
                    || first_pipeline.canonical_payload()
                        != second_pipeline.canonical_payload()
                {
                    return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
                }
                return Ok(ScyllaRealmProcessorExactContinuation {
                    continuation: first,
                    pipeline: second_pipeline,
                });
            }
        };
        let continuation = RealmProcessorGenerationContinuation::try_from_storage(
            pipeline.processing(),
            pipeline.revision(),
            phase,
            None,
        )
        .map_err(backend)?;
        let PendingPipelineReadState::Current(second_pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(backend)?
        else {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        };
        if !same_pipeline_snapshot(&pipeline, &second_pipeline) {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(ScyllaRealmProcessorExactContinuation {
            continuation,
            pipeline: second_pipeline,
        })
    }

    pub(super) async fn prepare_narrow_writer(
        &self,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        request: SealedRealmProcessorNarrowWriterRequest<Hash>,
    ) -> Result<RealmProcessorNarrowWriterObservation, RealmProcessorNarrowWriterError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        };
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
            || writer.network() != self.network
            || writer.authority() != self.authority
            || writer.activation_digest().as_bytes() != &self.writer_activation_digest
        {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        }

        let first = self
            .observe_generation_continuation_exact()
            .await
            .map_err(narrow_capture)?;
        if first.continuation.phase()
            != RealmProcessorGenerationContinuationPhase::AwaitWriter
            || first.continuation.application() != Some(request.application())
        {
            return Err(RealmProcessorNarrowWriterError::IdentityMismatch);
        }

        let writer_before = writer.read_writer().await.map_err(narrow_writer)?;
        let predecessor = match writer_before.state() {
            BranchExactWriterState::Active(active) => *active.watermark(),
            BranchExactWriterState::WritePrepared(prepared) => {
                *prepared.intent().predecessor()
            }
            BranchExactWriterState::WritesVerified(verified) => {
                *verified.prepared().intent().predecessor()
            }
            BranchExactWriterState::ActivationPrepared
            | BranchExactWriterState::Blocked(_) => {
                return Err(RealmProcessorNarrowWriterError::Writer(
                    "writer is not active/prepared/verified".to_owned(),
                ))
            }
        };
        let processing = first.pipeline.processing();
        let candidate = BranchPendingMapping::new(
            *request.candidate(),
            processing.pending_id(),
        );
        let intent = BranchExactDualWriteIntent::try_realm(
            self.authority,
            predecessor,
            candidate,
            processing.proc_checkpoint_id(),
            request.reward_proof(),
        )
        .map_err(narrow_writer)?;
        let intent_digest = *intent.intent_digest().as_bytes();
        let barrier = writer
            .prepare_and_verify(intent, request.clock_sample())
            .await
            .map_err(narrow_writer)?;
        writer
            .require_fresh_barrier(&barrier)
            .await
            .map_err(narrow_writer)?;

        let fresh = self
            .observe_generation_continuation_exact()
            .await
            .map_err(narrow_capture)?;
        if fresh.continuation != first.continuation
            || !same_pipeline_snapshot(&fresh.pipeline, &first.pipeline)
        {
            return Err(RealmProcessorNarrowWriterError::ConcurrentMutation);
        }
        let verified = writer.read_writer().await.map_err(narrow_writer)?;
        let transition = seal_branch_exact_begin(&fresh.pipeline, &verified)
            .map_err(narrow_pipeline)?;
        match self
            .pipeline
            .apply(&transition)
            .await
            .map_err(narrow_pipeline)?
        {
            PendingPipelineWriteOutcome::Applied(_)
            | PendingPipelineWriteOutcome::Idempotent(_) => {}
            PendingPipelineWriteOutcome::Conflict(_) => {
                return Err(RealmProcessorNarrowWriterError::Pipeline(
                    "pipeline begin transition conflicted".to_owned(),
                ))
            }
        }

        writer
            .require_fresh_barrier(&barrier)
            .await
            .map_err(narrow_writer)?;
        let final_observation = self
            .observe_generation_continuation_exact()
            .await
            .map_err(narrow_capture)?;
        if final_observation.continuation.phase()
            != RealmProcessorGenerationContinuationPhase::AwaitWriterCompletion
            || final_observation.continuation.application() != Some(request.application())
            || final_observation.pipeline.processing() != processing
        {
            return Err(RealmProcessorNarrowWriterError::ConcurrentMutation);
        }
        RealmProcessorNarrowWriterObservation::try_from_storage(
            processing,
            request.application(),
            final_observation.pipeline.revision(),
            barrier.writer_revision().get(),
            intent_digest,
        )
    }

    fn validate_generation_request(
        &self,
        request: &SealedRealmProcessorGenerationContinuationRequest,
    ) -> Result<(), RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        Ok(())
    }

    async fn observe_deferred_actor_input_snapshot(
        &self,
    ) -> Result<ScyllaRealmProcessorDeferredActorInputSnapshot<Hash>, RealmProcessorDurableCaptureError>
    {
        let exact = self.observe_generation_continuation_exact().await?;
        if exact.continuation.phase()
            != RealmProcessorGenerationContinuationPhase::CaptureClosedSource
        {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        }
        let pipeline = exact.pipeline;
        let selected = self
            .deferred_carryover
            .observe_for_restart(
                pipeline.key(),
                pipeline.activation_digest(),
                pipeline.processing(),
            )
            .await
            .map_err(backend)?;

        let outcome = match selected {
            None => RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover {
                continuation: exact.continuation,
            },
            Some(carryover) => {
                if carryover.key() != pipeline.key()
                    || carryover.activation_digest() != pipeline.activation_digest()
                    || carryover.successor() != pipeline.processing()
                {
                    return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                }
                match carryover.source() {
                    RealmProcessorDeferredCarryoverSource::BootstrapEmpty { reason } => {
                        if reason != pipeline.bootstrap_reason() {
                            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                        }
                        RealmProcessorDeferredActorInputOutcome::Ready(
                            RealmProcessorDeferredActorInput::try_from_storage(
                                pipeline.processing(),
                                pipeline.bootstrap_reason(),
                                carryover,
                                None,
                            )
                            .map_err(backend)?,
                        )
                    }
                    RealmProcessorDeferredCarryoverSource::Predecessor {
                        predecessor,
                        terminal_slot,
                        terminal_store_fingerprint,
                        terminal_digest,
                        rotation_intent_digest,
                        assignment_digest,
                        application_store_fingerprint,
                        application,
                    } => {
                        let terminal = self
                            .generation_terminal
                            .observe_for_restart::<Hash>(
                                pipeline.key(),
                                pipeline.activation_digest(),
                                predecessor,
                            )
                            .await
                            .map_err(backend)?
                            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
                        let PendingProcessingState::Sealing(close) =
                            pipeline.processing_state()
                        else {
                            return Err(
                                RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing,
                            );
                        };
                        let expected_current = terminal
                            .candidate_pipeline()
                            .seal_begin_queue_close(close)
                            .map_err(backend)?;
                        if terminal.key() != pipeline.key()
                            || terminal.activation_digest() != pipeline.activation_digest()
                            || terminal.source() != predecessor
                            || terminal.successor() != pipeline.processing()
                            || terminal.slot() != terminal_slot
                            || self.generation_terminal.restart_fingerprint()
                                != terminal_store_fingerprint
                            || terminal.digest() != terminal_digest
                            || terminal.rotation_intent_digest() != rotation_intent_digest
                            || terminal.assignment_digest() != &assignment_digest
                            || terminal.application_store_fingerprint()
                                != &application_store_fingerprint
                            || terminal.application() != application
                            || expected_current.candidate() != &pipeline
                        {
                            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                        }
                        let mut hasher = Sha256::new();
                        let archive = self
                            .validate_application_source(
                                pipeline.key(),
                                pipeline.activation_digest(),
                                predecessor,
                                application,
                                assignment_digest,
                                application_store_fingerprint,
                                &mut hasher,
                            )
                            .await?;
                        let terminal_after = self
                            .generation_terminal
                            .observe_for_restart::<Hash>(
                                pipeline.key(),
                                pipeline.activation_digest(),
                                predecessor,
                            )
                            .await
                            .map_err(backend)?
                            .ok_or(RealmProcessorDurableCaptureError::ConcurrentMutation)?;
                        if terminal_after != terminal {
                            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
                        }
                        RealmProcessorDeferredActorInputOutcome::Ready(
                            RealmProcessorDeferredActorInput::try_from_storage(
                                pipeline.processing(),
                                pipeline.bootstrap_reason(),
                                carryover,
                                Some(archive.semantic()),
                            )
                            .map_err(backend)?,
                        )
                    }
                }
            }
        };

        let carryover_after = self
            .deferred_carryover
            .observe_for_restart(
                pipeline.key(),
                pipeline.activation_digest(),
                pipeline.processing(),
            )
            .await
            .map_err(backend)?;
        if carryover_after != selected {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        let PendingPipelineReadState::Current(pipeline_after) =
            self.pipeline.read::<Hash>(pipeline.key()).await.map_err(backend)?
        else {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        };
        if !same_pipeline_snapshot(&pipeline, &pipeline_after) {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(ScyllaRealmProcessorDeferredActorInputSnapshot {
            outcome,
            pipeline: pipeline_after,
        })
    }

    async fn select_external_dependency_commitment(
        &self,
        pipeline: &StoredPendingPipeline<Hash>,
        input: &RealmProcessorDeferredActorInput,
    ) -> Result<Option<RealmProcessorExternalDependencyCommitment>, RealmProcessorDurableCaptureError>
    {
        let RealmProcessorDeferredActorInputSource::Predecessor {
            predecessor,
            terminal_digest,
            ..
        } = input.source()
        else {
            // Bootstrap generations require their own explicit dependency
            // commitment. Until that record is added they remain fail-closed
            // at the external-input qualification boundary.
            return Ok(None);
        };
        let terminal = self
            .generation_terminal
            .observe_for_restart::<Hash>(
                pipeline.key(),
                pipeline.activation_digest(),
                predecessor,
            )
            .await
            .map_err(backend)?
            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
        if terminal.digest() != terminal_digest
            || terminal.successor() != input.successor()
            || pipeline.processing() != input.successor()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let envelope = terminal
            .terminal_authorization_envelope()
            .map_err(backend)?;
        Ok(Some(envelope.external_dependency()))
    }

    fn validate_restart_identity(
        &self,
        request: &SealedRealmProcessorContinuationRestartRequest,
    ) -> Result<(), RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        Ok(())
    }

    fn validate_terminal_carryover_recovery_identity(
        &self,
        request: &SealedRealmProcessorTerminalCarryoverRecoveryRequest,
    ) -> Result<(), RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        Ok(())
    }

    async fn observe_restart_snapshot(
        &self,
    ) -> Result<ScyllaRealmProcessorRestartSnapshot, RealmProcessorDurableCaptureError> {
        let exact = self.observe_generation_continuation_exact().await?;
        let continuation = exact.continuation;
        let key = PendingGenerationLedgerKey::new(self.network, self.authority);
        let pipeline = exact.pipeline;
        if pipeline.processing() != continuation.processing()
            || pipeline.revision() != continuation.pipeline_revision()
            || pipeline.activation_digest().as_bytes() != &self.writer_activation_digest
            || pipeline.blocked_reason().is_some()
        {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"psy/rollback/realm-processor-restart-snapshot/v1");
        hash_pipeline(&mut hasher, &pipeline);

        let inbound = match self
            .deferred_carryover
            .observe_for_restart(key, pipeline.activation_digest(), pipeline.processing())
            .await
            .map_err(backend)?
        {
            None => RealmProcessorInboundCarryoverObservation::Missing,
            Some(carryover) => {
                hasher.update(carryover.to_canonical_bytes());
                match carryover.source() {
                    RealmProcessorDeferredCarryoverSource::BootstrapEmpty { .. } => {
                        if carryover.key() != key
                            || carryover.activation_digest() != pipeline.activation_digest()
                            || carryover.successor() != pipeline.processing()
                            || carryover.deferred_count() != 0
                        {
                            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                        }
                        RealmProcessorInboundCarryoverObservation::Bootstrap
                    }
                    RealmProcessorDeferredCarryoverSource::Predecessor {
                        predecessor,
                        terminal_slot,
                        terminal_store_fingerprint,
                        terminal_digest,
                        rotation_intent_digest,
                        assignment_digest,
                        application_store_fingerprint,
                        application,
                    } => {
                        let terminal = self
                            .generation_terminal
                            .observe_for_restart::<Hash>(
                                key,
                                pipeline.activation_digest(),
                                predecessor,
                            )
                            .await
                            .map_err(backend)?
                            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
                        if terminal_store_fingerprint
                            != self.generation_terminal.restart_fingerprint()
                            || terminal.slot() != terminal_slot
                            || terminal.digest() != terminal_digest
                            || terminal.rotation_intent_digest() != rotation_intent_digest
                            || terminal.assignment_digest() != &assignment_digest
                            || terminal.application_store_fingerprint()
                                != &application_store_fingerprint
                            || terminal.application() != application
                            || terminal.source() != predecessor
                            || terminal.successor() != pipeline.processing()
                            || terminal.candidate_pipeline().key() != pipeline.key()
                            || terminal.candidate_pipeline().activation_digest()
                                != pipeline.activation_digest()
                            || terminal.candidate_pipeline().processing()
                                != pipeline.processing()
                            || terminal.candidate_pipeline().gathering()
                                != pipeline.gathering()
                            || pipeline.revision().get()
                                < terminal.candidate_pipeline().revision().get()
                            || carryover.deferred_count() != application.deferred_count()
                            || carryover.deferred_digest() != application.deferred_digest()
                        {
                            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                        }
                        hasher.update(terminal.to_canonical_bytes());
                        self.validate_application_source(
                            key,
                            pipeline.activation_digest(),
                            predecessor,
                            application,
                            assignment_digest,
                            application_store_fingerprint,
                            &mut hasher,
                        )
                        .await?;
                        RealmProcessorInboundCarryoverObservation::Predecessor
                    }
                }
            }
        };

        let (terminal, stable_source_digest) = if inbound
            == RealmProcessorInboundCarryoverObservation::Missing
        {
            if self
                .generation_terminal
                .observe_for_restart::<Hash>(
                    pipeline.key(),
                    pipeline.activation_digest(),
                    pipeline.processing(),
                )
                .await
                .map_err(backend)?
                .is_some()
                || self
                    .deferred_carryover
                    .observe_for_restart(
                        pipeline.key(),
                        pipeline.activation_digest(),
                        pipeline.gathering(),
                    )
                    .await
                    .map_err(backend)?
                    .is_some()
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            (
                RealmProcessorTerminalCarryoverObservation::NotEvaluated,
                cloned_digest(&hasher),
            )
        } else {
            let outbound = self
                .observe_outbound_terminal(&pipeline, continuation, &mut hasher)
                .await?;
            (outbound.status, outbound.stable_source_digest)
        };
        let preparation = RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation,
            inbound,
            terminal,
        )
        .map_err(backend)?;

        let PendingPipelineReadState::Current(second_pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(backend)?
        else {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        };
        if !same_pipeline_snapshot(&pipeline, &second_pipeline) {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(ScyllaRealmProcessorRestartSnapshot {
            preparation,
            stable_source_digest,
            digest: hasher.finalize().into(),
            key,
            activation: pipeline.activation_digest(),
            processing: pipeline.processing(),
        })
    }

    async fn validate_application_source(
        &self,
        key: PendingGenerationLedgerKey,
        activation: psy_node_core::store::pending_generation_identity::PendingGenerationActivationDigest,
        processing: psy_node_core::store::pending_generation_identity::PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
        assignment_digest: [u8; 32],
        application_store_fingerprint: [u8; 32],
        hasher: &mut Sha256,
    ) -> Result<PersistedRealmProcessorApplicationArchiveReceipt, RealmProcessorDurableCaptureError>
    {
        if self.application_archive.restart_fingerprint().as_bytes()
            != &application_store_fingerprint
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let context = PendingQueueCaptureContext::try_new(key, activation, processing)
            .map_err(backend)?;
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            key,
            self.nats.base_namespace(),
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;
        if route.assignment().assignment().digest().as_bytes() != &assignment_digest {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let archive = self
            .application_archive
            .read_selected(application.archive_slot())
            .await
            .map_err(backend)?
            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
        let observed = RealmProcessorApplicationContinuation::try_from_storage(
            archive.header().slot(),
            archive.header().digest(),
            archive.semantic(),
        )
        .map_err(backend)?;
        if observed != application {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        self.transport_archive
            .revalidate_realm_application_header(route.assignment(), archive.header())
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;
        hasher.update(route.assignment().assignment().to_canonical_bytes());
        hasher.update(archive.header().to_canonical_bytes());
        hasher.update(archive.semantic().to_canonical_bytes());
        Ok(archive)
    }

    async fn observe_outbound_terminal(
        &self,
        pipeline: &StoredPendingPipeline<Hash>,
        continuation: RealmProcessorGenerationContinuation,
        hasher: &mut Sha256,
    ) -> Result<ScyllaRealmProcessorOutboundObservation, RealmProcessorDurableCaptureError> {
        let terminal_phase = matches!(
            continuation.phase(),
            RealmProcessorGenerationContinuationPhase::AwaitPublishedTerminal
                | RealmProcessorGenerationContinuationPhase::AwaitRetiredNoWorkTerminal
        );
        let current = self
            .generation_terminal
            .observe_for_restart::<Hash>(
                pipeline.key(),
                pipeline.activation_digest(),
                pipeline.processing(),
            )
            .await
            .map_err(backend)?;
        if !terminal_phase {
            if current.is_some() {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            return Ok(ScyllaRealmProcessorOutboundObservation {
                status: RealmProcessorTerminalCarryoverObservation::NotTerminalPhase,
                stable_source_digest: cloned_digest(hasher),
            });
        }
        let Some(current) = current else {
            if self
                .deferred_carryover
                .observe_for_restart(
                    pipeline.key(),
                    pipeline.activation_digest(),
                    pipeline.gathering(),
                )
                .await
                .map_err(backend)?
                .is_some()
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            return Ok(ScyllaRealmProcessorOutboundObservation {
                status:
                    RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization,
                stable_source_digest: cloned_digest(hasher),
            });
        };
        let application = continuation
            .application()
            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
        let expected_kind = match continuation.phase() {
            RealmProcessorGenerationContinuationPhase::AwaitPublishedTerminal => {
                RealmProcessorGenerationTerminalKind::Published
            }
            RealmProcessorGenerationContinuationPhase::AwaitRetiredNoWorkTerminal => {
                RealmProcessorGenerationTerminalKind::RetiredNoWork
            }
            _ => return Err(RealmProcessorDurableCaptureError::IdentityMismatch),
        };
        let assignment_digest = self
            .validate_current_application_source(pipeline, application, hasher)
            .await?;
        if current.key() != pipeline.key()
            || current.activation_digest() != pipeline.activation_digest()
            || current.source() != pipeline.processing()
            || current.successor() != pipeline.gathering()
            || current.kind() != expected_kind
            || current.expected_pipeline() != pipeline
            || current.assignment_digest() != &assignment_digest
            || current.application_store_fingerprint()
                != self.application_archive.restart_fingerprint().as_bytes()
            || current.application() != application
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        hasher.update(current.to_canonical_bytes());
        let stable_source_digest = cloned_digest(hasher);
        let carryover = self
            .deferred_carryover
            .observe_for_restart(
                pipeline.key(),
                pipeline.activation_digest(),
                pipeline.gathering(),
            )
            .await
            .map_err(backend)?;
        let Some(carryover) = carryover else {
            return Ok(ScyllaRealmProcessorOutboundObservation {
                status: RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover,
                stable_source_digest,
            });
        };
        let RealmProcessorDeferredCarryoverSource::Predecessor {
            predecessor,
            terminal_slot,
            terminal_store_fingerprint,
            terminal_digest,
            rotation_intent_digest,
            assignment_digest: carryover_assignment,
            application_store_fingerprint,
            application: carryover_application,
        } = carryover.source()
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if predecessor != current.source()
            || terminal_slot != current.slot()
            || terminal_store_fingerprint != self.generation_terminal.restart_fingerprint()
            || terminal_digest != current.digest()
            || rotation_intent_digest != current.rotation_intent_digest()
            || carryover_assignment != assignment_digest
            || application_store_fingerprint
                != *self.application_archive.restart_fingerprint().as_bytes()
            || carryover_application != application
            || carryover.successor() != current.successor()
            || carryover.deferred_count() != application.deferred_count()
            || carryover.deferred_digest() != application.deferred_digest()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        hasher.update(carryover.to_canonical_bytes());
        Ok(ScyllaRealmProcessorOutboundObservation {
            status: RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
            stable_source_digest,
        })
    }

    async fn validate_current_application_source(
        &self,
        pipeline: &StoredPendingPipeline<Hash>,
        application: RealmProcessorApplicationContinuation,
        hasher: &mut Sha256,
    ) -> Result<[u8; 32], RealmProcessorDurableCaptureError> {
        let context = PendingQueueCaptureContext::try_new(
            pipeline.key(),
            pipeline.activation_digest(),
            pipeline.processing(),
        )
        .map_err(backend)?;
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            pipeline.key(),
            self.nats.base_namespace(),
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        let assignment_digest = *route.assignment().assignment().digest().as_bytes();
        self.validate_application_source(
            pipeline.key(),
            pipeline.activation_digest(),
            pipeline.processing(),
            application,
            assignment_digest,
            *self.application_archive.restart_fingerprint().as_bytes(),
            hasher,
        )
        .await?;
        Ok(assignment_digest)
    }

    async fn open_exact(
        self: &Arc<Self>,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<ScyllaRealmProcessorDurableCapture<Hash>, RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        let context = request.context();
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
            || context.key().network() != self.network
            || context.key().authority() != self.authority
            || context.activation().as_bytes() != &self.writer_activation_digest
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }

        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            context.key(),
            self.nats.base_namespace(),
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        let PendingPipelineReadState::Current(pipeline) = self
            .pipeline
            .read::<Hash>(context.key())
            .await
            .map_err(backend)?
        else {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        };
        if pipeline.activation_digest() != context.activation()
            || pipeline.processing() != context.processing()
            || pipeline.blocked_reason().is_some()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        if matches!(
            pipeline.processing_state(),
            PendingProcessingState::WorkCaptured(_)
                | PendingProcessingState::EmptyQueueSealed(_)
        ) {
            let handoff = self
                .application_archive
                .recover_handoff_from_pipeline::<Hash>(
                    &self.pipeline,
                    route.assignment(),
                )
                .await
                .map_err(backend)?;
            let archive = self
                .application_archive
                .read_selected(handoff.archive_slot())
                .await
                .map_err(backend)?
                .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)?;
            self.transport_archive
                .revalidate_realm_application_header(
                    route.assignment(),
                    archive.header(),
                )
                .await
                .map_err(backend)?;
            let second = self
                .application_archive
                .recover_handoff_from_pipeline::<Hash>(
                    &self.pipeline,
                    route.assignment(),
                )
                .await
                .map_err(backend)?;
            let semantic = archive.semantic();
            let historical_input_matches = semantic
                .legacy_deferred_input_digest()
                .is_none_or(|digest| digest == request.deferred_input().digest());
            if handoff.archive_slot() != second.archive_slot()
                || handoff.archive_digest() != second.archive_digest()
                || handoff.semantic_digest() != second.semantic_digest()
                || handoff.pipeline_revision() != second.pipeline_revision()
                || !historical_input_matches
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            let deferred_input_digest = request.deferred_input().digest();
            let deferred_input = request.into_deferred_input();
            return Ok(ScyllaRealmProcessorDurableCapture {
                factory: Arc::clone(self),
                pipeline: self.pipeline.clone(),
                transport_archive: self.transport_archive.clone(),
                application_archive: self.application_archive.clone(),
                context,
                deferred_pipeline: pipeline,
                deferred_input: Some(deferred_input),
                deferred_input_digest,
                external_dependency_commitment: None,
                actor_input_digest: semantic.actor_input_digest(),
                mode: ScyllaRealmProcessorCaptureMode::Recovered(handoff),
                _hash: PhantomData,
            });
        }
        if !matches!(pipeline.processing_state(), PendingProcessingState::Sealing(_)) {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        }
        // Fresh C: repeat the complete successor carryover/terminal/archive
        // snapshot before any consumer provisioning, owner claim, NATS or
        // actor side effect. Compare both the full typed input and the exact
        // pipeline row selected by A/B.
        let fresh = self.observe_deferred_actor_input_snapshot().await?;
        let RealmProcessorDeferredActorInputOutcome::Ready(fresh_input) = fresh.outcome else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if fresh_input != *request.deferred_input()
            || !same_pipeline_snapshot(&pipeline, &fresh.pipeline)
        {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        let external_dependency_commitment = self
            .select_external_dependency_commitment(&fresh.pipeline, &fresh_input)
            .await?;
        let close = self
            .pipeline
            .read_queue_close_exact::<Hash>(context)
            .await
            .map_err(backend)?;
        let publisher = Arc::new(
            self.provision
                .resolve_assignment_route(&self.nats, route)
                .await
                .map_err(backend)?,
        );
        let live = self
            .nats
            .observe_recoverable_segment_instance(publisher.segment().clone())
            .await
            .map_err(backend)?;
        if live.instance_id() != publisher.instance_id() {
            return Err(RealmProcessorDurableCaptureError::RuntimeCapabilityMismatch);
        }

        let source_route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::RealmUserUpdate,
            publisher.segment(),
        )
        .map_err(backend)?;
        let spec = RecoverableNatsCaptureSpec::for_segment(
            publisher.segment().clone(),
            source_route.subject(),
            CAPTURE_BATCH_LIMIT,
        )
        .map_err(backend)?;
        let gate_identity = PendingQueueConsumerGateIdentity::new(
            publisher.segment().segment_id(),
            publisher.segment().digest(),
            live.instance_id(),
        );
        let gate_open = self
            .consumer_gate
            .bootstrap_open(gate_identity)
            .await
            .map_err(backend)?;
        let consumer = match self
            .consumer_gate
            .resume_capture_consumer(
                &self.nats,
                &gate_open,
                &live,
                spec.clone(),
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(PendingQueueConsumerGateError::ProvisioningNotFound) => {
                self.consumer_gate
                    .provision_capture_consumer(
                        &self.nats,
                        &gate_open,
                        &live,
                        spec.clone(),
                        consumer_operation(&request, &spec)?,
                    )
                    .await
                    .map_err(backend)?
            }
            Err(error) => return Err(backend(error)),
        };

        let identity = PendingQueueArtifactIdentity::try_new(
            context,
            spec.source_identity().map_err(backend)?,
        )
        .map_err(backend)?;
        let attempt = owner_attempt(&request, &identity)?;
        let reason = owner_reason(&request, &identity)?;
        let owner = match self
            .artifact
            .claim_owner(&identity, attempt, reason)
            .await
        {
            Ok(owner) => owner,
            Err(PendingQueueArtifactStoreError::OwnerAlreadyHeld) => self
                .artifact
                .startup_takeover_owner(&identity, attempt, reason)
                .await
                .map_err(backend)?,
            Err(error) => return Err(backend(error)),
        };
        let source = ScyllaBackedRecoverableNatsSource::new(
            self.nats.clone(),
            self.artifact.clone(),
            self.consumer_gate.clone(),
            spec,
            consumer,
            owner,
        )
        .map_err(backend)?;
        let publish_store = Arc::new(
            ScyllaPendingQueuePublishStore::bind_assignment_transport(
                self.publish_factory.clone(),
                publisher.clone(),
            )
            .map_err(backend)?,
        );
        let deferred_input_digest = request.deferred_input().digest();
        let deferred_input = request.into_deferred_input();
        Ok(ScyllaRealmProcessorDurableCapture {
            factory: Arc::clone(self),
            pipeline: self.pipeline.clone(),
            transport_archive: self.transport_archive.clone(),
            application_archive: self.application_archive.clone(),
            context,
            deferred_pipeline: fresh.pipeline,
            deferred_input: Some(deferred_input),
            deferred_input_digest,
            external_dependency_commitment,
            actor_input_digest: None,
            mode: ScyllaRealmProcessorCaptureMode::Active {
                source,
                close,
                publisher,
                publish_store,
            },
            _hash: PhantomData,
        })
    }
}

#[async_trait]
impl<Hash> RealmProcessorDurableCaptureFactory
    for ScyllaRealmProcessorDurableCaptureFactory<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn realm_id(&self) -> u32 {
        match self.authority {
            AuthorityScope::Realm { realm_id, .. } => realm_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn realm_sub_id(&self) -> u16 {
        match self.authority {
            AuthorityScope::Realm { realm_sub_id, .. } => realm_sub_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn writer_activation_digest(&self) -> [u8; 32] {
        self.writer_activation_digest
    }

    fn queue_readiness_digest(&self) -> [u8; 32] {
        self.queue_readiness_digest
    }

    async fn observe_generation_continuation(
        &self,
        request: SealedRealmProcessorGenerationContinuationRequest,
    ) -> Result<RealmProcessorGenerationContinuation, RealmProcessorDurableCaptureError> {
        self.validate_generation_request(&request)?;
        Ok(self
            .observe_generation_continuation_exact()
            .await?
            .continuation)
    }

    async fn prepare_deferred_actor_input(
        &self,
        request: SealedRealmProcessorGenerationContinuationRequest,
    ) -> Result<RealmProcessorDeferredActorInputOutcome, RealmProcessorDurableCaptureError> {
        self.validate_generation_request(&request)?;
        let first = self.observe_deferred_actor_input_snapshot().await?;
        let second = self.observe_deferred_actor_input_snapshot().await?;
        if first.outcome != second.outcome
            || !same_pipeline_snapshot(&first.pipeline, &second.pipeline)
        {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(second.outcome)
    }

    async fn open(
        self: Arc<Self>,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError> {
        Ok(Box::new(self.open_exact(request).await?))
    }
}

#[async_trait]
impl<Hash> RealmProcessorContinuationRestartFactory<Hash>
    for ScyllaRealmProcessorDurableCaptureFactory<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn realm_id(&self) -> u32 {
        match self.authority {
            AuthorityScope::Realm { realm_id, .. } => realm_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn realm_sub_id(&self) -> u16 {
        match self.authority {
            AuthorityScope::Realm { realm_sub_id, .. } => realm_sub_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn writer_activation_digest(&self) -> [u8; 32] {
        self.writer_activation_digest
    }

    fn queue_readiness_digest(&self) -> [u8; 32] {
        self.queue_readiness_digest
    }

    async fn open(
        self: Arc<Self>,
        request: SealedRealmProcessorContinuationRestartRequest,
    ) -> Result<Box<dyn RealmProcessorContinuationRestartPort>, RealmProcessorDurableCaptureError>
    {
        self.validate_restart_identity(&request)?;
        Ok(Box::new(ScyllaRealmProcessorContinuationRestart {
            factory: self,
            request,
        }))
    }
}

#[async_trait]
impl<Hash> RealmProcessorTerminalCarryoverRecoveryFactory<Hash>
    for ScyllaRealmProcessorDurableCaptureFactory<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn realm_id(&self) -> u32 {
        match self.authority {
            AuthorityScope::Realm { realm_id, .. } => realm_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn realm_sub_id(&self) -> u16 {
        match self.authority {
            AuthorityScope::Realm { realm_sub_id, .. } => realm_sub_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn writer_activation_digest(&self) -> [u8; 32] {
        self.writer_activation_digest
    }

    fn queue_readiness_digest(&self) -> [u8; 32] {
        self.queue_readiness_digest
    }

    async fn open(
        self: Arc<Self>,
        request: SealedRealmProcessorTerminalCarryoverRecoveryRequest,
    ) -> Result<Box<dyn RealmProcessorTerminalCarryoverRecoveryPort>, RealmProcessorDurableCaptureError>
    {
        self.validate_terminal_carryover_recovery_identity(&request)?;
        Ok(Box::new(
            ScyllaRealmProcessorTerminalCarryoverRecovery {
                factory: self,
                request,
            },
        ))
    }
}

struct ScyllaRealmProcessorExactContinuation<Hash> {
    continuation: RealmProcessorGenerationContinuation,
    pipeline: StoredPendingPipeline<Hash>,
}

struct ScyllaRealmProcessorDeferredActorInputSnapshot<Hash> {
    outcome: RealmProcessorDeferredActorInputOutcome,
    pipeline: StoredPendingPipeline<Hash>,
}

struct ScyllaRealmProcessorOutboundObservation {
    status: RealmProcessorTerminalCarryoverObservation,
    stable_source_digest: [u8; 32],
}

struct ScyllaRealmProcessorRestartSnapshot {
    preparation: RealmProcessorReadOnlyRestartPreparation,
    stable_source_digest: [u8; 32],
    digest: [u8; 32],
    key: PendingGenerationLedgerKey,
    activation: PendingGenerationActivationDigest,
    processing: PendingGenerationContext,
}

struct ScyllaRealmProcessorContinuationRestart<Hash> {
    factory: Arc<ScyllaRealmProcessorDurableCaptureFactory<Hash>>,
    request: SealedRealmProcessorContinuationRestartRequest,
}

struct ScyllaRealmProcessorTerminalCarryoverRecovery<Hash> {
    factory: Arc<ScyllaRealmProcessorDurableCaptureFactory<Hash>>,
    request: SealedRealmProcessorTerminalCarryoverRecoveryRequest,
}

#[async_trait]
impl<Hash> RealmProcessorContinuationRestartPort
    for ScyllaRealmProcessorContinuationRestart<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn observe_and_prepare(
        self: Box<Self>,
    ) -> Result<RealmProcessorReadOnlyRestartPreparation, RealmProcessorDurableCaptureError>
    {
        self.factory.validate_restart_identity(&self.request)?;
        let first = self.factory.observe_restart_snapshot().await?;
        let second = self.factory.observe_restart_snapshot().await?;
        if first.preparation != second.preparation || first.digest != second.digest {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(first.preparation)
    }
}

#[async_trait]
impl<Hash> RealmProcessorTerminalCarryoverRecoveryPort
    for ScyllaRealmProcessorTerminalCarryoverRecovery<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn recover_and_prepare(
        self: Box<Self>,
    ) -> Result<RealmProcessorTerminalCarryoverRecoveryOutcome, RealmProcessorDurableCaptureError>
    {
        self.factory
            .validate_terminal_carryover_recovery_identity(&self.request)?;
        let first = self.factory.observe_restart_snapshot().await?;
        #[cfg(all(test, feature = "rf3-test-support"))]
        qualification_pause_after_snapshot_a_if_armed().await;
        let repairs_carryover = matches!(
            first.preparation.terminal(),
            RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover
        );
        if repairs_carryover {
            self.factory
                .deferred_carryover
                .persist_from_selected_terminal::<Hash>(
                    self.factory.generation_terminal.as_ref(),
                    first.key,
                    first.activation,
                    first.processing,
                )
                .await
                .map_err(backend)?;
            #[cfg(all(test, feature = "rf3-test-support"))]
            if QUALIFICATION_FAIL_AFTER_CARRYOVER_PERSIST.swap(false, Ordering::SeqCst) {
                return Err(RealmProcessorDurableCaptureError::Backend(
                    "qualification-only failure after carryover persist".to_owned(),
                ));
            }
        }

        let second = self.factory.observe_restart_snapshot().await?;
        let third = self.factory.observe_restart_snapshot().await?;
        finish_terminal_carryover_recovery(&first, &second, &third, repairs_carryover)
    }
}

fn finish_terminal_carryover_recovery(
    first: &ScyllaRealmProcessorRestartSnapshot,
    second: &ScyllaRealmProcessorRestartSnapshot,
    third: &ScyllaRealmProcessorRestartSnapshot,
    repairs_carryover: bool,
) -> Result<RealmProcessorTerminalCarryoverRecoveryOutcome, RealmProcessorDurableCaptureError> {
    if first.key != second.key
        || second.key != third.key
        || first.activation != second.activation
        || second.activation != third.activation
        || first.processing != second.processing
        || second.processing != third.processing
    {
        return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
    }
    if repairs_carryover {
        if first.stable_source_digest != second.stable_source_digest
            || second.stable_source_digest != third.stable_source_digest
            || second.preparation != third.preparation
            || second.digest != third.digest
            || !matches!(
                second.preparation.terminal(),
                RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved
            )
        {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
    } else if first.preparation != second.preparation
        || second.preparation != third.preparation
        || first.digest != second.digest
        || second.digest != third.digest
        || first.stable_source_digest != second.stable_source_digest
        || second.stable_source_digest != third.stable_source_digest
    {
        return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
    }
    RealmProcessorTerminalCarryoverRecoveryOutcome::try_from_storage(second.preparation)
        .map_err(backend)
}

fn hash_pipeline<Hash: Q256BitHash>(hasher: &mut Sha256, pipeline: &StoredPendingPipeline<Hash>) {
    hasher.update(pipeline.revision().get().to_be_bytes());
    hasher.update(pipeline.canonical_payload());
}

fn cloned_digest(hasher: &Sha256) -> [u8; 32] {
    hasher.clone().finalize().into()
}

fn same_pipeline_snapshot<Hash: Q256BitHash>(
    first: &StoredPendingPipeline<Hash>,
    second: &StoredPendingPipeline<Hash>,
) -> bool {
    first.revision() == second.revision()
        && first.canonical_payload() == second.canonical_payload()
}

struct ScyllaRealmProcessorDurableCapture<Hash> {
    factory: Arc<ScyllaRealmProcessorDurableCaptureFactory<Hash>>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    transport_archive: Arc<ScyllaPendingQueueSemanticAggregateStore>,
    application_archive: Arc<ScyllaRealmProcessorApplicationArchiveStore>,
    context: psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext,
    deferred_pipeline: StoredPendingPipeline<Hash>,
    deferred_input: Option<RealmProcessorDeferredActorInput>,
    deferred_input_digest:
        psy_node_core::queue::realm_processor_deferred_actor_input::RealmProcessorDeferredActorInputDigest,
    external_dependency_commitment: Option<RealmProcessorExternalDependencyCommitment>,
    actor_input_digest: Option<RealmProcessorActorInputDigest>,
    mode: ScyllaRealmProcessorCaptureMode,
    _hash: PhantomData<Hash>,
}

enum ScyllaRealmProcessorCaptureMode {
    Active {
        source: ScyllaBackedRecoverableNatsSource,
        close: super::PersistedPendingQueueCloseReceipt,
        publisher: Arc<AssignmentBoundRecoverablePendingQueuePublisher>,
        publish_store: Arc<ScyllaPendingQueuePublishStore>,
    },
    Recovered(PersistedRealmProcessorApplicationHandoffReceipt),
}

impl<Hash> ScyllaRealmProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn revalidate_deferred_actor_input(
        &self,
    ) -> Result<(), RealmProcessorDurableCaptureError> {
        let fresh = self
            .factory
            .observe_deferred_actor_input_snapshot()
            .await?;
        let RealmProcessorDeferredActorInputOutcome::Ready(input) = fresh.outcome else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if self
            .deferred_input
            .as_ref()
            .is_some_and(|expected| expected != &input)
            || input.successor() != self.context.processing()
            || input.digest() != self.deferred_input_digest
            || !same_pipeline_snapshot(&fresh.pipeline, &self.deferred_pipeline)
            || fresh.pipeline.key() != self.context.key()
            || fresh.pipeline.activation_digest() != self.context.activation()
            || fresh.pipeline.processing() != self.context.processing()
        {
            return Err(RealmProcessorDurableCaptureError::ConcurrentMutation);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash> RealmProcessorDurableCapturePort
    for ScyllaRealmProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn take_deferred_actor_input(
        &mut self,
    ) -> Result<RealmProcessorDeferredActorInput, RealmProcessorDurableCaptureError> {
        let ScyllaRealmProcessorCaptureMode::Active { .. } = &self.mode else {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        };
        // Capture/replay may wait on the durable source after open-time fresh C.
        // Re-select the complete typed lineage immediately before handing it to
        // the command-only actor.  While the input is still owned here we can
        // compare the full value, not only its digest.
        self.revalidate_deferred_actor_input().await?;
        self.deferred_input
            .take()
            .ok_or(RealmProcessorDurableCaptureError::IdentityMismatch)
    }

    async fn capture_next(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError> {
        let ScyllaRealmProcessorCaptureMode::Active { source, close, .. } = &self.mode else {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        };
        source
            .capture_one::<Hash>(&self.pipeline, self.context, close)
            .await
            .map(|outcome| {
                outcome.map(|outcome| match outcome {
                    PendingQueueNatsCaptureOutcome::Data(data) => {
                        RealmProcessorDurableCaptureOutcome::Data(data)
                    }
                    PendingQueueNatsCaptureOutcome::Sealed { data, boundary } => {
                        RealmProcessorDurableCaptureOutcome::Sealed { data, boundary }
                    }
                })
            })
            .map_err(backend)
    }

    async fn replay_complete_generation(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCapturedGeneration>, RealmProcessorDurableCaptureError>
    {
        let ScyllaRealmProcessorCaptureMode::Active { source, close, publisher, .. } = &self.mode else {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        };
        let Some((candidates, boundary)) = source
            .replay_closed_source::<Hash>(&self.pipeline, self.context, close)
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        project_complete_generation(
            self.context,
            publisher.assignment_receipt().assignment(),
            candidates,
            boundary,
        )
            .map(Some)
    }

    async fn qualify_external_actor_input(
        &mut self,
        generation: RealmProcessorDurableCapturedGeneration,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        let ScyllaRealmProcessorCaptureMode::Active { .. } = &self.mode else {
            return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
        };
        if generation.context() != self.context {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        self.revalidate_deferred_actor_input().await?;
        let input = match self.external_dependency_commitment.take() {
            Some(expected) => {
                let input = self
                    .factory
                    .external_dependency_loader
                    .load_committed_exact(generation, expected)
                    .await?;
                if input.dependency_commitment() != expected {
                    return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                }
                input
            }
            None => {
                let Some(deferred_input) = self.deferred_input.as_ref() else {
                    return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                };
                if !matches!(
                    deferred_input.source(),
                    RealmProcessorDeferredActorInputSource::BootstrapEmpty { .. }
                ) {
                    return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
                }
                self.factory
                    .external_dependency_loader
                    .load_current_exact(generation)
                    .await?
            }
        };
        self.revalidate_deferred_actor_input().await?;
        if input.context() != self.context {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        self.actor_input_digest = Some(
            RealmProcessorActorInputDigest::try_from_exact_parts(
                self.context,
                self.deferred_input_digest,
                input.digest(),
            )
            .map_err(backend)?,
        );
        Ok(input)
    }

    async fn recover_application_handoff(
        &mut self,
    ) -> Result<Option<RealmProcessorApplicationHandoffObservation>, RealmProcessorDurableCaptureError>
    {
        match &self.mode {
            ScyllaRealmProcessorCaptureMode::Active { .. } => Ok(None),
            ScyllaRealmProcessorCaptureMode::Recovered(receipt) => {
                handoff_observation(receipt).map(Some)
            }
        }
    }

    async fn persist_application_and_handoff(
        &mut self,
        semantic: RealmProcessorSemanticOutput,
    ) -> Result<RealmProcessorApplicationHandoffObservation, RealmProcessorDurableCaptureError>
    {
        if self.deferred_input.is_some()
            || semantic.actor_input_digest() != self.actor_input_digest
            || self.actor_input_digest.is_none()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        self.revalidate_deferred_actor_input().await?;
        let handoff = {
            let ScyllaRealmProcessorCaptureMode::Active {
                source,
                close,
                publisher,
                publish_store,
            } = &self.mode
            else {
                return Err(RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing);
            };
            let (fresh_generation, transport_receipt) = verify_transport_archive::<Hash>(
                &self.pipeline,
                &self.transport_archive,
                self.context,
                source,
                close,
                publisher,
                publish_store,
            )
            .await?;
            require_semantic_matches_generation(&semantic, &fresh_generation)?;
            let binding = transport_receipt
                .realm_application_binding(
                    publisher.assignment_receipt(),
                    close,
                    &semantic,
                )
                .map_err(backend)?;
            let plan = RealmProcessorApplicationArchivePlan::try_new(binding, &semantic)
                .map_err(backend)?;
            let archive = self
                .application_archive
                .persist_and_readback(&plan)
                .await
                .map_err(backend)?;

            // The immutable archive now commits the actor-input digest through
            // semantic v2. Re-select the successor lineage once more while the
            // pipeline is still the exact Sealing predecessor.
            self.revalidate_deferred_actor_input().await?;

            // Fresh B: re-read the closed source, NATS retained set,
            // assignment route, transport aggregate and close fence after the
            // immutable application header is visible but before the CAS.
            let (second_generation, second_transport) = verify_transport_archive::<Hash>(
                &self.pipeline,
                &self.transport_archive,
                self.context,
                source,
                close,
                publisher,
                publish_store,
            )
            .await?;
            require_semantic_matches_generation(&semantic, &second_generation)?;
            if transport_receipt.slot() != second_transport.slot()
                || transport_receipt.digest() != second_transport.digest()
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            let handoff = self.application_archive
                .handoff_to_pipeline::<Hash>(
                    &self.pipeline,
                    publisher.assignment_receipt(),
                    close,
                    &archive,
                )
                .await
                .map_err(backend)?;
            self.transport_archive
                .revalidate_realm_application_header(
                    publisher.assignment_receipt(),
                    archive.header(),
                )
                .await
                .map_err(backend)?;
            let recovered = self.application_archive
                .recover_handoff_from_pipeline::<Hash>(
                    &self.pipeline,
                    publisher.assignment_receipt(),
                )
                .await
                .map_err(backend)?;
            if handoff.archive_slot() != recovered.archive_slot()
                || handoff.archive_digest() != recovered.archive_digest()
                || handoff.semantic_digest() != recovered.semantic_digest()
                || handoff.pipeline_revision() != recovered.pipeline_revision()
            {
                return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
            }
            handoff
        };
        let observation = handoff_observation(&handoff)?;
        self.mode = ScyllaRealmProcessorCaptureMode::Recovered(handoff);
        Ok(observation)
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_transport_archive<Hash: Q256BitHash>(
    pipeline: &ScyllaPendingPipelineStore,
    transport_archive: &ScyllaPendingQueueSemanticAggregateStore,
    context: psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext,
    source: &ScyllaBackedRecoverableNatsSource,
    close: &super::PersistedPendingQueueCloseReceipt,
    publisher: &AssignmentBoundRecoverablePendingQueuePublisher,
    publish_store: &ScyllaPendingQueuePublishStore,
) -> Result<
    (
        RealmProcessorDurableCapturedGeneration,
        PersistedPendingQueueSemanticGenerationReceipt,
    ),
    RealmProcessorDurableCaptureError,
> {
    publisher.revalidate_exact().await.map_err(backend)?;
    let Some((candidates, boundary)) = source
        .replay_closed_source::<Hash>(pipeline, context, close)
        .await
        .map_err(backend)?
    else {
        return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
    };
    let generation = project_complete_generation(
        context,
        publisher.assignment_receipt().assignment(),
        candidates,
        boundary,
    )?;
    let nats_scan = publisher
        .scan_source_retained_set(PendingQueuePublisherKind::RealmUserUpdate)
        .await
        .map_err(backend)?;
    let source_receipt = verify_semantic_source_terminal::<Hash>(
        pipeline,
        publish_store,
        source.artifact_store(),
        publisher.assignment_receipt(),
        source.owner_permit(),
        close,
        source.contract(),
        PendingQueuePublisherKind::RealmUserUpdate,
        nats_scan,
    )
    .await
    .map_err(backend)?;
    let aggregate = StoredPendingQueueSemanticGeneration::try_from_source_receipts(
        publisher.assignment_receipt(),
        close,
        vec![source_receipt],
    )
    .map_err(backend)?;
    let receipt = transport_archive
        .persist_verified::<Hash>(
            pipeline,
            publisher.assignment_receipt(),
            close,
            &aggregate,
        )
        .await
        .map_err(backend)?;
    publisher.revalidate_exact().await.map_err(backend)?;
    Ok((generation, receipt))
}

fn require_semantic_matches_generation(
    semantic: &RealmProcessorSemanticOutput,
    generation: &RealmProcessorDurableCapturedGeneration,
) -> Result<(), RealmProcessorDurableCaptureError> {
    if semantic.context_digest() != generation.context().digest()
        || semantic.generation_digest() != generation.digest()
        || semantic.boundary_digest() != generation.boundary().digest()
        || semantic.item_count() != generation.item_count()
    {
        return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
    }
    Ok(())
}

fn handoff_observation(
    receipt: &PersistedRealmProcessorApplicationHandoffReceipt,
) -> Result<RealmProcessorApplicationHandoffObservation, RealmProcessorDurableCaptureError> {
    RealmProcessorApplicationHandoffObservation::try_from_storage(
        *receipt.archive_slot().as_bytes(),
        *receipt.archive_digest(),
        *receipt.semantic_digest(),
        receipt.pipeline_revision().get(),
        receipt.has_application_work(),
    )
}

fn project_complete_generation(
    context: psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    candidates: Vec<PendingQueueCaptureCandidate>,
    boundary: PendingQueueGenerationBoundary,
) -> Result<RealmProcessorDurableCapturedGeneration, RealmProcessorDurableCaptureError> {
    if assignment.context() != context || boundary.context() != context {
        return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
    }
    let mut expected_ordinal = 1_u32;
    let mut previous_subject_sequence = 0_u64;
    let mut previous_envelope_digest = [0_u8; 32];
    let mut batches = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.context() != context
            || candidate.source_identity() != boundary.source_identity()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let PendingQueueSourceCursorView::NatsJetStream {
            stream_sequences, ..
        } = candidate.source().view()
        else {
            return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
        };
        if stream_sequences.len() != candidate.items().len() {
            return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
        }
        let mut business_items = Vec::with_capacity(candidate.items().len());
        for (stream_sequence, encoded) in stream_sequences
            .iter()
            .copied()
            .zip(candidate.items())
        {
            let envelope = PendingQueuePublishEnvelope::decode_canonical(encoded)
                .map_err(backend)?;
            if envelope.publisher_kind() != PendingQueuePublisherKind::RealmUserUpdate
                || envelope.artifact_identity() != candidate.artifact_identity()
                || envelope.segment_id() != assignment.segment_id()
                || envelope.contract_digest() != assignment.contract_digest()
                || envelope.assignment_digest() != assignment.digest()
                || envelope.member_ordinal().get() != expected_ordinal
                || envelope.previous_subject_sequence() != previous_subject_sequence
                || envelope.previous_envelope_digest() != previous_envelope_digest
            {
                return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
            }
            let PendingQueueEnvelopeBody::Data(payload) = envelope.body() else {
                return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
            };
            business_items.push(RealmProcessorDurableCapturedItem::try_new(
                stream_sequence,
                *envelope.digest().as_bytes(),
                payload.clone(),
            )?);
            expected_ordinal = expected_ordinal
                .checked_add(1)
                .ok_or(RealmProcessorDurableCaptureError::MalformedCompleteGeneration)?;
            previous_subject_sequence = stream_sequence;
            previous_envelope_digest = *envelope.digest().as_bytes();
        }
        batches.push(
            RealmProcessorDurableCapturedBatch::try_from_verified_envelopes(
                candidate,
                business_items,
            )?,
        );
    }
    let PendingQueueBoundaryObservation::NatsJetStream {
        seal_marker_stream_sequence,
        last_data_stream_sequence,
        ..
    } = boundary.observation()
    else {
        return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
    };
    if *last_data_stream_sequence != previous_subject_sequence
        || *seal_marker_stream_sequence <= *last_data_stream_sequence
    {
        return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
    }
    RealmProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
        context,
        batches,
        boundary,
    )
}

fn consumer_operation(
    request: &SealedRealmProcessorDurableCaptureRequest,
    spec: &RecoverableNatsCaptureSpec,
) -> Result<RecoverableNatsConsumerProvisioningOperationId, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_OPERATION_DOMAIN);
    hasher.update(request.startup_permit_digest().as_bytes());
    hasher.update(request.context().digest().as_bytes());
    hasher.update(spec.consumer_digest());
    RecoverableNatsConsumerProvisioningOperationId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_attempt(
    request: &SealedRealmProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerAttemptId, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_ATTEMPT_DOMAIN);
    hasher.update(request.startup_permit_digest().as_bytes());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerAttemptId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_reason(
    request: &SealedRealmProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerReasonDigest, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_REASON_DOMAIN);
    hasher.update(request.writer_activation_digest());
    hasher.update(request.queue_readiness_digest());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerReasonDigest::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn backend(error: impl std::fmt::Display) -> RealmProcessorDurableCaptureError {
    RealmProcessorDurableCaptureError::Backend(error.to_string())
}

fn narrow_capture(
    error: RealmProcessorDurableCaptureError,
) -> RealmProcessorNarrowWriterError {
    match error {
        RealmProcessorDurableCaptureError::ConcurrentMutation => {
            RealmProcessorNarrowWriterError::ConcurrentMutation
        }
        RealmProcessorDurableCaptureError::IdentityMismatch
        | RealmProcessorDurableCaptureError::RuntimeCapabilityMismatch
        | RealmProcessorDurableCaptureError::ApplicationHandoffNotSealing => {
            RealmProcessorNarrowWriterError::IdentityMismatch
        }
        other => RealmProcessorNarrowWriterError::Backend(other.to_string()),
    }
}

fn narrow_writer(error: impl std::fmt::Display) -> RealmProcessorNarrowWriterError {
    RealmProcessorNarrowWriterError::Writer(error.to_string())
}

fn narrow_pipeline(error: impl std::fmt::Display) -> RealmProcessorNarrowWriterError {
    RealmProcessorNarrowWriterError::Pipeline(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::recoverable_ephemeral::{
            PendingQueueCaptureContext, PendingQueueSourceCursor,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::{
                PendingPipelineRevision, PendingQueueCloseIntentDigest,
            },
        },
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueueSealSummary,
            PendingQueueSourceQuota,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    fn fixture_for(
        pending_id: u64,
        pending_proc_id: u128,
    ) -> (
        PendingQueueCaptureContext,
        PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
    ) {
        let authority = AuthorityScope::Realm {
            realm_id: 3,
            realm_sub_id: 0,
        };
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(pending_id, pending_proc_id)
                .unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                1024 * 1024 * 1024,
                128 * 1024 * 1024,
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            vec![PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::RealmUserUpdate,
                100,
                127 * 1024 * 1024,
                1024 * 1024,
            )
            .unwrap()],
            128 * 1024 * 1024,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let assignment = match PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &validated,
            budget,
            8,
        )
        .unwrap()
        .candidate()
        .reserve_generation(context)
        .unwrap()
        {
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => assignment,
            _ => unreachable!(),
        };
        let route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::RealmUserUpdate,
            &segment,
        )
        .unwrap();
        (context, assignment, route)
    }

    fn restart_preparation(
        terminal: RealmProcessorTerminalCarryoverObservation,
    ) -> RealmProcessorReadOnlyRestartPreparation {
        let application = RealmProcessorApplicationContinuation::try_from_committed_parts(
            psy_node_core::queue::realm_processor_application_archive::RealmProcessorApplicationArchiveSlot::try_new([11; 32]).unwrap(),
            psy_node_core::queue::realm_processor_application_archive::RealmProcessorApplicationArchiveDigest::try_new([12; 32]).unwrap(),
            psy_node_core::queue::realm_processor_semantic_output::RealmProcessorSemanticOutputDigest::try_new([13; 32]).unwrap(),
            true,
            1,
            psy_node_core::queue::realm_processor_generation_continuation::RealmProcessorDeferredCarryoverDigest::try_new([14; 32]).unwrap(),
        )
        .unwrap();
        let continuation = RealmProcessorGenerationContinuation::try_from_storage(
            PendingGenerationContext::try_from_legacy(17, 19).unwrap(),
            PendingPipelineRevision::try_new(7).unwrap(),
            RealmProcessorGenerationContinuationPhase::AwaitPublishedTerminal,
            Some(application),
        )
        .unwrap();
        RealmProcessorReadOnlyRestartPreparation::try_from_storage(
            continuation,
            RealmProcessorInboundCarryoverObservation::Predecessor,
            terminal,
        )
        .unwrap()
    }

    fn restart_snapshot(
        preparation: RealmProcessorReadOnlyRestartPreparation,
        stable_source: u8,
        full: u8,
    ) -> ScyllaRealmProcessorRestartSnapshot {
        ScyllaRealmProcessorRestartSnapshot {
            preparation,
            stable_source_digest: [stable_source; 32],
            digest: [full; 32],
            key: PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 3,
                    realm_sub_id: 0,
                },
            ),
            activation: PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            processing: preparation.continuation().processing(),
        }
    }

    fn fixture() -> (
        PendingQueueCaptureContext,
        PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
    ) {
        fixture_for(7, 99)
    }

    fn data(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        ordinal: u32,
        previous_sequence: u64,
        previous_digest: [u8; 32],
        payload: &[u8],
    ) -> PendingQueuePublishEnvelope {
        PendingQueuePublishEnvelope::data(
            route,
            assignment,
            PendingQueuePublishIntentId::try_new([ordinal as u8; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(ordinal).unwrap(),
            previous_sequence,
            previous_digest,
            payload.to_vec(),
        )
        .unwrap()
    }

    fn candidate(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        sequences: &[u64],
        envelopes: &[PendingQueuePublishEnvelope],
    ) -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            context,
            route.source_identity().clone(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], sequences).unwrap(),
            envelopes
                .iter()
                .map(PendingQueuePublishEnvelope::to_canonical_bytes)
                .collect(),
        )
        .unwrap()
    }

    fn boundary(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        seal_sequence: u64,
        last_data_sequence: u64,
    ) -> PendingQueueGenerationBoundary {
        PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap(),
            route.source_identity().clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: seal_sequence,
                last_data_stream_sequence: last_data_sequence,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap()
    }

    fn complete_generation(
    ) -> Result<RealmProcessorDurableCapturedGeneration, RealmProcessorDurableCaptureError> {
        let (context, assignment, route) = fixture();
        let first = data(&route, &assignment, 1, 0, [0; 32], b"first");
        let second = data(
            &route,
            &assignment,
            2,
            10,
            *first.digest().as_bytes(),
            b"second",
        );
        project_complete_generation(
            context,
            &assignment,
            vec![
                candidate(context, &route, &[10], &[first]),
                candidate(context, &route, &[11], &[second]),
            ],
            boundary(context, &route, 12, 11),
        )
    }

    #[test]
    fn exhaustive_projection_preserves_business_order_and_is_deterministic() {
        let first = complete_generation().unwrap();
        let first_digest = first.digest();
        assert_eq!(first.item_count(), 2);
        assert_eq!(first.batches().len(), 2);
        assert_eq!(
            first.into_business_items(),
            vec![b"first".to_vec(), b"second".to_vec()],
        );
        assert_eq!(complete_generation().unwrap().digest(), first_digest);
    }

    #[test]
    fn projection_rejects_broken_cross_batch_chain_and_boundary() {
        let (context, assignment, route) = fixture();
        let first = data(&route, &assignment, 1, 0, [0; 32], b"first");
        let wrong_previous = data(
            &route,
            &assignment,
            2,
            9,
            *first.digest().as_bytes(),
            b"second",
        );
        assert!(matches!(
            project_complete_generation(
                context,
                &assignment,
                vec![
                    candidate(context, &route, &[10], &[first]),
                    candidate(context, &route, &[11], &[wrong_previous]),
                ],
                boundary(context, &route, 12, 11),
            ),
            Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration)
        ));

        let first = data(&route, &assignment, 1, 0, [0; 32], b"first");
        assert!(matches!(
            project_complete_generation(
                context,
                &assignment,
                vec![candidate(context, &route, &[10], &[first])],
                boundary(context, &route, 12, 11),
            ),
            Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration)
        ));
    }

    #[test]
    fn projection_rejects_non_data_envelope_and_wrong_assignment() {
        let (context, assignment, route) = fixture();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([1; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            PendingQueueSealSummary::try_new(
                PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap(),
                0,
                0,
                0,
                [0; 32],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            project_complete_generation(
                context,
                &assignment,
                vec![candidate(context, &route, &[10], &[seal])],
                boundary(context, &route, 11, 10),
            ),
            Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration)
        ));

        let (_, other_assignment, _) = fixture_for(8, 100);
        let first = data(&route, &assignment, 1, 0, [0; 32], b"first");
        assert!(matches!(
            project_complete_generation(
                context,
                &other_assignment,
                vec![candidate(context, &route, &[10], &[first])],
                boundary(context, &route, 11, 10),
            ),
            Err(RealmProcessorDurableCaptureError::IdentityMismatch)
        ));
    }

    #[test]
    fn empty_closed_generation_is_structural_input_not_a_semantic_terminal() {
        let (context, assignment, route) = fixture();
        let generation = project_complete_generation(
            context,
            &assignment,
            Vec::new(),
            boundary(context, &route, 1, 0),
        )
        .unwrap();
        assert_eq!(generation.item_count(), 0);
        assert!(generation.batches().is_empty());
        assert_ne!(generation.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn high_level_owner_exposes_no_raw_backend_or_ack_authority() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let port = production
            .split("impl<Hash> RealmProcessorDurableCapturePort")
            .nth(1)
            .unwrap();
        assert!(!port.contains("double_ack"));
        assert!(!port.contains("Session"));
        assert!(!production.contains("pub fn new("));
        assert!(!production.contains("impl Clone for ScyllaRealmProcessorDurableCapture"));
    }

    #[test]
    fn application_handoff_revalidates_transport_before_and_after_archive() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let method = source
            .split("async fn persist_application_and_handoff")
            .nth(1)
            .unwrap()
            .split("async fn verify_transport_archive")
            .next()
            .unwrap();
        assert_eq!(method.matches("verify_transport_archive::<Hash>").count(), 2);
        let first = method.find("verify_transport_archive::<Hash>").unwrap();
        let archive = method.find("persist_and_readback(&plan)").unwrap();
        let second = method.rfind("verify_transport_archive::<Hash>").unwrap();
        let cas = method.find("handoff_to_pipeline::<Hash>").unwrap();
        assert!(first < archive && archive < second && second < cas);
        assert!(method.contains("revalidate_realm_application_header"));
        assert!(method.contains("recover_handoff_from_pipeline::<Hash>"));
    }

    #[test]
    fn continuation_observer_brackets_full_pipeline_and_assignment_route() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let method = source
            .split("async fn observe_generation_continuation_exact(")
            .nth(1)
            .unwrap()
            .split("fn validate_restart_identity(")
            .next()
            .unwrap();
        assert_eq!(method.matches("revalidate_assignment_route(&route)").count(), 3);
        assert!(method.contains("pipeline.revision() != first_pipeline.revision()"));
        assert!(method.contains("first_pipeline.revision() != second_pipeline.revision()"));
        assert!(method.contains(
            "pipeline.canonical_payload() != first_pipeline.canonical_payload()"
        ));
        assert!(method.contains("first_pipeline.canonical_payload()"));
        assert!(method.contains("!= second_pipeline.canonical_payload()"));
        assert!(method.contains("PendingProcessingState::Baseline(_)"));
        assert!(method.contains("AwaitPrimeOrRotate"));
        assert!(method.contains("PendingProcessingState::Ready"));
        assert!(method.contains("AwaitQueueClose"));
        assert!(method.contains("same_pipeline_snapshot(&pipeline, &second_pipeline)"));

        let equality = source
            .split("fn same_pipeline_snapshot")
            .nth(1)
            .unwrap()
            .split("struct ScyllaRealmProcessorDurableCapture")
            .next()
            .unwrap();
        assert!(equality.contains("first.revision() == second.revision()"));
        assert!(equality.contains(
            "first.canonical_payload() == second.canonical_payload()"
        ));
    }

    #[test]
    fn narrow_writer_is_storage_selected_verified_before_inflight_and_stops_before_publish() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let method = source
            .split("pub(super) async fn prepare_narrow_writer")
            .nth(1)
            .unwrap()
            .split("fn validate_generation_request")
            .next()
            .unwrap();
        let first = method.find("observe_generation_continuation_exact").unwrap();
        let writer = method.find(".prepare_and_verify(intent").unwrap();
        let barrier = method.find(".require_fresh_barrier(&barrier)").unwrap();
        let fresh = method[first + 1..]
            .find("observe_generation_continuation_exact")
            .map(|offset| first + 1 + offset)
            .unwrap();
        let begin = method.find("seal_branch_exact_begin").unwrap();
        let pipeline = method.find(".apply(&transition)").unwrap();
        let final_observation = method.rfind("observe_generation_continuation_exact").unwrap();
        assert!(first < writer);
        assert!(writer < barrier);
        assert!(barrier < fresh);
        assert!(fresh < begin && begin < pipeline);
        assert!(pipeline < final_observation);
        assert!(method.contains("RealmProcessorGenerationContinuationPhase::AwaitWriter"));
        assert!(method.contains(
            "RealmProcessorGenerationContinuationPhase::AwaitWriterCompletion"
        ));
        assert!(method.contains("first.continuation.application() != Some(request.application())"));
        assert!(method.contains("same_pipeline_snapshot(&fresh.pipeline, &first.pipeline)"));
        for forbidden in [
            "finish_published",
            "seal_branch_exact_publish",
            "seal_branch_exact_no_work",
            "seal_rotation",
            "authority_head",
            "publish_marker",
            "NatsJetStreamClient",
        ] {
            assert!(
                !method.contains(forbidden),
                "narrow writer crossed the c4d boundary: {forbidden}"
            );
        }
    }

    #[test]
    fn continuation_restart_is_storage_selected_one_shot_and_read_only() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let restart = source
            .split("async fn observe_restart_snapshot(")
            .nth(1)
            .unwrap()
            .split("async fn open_exact(")
            .next()
            .unwrap();
        assert!(restart.contains("observe_for_restart"));
        assert!(restart.contains("observe_generation_continuation_exact"));
        assert!(restart.contains("ConcurrentMutation"));
        assert!(restart.contains("RealmProcessorInboundCarryoverObservation::Missing"));
        assert!(restart.contains("let pipeline = exact.pipeline"));
        assert!(restart.contains("generation_terminal"));
        assert!(restart.contains("deferred_carryover"));
        for forbidden in [
            ".persist(",
            ".apply(",
            "seal_rotation(",
            "terminal_authorization:",
            "publish_marker",
            "finish_published",
        ] {
            assert!(
                !restart.contains(forbidden),
                "restart preparation must be read-only: {forbidden}"
            );
        }

        let terminal_store = include_str!("realm_processor_generation_terminal.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let carryover_store = include_str!("realm_processor_deferred_carryover.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(terminal_store.contains("pub(super) async fn observe_for_restart"));
        assert!(carryover_store.contains("pub(super) async fn observe_for_restart"));
        assert!(!terminal_store.contains("pub(super) async fn persist(\n"));
        assert!(!carryover_store.contains("pub(super) async fn persist(\n"));
        assert!(carryover_store.contains(
            "pub(super) async fn persist_from_selected_terminal"
        ));
    }

    #[test]
    fn terminal_carryover_recovery_requires_stable_source_and_exact_post_write_snapshots() {
        let terminal_only = restart_snapshot(
            restart_preparation(
                RealmProcessorTerminalCarryoverObservation::UnqualifiedTerminalObservedAwaitCarryover,
            ),
            1,
            2,
        );
        let complete = restart_snapshot(
            restart_preparation(
                RealmProcessorTerminalCarryoverObservation::TerminalAndCarryoverObserved,
            ),
            1,
            3,
        );
        assert!(matches!(
            finish_terminal_carryover_recovery(&terminal_only, &complete, &complete, true),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::Prepared(_))
        ));

        let source_drift = restart_snapshot(complete.preparation, 9, 3);
        assert_eq!(
            finish_terminal_carryover_recovery(
                &terminal_only,
                &source_drift,
                &source_drift,
                true,
            ),
            Err(RealmProcessorDurableCaptureError::ConcurrentMutation)
        );
        let full_drift = restart_snapshot(complete.preparation, 1, 4);
        assert_eq!(
            finish_terminal_carryover_recovery(
                &terminal_only,
                &complete,
                &full_drift,
                true,
            ),
            Err(RealmProcessorDurableCaptureError::ConcurrentMutation)
        );

        let await_authorization = restart_snapshot(
            restart_preparation(
                RealmProcessorTerminalCarryoverObservation::AwaitVerifiedTerminalAuthorization,
            ),
            5,
            6,
        );
        assert!(matches!(
            finish_terminal_carryover_recovery(
                &await_authorization,
                &await_authorization,
                &await_authorization,
                false,
            ),
            Ok(RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitVerifiedTerminalAuthorization(_))
        ));
        assert_eq!(
            finish_terminal_carryover_recovery(
                &await_authorization,
                &complete,
                &complete,
                false,
            ),
            Err(RealmProcessorDurableCaptureError::ConcurrentMutation)
        );
    }

    #[test]
    fn post_cas_open_recovers_without_recreating_close_or_nats_owner() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let open = source
            .split("async fn open_exact")
            .nth(1)
            .unwrap()
            .split("#[async_trait]")
            .next()
            .unwrap();
        let recovered = open
            .split("PendingProcessingState::WorkCaptured")
            .nth(1)
            .unwrap()
            .split("if !matches!(pipeline.processing_state()")
            .next()
            .unwrap();
        assert!(recovered.contains("recover_handoff_from_pipeline"));
        assert!(recovered.contains("revalidate_realm_application_header"));
        assert!(!recovered.contains("claim_owner"));
        assert!(!recovered.contains("read_queue_close_exact"));
    }

    #[test]
    fn terminal_carryover_recovery_cannot_create_terminal_reserve_or_rotate() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let recovery = source
            .split("impl<Hash> RealmProcessorTerminalCarryoverRecoveryPort")
            .nth(1)
            .unwrap()
            .split("fn hash_pipeline")
            .next()
            .unwrap();
        assert!(recovery.contains("persist_from_selected_terminal"));
        assert!(recovery.contains("stable_source_digest"));
        assert!(recovery.contains("TerminalAndCarryoverObserved"));
        for forbidden in [
            "generation_terminal.persist",
            "RealmProcessorGenerationTerminal::try_new",
            "PendingCounterAdapter",
            "ReservedPendingGeneration",
            "seal_rotation(",
            "pipeline.apply",
            "authority_head",
        ] {
            assert!(
                !recovery.contains(forbidden),
                "derived recovery must not gain terminal/rotation authority: {forbidden}"
            );
        }
    }

    #[test]
    fn restart_owner_is_not_called_by_production_processor_or_serving_composition() {
        let process = include_str!(
            "../../../psy_node_common/src/realm/processor/core/process_block.rs"
        );
        let create = include_str!(
            "../../../psy_node_common/src/realm/processor/create.rs"
        );
        assert!(!process.contains("open_continuation_restart"));
        assert!(!process.contains("open_terminal_carryover_recovery"));
        assert!(process.contains("REALM_BRANCH_EXACT_FULL_COMMIT_COVERAGE_NOT_INTEGRATED"));
        assert!(create.contains("ServingCompositionNotIntegrated"));
    }

    #[test]
    fn deferred_actor_input_is_storage_selected_revalidated_and_processor_ordered() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let snapshot = source
            .split("async fn observe_deferred_actor_input_snapshot")
            .nth(1)
            .unwrap()
            .split("fn validate_restart_identity")
            .next()
            .unwrap();
        for required in [
            "observe_generation_continuation_exact",
            "deferred_carryover",
            "generation_terminal",
            "seal_begin_queue_close",
            "validate_application_source",
            "RealmProcessorDeferredActorInput::try_from_storage",
            "AwaitExplicitCarryover",
            "same_pipeline_snapshot",
        ] {
            assert!(snapshot.contains(required), "missing loader fence: {required}");
        }
        assert!(
            snapshot.find("deferred_carryover").unwrap()
                < snapshot.find("generation_terminal").unwrap()
        );
        assert!(
            snapshot.find("generation_terminal").unwrap()
                < snapshot.find("validate_application_source").unwrap()
        );
        for forbidden in [
            ".persist(",
            ".apply(",
            "claim_owner",
            "create_consumer",
            "seal_rotation(",
            "authority_head",
        ] {
            assert!(
                !snapshot.contains(forbidden),
                "read-only input loader gained side effects: {forbidden}"
            );
        }

        let prepare = source
            .split("async fn prepare_deferred_actor_input")
            .nth(1)
            .unwrap()
            .split("async fn open(")
            .next()
            .unwrap();
        assert_eq!(
            prepare
                .matches("observe_deferred_actor_input_snapshot")
                .count(),
            2
        );
        assert!(prepare.contains("same_pipeline_snapshot"));

        let open = source
            .split("async fn open_exact")
            .nth(1)
            .unwrap()
            .split("impl<Hash> RealmProcessorDurableCaptureFactory")
            .next()
            .unwrap();
        let fresh_c = open.find("observe_deferred_actor_input_snapshot").unwrap();
        for side_effect in [
            "resolve_assignment_route",
            "bootstrap_open",
            "provision_capture_consumer",
            "claim_owner",
        ] {
            assert!(
                fresh_c < open.find(side_effect).unwrap(),
                "fresh C must precede {side_effect}"
            );
        }

        let capture = source
            .split("impl<Hash> RealmProcessorDurableCapturePort")
            .nth(1)
            .unwrap();
        let revalidate = source
            .split("async fn revalidate_deferred_actor_input")
            .nth(1)
            .unwrap()
            .split("impl<Hash> RealmProcessorDurableCapturePort")
            .next()
            .unwrap();
        assert!(revalidate.contains("deferred_pipeline"));
        assert!(revalidate.contains("same_pipeline_snapshot"));
        let take = capture
            .split("async fn take_deferred_actor_input")
            .nth(1)
            .unwrap()
            .split("async fn capture_next")
            .next()
            .unwrap();
        assert!(take.contains("revalidate_deferred_actor_input().await"));
        assert!(take.find("revalidate_deferred_actor_input").unwrap()
            < take.find(".take()").unwrap());

        let process = include_str!(
            "../../../psy_node_common/src/realm/processor/core/process_block.rs"
        );
        let process = process
            .split("async fn get_results_from_gatherers")
            .nth(1)
            .unwrap()
            .split("pub async fn sync_and_verify")
            .next()
            .unwrap();
        let prepare = process.find("prepare_deferred_actor_input").unwrap();
        let open = process
            .find("open_durable_capture_for_deferred_input")
            .unwrap();
        let replay = process.find("replay_complete_generation").unwrap();
        let take = process.find("take_deferred_actor_input").unwrap();
        let apply = process.find("apply_durable_generation").unwrap();
        let finalize = process.find("finalize_durable_generation").unwrap();
        let semantic = process.find("build_branch_exact_semantic_output").unwrap();
        let archive = process.find("persist_application_and_handoff").unwrap();
        assert!(prepare < open);
        assert!(open < replay);
        assert!(replay < take);
        assert!(take < apply);
        assert!(apply < finalize);
        assert!(finalize < semantic);
        assert!(semantic < archive);
    }
}
