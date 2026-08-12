//! Exact projection of the three closed Coordinator queue sources.
//!
//! This module accepts only candidates reconstructed by the durable artifact
//! scanner.  It validates every recoverable NATS envelope against the selected
//! generation assignment and the source's close boundary before producing the
//! driver-independent Coordinator input. The storage-owned port keeps NATS
//! delivery and ACK authority private and delegates persist-before-ACK to the
//! recoverable source adapter. It exposes no pipeline transition or actor
//! invocation.

use std::{error::Error, fmt, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        coordinator_processor_durable_capture::{
            CoordinatorProcessorDurableCaptureError,
            CoordinatorProcessorDurableCaptureFactory,
            CoordinatorProcessorDurableCapturePort,
            CoordinatorProcessorDurableCapturedGeneration,
            CoordinatorProcessorDurableCapturedItem,
            CoordinatorProcessorDurableCapturedSource,
            CoordinatorProcessorSourceKind,
            SealedCoordinatorProcessorDurableCaptureRequest,
        },
        recoverable_artifact::{
            PendingQueueArtifactOwnerAttemptId,
            PendingQueueArtifactOwnerReasonDigest,
        },
        recoverable_ephemeral::{
            PendingQueueArtifactIdentity,
            PendingQueueBoundaryObservation,
            PendingQueueCaptureCandidate,
            PendingQueueCaptureContext,
            PendingQueueGenerationBoundary,
            PendingQueueSourceCursorView,
        },
    },
    store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingPipelineReadState, PendingProcessingState,
        },
    },
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

use super::{
    PendingQueueArtifactStoreError, PendingQueueSidecarReady,
    ScyllaPendingPipelineStore, ScyllaPendingQueueArtifactStore,
    ScyllaPendingQueueSegmentLedgerStore,
    pending_queue_consumer_gate::{
        PendingQueueConsumerGateError, PendingQueueConsumerGateIdentity,
        ScyllaPendingQueueConsumerGateStore,
    },
    pending_queue_nats_capture::ScyllaBackedRecoverableNatsSource,
    pending_queue_stream_provision::{
        AssignmentBoundRecoverablePendingQueuePublisher,
        ScyllaPendingQueueStreamProvisionStore,
    },
};

const OWNER_ATTEMPT_DOMAIN: &[u8] =
    b"psy/rollback/coordinator-processor-capture-owner-attempt/v1";
const OWNER_REASON_DOMAIN: &[u8] =
    b"psy/rollback/coordinator-processor-capture-owner-reason/v1";
const CONSUMER_OPERATION_DOMAIN: &[u8] =
    b"psy/rollback/coordinator-processor-capture-consumer-operation/v1";
const CAPTURE_BATCH_LIMIT: usize = 1024;

#[derive(Debug)]
struct CoordinatorProcessorClosedSourceReadback {
    kind: CoordinatorProcessorSourceKind,
    candidates: Vec<PendingQueueCaptureCandidate>,
    boundary: PendingQueueGenerationBoundary,
}

impl CoordinatorProcessorClosedSourceReadback {
    fn new(
        kind: CoordinatorProcessorSourceKind,
        candidates: Vec<PendingQueueCaptureCandidate>,
        boundary: PendingQueueGenerationBoundary,
    ) -> Self {
        Self {
            kind,
            candidates,
            boundary,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorProcessorDurableProjectionError {
    IdentityMismatch,
    MalformedCompleteSource,
    Core(String),
    Envelope(String),
}

impl fmt::Display for CoordinatorProcessorDurableProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorProcessorDurableProjectionError {}

fn project_complete_generation(
    context: PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    sources: Vec<CoordinatorProcessorClosedSourceReadback>,
) -> Result<
    CoordinatorProcessorDurableCapturedGeneration,
    CoordinatorProcessorDurableProjectionError,
> {
    if assignment.context() != context
        || context.key().authority()
            != psy_data::protocol::chain_context::AuthorityScope::Coordinator
        || usize::from(assignment.expected_source_count())
            != CoordinatorProcessorSourceKind::ALL.len()
        || assignment.source_quotas().len()
            != CoordinatorProcessorSourceKind::ALL.len()
        || sources.len() != CoordinatorProcessorSourceKind::ALL.len()
        || sources
            .iter()
            .map(|source| source.kind)
            .ne(CoordinatorProcessorSourceKind::ALL)
        || sources
            .iter()
            .map(|source| source.boundary.close_intent())
            .skip(1)
            .any(|close| close != sources[0].boundary.close_intent())
    {
        return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
    }

    let projected = sources
        .into_iter()
        .map(|source| project_complete_source(context, assignment, source))
        .collect::<Result<Vec<_>, _>>()?;
    CoordinatorProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
        context, projected,
    )
    .map_err(core)
}

fn project_complete_source(
    context: PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    source: CoordinatorProcessorClosedSourceReadback,
) -> Result<
    CoordinatorProcessorDurableCapturedSource,
    CoordinatorProcessorDurableProjectionError,
> {
    if source.boundary.context() != context {
        return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
    }
    let expected_publisher = publisher_kind(source.kind);
    let quota = assignment
        .source_quotas()
        .iter()
        .copied()
        .find(|quota| quota.publisher_kind() == expected_publisher)
        .ok_or(CoordinatorProcessorDurableProjectionError::IdentityMismatch)?;
    let mut expected_ordinal = 1_u32;
    let mut previous_subject_sequence = 0_u64;
    let mut previous_envelope_digest = [0_u8; 32];
    let mut encoded_bytes = 0_u64;
    let mut business_items = Vec::new();

    for candidate in source.candidates {
        if candidate.context() != context
            || candidate.source_identity() != source.boundary.source_identity()
        {
            return Err(CoordinatorProcessorDurableProjectionError::IdentityMismatch);
        }
        let PendingQueueSourceCursorView::NatsJetStream {
            stream_sequences, ..
        } = candidate.source().view()
        else {
            return Err(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            );
        };
        if stream_sequences.len() != candidate.items().len() {
            return Err(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            );
        }

        business_items.reserve(candidate.items().len());
        for (stream_sequence, encoded) in stream_sequences
            .iter()
            .copied()
            .zip(candidate.items())
        {
            encoded_bytes = encoded_bytes
                .checked_add(u64::try_from(encoded.len()).map_err(|_| {
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource
                })?)
                .ok_or(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                )?;
            let envelope = PendingQueuePublishEnvelope::decode_canonical(encoded)
                .map_err(|error| {
                    CoordinatorProcessorDurableProjectionError::Envelope(
                        error.to_string(),
                    )
                })?;
            if stream_sequence == 0
                || (previous_subject_sequence != 0
                    && stream_sequence <= previous_subject_sequence)
                || envelope.publisher_kind() != expected_publisher
                || envelope.artifact_identity() != candidate.artifact_identity()
                || envelope.segment_id() != assignment.segment_id()
                || envelope.contract_digest() != assignment.contract_digest()
                || envelope.assignment_digest() != assignment.digest()
                || envelope.member_ordinal().get() != expected_ordinal
                || envelope.previous_subject_sequence()
                    != previous_subject_sequence
                || envelope.previous_envelope_digest()
                    != previous_envelope_digest
            {
                return Err(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                );
            }
            let PendingQueueEnvelopeBody::Data(payload) = envelope.body() else {
                return Err(
                    CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
                );
            };
            business_items.push(
                CoordinatorProcessorDurableCapturedItem::try_new(
                    stream_sequence,
                    *envelope.digest().as_bytes(),
                    payload.clone(),
                )
                .map_err(core)?,
            );
            expected_ordinal = expected_ordinal.checked_add(1).ok_or(
                CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
            )?;
            previous_subject_sequence = stream_sequence;
            previous_envelope_digest = *envelope.digest().as_bytes();
        }
    }

    let PendingQueueBoundaryObservation::NatsJetStream {
        seal_marker_stream_sequence,
        last_data_stream_sequence,
        ..
    } = source.boundary.observation()
    else {
        return Err(
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    };
    if *last_data_stream_sequence != previous_subject_sequence
        || *seal_marker_stream_sequence <= *last_data_stream_sequence
        || business_items.len() > quota.max_data_members() as usize
        || encoded_bytes > quota.max_data_stored_bytes()
    {
        return Err(
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    CoordinatorProcessorDurableCapturedSource::try_from_exhaustive_readback(
        source.kind,
        context,
        source.boundary.source_identity().digest(),
        source.boundary.digest(),
        business_items,
    )
    .map_err(core)
}

const fn publisher_kind(
    kind: CoordinatorProcessorSourceKind,
) -> PendingQueuePublisherKind {
    match kind {
        CoordinatorProcessorSourceKind::Registration => {
            PendingQueuePublisherKind::CoordinatorRegistration
        }
        CoordinatorProcessorSourceKind::Deploy => {
            PendingQueuePublisherKind::CoordinatorDeploy
        }
        CoordinatorProcessorSourceKind::Guta => {
            PendingQueuePublisherKind::CoordinatorGuta
        }
    }
}

fn core(
    error: CoordinatorProcessorDurableCaptureError,
) -> CoordinatorProcessorDurableProjectionError {
    CoordinatorProcessorDurableProjectionError::Core(error.to_string())
}

/// Verified-sidecar composition for the three fixed Coordinator sources.
/// The factory is crate-private: callers outside the Scylla rollback
/// composition cannot obtain an ACK-capable capture owner.
pub(crate) struct ScyllaCoordinatorProcessorDurableCaptureFactory<Hash> {
    network: NetworkId,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    nats: Arc<NatsJetStreamClient>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    provision: Arc<ScyllaPendingQueueStreamProvisionStore>,
    artifact: Arc<ScyllaPendingQueueArtifactStore>,
    consumer_gate: Arc<ScyllaPendingQueueConsumerGateStore>,
    _hash: PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaCoordinatorProcessorDurableCaptureFactory<Hash> {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        ready: &PendingQueueSidecarReady,
        nats: Arc<NatsJetStreamClient>,
    ) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if ready.view().authority() != AuthorityScope::Coordinator {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        }
        let keyspaces = ready.view().verified().stored().keyspaces();
        let control = keyspaces.control().clone();
        let pipeline = Arc::new(
            ScyllaPendingPipelineStore::prepare(session.clone(), control.clone())
                .await
                .map_err(backend)?,
        );
        let key = PendingGenerationLedgerKey::new(network, AuthorityScope::Coordinator);
        let PendingPipelineReadState::Current(current_pipeline) =
            pipeline.read::<Hash>(key).await.map_err(backend)?
        else {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        };
        if current_pipeline.key() != key || current_pipeline.blocked_reason().is_some() {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        }
        let writer_activation_digest = *current_pipeline.activation_digest().as_bytes();
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
        let consumer_gate = Arc::new(
            ScyllaPendingQueueConsumerGateStore::prepare(
                session.clone(),
                control,
            )
            .await
            .map_err(backend)?,
        );
        let artifact = Arc::new(
            ScyllaPendingQueueArtifactStore::prepare(
                session,
                keyspaces.artifact_keyspaces().map_err(backend)?,
            )
            .await
            .map_err(backend)?,
        );
        Ok(Self {
            network,
            writer_activation_digest,
            queue_readiness_digest: *ready.view().ready_digest(),
            nats,
            pipeline,
            ledger,
            provision,
            artifact,
            consumer_gate,
            _hash: PhantomData,
        })
    }

    async fn open_exact(
        self: &Arc<Self>,
        request: SealedCoordinatorProcessorDurableCaptureRequest,
    ) -> Result<ScyllaCoordinatorProcessorDurableCapture<Hash>, CoordinatorProcessorDurableCaptureError> {
        if request.network() != self.network
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
        {
            return Err(CoordinatorProcessorDurableCaptureError::RuntimeCapabilityMismatch);
        }
        let key = PendingGenerationLedgerKey::new(
            self.network,
            AuthorityScope::Coordinator,
        );
        let PendingPipelineReadState::Current(pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(backend)?
        else {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        };
        let activation = PendingGenerationActivationDigest::try_new(
            self.writer_activation_digest,
        )
        .map_err(backend)?;
        if pipeline.key() != key
            || pipeline.activation_digest() != activation
            || pipeline.blocked_reason().is_some()
            || !matches!(pipeline.processing_state(), PendingProcessingState::Sealing(_))
        {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        }
        let context = PendingQueueCaptureContext::try_new(
            key,
            activation,
            pipeline.processing(),
        )
        .map_err(backend)?;
        let close = self
            .pipeline
            .read_queue_close_exact::<Hash>(context)
            .await
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
            return Err(CoordinatorProcessorDurableCaptureError::RuntimeCapabilityMismatch);
        }
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
        let mut sources = Vec::with_capacity(CoordinatorProcessorSourceKind::ALL.len());
        for kind in CoordinatorProcessorSourceKind::ALL {
            let source_route = RecoverableNatsSourceRoute::try_new(
                context,
                publisher_kind(kind),
                publisher.segment(),
            )
            .map_err(backend)?;
            let spec = RecoverableNatsCaptureSpec::for_segment(
                publisher.segment().clone(),
                source_route.subject(),
                CAPTURE_BATCH_LIMIT,
            )
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
                Err(PendingQueueConsumerGateError::ProvisioningNotFound) => self
                    .consumer_gate
                    .provision_capture_consumer(
                        &self.nats,
                        &gate_open,
                        &live,
                        spec.clone(),
                        consumer_operation(&request, context, &spec)?,
                    )
                    .await
                    .map_err(backend)?,
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
            sources.push((kind, source));
        }
        self.pipeline
            .revalidate_queue_close_exact::<Hash>(context, &close)
            .await
            .map_err(backend)?;
        publisher.revalidate_exact().await.map_err(backend)?;
        Ok(ScyllaCoordinatorProcessorDurableCapture {
            pipeline: self.pipeline.clone(),
            publisher,
            context,
            close,
            sources,
            _hash: PhantomData,
        })
    }
}

#[async_trait]
impl<Hash> CoordinatorProcessorDurableCaptureFactory
    for ScyllaCoordinatorProcessorDurableCaptureFactory<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn writer_activation_digest(&self) -> [u8; 32] {
        self.writer_activation_digest
    }

    fn queue_readiness_digest(&self) -> [u8; 32] {
        self.queue_readiness_digest
    }

    async fn open(
        self: Arc<Self>,
        request: SealedCoordinatorProcessorDurableCaptureRequest,
    ) -> Result<Box<dyn CoordinatorProcessorDurableCapturePort>, CoordinatorProcessorDurableCaptureError> {
        Ok(Box::new(self.open_exact(request).await?))
    }
}

struct ScyllaCoordinatorProcessorDurableCapture<Hash> {
    pipeline: Arc<ScyllaPendingPipelineStore>,
    publisher: Arc<AssignmentBoundRecoverablePendingQueuePublisher>,
    context: PendingQueueCaptureContext,
    close: super::PersistedPendingQueueCloseReceipt,
    sources: Vec<(CoordinatorProcessorSourceKind, ScyllaBackedRecoverableNatsSource)>,
    _hash: PhantomData<Hash>,
}

impl<Hash> ScyllaCoordinatorProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn replay_exact(
        &self,
    ) -> Result<Option<CoordinatorProcessorDurableCapturedGeneration>, CoordinatorProcessorDurableCaptureError> {
        self.publisher.revalidate_exact().await.map_err(backend)?;
        let mut complete = Vec::with_capacity(self.sources.len());
        for (kind, source) in &self.sources {
            let Some((candidates, boundary)) = source
                .replay_closed_source::<Hash>(
                    &self.pipeline,
                    self.context,
                    &self.close,
                )
                .await
                .map_err(backend)?
            else {
                return Ok(None);
            };
            complete.push(CoordinatorProcessorClosedSourceReadback::new(
                *kind,
                candidates,
                boundary,
            ));
        }
        let generation = project_complete_generation(
            self.context,
            self.publisher.assignment_receipt().assignment(),
            complete,
        )
        .map_err(projection)?;
        self.publisher.revalidate_exact().await.map_err(backend)?;
        self.pipeline
            .revalidate_queue_close_exact::<Hash>(self.context, &self.close)
            .await
            .map_err(backend)?;
        Ok(Some(generation))
    }
}

#[async_trait]
impl<Hash> CoordinatorProcessorDurableCapturePort
    for ScyllaCoordinatorProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn capture_or_replay(
        &mut self,
    ) -> Result<Option<CoordinatorProcessorDurableCapturedGeneration>, CoordinatorProcessorDurableCaptureError> {
        if let Some(generation) = self.replay_exact().await? {
            return Ok(Some(generation));
        }
        for (_, source) in &self.sources {
            if source
                .replay_closed_source::<Hash>(
                    &self.pipeline,
                    self.context,
                    &self.close,
                )
                .await
                .map_err(backend)?
                .is_none()
            {
                source
                    .capture_one::<Hash>(
                        &self.pipeline,
                        self.context,
                        &self.close,
                    )
                    .await
                    .map_err(backend)?;
            }
        }
        self.replay_exact().await
    }
}

fn consumer_operation(
    request: &SealedCoordinatorProcessorDurableCaptureRequest,
    context: PendingQueueCaptureContext,
    spec: &RecoverableNatsCaptureSpec,
) -> Result<RecoverableNatsConsumerProvisioningOperationId, CoordinatorProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_OPERATION_DOMAIN);
    hasher.update(request.owner_attempt_digest());
    hasher.update(context.digest().as_bytes());
    hasher.update(spec.consumer_digest());
    RecoverableNatsConsumerProvisioningOperationId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_attempt(
    request: &SealedCoordinatorProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerAttemptId, CoordinatorProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_ATTEMPT_DOMAIN);
    hasher.update(request.owner_attempt_digest());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerAttemptId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_reason(
    request: &SealedCoordinatorProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerReasonDigest, CoordinatorProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_REASON_DOMAIN);
    hasher.update(request.writer_activation_digest());
    hasher.update(request.queue_readiness_digest());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerReasonDigest::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn projection(
    error: CoordinatorProcessorDurableProjectionError,
) -> CoordinatorProcessorDurableCaptureError {
    match error {
        CoordinatorProcessorDurableProjectionError::IdentityMismatch => {
            CoordinatorProcessorDurableCaptureError::IdentityMismatch
        }
        other => CoordinatorProcessorDurableCaptureError::Backend(other.to_string()),
    }
}

fn backend(error: impl fmt::Display) -> CoordinatorProcessorDurableCaptureError {
    CoordinatorProcessorDurableCaptureError::Backend(error.to_string())
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
            PendingQueueSourceCursor,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::PendingQueueCloseIntentDigest,
        },
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueueSourceQuota,
            RecoverableNatsSourceRoute,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    struct Fixture {
        context: PendingQueueCaptureContext,
        assignment: PendingQueueGenerationSegmentAssignment,
        routes: [RecoverableNatsSourceRoute; 3],
    }

    struct TestCaptureFactory;

    #[async_trait]
    impl CoordinatorProcessorDurableCaptureFactory for TestCaptureFactory {
        fn network(&self) -> NetworkId {
            NetworkId::try_from_chain_id(1337).unwrap()
        }

        fn writer_activation_digest(&self) -> [u8; 32] {
            [3; 32]
        }

        fn queue_readiness_digest(&self) -> [u8; 32] {
            [4; 32]
        }

        async fn open(
            self: Arc<Self>,
            _request: SealedCoordinatorProcessorDurableCaptureRequest,
        ) -> Result<
            Box<dyn CoordinatorProcessorDurableCapturePort>,
            CoordinatorProcessorDurableCaptureError,
        > {
            Err(CoordinatorProcessorDurableCaptureError::Backend(
                "test factory has no backend".to_owned(),
            ))
        }
    }

    fn fixture() -> Fixture {
        fixture_with_data_limits([127 * 1024 * 1024; 3])
    }

    fn fixture_with_data_limits(max_data_stored_bytes: [u64; 3]) -> Fixture {
        let generation_budget_bytes = max_data_stored_bytes
            .iter()
            .map(|bytes| bytes + 1024 * 1024)
            .sum::<u64>();
        let authority = AuthorityScope::Coordinator;
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(7, 99).unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                1024 * 1024 * 1024,
                i64::try_from(generation_budget_bytes).unwrap(),
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let quotas = [
            PendingQueuePublisherKind::CoordinatorRegistration,
            PendingQueuePublisherKind::CoordinatorDeploy,
            PendingQueuePublisherKind::CoordinatorGuta,
        ]
        .into_iter()
        .zip(max_data_stored_bytes)
        .map(|(kind, max_data_stored_bytes)| {
            PendingQueueSourceQuota::try_new(
                kind,
                100,
                max_data_stored_bytes,
                1024 * 1024,
            )
            .unwrap()
        })
        .collect();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            generation_budget_bytes,
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
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => {
                assignment
            }
            _ => unreachable!(),
        };
        let routes = [
            PendingQueuePublisherKind::CoordinatorRegistration,
            PendingQueuePublisherKind::CoordinatorDeploy,
            PendingQueuePublisherKind::CoordinatorGuta,
        ]
        .map(|kind| RecoverableNatsSourceRoute::try_new(context, kind, &segment).unwrap());
        Fixture {
            context,
            assignment,
            routes,
        }
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
        boundary_with_close(
            context,
            route,
            seal_sequence,
            last_data_sequence,
            9,
        )
    }

    fn boundary_with_close(
        context: PendingQueueCaptureContext,
        route: &RecoverableNatsSourceRoute,
        seal_sequence: u64,
        last_data_sequence: u64,
        close_marker: u8,
    ) -> PendingQueueGenerationBoundary {
        PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([close_marker; 32]).unwrap(),
            route.source_identity().clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: seal_sequence,
                last_data_stream_sequence: last_data_sequence,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap()
    }

    fn closed_source(
        fixture: &Fixture,
        kind: CoordinatorProcessorSourceKind,
        route_index: usize,
        base_sequence: u64,
        payloads: &[&[u8]],
    ) -> CoordinatorProcessorClosedSourceReadback {
        let route = &fixture.routes[route_index];
        let mut previous_sequence = 0;
        let mut previous_digest = [0; 32];
        let mut envelopes = Vec::with_capacity(payloads.len());
        let mut sequences = Vec::with_capacity(payloads.len());
        for (index, payload) in payloads.iter().enumerate() {
            let sequence = base_sequence + index as u64;
            let envelope = data(
                route,
                &fixture.assignment,
                index as u32 + 1,
                previous_sequence,
                previous_digest,
                payload,
            );
            previous_sequence = sequence;
            previous_digest = *envelope.digest().as_bytes();
            sequences.push(sequence);
            envelopes.push(envelope);
        }
        let candidates = if envelopes.is_empty() {
            Vec::new()
        } else {
            vec![candidate(
                fixture.context,
                route,
                &sequences,
                &envelopes,
            )]
        };
        CoordinatorProcessorClosedSourceReadback::new(
            kind,
            candidates,
            boundary(
                fixture.context,
                route,
                previous_sequence.saturating_add(1).max(1),
                previous_sequence,
            ),
        )
    }

    #[test]
    fn three_closed_sources_project_in_fixed_order_with_explicit_empty() {
        let fixture = fixture();
        let generation = project_complete_generation(
            fixture.context,
            &fixture.assignment,
            vec![
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Registration,
                    0,
                    10,
                    &[b"registration-1", b"registration-2"],
                ),
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Deploy,
                    1,
                    20,
                    &[],
                ),
                closed_source(
                    &fixture,
                    CoordinatorProcessorSourceKind::Guta,
                    2,
                    30,
                    &[b"guta-1"],
                ),
            ],
        )
        .unwrap();

        assert_eq!(generation.total_items(), 3);
        assert_eq!(generation.registration().items().len(), 2);
        assert!(generation.deploy().items().is_empty());
        assert_eq!(generation.guta().items().len(), 1);
        assert_ne!(generation.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn missing_or_wrongly_ordered_source_is_rejected() {
        let fixture = fixture();
        let sources = vec![
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Deploy,
                1,
                20,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Registration,
                0,
                10,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Guta,
                2,
                30,
                &[],
            ),
        ];
        assert_eq!(
            project_complete_generation(
                fixture.context,
                &fixture.assignment,
                sources,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::IdentityMismatch,
        );
    }

    #[test]
    fn publisher_kind_chain_and_boundary_are_fail_closed() {
        let fixture = fixture();
        let wrong_kind = closed_source(
            &fixture,
            CoordinatorProcessorSourceKind::Registration,
            2,
            10,
            &[b"wrong-publisher"],
        );
        assert_eq!(
            project_complete_source(
                fixture.context,
                &fixture.assignment,
                wrong_kind,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );

        let route = &fixture.routes[0];
        let first = data(route, &fixture.assignment, 1, 0, [0; 32], b"first");
        let second = data(
            route,
            &fixture.assignment,
            2,
            9,
            *first.digest().as_bytes(),
            b"second",
        );
        let broken = CoordinatorProcessorClosedSourceReadback::new(
            CoordinatorProcessorSourceKind::Registration,
            vec![candidate(
                fixture.context,
                route,
                &[10, 11],
                &[first, second],
            )],
            boundary(fixture.context, route, 12, 11),
        );
        assert_eq!(
            project_complete_source(
                fixture.context,
                &fixture.assignment,
                broken,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    #[test]
    fn cross_source_close_and_assignment_quota_are_enforced() {
        let fixture = fixture();
        let mut sources = vec![
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Registration,
                0,
                10,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Deploy,
                1,
                20,
                &[],
            ),
            closed_source(
                &fixture,
                CoordinatorProcessorSourceKind::Guta,
                2,
                30,
                &[],
            ),
        ];
        sources[2].boundary = boundary_with_close(
            fixture.context,
            &fixture.routes[2],
            1,
            0,
            7,
        );
        assert_eq!(
            project_complete_generation(
                fixture.context,
                &fixture.assignment,
                sources,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::IdentityMismatch,
        );

        let tiny = fixture_with_data_limits([
            1,
            127 * 1024 * 1024,
            127 * 1024 * 1024,
        ]);
        let oversized = closed_source(
            &tiny,
            CoordinatorProcessorSourceKind::Registration,
            0,
            10,
            &[b"larger-than-one-byte"],
        );
        assert_eq!(
            project_complete_source(tiny.context, &tiny.assignment, oversized)
                .unwrap_err(),
            CoordinatorProcessorDurableProjectionError::MalformedCompleteSource,
        );
    }

    #[test]
    fn process_attempt_and_source_identity_domain_separate_owner_fences() {
        let fixture = fixture();
        let factory = TestCaptureFactory;
        let first_request =
            SealedCoordinatorProcessorDurableCaptureRequest::seal(&factory, [9; 32])
                .unwrap();
        let second_request =
            SealedCoordinatorProcessorDurableCaptureRequest::seal(&factory, [10; 32])
                .unwrap();
        let registration = PendingQueueArtifactIdentity::try_new(
            fixture.context,
            fixture.routes[0].source_identity().clone(),
        )
        .unwrap();
        let deploy = PendingQueueArtifactIdentity::try_new(
            fixture.context,
            fixture.routes[1].source_identity().clone(),
        )
        .unwrap();

        let first_registration = owner_attempt(&first_request, &registration).unwrap();
        assert_eq!(
            first_registration,
            owner_attempt(&first_request, &registration).unwrap(),
        );
        assert_ne!(
            first_registration,
            owner_attempt(&second_request, &registration).unwrap(),
        );
        assert_ne!(
            first_registration,
            owner_attempt(&first_request, &deploy).unwrap(),
        );
        assert_eq!(
            owner_reason(&first_request, &registration).unwrap(),
            owner_reason(&second_request, &registration).unwrap(),
        );
    }

    #[test]
    fn storage_owner_keeps_ack_tokens_and_pipeline_mutation_private() {
        let source = include_str!("coordinator_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("double_ack"));
        assert!(production.contains("ScyllaBackedRecoverableNatsSource"));
        assert!(production.contains("capture_one::<Hash>"));
        assert!(production.contains("replay_closed_source::<Hash>"));
        assert!(production.contains("CoordinatorProcessorSourceKind::ALL"));
        assert!(production.contains("read_queue_close_exact::<Hash>"));
        assert!(production.contains("revalidate_queue_close_exact::<Hash>"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("PendingPipelineWriteOutcome"));
        let prepare = production
            .split("pub(crate) async fn prepare")
            .nth(1)
            .unwrap()
            .split("async fn open_exact")
            .next()
            .unwrap();
        assert!(prepare.contains("PendingPipelineReadState::Current"));
        assert!(prepare.contains("current_pipeline.activation_digest()"));
        assert!(!prepare.contains("writer_activation_digest: [u8; 32]"));
    }
}
