//! Storage-owned durable capture authority for one Realm Processor iteration.
//!
//! This is intentionally not wired to the legacy gatherer yet.  It composes
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
        realm_processor_durable_capture::{
            RealmProcessorDurableCaptureError,
            RealmProcessorDurableCaptureFactory,
            RealmProcessorDurableCaptureOutcome,
            RealmProcessorDurableCapturePort,
            RealmProcessorDurableCapturedBatch,
            RealmProcessorDurableCapturedGeneration,
            SealedRealmProcessorDurableCaptureRequest,
        },
        recoverable_artifact::{
            PendingQueueArtifactOwnerAttemptId,
            PendingQueueArtifactOwnerReasonDigest,
        },
        recoverable_ephemeral::{
            PendingQueueArtifactIdentity, PendingQueueBoundaryObservation,
            PendingQueueCaptureCandidate, PendingQueueGenerationBoundary,
            PendingQueueSourceCursorView,
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
};
use super::pending_queue_consumer_gate::{
    PendingQueueConsumerGateError, PendingQueueConsumerGateIdentity,
    ScyllaPendingQueueConsumerGateStore,
};
use super::pending_queue_nats_capture::{
    PendingQueueNatsCaptureOutcome, ScyllaBackedRecoverableNatsSource,
};
use super::pending_queue_stream_provision::ScyllaPendingQueueStreamProvisionStore;

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
            authority,
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
        &self,
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

        let close = self
            .pipeline
            .read_queue_close_exact::<Hash>(context)
            .await
            .map_err(backend)?;
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
        let provisioned = self
            .provision
            .read_provisioned(route.ledger_key(), route.segment())
            .await
            .map_err(backend)?;
        let live = self
            .nats
            .observe_recoverable_segment_instance(route.segment().clone())
            .await
            .map_err(backend)?;
        if live.instance_id() != provisioned.instance_id() {
            return Err(RealmProcessorDurableCaptureError::RuntimeCapabilityMismatch);
        }

        let source_route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::RealmUserUpdate,
            route.segment(),
        )
        .map_err(backend)?;
        let spec = RecoverableNatsCaptureSpec::for_segment(
            route.segment().clone(),
            source_route.subject(),
            CAPTURE_BATCH_LIMIT,
        )
        .map_err(backend)?;
        let gate_identity = PendingQueueConsumerGateIdentity::new(
            route.segment().segment_id(),
            route.segment().digest(),
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
        Ok(ScyllaRealmProcessorDurableCapture {
            source,
            pipeline: self.pipeline.clone(),
            context,
            close,
            assignment: route.assignment().assignment().clone(),
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

    async fn open(
        &self,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError> {
        Ok(Box::new(self.open_exact(request).await?))
    }
}

struct ScyllaRealmProcessorDurableCapture<Hash> {
    source: ScyllaBackedRecoverableNatsSource,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    context: psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext,
    close: super::PersistedPendingQueueCloseReceipt,
    assignment: PendingQueueGenerationSegmentAssignment,
    _hash: PhantomData<Hash>,
}

#[async_trait]
impl<Hash> RealmProcessorDurableCapturePort
    for ScyllaRealmProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn capture_next(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError> {
        self.source
            .capture_one::<Hash>(&self.pipeline, self.context, &self.close)
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
        let Some((candidates, boundary)) = self
            .source
            .replay_closed_source::<Hash>(&self.pipeline, self.context, &self.close)
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        project_complete_generation(self.context, &self.assignment, candidates, boundary)
            .map(Some)
    }
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
            business_items.push(payload.clone());
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
}
