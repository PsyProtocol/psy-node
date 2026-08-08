//! Default-off composition of one dedicated JetStream pull consumer and the
//! Scylla pending-queue artifact store.
//!
//! The module is deliberately crate-private.  Keeping the unacknowledged NATS
//! messages, the opaque Scylla readback receipt, the terminal ACK, and the
//! header continuation in one boundary prevents a caller from manufacturing
//! an ACK claim.  Production setup and legacy queue publishers do not refer to
//! this module yet.

use std::{
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueArtifactIdentity, PendingQueueBoundaryObservation,
    PendingQueueCaptureCandidate, PendingQueueCaptureContext,
    PendingQueueGenerationBoundary, PendingQueueSourceCursor,
    PendingQueueSourceCursorView,
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_publish::{
        PendingQueueEnvelopeBody, PendingQueuePublishEnvelope,
        PendingQueuePublisherKind,
    },
    recoverable_transport::{
        RecoverableNatsCaptureConsumer, RecoverableNatsCaptureSpec,
        RecoverableNatsDeliveryBatch, RecoverableNatsTransportError,
    },
};
use tokio::sync::Mutex;

use super::{
    DurablySelectedPendingQueueBatchReceipt, PendingQueueArtifactStoreError,
    PendingQueueArtifactOwnerPermit, PersistedPendingQueueCloseReceipt,
    ScyllaPendingPipelineStore, ScyllaPendingQueueArtifactStore,
};

const DEFAULT_FETCH_EXPIRES: Duration = Duration::from_millis(250);

type RecoverableNatsConsumerContract = RecoverableNatsCaptureSpec;

#[derive(Debug)]
pub(super) enum PendingQueueNatsCaptureOutcome {
    Data(PendingQueueCaptureCandidate),
    Sealed {
        data: Option<PendingQueueCaptureCandidate>,
        boundary: PendingQueueGenerationBoundary,
    },
}

struct ClassifiedRecoverableDelivery {
    token: RecoverableNatsDeliveryBatch,
    data: Option<PendingQueueCaptureCandidate>,
    data_count: usize,
    boundary: Option<PendingQueueGenerationBoundary>,
}

fn verify_candidate<'candidate>(
    contract: &RecoverableNatsConsumerContract,
    candidate: &'candidate PendingQueueCaptureCandidate,
) -> Result<&'candidate [u64], PendingQueueNatsCaptureError> {
    if candidate.source_identity()
        != &contract
            .source_identity()
            .map_err(nats_transport)?
    {
        return Err(PendingQueueNatsCaptureError::SourceIdentityMismatch);
    }
    let PendingQueueSourceCursorView::NatsJetStream {
        consumer_digest,
        stream_sequences,
        ..
    } = candidate.source().view()
    else {
        return Err(PendingQueueNatsCaptureError::SourceCursorMismatch);
    };
    if consumer_digest != &contract.consumer_digest() {
        return Err(PendingQueueNatsCaptureError::ConsumerDigestMismatch);
    }
    Ok(stream_sequences)
}

/// Concrete default-off composition.  No constructor is exported from the
/// rollback module and production setup does not instantiate it.
pub(super) struct ScyllaBackedRecoverableNatsSource {
    client: Arc<NatsJetStreamClient>,
    store: Arc<ScyllaPendingQueueArtifactStore>,
    contract: RecoverableNatsConsumerContract,
    owner: PendingQueueArtifactOwnerPermit,
    fetch_expires: Duration,
    serial: Mutex<()>,
}

impl ScyllaBackedRecoverableNatsSource {
    pub(super) fn new(
        client: Arc<NatsJetStreamClient>,
        store: Arc<ScyllaPendingQueueArtifactStore>,
        contract: RecoverableNatsConsumerContract,
        owner: PendingQueueArtifactOwnerPermit,
    ) -> Result<Self, PendingQueueNatsCaptureError> {
        if client.base_namespace() != contract.namespace() {
            return Err(PendingQueueNatsCaptureError::ClientContractMismatch);
        }
        Ok(Self {
            client,
            store,
            contract,
            owner,
            fetch_expires: DEFAULT_FETCH_EXPIRES,
            serial: Mutex::new(()),
        })
    }

    /// Recovers a previously selected batch first; otherwise fetches one new
    /// unacknowledged batch.  Exact Scylla readback always precedes terminal
    /// Data ACK is confirmed before Data progress advances; a trailing Seal is
    /// ACKed only after its exact CloseObserved boundary is durable.
    pub(super) async fn capture_one<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        context: PendingQueueCaptureContext,
        close_receipt: &PersistedPendingQueueCloseReceipt,
    ) -> Result<Option<PendingQueueNatsCaptureOutcome>, PendingQueueNatsCaptureError> {
        if !close_receipt.matches_context(context) {
            return Err(PendingQueueNatsCaptureError::CloseContextMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(context, close_receipt)
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Pipeline(error.to_string()))?;
        let _serial = self.serial.lock().await;
        let identity = PendingQueueArtifactIdentity::try_new(
            context,
            self.contract
                .source_identity()
                .map_err(nats_transport)?,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        if self.owner.slot()
            != psy_node_core::queue::recoverable_artifact::slot_for(&identity)
        {
            return Err(PendingQueueNatsCaptureError::OwnerPermitMismatch);
        }
        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        let mut consumer = self.ensure_attested_consumer().await?;
        // Consumer lookup/validation crosses systems and may take an
        // unbounded amount of time. Revalidate immediately before either
        // recovery fetch or a new pull so a completed takeover fences this
        // instance before it can consume max_ack_pending capacity.
        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;

        if let Some((selected, receipt)) = self
            .store
            .recover_selected_batch(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?
        {
            verify_candidate(&self.contract, &selected)?;
            if self.ack_floor_covers(&mut consumer, &selected).await? {
                self.confirm_after_ack(receipt, &selected).await?;
                return Ok(Some(PendingQueueNatsCaptureOutcome::Data(selected)));
            }
            let token = self
                .fetch_exact_candidate(&mut consumer, &selected)
                .await?;
            self.ack_and_confirm(token, receipt, &selected, &mut consumer)
                .await?;
            return Ok(Some(PendingQueueNatsCaptureOutcome::Data(selected)));
        }

        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        let Some(classified) = self.fetch_new(&mut consumer, context).await? else {
            return Ok(None);
        };
        if classified
            .boundary
            .as_ref()
            .is_some_and(|boundary| boundary.close_intent() != close_receipt.close_intent())
        {
            return Err(PendingQueueNatsCaptureError::CloseIntentMismatch);
        }
        let (data_token, seal_token) = classified
            .token
            .split_at(classified.data_count)
            .map_err(nats_transport)?;
        let receipt = match classified.data.as_ref() {
            Some(candidate) => Some(
                self.store
                    .persist_selected_batch(&self.owner, candidate)
                    .await
                    .map_err(PendingQueueNatsCaptureError::Store)?,
            ),
            None => None,
        };
        if let (Some(receipt), Some(candidate)) =
            (receipt, classified.data.as_ref())
        {
            data_token
                .ok_or(PendingQueueNatsCaptureError::DeliveryContract)?
                .double_ack_all(&mut consumer)
                .await
                .map_err(nats_transport)?;
            if !self.ack_floor_covers(&mut consumer, candidate).await? {
                return Err(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery);
            }
            self.confirm_after_ack(receipt, candidate).await?;
        } else if data_token.is_some() {
            return Err(PendingQueueNatsCaptureError::DeliveryContract);
        }
        if let Some(boundary) = classified.boundary.as_ref() {
            pipeline_store
                .revalidate_queue_close_exact::<Hash>(context, close_receipt)
                .await
                .map_err(|error| PendingQueueNatsCaptureError::Pipeline(error.to_string()))?;
            self.store
                .observe_close_before_backend_ack(
                    &self.owner,
                    &identity,
                    boundary.clone(),
                )
                .await
                .map_err(PendingQueueNatsCaptureError::Store)?;
            let seal_token =
                seal_token.ok_or(PendingQueueNatsCaptureError::DeliveryContract)?;
            if seal_token.len() != 1 {
                return Err(PendingQueueNatsCaptureError::DeliveryContract);
            }
            seal_token
                .double_ack_all(&mut consumer)
                .await
                .map_err(nats_transport)?;
        } else if seal_token.is_some() {
            return Err(PendingQueueNatsCaptureError::DeliveryContract);
        }
        Ok(Some(match classified.boundary {
            Some(boundary) => PendingQueueNatsCaptureOutcome::Sealed {
                data: classified.data,
                boundary,
            },
            None => PendingQueueNatsCaptureOutcome::Data(
                classified
                    .data
                    .ok_or(PendingQueueNatsCaptureError::DeliveryContract)?,
            ),
        }))
    }

    async fn ensure_attested_consumer(
        &self,
    ) -> Result<RecoverableNatsCaptureConsumer, PendingQueueNatsCaptureError> {
        self.client
            .open_recoverable_capture(self.contract.clone())
            .await
            .map_err(nats_transport)
    }

    async fn fetch_new(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        context: PendingQueueCaptureContext,
    ) -> Result<
        Option<ClassifiedRecoverableDelivery>,
        PendingQueueNatsCaptureError,
    > {
        let token = self
            .fetch_token(consumer, self.contract.max_batch_items())
            .await?;
        let Some(token) = token else {
            return Ok(None);
        };
        classify_delivery(&self.contract, context, token).map(Some)
    }

    async fn fetch_exact_candidate(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        selected: &PendingQueueCaptureCandidate,
    ) -> Result<RecoverableNatsDeliveryBatch, PendingQueueNatsCaptureError> {
        let expected_sequences = verify_candidate(&self.contract, selected)?;
        let ack_floor_stream_sequence = consumer
            .observation()
            .await
            .map_err(nats_transport)?
            .ack_floor_stream_sequence();
        let remaining = &expected_sequences[expected_sequences
            .partition_point(|sequence| *sequence <= ack_floor_stream_sequence)..];
        if remaining.is_empty() {
            return Err(PendingQueueNatsCaptureError::AckFloorAlreadyComplete);
        }
        let token = self
            .fetch_token(consumer, remaining.len())
            .await?
            .ok_or(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery)?;
        verify_unacked_prefix(
            expected_sequences,
            selected.items(),
            ack_floor_stream_sequence,
            token.stream_sequences(),
            token.payloads().iter().map(Vec::as_slice),
        )
        .map_err(|_| PendingQueueNatsCaptureError::RedeliveryMismatch)?;
        Ok(token)
    }

    async fn fetch_token(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        max_items: usize,
    ) -> Result<Option<RecoverableNatsDeliveryBatch>, PendingQueueNatsCaptureError> {
        consumer
            .fetch(max_items, self.fetch_expires)
            .await
            .map_err(nats_transport)
    }

    async fn ack_and_confirm(
        &self,
        token: RecoverableNatsDeliveryBatch,
        receipt: DurablySelectedPendingQueueBatchReceipt,
        candidate: &PendingQueueCaptureCandidate,
        consumer: &mut RecoverableNatsCaptureConsumer,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        let expected = verify_candidate(&self.contract, candidate)?;
        let before = consumer
            .observation()
            .await
            .map_err(nats_transport)?;
        verify_unacked_prefix(
            expected,
            candidate.items(),
            before.ack_floor_stream_sequence(),
            token.stream_sequences(),
            token.payloads().iter().map(Vec::as_slice),
        )
        .map_err(|_| PendingQueueNatsCaptureError::AckTokenMismatch)?;
        token
            .double_ack_all(consumer)
            .await
            .map_err(nats_transport)?;
        if !self.ack_floor_covers(consumer, candidate).await? {
            return Err(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery);
        }
        self.confirm_after_ack(receipt, candidate).await
    }

    async fn ack_floor_covers(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<bool, PendingQueueNatsCaptureError> {
        let sequences = verify_candidate(&self.contract, candidate)?;
        let last = *sequences
            .last()
            .ok_or(PendingQueueNatsCaptureError::SourceCursorMismatch)?;
        let info = consumer
            .observation()
            .await
            .map_err(nats_transport)?;
        Ok(info.ack_floor_consumer_sequence() > 0
            && info.ack_floor_stream_sequence() >= last)
    }

    async fn confirm_after_ack(
        &self,
        receipt: DurablySelectedPendingQueueBatchReceipt,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        self.store
            .confirm_selected_ack_after_backend(&self.owner, receipt, candidate)
            .await
            .map(|_| ())
            .map_err(PendingQueueNatsCaptureError::Store)
    }
}

fn classify_delivery(
    contract: &RecoverableNatsConsumerContract,
    context: PendingQueueCaptureContext,
    token: RecoverableNatsDeliveryBatch,
) -> Result<ClassifiedRecoverableDelivery, PendingQueueNatsCaptureError> {
    let (data, boundary) = classify_payloads(
        contract,
        context,
        token.stream_sequences(),
        token.payloads(),
    )?;
    let data_count = usize::try_from(data.as_ref().map_or(0, |value| value.item_count()))
        .map_err(|_| PendingQueueNatsCaptureError::DeliveryContract)?;
    Ok(ClassifiedRecoverableDelivery {
        token,
        data_count,
        data,
        boundary,
    })
}

fn classify_payloads(
    contract: &RecoverableNatsConsumerContract,
    context: PendingQueueCaptureContext,
    stream_sequences: &[u64],
    payloads: &[Vec<u8>],
) -> Result<
    (
        Option<PendingQueueCaptureCandidate>,
        Option<PendingQueueGenerationBoundary>,
    ),
    PendingQueueNatsCaptureError,
> {
    if stream_sequences.len() != payloads.len() || stream_sequences.is_empty() {
        return Err(PendingQueueNatsCaptureError::DeliveryContract);
    }
    let source_identity = contract.source_identity().map_err(nats_transport)?;
    let mut publisher_kind: Option<PendingQueuePublisherKind> = None;
    let mut previous_in_batch: Option<(u64, [u8; 32])> = None;
    let mut data_sequences = Vec::new();
    let mut data_items = Vec::new();
    let mut boundary = None;
    for (stream_sequence, canonical_envelope) in stream_sequences
        .iter()
        .copied()
        .zip(payloads)
    {
        if boundary.is_some() {
            return Err(PendingQueueNatsCaptureError::DataAfterSeal);
        }
        let envelope = PendingQueuePublishEnvelope::decode_canonical(
            canonical_envelope,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Envelope(error.to_string()))?;
        if envelope.artifact_identity().context() != context
            || envelope.artifact_identity().source() != &source_identity
            || publisher_kind.is_some_and(|kind| kind != envelope.publisher_kind())
        {
            return Err(PendingQueueNatsCaptureError::SourceIdentityMismatch);
        }
        publisher_kind.get_or_insert(envelope.publisher_kind());
        if let Some((previous_sequence, previous_digest)) = previous_in_batch {
            if envelope.previous_subject_sequence() != previous_sequence
                || envelope.previous_envelope_digest() != previous_digest
            {
                return Err(PendingQueueNatsCaptureError::EnvelopeChainMismatch);
            }
        }
        previous_in_batch = Some((stream_sequence, *envelope.digest().as_bytes()));
        match envelope.body() {
            PendingQueueEnvelopeBody::Data(_) => {
                data_sequences.push(stream_sequence);
                data_items.push(canonical_envelope.clone());
            }
            PendingQueueEnvelopeBody::Seal(summary) => {
                boundary = Some(
                    PendingQueueGenerationBoundary::try_from_backend_observation(
                        context,
                        summary.close_intent(),
                        source_identity.clone(),
                        PendingQueueBoundaryObservation::NatsJetStream {
                            seal_marker_stream_sequence: stream_sequence,
                            last_data_stream_sequence: envelope
                                .previous_subject_sequence(),
                            seal_marker_digest: *envelope.digest().as_bytes(),
                        },
                    )
                    .map_err(|error| {
                        PendingQueueNatsCaptureError::Core(error.to_string())
                    })?,
                );
            }
        }
    }

    let data = if data_items.is_empty() {
        None
    } else {
        let cursor = PendingQueueSourceCursor::nats_jetstream(
            contract.consumer_digest(),
            &data_sequences,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        Some(
            PendingQueueCaptureCandidate::try_new(
                context,
                source_identity,
                cursor,
                data_items,
            )
            .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?,
        )
    };
    if data.is_none() && boundary.is_none() {
        return Err(PendingQueueNatsCaptureError::DeliveryContract);
    }
    Ok((data, boundary))
}

fn verify_unacked_prefix<'payload>(
    expected_sequences: &[u64],
    expected_items: &[Vec<u8>],
    ack_floor_stream_sequence: u64,
    actual_sequences: &[u64],
    actual_items: impl Iterator<Item = &'payload [u8]>,
) -> Result<(), ()> {
    let first_unacked = expected_sequences
        .partition_point(|sequence| *sequence <= ack_floor_stream_sequence);
    let remaining_sequences = &expected_sequences[first_unacked..];
    if actual_sequences.is_empty()
        || actual_sequences.len() > remaining_sequences.len()
        || actual_sequences != &remaining_sequences[..actual_sequences.len()]
        || actual_items.ne(
            expected_items[first_unacked..first_unacked + actual_sequences.len()]
                .iter()
                .map(Vec::as_slice),
        )
    {
        Err(())
    } else {
        Ok(())
    }
}

fn nats_transport(error: RecoverableNatsTransportError) -> PendingQueueNatsCaptureError {
    PendingQueueNatsCaptureError::Nats(error.to_string())
}

#[derive(Debug)]
pub(super) enum PendingQueueNatsCaptureError {
    EmptyAddressComponent,
    InvalidReplicaRequirement(usize),
    InvalidBatchLimit(usize),
    EmptyConsumerDigest,
    ClientContractMismatch,
    OwnerPermitMismatch,
    CloseContextMismatch,
    CloseIntentMismatch,
    StreamContract(String),
    ConsumerContract,
    SourceIdentityMismatch,
    SourceCursorMismatch,
    ConsumerDigestMismatch,
    DeliveryContract,
    Envelope(String),
    EnvelopeChainMismatch,
    DataAfterSeal,
    SelectedAwaitingRedelivery,
    RedeliveryMismatch,
    AckTokenMismatch,
    AckFloorAlreadyComplete,
    AckIndeterminate(String),
    Core(String),
    Pipeline(String),
    Nats(String),
    Store(PendingQueueArtifactStoreError),
}

impl fmt::Display for PendingQueueNatsCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAddressComponent => formatter.write_str("empty NATS address component"),
            Self::InvalidReplicaRequirement(value) => {
                write!(formatter, "invalid minimum stream replicas {value}")
            }
            Self::InvalidBatchLimit(value) => write!(formatter, "invalid batch limit {value}"),
            Self::EmptyConsumerDigest => formatter.write_str("empty consumer digest"),
            Self::ClientContractMismatch => formatter.write_str("NATS client/contract mismatch"),
            Self::OwnerPermitMismatch => formatter.write_str("artifact owner permit mismatch"),
            Self::CloseContextMismatch => formatter.write_str("durable close context mismatch"),
            Self::CloseIntentMismatch => formatter.write_str("durable close intent mismatch"),
            Self::StreamContract(reason) => write!(formatter, "unsafe stream contract: {reason}"),
            Self::ConsumerContract => formatter.write_str("dedicated consumer contract mismatch"),
            Self::SourceIdentityMismatch => formatter.write_str("source identity mismatch"),
            Self::SourceCursorMismatch => formatter.write_str("source cursor mismatch"),
            Self::ConsumerDigestMismatch => formatter.write_str("consumer digest mismatch"),
            Self::DeliveryContract => formatter.write_str("NATS delivery contract mismatch"),
            Self::Envelope(reason) => write!(formatter, "invalid recoverable envelope: {reason}"),
            Self::EnvelopeChainMismatch => formatter.write_str("recoverable envelope chain mismatch"),
            Self::DataAfterSeal => formatter.write_str("recoverable Data observed after Seal"),
            Self::SelectedAwaitingRedelivery => formatter.write_str("selected batch awaits redelivery"),
            Self::RedeliveryMismatch => formatter.write_str("redelivery differs from durable selection"),
            Self::AckTokenMismatch => formatter.write_str("ACK token differs from durable selection"),
            Self::AckFloorAlreadyComplete => formatter.write_str("ACK floor already covers selected batch"),
            Self::AckIndeterminate(reason) => write!(formatter, "NATS ACK is indeterminate: {reason}"),
            Self::Core(reason) => write!(formatter, "core queue contract failed: {reason}"),
            Self::Pipeline(reason) => write!(formatter, "pipeline close fence failed: {reason}"),
            Self::Nats(reason) => write!(formatter, "NATS operation failed: {reason}"),
            Self::Store(error) => write!(formatter, "artifact store failed: {error}"),
        }
    }
}

impl Error for PendingQueueNatsCaptureError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_node_core::store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::PendingQueueCloseIntentDigest,
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueGenerationSegmentAssignment,
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueuePublishSourceState,
            PendingQueueSourceQuota, RecoverableNatsSourceRoute,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    fn contract() -> RecoverableNatsConsumerContract {
        RecoverableNatsConsumerContract::try_new(
            "psy",
            "psy_stream",
            "psy.pq.r0.rs0.u1.qt1.g0",
            3,
            1024,
        )
        .unwrap()
    }

    fn branch_exact_fixture() -> (
        PendingQueueCaptureContext,
        PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
        RecoverableNatsConsumerContract,
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
            PendingGenerationContext::try_from_legacy(7, 99).unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
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
        let quota = PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            100,
            127 * 1024 * 1024,
            1024 * 1024,
        )
        .unwrap();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            vec![quota],
            128 * 1024 * 1024,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &validated,
            budget,
            8,
        )
        .unwrap();
        let assignment = match bootstrap
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
        let contract = RecoverableNatsConsumerContract::for_segment(
            segment,
            route.subject(),
            1024,
        )
        .unwrap();
        (context, assignment, route, contract)
    }

    #[test]
    fn typed_transport_contract_remains_deterministic() {
        let first = contract();
        let second = contract();
        assert_eq!(first, second);
        assert_eq!(first.durable(), second.durable());
        assert_eq!(first.namespace(), "psy");
        assert_eq!(first.stream(), "psy_stream");
        assert_eq!(first.subject(), "psy.pq.r0.rs0.u1.qt1.g0");
        assert_ne!(first.consumer_digest(), [0; 32]);
    }

    #[test]
    fn partial_ack_recovery_accepts_only_the_exact_remaining_prefix() {
        let sequences = [10, 12, 15, 19];
        let items = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];

        // No ACK: the complete delivery is valid.
        verify_unacked_prefix(
            &sequences,
            &items,
            0,
            &sequences,
            items.iter().map(Vec::as_slice),
        )
        .unwrap();
        // One ACK and N-1 ACKs: a partial redelivery prefix is valid and can
        // make bounded progress across repeated capture calls.
        verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[12, 15],
            items[1..3].iter().map(Vec::as_slice),
        )
        .unwrap();
        verify_unacked_prefix(
            &sequences,
            &items,
            15,
            &[19],
            items[3..].iter().map(Vec::as_slice),
        )
        .unwrap();

        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[15],
            items[2..3].iter().map(Vec::as_slice),
        )
        .is_err());
        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[12],
            items[2..3].iter().map(Vec::as_slice),
        )
        .is_err());
        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            19,
            &[],
            std::iter::empty(),
        )
        .is_err());
    }

    #[test]
    fn typed_classifier_excludes_seal_from_business_artifact() {
        let (context, assignment, route, contract) = branch_exact_fixture();
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([11; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            b"payload".to_vec(),
        )
        .unwrap();
        let mut source = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        let selected = source.select(&data).unwrap().current().clone();
        let accepted = selected.record_published(10).unwrap();
        source = accepted
            .candidate()
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([12; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            10,
            *data.digest().as_bytes(),
            source
                .seal_summary(PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let (candidate, boundary) = classify_payloads(
            &contract,
            context,
            &[10, 20],
            &[data.to_canonical_bytes(), seal.to_canonical_bytes()],
        )
        .unwrap();
        let candidate = candidate.unwrap();
        assert_eq!(candidate.items(), &[data.to_canonical_bytes()]);
        assert_eq!(candidate.item_count(), 1);
        assert_eq!(
            boundary.unwrap().close_intent(),
            PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap()
        );

        assert!(matches!(
            classify_payloads(
                &contract,
                context,
                &[20, 30],
                &[seal.to_canonical_bytes(), data.to_canonical_bytes()],
            ),
            Err(PendingQueueNatsCaptureError::DataAfterSeal)
        ));
    }

}
