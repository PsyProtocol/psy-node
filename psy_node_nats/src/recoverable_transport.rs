//! Narrow JetStream transport capabilities for recoverable pending queues.
//!
//! Raw [`jetstream::Context`] never leaves `psy_node_nats`.  Producers may
//! publish only a typed canonical envelope to its exact V2 segment subject;
//! capture code may only open an attested explicit-ACK consumer and receive an
//! opaque delivery batch whose raw messages can only be acknowledged through
//! this module.

use std::{error::Error, fmt, sync::Arc, time::Duration};

use async_nats::{
    jetstream::{
        self,
        consumer::{
            pull::Config as PullConfig, AckPolicy, DeliverPolicy, PullConsumer,
            ReplayPolicy,
        },
        context::Publish,
        stream::{RawMessageErrorKind, RetentionPolicy, StorageType},
    },
    ToServerAddrs,
};
use bytes::Bytes;
use futures::StreamExt;
use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueSourceIdentity, MAX_RECOVERABLE_QUEUE_BATCH_ITEMS,
};
use sha2::{Digest, Sha256};

use crate::{
    queue::NatsJetStreamClient,
    recoverable_assignment::PendingQueueGenerationSegmentAssignment,
    recoverable_publish::{
        PendingQueuePublishEnvelope, PendingQueuePublisherKind,
        RecoverableNatsSourceRoute,
    },
    recoverable_segment::RecoverableNatsStreamSegment,
    recoverable_terminal::{
        PendingQueueSourceTruncationReceipt, PendingQueueSourceTruncationScanner,
        PendingQueueTerminalError,
    },
};

const DURABLE_PREFIX: &str = "psy_beq_v2_";
const DURABLE_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-durable/v1";
const CONSUMER_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-consumer/v1";
const DEFAULT_ACK_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsCaptureSpec {
    namespace: String,
    stream: String,
    subject: String,
    durable: String,
    minimum_stream_replicas: usize,
    max_batch_items: usize,
    ack_wait: Duration,
    v2_segment: Option<RecoverableNatsStreamSegment>,
    consumer_digest: [u8; 32],
}

impl RecoverableNatsCaptureSpec {
    pub fn try_new(
        namespace: impl Into<String>,
        stream: impl Into<String>,
        subject: impl Into<String>,
        minimum_stream_replicas: usize,
        max_batch_items: usize,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let namespace = namespace.into();
        let stream = stream.into();
        let subject = subject.into();
        if namespace.is_empty()
            || stream.is_empty()
            || subject.is_empty()
            || minimum_stream_replicas == 0
            || minimum_stream_replicas > 5
            || max_batch_items == 0
            || max_batch_items > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS
            || !subject_matches(&format!("{namespace}.>"), &subject)
        {
            return Err(RecoverableNatsTransportError::InvalidCaptureSpec);
        }
        Self::build(
            namespace,
            stream,
            subject,
            minimum_stream_replicas,
            max_batch_items,
            None,
        )
    }

    /// Captures one exact subject from an exact finite V2 segment. The whole
    /// normalized segment contract, not merely its stream name, is attested.
    pub fn for_segment(
        segment: RecoverableNatsStreamSegment,
        subject: impl Into<String>,
        max_batch_items: usize,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let subject = subject.into();
        if !subject_matches(
            &format!("{}.>", segment.subject_prefix()),
            &subject,
        ) || max_batch_items == 0
            || max_batch_items > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS
        {
            return Err(RecoverableNatsTransportError::InvalidCaptureSpec);
        }
        Self::build(
            segment.base_namespace().to_owned(),
            segment.stream_name().to_owned(),
            subject,
            segment.retention().stream_replicas(),
            max_batch_items,
            Some(segment),
        )
    }

    fn build(
        namespace: String,
        stream: String,
        subject: String,
        minimum_stream_replicas: usize,
        max_batch_items: usize,
        v2_segment: Option<RecoverableNatsStreamSegment>,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let mut durable_seed = Sha256::new();
        durable_seed.update(DURABLE_DIGEST_DOMAIN);
        hash_component(&mut durable_seed, namespace.as_bytes());
        hash_component(&mut durable_seed, stream.as_bytes());
        hash_component(&mut durable_seed, subject.as_bytes());
        durable_seed.update((minimum_stream_replicas as u64).to_be_bytes());
        durable_seed.update((max_batch_items as u64).to_be_bytes());
        if let Some(segment) = &v2_segment {
            durable_seed.update([1]);
            durable_seed.update(segment.digest().as_bytes());
        } else {
            durable_seed.update([0]);
        }
        let durable_seed: [u8; 32] = durable_seed.finalize().into();
        let durable = format!("{DURABLE_PREFIX}{}", hex_prefix(&durable_seed, 16));
        let ack_wait = DEFAULT_ACK_WAIT;
        let segment_contract_digest = v2_segment
            .as_ref()
            .map(|segment| *segment.digest().as_bytes());
        let consumer_digest = canonical_consumer_digest(
            &namespace,
            &stream,
            &subject,
            &durable,
            minimum_stream_replicas,
            max_batch_items,
            ack_wait,
            segment_contract_digest.as_ref(),
        );
        Ok(Self {
            namespace,
            stream,
            subject,
            durable,
            minimum_stream_replicas,
            max_batch_items,
            ack_wait,
            v2_segment,
            consumer_digest,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn stream(&self) -> &str {
        &self.stream
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn durable(&self) -> &str {
        &self.durable
    }

    pub const fn consumer_digest(&self) -> [u8; 32] {
        self.consumer_digest
    }

    pub const fn max_batch_items(&self) -> usize {
        self.max_batch_items
    }

    pub fn source_identity(
        &self,
    ) -> Result<PendingQueueSourceIdentity, RecoverableNatsTransportError> {
        PendingQueueSourceIdentity::nats_jetstream(
            self.namespace.clone(),
            self.stream.clone(),
            self.subject.clone(),
        )
        .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))
    }

    pub fn pull_config(&self) -> PullConfig {
        PullConfig {
            durable_name: Some(self.durable.clone()),
            name: Some(self.durable.clone()),
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: self.ack_wait,
            max_deliver: -1,
            filter_subject: self.subject.clone(),
            replay_policy: ReplayPolicy::Instant,
            max_waiting: 1,
            max_ack_pending: self.max_batch_items as i64,
            max_batch: self.max_batch_items as i64,
            ..Default::default()
        }
    }

    pub fn attest_stream(
        &self,
        actual: &jetstream::stream::Config,
    ) -> Result<(), RecoverableNatsTransportError> {
        if let Some(segment) = &self.v2_segment {
            return segment
                .validate_stream_config_structure(actual)
                .map(|_| ())
                .map_err(|_| RecoverableNatsTransportError::StreamContract);
        }
        if actual.name != self.stream
            || actual.retention != RetentionPolicy::Limits
            || actual.storage != StorageType::File
            || actual.num_replicas < self.minimum_stream_replicas
            || actual.max_messages != -1
            || actual.max_messages_per_subject != -1
            || actual.max_bytes != -1
            || actual.max_age != Duration::ZERO
            || !actual.deny_delete
            || !actual.deny_purge
            || !actual
                .subjects
                .iter()
                .any(|filter| subject_matches(filter, &self.subject))
        {
            return Err(RecoverableNatsTransportError::StreamContract);
        }
        Ok(())
    }

    pub fn attest_consumer(
        &self,
        actual: &jetstream::consumer::Config,
    ) -> Result<(), RecoverableNatsTransportError> {
        let expected = self.pull_config();
        let segment_contract_digest = self
            .v2_segment
            .as_ref()
            .map(|segment| *segment.digest().as_bytes());
        if actual.durable_name.as_deref() != Some(self.durable.as_str())
            || actual.name.as_deref() != Some(self.durable.as_str())
            || actual.deliver_subject.is_some()
            || actual.deliver_group.is_some()
            || actual.description.is_some()
            || actual.deliver_policy != expected.deliver_policy
            || actual.ack_policy != AckPolicy::Explicit
            || actual.ack_wait != self.ack_wait
            || actual.max_deliver != -1
            || actual.filter_subject != self.subject
            || !actual.filter_subjects.is_empty()
            || actual.replay_policy != ReplayPolicy::Instant
            || actual.rate_limit != 0
            || actual.sample_frequency != 0
            || actual.max_waiting != 1
            || actual.max_ack_pending != self.max_batch_items as i64
            || actual.headers_only
            || actual.flow_control
            || actual.idle_heartbeat != Duration::ZERO
            || actual.max_batch != self.max_batch_items as i64
            || actual.max_bytes != 0
            || actual.max_expires != Duration::ZERO
            || actual.inactive_threshold != Duration::ZERO
            || (actual.num_replicas != 0
                && actual.num_replicas < self.minimum_stream_replicas)
            || actual.memory_storage
            || actual
                .metadata
                .keys()
                .any(|key| !key.starts_with("_nats."))
            || !actual.backoff.is_empty()
            || actual.priority_policy != jetstream::consumer::PriorityPolicy::None
            || !actual.priority_groups.is_empty()
            || actual.pause_until.is_some()
            || canonical_consumer_digest(
                &self.namespace,
                &self.stream,
                &actual.filter_subject,
                actual
                    .durable_name
                    .as_deref()
                    .ok_or(RecoverableNatsTransportError::ConsumerContract)?,
                self.minimum_stream_replicas,
                usize::try_from(actual.max_batch)
                    .map_err(|_| RecoverableNatsTransportError::ConsumerContract)?,
                actual.ack_wait,
                segment_contract_digest.as_ref(),
            ) != self.consumer_digest
        {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        Ok(())
    }
}

pub struct RecoverableNatsCaptureConsumer {
    inner: PullConsumer,
    spec: RecoverableNatsCaptureSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverableNatsConsumerObservation {
    ack_floor_consumer_sequence: u64,
    ack_floor_stream_sequence: u64,
}

impl RecoverableNatsConsumerObservation {
    pub const fn ack_floor_consumer_sequence(self) -> u64 {
        self.ack_floor_consumer_sequence
    }

    pub const fn ack_floor_stream_sequence(self) -> u64 {
        self.ack_floor_stream_sequence
    }
}

pub struct RecoverableNatsDeliveryBatch {
    messages: Vec<jetstream::Message>,
    stream_sequences: Vec<u64>,
    payloads: Vec<Vec<u8>>,
    consumer_digest: [u8; 32],
}

impl RecoverableNatsDeliveryBatch {
    pub fn stream_sequences(&self) -> &[u64] {
        &self.stream_sequences
    }

    pub fn payloads(&self) -> &[Vec<u8>] {
        &self.payloads
    }

    pub async fn double_ack_all(
        self,
        consumer: &mut RecoverableNatsCaptureConsumer,
    ) -> Result<RecoverableNatsConsumerObservation, RecoverableNatsTransportError> {
        if self.consumer_digest != consumer.spec.consumer_digest
            || self.messages.len() != self.stream_sequences.len()
            || self.messages.len() != self.payloads.len()
        {
            return Err(RecoverableNatsTransportError::DeliveryContract);
        }
        let last = *self
            .stream_sequences
            .last()
            .ok_or(RecoverableNatsTransportError::EmptyDelivery)?;
        for (message, sequence) in self
            .messages
            .into_iter()
            .zip(self.stream_sequences.iter().copied())
        {
            if let Err(error) = message.double_ack().await {
                let observed = consumer.observation().await.map_err(|read| {
                    RecoverableNatsTransportError::AckIndeterminate(format!(
                        "double_ack={error}; consumer_info={read}"
                    ))
                })?;
                if observed.ack_floor_stream_sequence < sequence {
                    return Err(RecoverableNatsTransportError::AckIndeterminate(
                        error.to_string(),
                    ));
                }
            }
        }
        let observed = consumer.observation().await?;
        if observed.ack_floor_consumer_sequence == 0
            || observed.ack_floor_stream_sequence < last
        {
            return Err(RecoverableNatsTransportError::AckIndeterminate(
                "ack floor does not cover delivery".into(),
            ));
        }
        Ok(observed)
    }
}

impl RecoverableNatsCaptureConsumer {
    pub async fn observation(
        &mut self,
    ) -> Result<RecoverableNatsConsumerObservation, RecoverableNatsTransportError> {
        let info = self
            .inner
            .info()
            .await
            .map_err(nats)?
            .clone();
        if info.stream_name != self.spec.stream || info.name != self.spec.durable {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        self.spec.attest_consumer(&info.config)?;
        Ok(RecoverableNatsConsumerObservation {
            ack_floor_consumer_sequence: info.ack_floor.consumer_sequence,
            ack_floor_stream_sequence: info.ack_floor.stream_sequence,
        })
    }

    pub async fn fetch(
        &mut self,
        max_items: usize,
        expires: Duration,
    ) -> Result<Option<RecoverableNatsDeliveryBatch>, RecoverableNatsTransportError> {
        if max_items == 0 || max_items > self.spec.max_batch_items {
            return Err(RecoverableNatsTransportError::BatchLimit);
        }
        self.observation().await?;
        let mut stream = self
            .inner
            .fetch()
            .max_messages(max_items)
            .expires(expires)
            .messages()
            .await
            .map_err(nats)?;
        let mut messages = Vec::with_capacity(max_items);
        let mut stream_sequences = Vec::with_capacity(max_items);
        let mut payloads = Vec::with_capacity(max_items);
        while let Some(message) = stream.next().await {
            let message = message.map_err(nats)?;
            let info = message.info().map_err(nats)?;
            if info.stream != self.spec.stream
                || info.consumer != self.spec.durable
                || message.message.subject.as_str() != self.spec.subject
                || info.stream_sequence == 0
                || stream_sequences
                    .last()
                    .is_some_and(|previous| *previous >= info.stream_sequence)
            {
                return Err(RecoverableNatsTransportError::DeliveryContract);
            }
            stream_sequences.push(info.stream_sequence);
            payloads.push(message.message.payload.to_vec());
            messages.push(message);
        }
        if messages.is_empty() {
            return Ok(None);
        }
        Ok(Some(RecoverableNatsDeliveryBatch {
            messages,
            stream_sequences,
            payloads,
            consumer_digest: self.spec.consumer_digest,
        }))
    }
}

#[derive(Clone)]
pub struct RecoverablePendingQueueNatsPublisher {
    context: Arc<jetstream::Context>,
    segment: RecoverableNatsStreamSegment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverableNatsPublishDisposition {
    PubAck,
    LeaderReadback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverableNatsPublishOutcome {
    subject_sequence: u64,
    disposition: RecoverableNatsPublishDisposition,
}

impl RecoverableNatsPublishOutcome {
    pub const fn subject_sequence(self) -> u64 {
        self.subject_sequence
    }

    pub const fn disposition(self) -> RecoverableNatsPublishDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedRecoverableNatsPublish {
    subject: String,
    expected_stream: String,
    expected_last_subject_sequence: u64,
    message_id: String,
    payload: Vec<u8>,
    envelope_digest: [u8; 32],
}

impl SealedRecoverableNatsPublish {
    fn try_new(
        segment: &RecoverableNatsStreamSegment,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<Self, RecoverableNatsTransportError> {
        Ok(Self {
            subject: envelope
                .exact_subject(segment)
                .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?,
            expected_stream: segment.stream_name().to_owned(),
            expected_last_subject_sequence: envelope.previous_subject_sequence(),
            message_id: envelope.message_id(),
            payload: envelope.to_canonical_bytes(),
            envelope_digest: *envelope.digest().as_bytes(),
        })
    }

    fn request(&self) -> Publish {
        Publish::build()
            .payload(Bytes::from(self.payload.clone()))
            .message_id(&self.message_id)
            .expected_stream(&self.expected_stream)
            .expected_last_subject_sequence(self.expected_last_subject_sequence)
    }
}

impl RecoverablePendingQueueNatsPublisher {
    pub async fn connect<A: ToServerAddrs>(
        addresses: A,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let client = async_nats::connect(addresses).await.map_err(nats)?;
        Self::from_context(Arc::new(jetstream::new(client)), segment).await
    }

    async fn from_context(
        context: Arc<jetstream::Context>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let mut stream = context
            .get_stream(segment.stream_name())
            .await
            .map_err(nats)?;
        let info = stream.info().await.map_err(nats)?.clone();
        segment
            .validate_stream_config_structure(&info.config)
            .map_err(|_| RecoverableNatsTransportError::StreamContract)?;
        Ok(Self { context, segment })
    }

    pub async fn publish(
        &self,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<RecoverableNatsPublishOutcome, RecoverableNatsTransportError> {
        let sealed = SealedRecoverableNatsPublish::try_new(&self.segment, envelope)?;
        let attempt = self
            .context
            .send_publish(sealed.subject.clone(), sealed.request())
            .await;
        match attempt {
            Ok(ack_future) => match ack_future.await {
                Ok(ack)
                    if ack.stream == sealed.expected_stream
                        && ack.domain.is_empty()
                        && ack.sequence > sealed.expected_last_subject_sequence =>
                {
                    if ack.duplicate {
                        let sequence = self.reconcile(&sealed, Some(ack.sequence)).await?;
                        Ok(RecoverableNatsPublishOutcome {
                            subject_sequence: sequence,
                            disposition: RecoverableNatsPublishDisposition::LeaderReadback,
                        })
                    } else {
                        Ok(RecoverableNatsPublishOutcome {
                            subject_sequence: ack.sequence,
                            disposition: RecoverableNatsPublishDisposition::PubAck,
                        })
                    }
                }
                Ok(ack) => Err(RecoverableNatsTransportError::AckMismatch {
                    stream: ack.stream,
                    domain: ack.domain,
                    sequence: ack.sequence,
                }),
                Err(_) => {
                    let sequence = self.reconcile(&sealed, None).await?;
                    Ok(RecoverableNatsPublishOutcome {
                        subject_sequence: sequence,
                        disposition: RecoverableNatsPublishDisposition::LeaderReadback,
                    })
                }
            },
            Err(_) => {
                let sequence = self.reconcile(&sealed, None).await?;
                Ok(RecoverableNatsPublishOutcome {
                    subject_sequence: sequence,
                    disposition: RecoverableNatsPublishDisposition::LeaderReadback,
                })
            }
        }
    }

    /// Replays the exact retained set for one typed source from the stream
    /// leader and verifies that the last retained member is Seal.
    ///
    /// The before/after last-message observations reject a source that changes
    /// during the scan. The returned receipt proves only the NATS retained set;
    /// it is not a semantic generation terminal and cannot authorize rotation,
    /// pipeline publication, or garbage collection.
    pub async fn scan_source_retained_set(
        &self,
        assignment: &PendingQueueGenerationSegmentAssignment,
        publisher_kind: PendingQueuePublisherKind,
    ) -> Result<PendingQueueSourceTruncationReceipt, RecoverableNatsTransportError> {
        if assignment.segment_id() != self.segment.segment_id()
            || assignment.contract_digest() != self.segment.digest()
        {
            return Err(RecoverableNatsTransportError::StreamContract);
        }
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(),
            publisher_kind,
            &self.segment,
        )
        .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        let subject = route.subject();
        let mut stream = self
            .context
            .get_stream(self.segment.stream_name())
            .await
            .map_err(nats)?;
        let info = stream.info().await.map_err(nats)?.clone();
        self.segment
            .validate_stream_config_structure(&info.config)
            .map_err(|_| RecoverableNatsTransportError::StreamContract)?;
        let before = match stream.get_last_raw_message_by_subject(subject).await {
            Ok(message) => message,
            Err(error) if error.kind() == RawMessageErrorKind::NoMessageFound => {
                return Err(RecoverableNatsTransportError::SourceNotSealed)
            }
            Err(error) => return Err(nats(error)),
        };
        if before.subject.as_str() != subject || before.sequence == 0 {
            return Err(RecoverableNatsTransportError::SourceScanChanged);
        }

        let last_sequence = before.sequence;
        let last_payload = before.payload.clone();
        let mut next_sequence = 1_u64;
        let mut scanner = PendingQueueSourceTruncationScanner::try_new(
            &route,
            assignment,
        )
        .map_err(source_scan)?;
        loop {
            let observed = stream
                .get_first_raw_message_by_subject(subject, next_sequence)
                .await
                .map_err(nats)?;
            if observed.subject.as_str() != subject
                || observed.sequence < next_sequence
                || observed.sequence > last_sequence
            {
                return Err(RecoverableNatsTransportError::SourceScanChanged);
            }
            scanner
                .observe(observed.sequence, &observed.payload)
                .map_err(source_scan)?;
            if observed.sequence == last_sequence {
                break;
            }
            next_sequence = observed
                .sequence
                .checked_add(1)
                .ok_or(RecoverableNatsTransportError::SourceScanChanged)?;
        }
        let receipt = scanner.finish().map_err(source_scan)?;

        let after = stream
            .get_last_raw_message_by_subject(subject)
            .await
            .map_err(nats)?;
        if after.subject.as_str() != subject
            || after.sequence != last_sequence
            || after.payload != last_payload
        {
            return Err(RecoverableNatsTransportError::SourceScanChanged);
        }
        Ok(receipt)
    }

    async fn reconcile(
        &self,
        sealed: &SealedRecoverableNatsPublish,
        expected_ack_sequence: Option<u64>,
    ) -> Result<u64, RecoverableNatsTransportError> {
        let stream = self
            .context
            .get_stream_no_info(&sealed.expected_stream)
            .await
            .map_err(nats)?;
        let observed = stream
            .get_last_raw_message_by_subject(&sealed.subject)
            .await
            .map_err(|error| RecoverableNatsTransportError::Indeterminate(error.to_string()))?;
        classify_leader_observation(
            sealed,
            observed.subject.as_str(),
            observed.sequence,
            &observed.payload,
            expected_ack_sequence,
        )
    }
}

impl NatsJetStreamClient {
    pub async fn recoverable_pending_publisher(
        &self,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<RecoverablePendingQueueNatsPublisher, RecoverableNatsTransportError> {
        if self.base_namespace() != segment.base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        RecoverablePendingQueueNatsPublisher::from_context(
            self.raw_context_for_recoverable_transport(),
            segment,
        )
        .await
    }

    pub async fn open_recoverable_capture(
        &self,
        spec: RecoverableNatsCaptureSpec,
    ) -> Result<RecoverableNatsCaptureConsumer, RecoverableNatsTransportError> {
        if self.base_namespace() != spec.namespace {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let context = self.raw_context_for_recoverable_transport();
        let stream = context.get_stream(&spec.stream).await.map_err(nats)?;
        let stream_info = stream.get_info().await.map_err(nats)?;
        spec.attest_stream(&stream_info.config)?;
        let mut consumer = stream
            .create_consumer_strict(spec.pull_config())
            .await
            .map_err(nats)?;
        let info = consumer.info().await.map_err(nats)?.clone();
        if info.stream_name != spec.stream || info.name != spec.durable {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        spec.attest_consumer(&info.config)?;
        Ok(RecoverableNatsCaptureConsumer {
            inner: consumer,
            spec,
        })
    }
}

fn classify_leader_observation(
    sealed: &SealedRecoverableNatsPublish,
    observed_subject: &str,
    observed_sequence: u64,
    observed_payload: &[u8],
    expected_ack_sequence: Option<u64>,
) -> Result<u64, RecoverableNatsTransportError> {
    if observed_subject != sealed.subject
        || observed_sequence <= sealed.expected_last_subject_sequence
        || expected_ack_sequence.is_some_and(|sequence| sequence != observed_sequence)
        || observed_payload != sealed.payload
    {
        return Err(RecoverableNatsTransportError::FenceConflict {
            expected_previous: sealed.expected_last_subject_sequence,
            observed: observed_sequence,
        });
    }
    let decoded = PendingQueuePublishEnvelope::decode_canonical(observed_payload)
        .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
    if decoded.digest().as_bytes() != &sealed.envelope_digest
        || decoded.message_id() != sealed.message_id
    {
        return Err(RecoverableNatsTransportError::PayloadMismatch);
    }
    Ok(observed_sequence)
}

fn canonical_consumer_digest(
    namespace: &str,
    stream: &str,
    subject: &str,
    durable: &str,
    minimum_stream_replicas: usize,
    max_batch_items: usize,
    ack_wait: Duration,
    segment_contract_digest: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_DIGEST_DOMAIN);
    hasher.update(1_u16.to_be_bytes());
    for component in [namespace, stream, subject, durable] {
        hash_component(&mut hasher, component.as_bytes());
    }
    hasher.update((minimum_stream_replicas as u64).to_be_bytes());
    hasher.update([1_u8]);
    hasher.update([2_u8]);
    hasher.update((ack_wait.as_nanos() as u64).to_be_bytes());
    hasher.update((-1_i64).to_be_bytes());
    hasher.update((max_batch_items as u64).to_be_bytes());
    hasher.update((max_batch_items as u64).to_be_bytes());
    hasher.update([1_u8]);
    hasher.update(1_i64.to_be_bytes());
    hasher.update(0_u64.to_be_bytes());
    hasher.update([0_u8; 12]);
    if let Some(digest) = segment_contract_digest {
        hasher.update([1]);
        hasher.update(digest);
    } else {
        hasher.update([0]);
    }
    hasher.finalize().into()
}

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hex_prefix(bytes: &[u8; 32], len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(len * 2);
    for byte in bytes.iter().take(len) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn subject_matches(filter: &str, subject: &str) -> bool {
    let filter: Vec<&str> = filter.split('.').collect();
    let subject: Vec<&str> = subject.split('.').collect();
    let mut subject_index = 0;
    for (index, token) in filter.iter().enumerate() {
        if *token == ">" {
            return index + 1 == filter.len() && subject_index < subject.len();
        }
        if subject_index == subject.len()
            || (*token != "*" && *token != subject[subject_index])
        {
            return false;
        }
        subject_index += 1;
    }
    subject_index == subject.len()
}

fn nats(error: impl fmt::Display) -> RecoverableNatsTransportError {
    RecoverableNatsTransportError::Nats(error.to_string())
}

fn source_scan(error: PendingQueueTerminalError) -> RecoverableNatsTransportError {
    match error {
        PendingQueueTerminalError::SourceNotSealed => {
            RecoverableNatsTransportError::SourceNotSealed
        }
        other => RecoverableNatsTransportError::SourceScan(other.to_string()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoverableNatsTransportError {
    InvalidCaptureSpec,
    ClientNamespaceMismatch,
    StreamContract,
    ConsumerContract,
    DeliveryContract,
    EmptyDelivery,
    BatchLimit,
    PayloadMismatch,
    SourceNotSealed,
    SourceScanChanged,
    SourceScan(String),
    AckMismatch {
        stream: String,
        domain: String,
        sequence: u64,
    },
    FenceConflict {
        expected_previous: u64,
        observed: u64,
    },
    AckIndeterminate(String),
    Indeterminate(String),
    Core(String),
    Nats(String),
}

impl fmt::Display for RecoverableNatsTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RecoverableNatsTransportError {}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use async_nats::jetstream::{
        consumer::IntoConsumerConfig,
        stream::{Config as StreamConfig, RetentionPolicy, StorageType},
    };

    use super::*;
    use crate::recoverable_assignment::{
        PendingQueueSegmentLedgerBootstrap, PendingQueueSegmentReservationPlan,
    };
    use crate::recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
        PendingQueuePublishIntentId, PendingQueuePublishSourceState,
        PendingQueuePublisherKind, PendingQueueSourceQuota, RecoverableNatsSourceRoute,
    };
    use crate::recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
    };
    use psy_data::protocol::{
        canonical_chain::NetworkId, chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::recoverable_ephemeral::PendingQueueCaptureContext,
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    fn capture_spec() -> RecoverableNatsCaptureSpec {
        RecoverableNatsCaptureSpec::try_new(
            "psy",
            "psy_stream",
            "psy.pq.r0.rs0.u1.qt1.g0",
            3,
            1024,
        )
        .unwrap()
    }

    fn safe_stream() -> StreamConfig {
        StreamConfig {
            name: "psy_stream".into(),
            subjects: vec!["psy.>".into()],
            max_messages: -1,
            max_bytes: -1,
            max_messages_per_subject: -1,
            max_age: Duration::ZERO,
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            num_replicas: 3,
            deny_delete: true,
            deny_purge: true,
            ..Default::default()
        }
    }

    fn envelope() -> (RecoverableNatsStreamSegment, PendingQueuePublishEnvelope) {
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
        envelope_for_segment(segment)
    }

    fn envelope_for_segment(
        segment: RecoverableNatsStreamSegment,
    ) -> (RecoverableNatsStreamSegment, PendingQueuePublishEnvelope) {
        let (segment, _, envelope) = fixture_for_segment(segment);
        (segment, envelope)
    }

    fn fixture_for_segment(
        segment: RecoverableNatsStreamSegment,
    ) -> (
        RecoverableNatsStreamSegment,
        PendingQueueGenerationSegmentAssignment,
        PendingQueuePublishEnvelope,
    ) {
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
        let mib = 1024 * 1024_u64;
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorRegistration,
                    10_000,
                    15 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorDeploy,
                    10_000,
                    47 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorGuta,
                    10_000,
                    63 * mib,
                    mib,
                )
                .unwrap(),
            ],
            128 * mib,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
            key, &validated, budget, 8,
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
            PendingQueuePublisherKind::CoordinatorGuta,
            &segment,
        )
        .unwrap();
        let source = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        let envelope = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([9; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            source.last_subject_sequence(),
            source.last_envelope_digest(),
            b"typed-transport".to_vec(),
        )
        .unwrap();
        (segment, assignment, envelope)
    }

    #[test]
    fn capture_contract_is_deterministic_and_attested() {
        let first = capture_spec();
        let second = capture_spec();
        assert_eq!(first, second);
        assert_eq!(first.durable.len(), DURABLE_PREFIX.len() + 32);
        assert_eq!(first.pull_config().ack_policy, AckPolicy::Explicit);
        first.attest_stream(&safe_stream()).unwrap();
        first
            .attest_consumer(&first.pull_config().into_consumer_config())
            .unwrap();

        let mut unsafe_stream = safe_stream();
        unsafe_stream.max_age = Duration::from_secs(1);
        assert!(first.attest_stream(&unsafe_stream).is_err());
        let mut unsafe_consumer = first.pull_config().into_consumer_config();
        unsafe_consumer.max_waiting = 2;
        assert!(first.attest_consumer(&unsafe_consumer).is_err());
    }

    #[test]
    fn v2_capture_is_bound_to_the_complete_finite_segment_contract() {
        let (segment, envelope) = envelope();
        let subject = envelope.exact_subject(&segment).unwrap();
        let spec = RecoverableNatsCaptureSpec::for_segment(
            segment.clone(),
            subject.clone(),
            1024,
        )
        .unwrap();
        assert_eq!(spec.namespace(), segment.base_namespace());
        assert_eq!(spec.stream(), segment.stream_name());
        assert_eq!(spec.subject(), subject);
        spec.attest_stream(&segment.stream_config()).unwrap();

        let mut unbounded = segment.stream_config();
        unbounded.max_bytes = -1;
        assert!(spec.attest_stream(&unbounded).is_err());

        let other = RecoverableNatsStreamSegment::try_new(
            segment.base_namespace(),
            RecoverableNatsSegmentId::try_new(2).unwrap(),
            segment.retention(),
        )
        .unwrap();
        assert!(RecoverableNatsCaptureSpec::for_segment(other, spec.subject(), 1024)
            .is_err());
    }

    #[test]
    fn publish_plan_and_leader_readback_are_exact() {
        let (segment, envelope) = envelope();
        let sealed = SealedRecoverableNatsPublish::try_new(&segment, &envelope).unwrap();
        assert_eq!(sealed.expected_stream, segment.stream_name());
        assert_eq!(sealed.subject, envelope.exact_subject(&segment).unwrap());
        assert!(classify_leader_observation(
            &sealed,
            &sealed.subject,
            11,
            &sealed.payload,
            Some(11),
        )
        .is_ok());
        assert!(classify_leader_observation(
            &sealed,
            &sealed.subject,
            11,
            b"wrong",
            Some(11),
        )
        .is_err());
    }

    #[test]
    fn capture_spec_rejects_cross_namespace_and_unbounded_batch() {
        assert!(RecoverableNatsCaptureSpec::try_new("psy", "s", "other.x", 3, 1)
            .is_err());
        assert!(RecoverableNatsCaptureSpec::try_new(
            "psy",
            "s",
            "psy.x",
            3,
            MAX_RECOVERABLE_QUEUE_BATCH_ITEMS + 1,
        )
        .is_err());
    }

    /// Live transport proof. The URL must address a disposable three-node
    /// JetStream cluster because the production segment contract refuses to
    /// weaken RF=3 for a test.
    #[tokio::test]
    #[ignore = "requires PSY_TEST_NATS_URL and a disposable RF=3 JetStream cluster"]
    async fn real_rf3_typed_publish_retry_capture_and_ack() {
        let url = std::env::var("PSY_TEST_NATS_URL")
            .expect("PSY_TEST_NATS_URL must point at a disposable RF=3 cluster");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let base = format!("psy_c2b2b2_{nonce}");
        let retention = envelope().0.retention();
        let segment = RecoverableNatsStreamSegment::try_new(
            base.clone(),
            RecoverableNatsSegmentId::try_new(nonce.max(1)).unwrap(),
            retention,
        )
        .unwrap();

        // Rebuild the envelope with the same typed context/budget machinery
        // but the unique live segment by reusing the test helper below.
        let (_, assignment, envelope) = fixture_for_segment(segment.clone());
        let raw = async_nats::connect(url.clone()).await.unwrap();
        let context = jetstream::new(raw);
        context.create_stream(segment.stream_config()).await.unwrap();

        let client = NatsJetStreamClient::new_connection(
            base,
            url,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await
        .unwrap();
        let publisher = client
            .recoverable_pending_publisher(segment.clone())
            .await
            .unwrap();
        let first = publisher.publish(&envelope).await.unwrap();
        assert_eq!(first.disposition(), RecoverableNatsPublishDisposition::PubAck);
        let retry = publisher.publish(&envelope).await.unwrap();
        assert_eq!(retry.subject_sequence(), first.subject_sequence());
        assert_eq!(
            retry.disposition(),
            RecoverableNatsPublishDisposition::LeaderReadback
        );

        assert_eq!(
            publisher
                .scan_source_retained_set(
                    &assignment,
                    PendingQueuePublisherKind::CoordinatorGuta,
                )
                .await
                .unwrap_err(),
            RecoverableNatsTransportError::SourceNotSealed
        );

        let subject = envelope.exact_subject(&segment).unwrap();
        let spec = RecoverableNatsCaptureSpec::for_segment(segment.clone(), subject, 16)
            .unwrap();
        let mut consumer = client.open_recoverable_capture(spec).await.unwrap();
        let batch = consumer
            .fetch(16, Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.payloads(), &[envelope.to_canonical_bytes()]);
        let observation = batch.double_ack_all(&mut consumer).await.unwrap();
        assert!(observation.ack_floor_stream_sequence() >= first.subject_sequence());

        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(),
            PendingQueuePublisherKind::CoordinatorGuta,
            &segment,
        )
        .unwrap();
        let source = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        let selected = source.select(&envelope).unwrap().current().clone();
        let accepted = selected
            .record_published(first.subject_sequence())
            .unwrap();
        let data_committed = accepted
            .candidate()
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([10; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            data_committed.last_subject_sequence(),
            data_committed.last_envelope_digest(),
            data_committed.seal_summary().unwrap(),
        )
        .unwrap();
        let seal_outcome = publisher.publish(&seal).await.unwrap();
        let seal_selected = data_committed.select(&seal).unwrap().current().clone();
        let seal_accepted = seal_selected
            .record_published(seal_outcome.subject_sequence())
            .unwrap();
        let sealed_source = seal_accepted
            .candidate()
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        let scan = publisher
            .scan_source_retained_set(
                &assignment,
                PendingQueuePublisherKind::CoordinatorGuta,
            )
            .await
            .unwrap();
        assert!(scan.matches_persisted_source(&sealed_source));
        assert_eq!(scan.retained_message_count(), 2);
        assert!(context
            .delete_stream(segment.stream_name())
            .await
            .unwrap()
            .success);
    }
}
