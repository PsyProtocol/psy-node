//! Narrow JetStream transport capabilities for recoverable pending queues.
//!
//! Raw [`jetstream::Context`] never leaves `psy_node_nats`.  Producers may
//! publish only a typed canonical envelope to its exact V2 segment subject;
//! capture code may only open an attested explicit-ACK consumer and receive an
//! opaque delivery batch whose raw messages can only be acknowledged through
//! this module.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use async_nats::{
    jetstream::{
        self,
        consumer::{
            pull::Config as PullConfig, AckPolicy, DeliverPolicy, PullConsumer,
            ReplayPolicy,
        },
        context::{GetStreamErrorKind, Publish},
        stream::{Info as StreamInfo, RawMessageErrorKind, RetentionPolicy, StorageType},
    },
    ToServerAddrs,
};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueSourceIdentity, MAX_RECOVERABLE_QUEUE_BATCH_ITEMS,
};
#[cfg(test)]
use psy_node_core::store::pending_generation_pipeline::PendingQueueCloseIntentDigest;
use sha2::{Digest, Sha256};

use crate::{
    queue::NatsJetStreamClient,
    recoverable_assignment::PendingQueueGenerationSegmentAssignment,
    recoverable_publish::{
        PendingQueuePublishEnvelope, PendingQueuePublisherKind,
        RecoverableNatsSourceRoute,
    },
    recoverable_segment::{
        LiveRecoverableNatsStreamInstance, RecoverableNatsStreamInstanceId,
        RecoverableNatsStreamSegment, RecoverableNatsStreamStateSnapshot,
        SealedRecoverableNatsStreamInstance,
    },
    recoverable_terminal::{
        PendingQueueNatsWholeStreamExpectedManifest,
        PendingQueueNatsWholeStreamScanReceipt, PendingQueueNatsWholeStreamScanner,
        PendingQueueSourceTruncationReceipt, PendingQueueSourceTruncationScanner,
        PendingQueueTerminalError,
    },
};

const DURABLE_PREFIX: &str = "psy_beq_v2_";
const DURABLE_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-durable/v1";
const CONSUMER_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-nats-consumer/v1";
const CONSUMER_INSTANCE_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-nats-consumer-instance/v1";
const CONSUMER_OPERATION_DESCRIPTION_PREFIX: &str = "psy-recoverable-operation-v1:";
const DEFAULT_ACK_WAIT: Duration = Duration::from_secs(30);
const CONSUMER_MANIFEST_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-nats-consumer-manifest/v1";
const CONSUMER_CONFIG_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-nats-consumer-config/v1";
const CONSUMER_INVENTORY_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-nats-consumer-inventory/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsExpectedConsumer {
    subject: String,
    consumer_digest: [u8; 32],
}

impl RecoverableNatsExpectedConsumer {
    pub fn try_new(
        subject: impl Into<String>,
        consumer_digest: [u8; 32],
    ) -> Result<Self, RecoverableNatsTransportError> {
        let subject = subject.into();
        if subject.is_empty() || consumer_digest == [0; 32] {
            return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
        }
        Ok(Self {
            subject,
            consumer_digest,
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub const fn consumer_digest(&self) -> &[u8; 32] {
        &self.consumer_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsConsumerManifestDigest([u8; 32]);

impl RecoverableNatsConsumerManifestDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsTransportError::ConsumerInventoryMismatch)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        Self::try_new(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsExpectedConsumerManifest {
    instance: SealedRecoverableNatsStreamInstance,
    consumers: Vec<RecoverableNatsExpectedConsumer>,
    digest: RecoverableNatsConsumerManifestDigest,
}

impl RecoverableNatsExpectedConsumerManifest {
    pub fn try_new(
        instance: SealedRecoverableNatsStreamInstance,
        mut consumers: Vec<RecoverableNatsExpectedConsumer>,
    ) -> Result<Self, RecoverableNatsTransportError> {
        consumers.sort_by(|left, right| left.subject.cmp(&right.subject));
        if consumers.len() as u64 != instance.state().consumer_count()
            || consumers.windows(2).any(|pair| pair[0].subject == pair[1].subject)
            || consumers.iter().any(|consumer| {
                !subject_matches(
                    &format!("{}.>", instance.segment().subject_prefix()),
                    &consumer.subject,
                )
            })
        {
            return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(CONSUMER_MANIFEST_DOMAIN);
        hasher.update(instance.instance_id().as_bytes());
        hasher.update(instance.segment().digest().as_bytes());
        hasher.update((consumers.len() as u64).to_be_bytes());
        for consumer in &consumers {
            hash_component(&mut hasher, consumer.subject.as_bytes());
            hasher.update(consumer.consumer_digest);
        }
        let digest = RecoverableNatsConsumerManifestDigest::try_new(
            hasher.finalize().into(),
        )?;
        Ok(Self {
            instance,
            consumers,
            digest,
        })
    }

    pub const fn instance(&self) -> &SealedRecoverableNatsStreamInstance {
        &self.instance
    }

    pub fn consumers(&self) -> &[RecoverableNatsExpectedConsumer] {
        &self.consumers
    }

    pub const fn digest(&self) -> RecoverableNatsConsumerManifestDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsConsumerInventoryDigest([u8; 32]);

impl RecoverableNatsConsumerInventoryDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsTransportError::ConsumerInventoryMismatch)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        Self::try_new(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsConsumerInventoryReceipt {
    instance_id: [u8; 32],
    manifest_digest: RecoverableNatsConsumerManifestDigest,
    inventory_digest: RecoverableNatsConsumerInventoryDigest,
    consumer_count: u64,
}

/// Stable caller-supplied identity of one durable-consumer provisioning
/// operation. The value is persisted before JetStream is mutated and must be
/// reused verbatim after a crash or an indeterminate response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsConsumerProvisioningOperationId([u8; 32]);

impl RecoverableNatsConsumerProvisioningOperationId {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsTransportError::ConsumerContract)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable identity of one server-created durable-consumer incarnation. A
/// later milestone derives this from the exact stream, consumer configuration
/// and server-provided creation timestamp; the gate only persists and compares
/// the opaque non-zero commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoverableNatsConsumerInstanceId([u8; 32]);

impl RecoverableNatsConsumerInstanceId {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableNatsTransportError> {
        if bytes == [0; 32] {
            Err(RecoverableNatsTransportError::ConsumerContract)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque proof that JetStream returned and then re-exposed one exact durable
/// consumer incarnation. Only the transport provisioning path can mint this
/// receipt; storage gates must not accept a caller-synthesized instance id.
pub struct RecoverableNatsProvisionedConsumerReceipt {
    stream_instance_id: [u8; 32],
    subject: String,
    consumer_digest: [u8; 32],
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
    consumer_instance_id: RecoverableNatsConsumerInstanceId,
}

impl RecoverableNatsProvisionedConsumerReceipt {
    pub const fn stream_instance_id(&self) -> &[u8; 32] {
        &self.stream_instance_id
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub const fn consumer_digest(&self) -> &[u8; 32] {
        &self.consumer_digest
    }

    pub const fn operation_id(&self) -> RecoverableNatsConsumerProvisioningOperationId {
        self.operation_id
    }

    pub const fn consumer_instance_id(&self) -> RecoverableNatsConsumerInstanceId {
        self.consumer_instance_id
    }
}

/// Durable expectation used only to open an already-provisioned consumer.
/// Constructing it does not grant create/update authority; the transport path
/// performs observation-only lookup and exact created-instance attestation.
pub struct RecoverableNatsExistingConsumerBinding {
    stream_instance_id: RecoverableNatsStreamInstanceId,
    subject: String,
    consumer_digest: [u8; 32],
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
    consumer_instance_id: RecoverableNatsConsumerInstanceId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverableNatsExpectedStreamMode {
    Live,
    Sealed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsProvisionedConsumerExpectation {
    subject: String,
    consumer_digest: [u8; 32],
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
    consumer_instance_id: RecoverableNatsConsumerInstanceId,
}

impl RecoverableNatsProvisionedConsumerExpectation {
    pub fn try_new(
        subject: impl Into<String>,
        consumer_digest: [u8; 32],
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
        consumer_instance_id: RecoverableNatsConsumerInstanceId,
    ) -> Result<Self, RecoverableNatsTransportError> {
        let subject = subject.into();
        if subject.is_empty() || consumer_digest == [0; 32] {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        Ok(Self {
            subject,
            consumer_digest,
            operation_id,
            consumer_instance_id,
        })
    }
}

impl RecoverableNatsExistingConsumerBinding {
    pub fn try_from_durable(
        stream_instance_id: RecoverableNatsStreamInstanceId,
        spec: &RecoverableNatsCaptureSpec,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
        consumer_instance_id: RecoverableNatsConsumerInstanceId,
    ) -> Result<Self, RecoverableNatsTransportError> {
        if spec.v2_segment.is_none() {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        Ok(Self {
            stream_instance_id,
            subject: spec.subject.clone(),
            consumer_digest: spec.consumer_digest,
            operation_id,
            consumer_instance_id,
        })
    }
}

impl RecoverableNatsConsumerInventoryReceipt {
    pub const fn instance_id(&self) -> &[u8; 32] {
        &self.instance_id
    }

    pub const fn manifest_digest(&self) -> RecoverableNatsConsumerManifestDigest {
        self.manifest_digest
    }

    pub const fn inventory_digest(&self) -> RecoverableNatsConsumerInventoryDigest {
        self.inventory_digest
    }

    pub const fn consumer_count(&self) -> u64 {
        self.consumer_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoverableNatsObservedConsumer {
    subject: String,
    name: String,
    consumer_digest: [u8; 32],
    config_digest: [u8; 32],
    created_nanos: i128,
    delivered_consumer_sequence: u64,
    delivered_stream_sequence: u64,
    delivered_last_active_nanos: Option<i128>,
    ack_floor_consumer_sequence: u64,
    ack_floor_stream_sequence: u64,
    ack_floor_last_active_nanos: Option<i128>,
    num_redelivered: usize,
}

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

    pub const fn v2_segment(&self) -> Option<&RecoverableNatsStreamSegment> {
        self.v2_segment.as_ref()
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

    fn pull_config_for_operation(
        &self,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    ) -> PullConfig {
        let mut config = self.pull_config();
        config.description = Some(consumer_operation_description(operation_id));
        config
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
            || actual.description.as_deref().is_some_and(|description| {
                !is_consumer_operation_description(description)
            })
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
    pub fn len(&self) -> usize { self.messages.len() }

    pub fn is_empty(&self) -> bool { self.messages.is_empty() }

    pub fn stream_sequences(&self) -> &[u64] {
        &self.stream_sequences
    }

    pub fn payloads(&self) -> &[Vec<u8>] {
        &self.payloads
    }

    /// Splits one fetched delivery without cloning backend ACK handles. This
    /// lets a concrete store durably confirm the Data prefix and persist a
    /// close boundary before the trailing Seal is ACKed.
    pub fn split_at(
        mut self,
        prefix_len: usize,
    ) -> Result<(Option<Self>, Option<Self>), RecoverableNatsTransportError> {
        if self.messages.len() != self.stream_sequences.len()
            || self.messages.len() != self.payloads.len()
            || prefix_len > self.messages.len()
        {
            return Err(RecoverableNatsTransportError::DeliveryContract);
        }
        let suffix_messages = self.messages.split_off(prefix_len);
        let suffix_sequences = self.stream_sequences.split_off(prefix_len);
        let suffix_payloads = self.payloads.split_off(prefix_len);
        let consumer_digest = self.consumer_digest;
        let prefix = (!self.messages.is_empty()).then_some(self);
        let suffix = (!suffix_messages.is_empty()).then_some(Self {
            messages: suffix_messages,
            stream_sequences: suffix_sequences,
            payloads: suffix_payloads,
            consumer_digest,
        });
        Ok((prefix, suffix))
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
pub enum RecoverableNatsSealDisposition {
    Applied,
    AlreadySealed,
    ReconciledAfterResponseLoss,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsSealOutcome {
    sealed: SealedRecoverableNatsStreamInstance,
    disposition: RecoverableNatsSealDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverableNatsDeleteDisposition {
    Applied,
    AlreadyAbsent,
    ReconciledAfterResponseLoss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverableNatsDeleteOutcome {
    instance_id: RecoverableNatsStreamInstanceId,
    disposition: RecoverableNatsDeleteDisposition,
}

impl RecoverableNatsDeleteOutcome {
    pub const fn instance_id(
        self,
    ) -> RecoverableNatsStreamInstanceId {
        self.instance_id
    }

    pub const fn disposition(self) -> RecoverableNatsDeleteDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsDeleteExpectation {
    segment: RecoverableNatsStreamSegment,
    instance_id: RecoverableNatsStreamInstanceId,
    state: RecoverableNatsStreamStateSnapshot,
}

impl RecoverableNatsDeleteExpectation {
    pub fn try_new(
        segment: RecoverableNatsStreamSegment,
        instance_id: RecoverableNatsStreamInstanceId,
        state: RecoverableNatsStreamStateSnapshot,
    ) -> Result<Self, RecoverableNatsTransportError> {
        if *instance_id.as_bytes() == [0; 32] {
            return Err(RecoverableNatsTransportError::DeleteContractDrift);
        }
        Ok(Self {
            segment,
            instance_id,
            state,
        })
    }

    pub fn from_sealed(instance: &SealedRecoverableNatsStreamInstance) -> Self {
        Self {
            segment: instance.segment().clone(),
            instance_id: instance.instance_id(),
            state: instance.state(),
        }
    }

    pub const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.segment
    }

    pub const fn instance_id(&self) -> RecoverableNatsStreamInstanceId {
        self.instance_id
    }

    pub const fn state(&self) -> RecoverableNatsStreamStateSnapshot {
        self.state
    }
}

impl RecoverableNatsSealOutcome {
    pub const fn sealed(&self) -> &SealedRecoverableNatsStreamInstance {
        &self.sealed
    }

    pub const fn disposition(&self) -> RecoverableNatsSealDisposition {
        self.disposition
    }
}

enum RecoverableNatsSegmentObservation {
    Live(LiveRecoverableNatsStreamInstance),
    Sealed(SealedRecoverableNatsStreamInstance),
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
    /// Irreversibly seals one exact server-created V2 stream incarnation.
    ///
    /// The caller cannot supply a raw stream name or config. A higher-level
    /// durable lifecycle must authorize this call; this façade itself proves
    /// only that the exact live observation became the exact sealed
    /// observation without changing retained state.
    pub async fn seal_recoverable_segment_instance(
        &self,
        expected: &LiveRecoverableNatsStreamInstance,
    ) -> Result<RecoverableNatsSealOutcome, RecoverableNatsTransportError> {
        if self.base_namespace() != expected.segment().base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let context = self.raw_context_for_recoverable_transport();
        let stream = context
            .get_stream(expected.segment().stream_name())
            .await
            .map_err(nats)?;
        let before = stream.get_info().await.map_err(nats)?;
        match classify_segment_observation(expected, &before)? {
            RecoverableNatsSegmentObservation::Sealed(sealed) => {
                return Ok(RecoverableNatsSealOutcome {
                    sealed,
                    disposition: RecoverableNatsSealDisposition::AlreadySealed,
                });
            }
            RecoverableNatsSegmentObservation::Live(live) if &live == expected => {}
            RecoverableNatsSegmentObservation::Live(_) => {
                return Err(RecoverableNatsTransportError::SealEvidenceChanged)
            }
        }
        if before.mirror.is_some() || !before.sources.is_empty() {
            return Err(RecoverableNatsTransportError::SealContractDrift);
        }

        let update = context
            .update_stream(expected.segment().sealed_stream_config())
            .await;
        let stream = context
            .get_stream(expected.segment().stream_name())
            .await
            .map_err(|error| {
                RecoverableNatsTransportError::SealIndeterminate(format!(
                    "update={}; readback={error}",
                    update
                        .as_ref()
                        .map(|_| "ok".to_owned())
                        .unwrap_or_else(|error| error.to_string()),
                ))
            })?;
        let after = stream.get_info().await.map_err(|error| {
            RecoverableNatsTransportError::SealIndeterminate(format!(
                "update={}; readback={error}",
                update
                    .as_ref()
                    .map(|_| "ok".to_owned())
                    .unwrap_or_else(|error| error.to_string()),
            ))
        })?;
        let outcome = classify_seal_readback(
            update.is_ok(),
            classify_segment_observation(expected, &after)?,
        )?;
        if before.created != after.created
            || before.state != after.state
            || before.mirror != after.mirror
            || before.sources != after.sources
        {
            return Err(RecoverableNatsTransportError::SealEvidenceChanged);
        }
        Ok(outcome)
    }

    /// Deletes one exact, already sealed V2 stream incarnation.
    ///
    /// JetStream only offers a name-based delete, so this façade performs an
    /// exact created-instance/state pre-read and a mandatory absence
    /// readback. A higher-level durable `DeleteRequested` receipt and
    /// stream-name non-reuse fence must authorize the call; this transport
    /// method cannot provide an atomic server-side compare-and-delete.
    pub async fn delete_recoverable_sealed_segment_instance(
        &self,
        expected: &RecoverableNatsDeleteExpectation,
    ) -> Result<RecoverableNatsDeleteOutcome, RecoverableNatsTransportError> {
        if self.base_namespace() != expected.segment().base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let context = self.raw_context_for_recoverable_transport();
        match context
            .get_stream(expected.segment().stream_name())
            .await
        {
            Ok(stream) => {
                let observed = expected
                    .segment()
                    .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
                    .map_err(|_| RecoverableNatsTransportError::DeleteContractDrift)?;
                require_same_delete_instance(expected, &observed)?;
            }
            Err(error) if is_stream_not_found(error.kind()) => {
                return Ok(RecoverableNatsDeleteOutcome {
                    instance_id: expected.instance_id(),
                    disposition: RecoverableNatsDeleteDisposition::AlreadyAbsent,
                });
            }
            Err(error) => {
                return Err(RecoverableNatsTransportError::DeleteIndeterminate(
                    error.to_string(),
                ));
            }
        }

        let deletion = context
            .delete_stream(expected.segment().stream_name())
            .await;
        if deletion.as_ref().is_ok_and(|status| !status.success) {
            return Err(RecoverableNatsTransportError::DeleteNotApplied);
        }
        match context
            .get_stream(expected.segment().stream_name())
            .await
        {
            Err(error) if is_stream_not_found(error.kind()) => {
                Ok(RecoverableNatsDeleteOutcome {
                    instance_id: expected.instance_id(),
                    disposition: if deletion.is_ok() {
                        RecoverableNatsDeleteDisposition::Applied
                    } else {
                        RecoverableNatsDeleteDisposition::ReconciledAfterResponseLoss
                    },
                })
            }
            Ok(stream) => {
                let observed = expected
                    .segment()
                    .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
                    .map_err(|_| RecoverableNatsTransportError::DeleteRecreatedInstance)?;
                require_same_delete_instance(expected, &observed)?;
                Err(match deletion {
                    Ok(_) => RecoverableNatsTransportError::DeleteNotApplied,
                    Err(error) => RecoverableNatsTransportError::DeleteIndeterminate(
                        error.to_string(),
                    ),
                })
            }
            Err(readback) => Err(RecoverableNatsTransportError::DeleteIndeterminate(format!(
                "delete={}; readback={readback}",
                deletion
                    .as_ref()
                    .map(|_| "ok".to_owned())
                    .unwrap_or_else(|error| error.to_string()),
            ))),
        }
    }

    pub async fn observe_recoverable_segment_instance(
        &self,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<LiveRecoverableNatsStreamInstance, RecoverableNatsTransportError> {
        if self.base_namespace() != segment.base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let stream = self
            .raw_context_for_recoverable_transport()
            .get_stream(segment.stream_name())
            .await
            .map_err(nats)?;
        let info = stream.get_info().await.map_err(nats)?;
        segment
            .attest_live_instance(&info)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))
    }

    pub async fn observe_recoverable_sealed_segment_instance(
        &self,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<SealedRecoverableNatsStreamInstance, RecoverableNatsTransportError> {
        if self.base_namespace() != segment.base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let stream = self
            .raw_context_for_recoverable_transport()
            .get_stream(segment.stream_name())
            .await
            .map_err(nats)?;
        let info = stream.get_info().await.map_err(nats)?;
        segment
            .attest_sealed_instance(&info)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))
    }

    /// Exhaustively reads sequence `1..=last` from one exact sealed stream
    /// incarnation. It does not seal or delete the stream and the receipt is
    /// not a GC permit until the Scylla segment lifecycle binds every
    /// assignment terminal in a later milestone.
    pub async fn scan_recoverable_sealed_segment(
        &self,
        manifest: PendingQueueNatsWholeStreamExpectedManifest,
    ) -> Result<PendingQueueNatsWholeStreamScanReceipt, RecoverableNatsTransportError> {
        let expected = manifest.instance().clone();
        if self.base_namespace() != expected.segment().base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let context = self.raw_context_for_recoverable_transport();
        let stream = context
            .get_stream(expected.segment().stream_name())
            .await
            .map_err(nats)?;
        let before = expected
            .segment()
            .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if before != expected {
            return Err(RecoverableNatsTransportError::WholeStreamScanChanged);
        }
        let mut scanner = PendingQueueNatsWholeStreamScanner::try_new(manifest)
            .map_err(source_scan)?;
        for sequence in 1..=expected.state().last_sequence() {
            let message = stream
                .get_raw_message(sequence)
                .await
                .map_err(|_| RecoverableNatsTransportError::WholeStreamScanChanged)?;
            scanner
                .observe(
                    message.sequence,
                    message.subject.as_str(),
                    &message.payload,
                )
                .map_err(source_scan)?;
        }
        let receipt = scanner.finish().map_err(source_scan)?;
        let after = expected
            .segment()
            .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if after != expected {
            return Err(RecoverableNatsTransportError::WholeStreamScanChanged);
        }
        Ok(receipt)
    }

    /// Enumerates the complete durable-consumer set of one exact sealed
    /// stream twice and accepts it only when every expected consumer has its
    /// exact typed contract and is fully quiescent. This is observation only;
    /// it neither deletes consumers nor grants stream-delete authority.
    pub async fn inventory_recoverable_sealed_segment_consumers(
        &self,
        manifest: RecoverableNatsExpectedConsumerManifest,
    ) -> Result<RecoverableNatsConsumerInventoryReceipt, RecoverableNatsTransportError> {
        let expected = manifest.instance().clone();
        if self.base_namespace() != expected.segment().base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let stream = self
            .raw_context_for_recoverable_transport()
            .get_stream(expected.segment().stream_name())
            .await
            .map_err(nats)?;
        let before = expected
            .segment()
            .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if before != expected {
            return Err(RecoverableNatsTransportError::ConsumerInventoryChanged);
        }
        let first = collect_recoverable_consumer_inventory(&stream, &manifest).await?;
        let second = collect_recoverable_consumer_inventory(&stream, &manifest).await?;
        let after = expected
            .segment()
            .attest_sealed_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if first != second || after != expected {
            return Err(RecoverableNatsTransportError::ConsumerInventoryChanged);
        }
        let inventory_digest = consumer_inventory_digest(manifest.digest(), &first)?;
        Ok(RecoverableNatsConsumerInventoryReceipt {
            instance_id: *expected.instance_id().as_bytes(),
            manifest_digest: manifest.digest(),
            inventory_digest,
            consumer_count: first.len() as u64,
        })
    }

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

    /// Performs the sole raw durable-consumer create operation. The caller
    /// must have durably registered `operation_id` before entering this
    /// method. A failed create is reconciled by exact existing-consumer
    /// readback; the returned receipt is opaque and binds the server-created
    /// consumer incarnation.
    pub async fn provision_recoverable_capture_consumer(
        &self,
        live: &LiveRecoverableNatsStreamInstance,
        spec: RecoverableNatsCaptureSpec,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    ) -> Result<RecoverableNatsProvisionedConsumerReceipt, RecoverableNatsTransportError> {
        if self.base_namespace() != spec.namespace {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        let segment = spec
            .v2_segment()
            .ok_or(RecoverableNatsTransportError::ConsumerContract)?;
        if segment != live.segment() {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        let context = self.raw_context_for_recoverable_transport();
        let stream = context.get_stream(&spec.stream).await.map_err(nats)?;
        let before = segment
            .attest_live_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if before.instance_id() != live.instance_id() {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        let mut consumer = match stream
            .create_consumer_strict(spec.pull_config_for_operation(operation_id))
            .await
        {
            Ok(consumer) => consumer,
            Err(create_error) => stream
                .get_consumer::<PullConfig>(&spec.durable)
                .await
                .map_err(|read_error| {
                    RecoverableNatsTransportError::ConsumerProvisioningIndeterminate(format!(
                        "create={create_error}; read={read_error}"
                    ))
                })?,
        };
        let first = consumer.info().await.map_err(nats)?.clone();
        let first_instance =
            consumer_instance_id(live.instance_id(), &spec, operation_id, &first)?;
        let after = segment
            .attest_live_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if after.instance_id() != live.instance_id() {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        let second = stream
            .get_consumer::<PullConfig>(&spec.durable)
            .await
            .map_err(nats)?
            .info()
            .await
            .map_err(nats)?
            .clone();
        let second_instance =
            consumer_instance_id(live.instance_id(), &spec, operation_id, &second)?;
        if first_instance != second_instance {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        Ok(RecoverableNatsProvisionedConsumerReceipt {
            stream_instance_id: *live.instance_id().as_bytes(),
            subject: spec.subject,
            consumer_digest: spec.consumer_digest,
            operation_id,
            consumer_instance_id: first_instance,
        })
    }

    /// Opens an existing durable consumer without creating or updating it.
    /// Both the stream and consumer server-created identities are re-attested
    /// before the handle is returned.
    pub async fn open_existing_recoverable_capture(
        &self,
        spec: RecoverableNatsCaptureSpec,
        binding: &RecoverableNatsExistingConsumerBinding,
    ) -> Result<RecoverableNatsCaptureConsumer, RecoverableNatsTransportError> {
        if self.base_namespace() != spec.namespace
            || binding.subject != spec.subject
            || binding.consumer_digest != spec.consumer_digest
        {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        let segment = spec
            .v2_segment()
            .ok_or(RecoverableNatsTransportError::ConsumerContract)?;
        let context = self.raw_context_for_recoverable_transport();
        let stream = context.get_stream(&spec.stream).await.map_err(nats)?;
        let live = segment
            .attest_live_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if live.instance_id() != binding.stream_instance_id {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        let mut consumer = stream
            .get_consumer::<PullConfig>(&spec.durable)
            .await
            .map_err(nats)?;
        let first = consumer.info().await.map_err(nats)?.clone();
        if consumer_instance_id(
            binding.stream_instance_id,
            &spec,
            binding.operation_id,
            &first,
        )?
            != binding.consumer_instance_id
        {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        let after = segment
            .attest_live_instance(&stream.get_info().await.map_err(nats)?)
            .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
        if after.instance_id() != binding.stream_instance_id {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        let mut second_consumer = stream
            .get_consumer::<PullConfig>(&spec.durable)
            .await
            .map_err(nats)?;
        let second = second_consumer.info().await.map_err(nats)?.clone();
        if consumer_instance_id(
            binding.stream_instance_id,
            &spec,
            binding.operation_id,
            &second,
        )?
            != binding.consumer_instance_id
        {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        if first.stream_name != spec.stream || first.name != spec.durable {
            return Err(RecoverableNatsTransportError::ConsumerContract);
        }
        Ok(RecoverableNatsCaptureConsumer {
            inner: second_consumer,
            spec,
        })
    }

    /// Enumerates the complete consumer set twice and verifies every exact
    /// server-created incarnation persisted by the durable mutation gate.
    /// This performs no consumer mutation and is valid both immediately
    /// before and immediately after physical stream seal.
    pub async fn verify_recoverable_provisioned_consumer_set(
        &self,
        segment: RecoverableNatsStreamSegment,
        stream_instance_id: RecoverableNatsStreamInstanceId,
        mode: RecoverableNatsExpectedStreamMode,
        mut expected: Vec<RecoverableNatsProvisionedConsumerExpectation>,
    ) -> Result<(), RecoverableNatsTransportError> {
        if self.base_namespace() != segment.base_namespace() {
            return Err(RecoverableNatsTransportError::ClientNamespaceMismatch);
        }
        expected.sort_by(|left, right| left.subject.cmp(&right.subject));
        if expected.windows(2).any(|pair| pair[0].subject == pair[1].subject) {
            return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
        }
        let stream = self
            .raw_context_for_recoverable_transport()
            .get_stream(segment.stream_name())
            .await
            .map_err(nats)?;
        let before = stream.get_info().await.map_err(nats)?;
        attest_expected_stream_instance(&segment, stream_instance_id, mode, &before)?;
        require_exact_consumer_count(&before, expected.len())?;
        let first = collect_exact_provisioned_consumers(
            &stream,
            &segment,
            stream_instance_id,
            &expected,
        )
        .await?;
        let second = collect_exact_provisioned_consumers(
            &stream,
            &segment,
            stream_instance_id,
            &expected,
        )
        .await?;
        let after = stream.get_info().await.map_err(nats)?;
        attest_expected_stream_instance(&segment, stream_instance_id, mode, &after)?;
        require_exact_consumer_count(&after, expected.len())?;
        if first != second {
            return Err(RecoverableNatsTransportError::ConsumerInventoryChanged);
        }
        Ok(())
    }
}

fn require_exact_consumer_count(
    info: &StreamInfo,
    expected: usize,
) -> Result<(), RecoverableNatsTransportError> {
    require_exact_consumer_count_value(info.state.consumer_count, expected)
}

fn require_exact_consumer_count_value(
    actual: usize,
    expected: usize,
) -> Result<(), RecoverableNatsTransportError> {
    if actual != expected {
        return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
    }
    Ok(())
}

fn attest_expected_stream_instance(
    segment: &RecoverableNatsStreamSegment,
    instance_id: RecoverableNatsStreamInstanceId,
    mode: RecoverableNatsExpectedStreamMode,
    info: &StreamInfo,
) -> Result<(), RecoverableNatsTransportError> {
    let observed_id = match mode {
        RecoverableNatsExpectedStreamMode::Live => segment
            .attest_live_instance(info)
            .map(|observed| observed.instance_id()),
        RecoverableNatsExpectedStreamMode::Sealed => segment
            .attest_sealed_instance(info)
            .map(|observed| observed.instance_id()),
    }
    .map_err(|error| RecoverableNatsTransportError::Core(error.to_string()))?;
    if observed_id != instance_id {
        return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
    }
    Ok(())
}

async fn collect_exact_provisioned_consumers(
    stream: &jetstream::stream::Stream,
    segment: &RecoverableNatsStreamSegment,
    stream_instance_id: RecoverableNatsStreamInstanceId,
    expected: &[RecoverableNatsProvisionedConsumerExpectation],
) -> Result<Vec<(String, RecoverableNatsConsumerInstanceId)>, RecoverableNatsTransportError> {
    let expected = expected
        .iter()
        .map(|entry| (entry.subject.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut infos = stream.consumers();
    let mut observed = Vec::with_capacity(expected.len());
    while let Some(info) = infos.try_next().await.map_err(nats)? {
        let max_batch = usize::try_from(info.config.max_batch)
            .map_err(|_| RecoverableNatsTransportError::ConsumerContract)?;
        let spec = RecoverableNatsCaptureSpec::for_segment(
            segment.clone(),
            info.config.filter_subject.clone(),
            max_batch,
        )?;
        let entry = expected
            .get(spec.subject())
            .ok_or(RecoverableNatsTransportError::ConsumerInventoryMismatch)?;
        if spec.consumer_digest() != entry.consumer_digest
            || consumer_instance_id(stream_instance_id, &spec, entry.operation_id, &info)?
                != entry.consumer_instance_id
        {
            return Err(RecoverableNatsTransportError::ConsumerInstanceChanged);
        }
        observed.push((entry.subject.clone(), entry.consumer_instance_id));
    }
    observed.sort_by(|left, right| left.0.cmp(&right.0));
    if observed.len() != expected.len()
        || observed
            .iter()
            .map(|entry| entry.0.as_str())
            .ne(expected.keys().copied())
    {
        return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
    }
    Ok(observed)
}

fn consumer_instance_id(
    stream_instance_id: RecoverableNatsStreamInstanceId,
    spec: &RecoverableNatsCaptureSpec,
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
    info: &jetstream::consumer::Info,
) -> Result<RecoverableNatsConsumerInstanceId, RecoverableNatsTransportError> {
    if info.stream_name != spec.stream || info.name != spec.durable {
        return Err(RecoverableNatsTransportError::ConsumerContract);
    }
    spec.attest_consumer(&info.config)?;
    if info.config.description.as_deref()
        != Some(consumer_operation_description(operation_id).as_str())
    {
        return Err(RecoverableNatsTransportError::ConsumerContract);
    }
    let created_nanos = info.created.unix_timestamp_nanos();
    if created_nanos <= 0 {
        return Err(RecoverableNatsTransportError::ConsumerContract);
    }
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_INSTANCE_DOMAIN);
    hasher.update(stream_instance_id.as_bytes());
    hasher.update(spec.consumer_digest());
    hasher.update(operation_id.as_bytes());
    hasher.update(recoverable_consumer_config_digest(spec, &info.config));
    hasher.update(created_nanos.to_be_bytes());
    RecoverableNatsConsumerInstanceId::try_new(hasher.finalize().into())
}

fn consumer_operation_description(
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
) -> String {
    let mut value = String::with_capacity(CONSUMER_OPERATION_DESCRIPTION_PREFIX.len() + 64);
    value.push_str(CONSUMER_OPERATION_DESCRIPTION_PREFIX);
    for byte in operation_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn is_consumer_operation_description(value: &str) -> bool {
    value.len() == CONSUMER_OPERATION_DESCRIPTION_PREFIX.len() + 64
        && value.starts_with(CONSUMER_OPERATION_DESCRIPTION_PREFIX)
        && value[CONSUMER_OPERATION_DESCRIPTION_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

async fn collect_recoverable_consumer_inventory(
    stream: &jetstream::stream::Stream,
    manifest: &RecoverableNatsExpectedConsumerManifest,
) -> Result<Vec<RecoverableNatsObservedConsumer>, RecoverableNatsTransportError> {
    let expected = manifest
        .consumers()
        .iter()
        .map(|consumer| (consumer.subject(), consumer.consumer_digest()))
        .collect::<BTreeMap<_, _>>();
    let mut infos = stream.consumers();
    let mut observed = Vec::with_capacity(expected.len());
    while let Some(info) = infos.try_next().await.map_err(nats)? {
        let max_batch = usize::try_from(info.config.max_batch)
            .map_err(|_| RecoverableNatsTransportError::ConsumerContract)?;
        let spec = RecoverableNatsCaptureSpec::for_segment(
            manifest.instance().segment().clone(),
            info.config.filter_subject.clone(),
            max_batch,
        )?;
        spec.attest_consumer(&info.config)?;
        let expected_digest = expected
            .get(spec.subject())
            .ok_or(RecoverableNatsTransportError::ConsumerInventoryMismatch)?;
        if info.stream_name != manifest.instance().segment().stream_name()
            || info.name != spec.durable()
            || expected_digest.as_slice() != spec.consumer_digest().as_slice()
            || info.num_pending != 0
            || info.num_ack_pending != 0
            || info.num_waiting != 0
            || info.push_bound
            || info.delivered.consumer_sequence == 0
            || info.delivered.consumer_sequence != info.ack_floor.consumer_sequence
            || info.delivered.stream_sequence != info.ack_floor.stream_sequence
        {
            return Err(RecoverableNatsTransportError::ConsumerNotQuiescent);
        }
        observed.push(RecoverableNatsObservedConsumer {
            subject: spec.subject().to_owned(),
            name: info.name,
            consumer_digest: spec.consumer_digest(),
            config_digest: recoverable_consumer_config_digest(&spec, &info.config),
            created_nanos: info.created.unix_timestamp_nanos(),
            delivered_consumer_sequence: info.delivered.consumer_sequence,
            delivered_stream_sequence: info.delivered.stream_sequence,
            delivered_last_active_nanos: info
                .delivered
                .last_active
                .map(|time| time.unix_timestamp_nanos()),
            ack_floor_consumer_sequence: info.ack_floor.consumer_sequence,
            ack_floor_stream_sequence: info.ack_floor.stream_sequence,
            ack_floor_last_active_nanos: info
                .ack_floor
                .last_active
                .map(|time| time.unix_timestamp_nanos()),
            num_redelivered: info.num_redelivered,
        });
    }
    observed.sort_by(|left, right| left.subject.cmp(&right.subject));
    if observed.len() != expected.len()
        || observed.windows(2).any(|pair| pair[0].subject == pair[1].subject)
        || observed
            .iter()
            .map(|entry| entry.subject.as_str())
            .ne(expected.keys().copied())
    {
        return Err(RecoverableNatsTransportError::ConsumerInventoryMismatch);
    }
    Ok(observed)
}

fn recoverable_consumer_config_digest(
    spec: &RecoverableNatsCaptureSpec,
    config: &jetstream::consumer::Config,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_CONFIG_DOMAIN);
    hasher.update(spec.consumer_digest());
    // JetStream may expose an inherited `num_replicas = 0` immediately after
    // create and later normalize the same consumer to the stream's explicit
    // replica count.  The typed spec already commits the minimum/effective
    // replica contract, so those two server representations must share one
    // physical identity while a genuinely different explicit value remains
    // distinct.
    let effective_replicas = if config.num_replicas == 0 {
        spec.minimum_stream_replicas
    } else {
        config.num_replicas
    };
    hasher.update((effective_replicas as u64).to_be_bytes());
    match config.description.as_deref() {
        Some(description) => {
            hasher.update([1]);
            hash_component(&mut hasher, description.as_bytes());
        }
        None => hasher.update([0]),
    }
    // `_nats.*` metadata is server-reserved and is not stable across the
    // CREATE/INFO/LIST APIs or a leader failover. `attest_consumer` rejects
    // every non-reserved key, so omitting this transport-owned view cannot
    // hide an application-level configuration change.
    hasher.finalize().into()
}

fn consumer_inventory_digest(
    manifest_digest: RecoverableNatsConsumerManifestDigest,
    consumers: &[RecoverableNatsObservedConsumer],
) -> Result<RecoverableNatsConsumerInventoryDigest, RecoverableNatsTransportError> {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_INVENTORY_DOMAIN);
    hasher.update(manifest_digest.as_bytes());
    hasher.update((consumers.len() as u64).to_be_bytes());
    for consumer in consumers {
        hash_component(&mut hasher, consumer.subject.as_bytes());
        hash_component(&mut hasher, consumer.name.as_bytes());
        hasher.update(consumer.consumer_digest);
        hasher.update(consumer.config_digest);
        hasher.update(consumer.created_nanos.to_be_bytes());
        hasher.update(consumer.delivered_consumer_sequence.to_be_bytes());
        hasher.update(consumer.delivered_stream_sequence.to_be_bytes());
        encode_optional_nanos(&mut hasher, consumer.delivered_last_active_nanos);
        hasher.update(consumer.ack_floor_consumer_sequence.to_be_bytes());
        hasher.update(consumer.ack_floor_stream_sequence.to_be_bytes());
        encode_optional_nanos(&mut hasher, consumer.ack_floor_last_active_nanos);
        hasher.update((consumer.num_redelivered as u64).to_be_bytes());
    }
    RecoverableNatsConsumerInventoryDigest::try_new(hasher.finalize().into())
}

fn encode_optional_nanos(hasher: &mut Sha256, value: Option<i128>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

fn is_stream_not_found(kind: GetStreamErrorKind) -> bool {
    matches!(
        kind,
        GetStreamErrorKind::JetStream(error)
            if error.error_code() == jetstream::ErrorCode::STREAM_NOT_FOUND
    )
}

fn require_same_delete_instance(
    expected: &RecoverableNatsDeleteExpectation,
    observed: &SealedRecoverableNatsStreamInstance,
) -> Result<(), RecoverableNatsTransportError> {
    if expected.instance_id() != observed.instance_id() {
        return Err(RecoverableNatsTransportError::DeleteRecreatedInstance);
    }
    if expected.segment() != observed.segment() || expected.state() != observed.state() {
        return Err(RecoverableNatsTransportError::DeleteEvidenceChanged);
    }
    Ok(())
}

fn classify_segment_observation(
    expected: &LiveRecoverableNatsStreamInstance,
    info: &StreamInfo,
) -> Result<RecoverableNatsSegmentObservation, RecoverableNatsTransportError> {
    if let Ok(sealed) = expected.segment().attest_sealed_instance(info) {
        require_same_segment_evidence(
            expected,
            sealed.instance_id(),
            sealed.state(),
        )?;
        return Ok(RecoverableNatsSegmentObservation::Sealed(sealed));
    }
    if let Ok(live) = expected.segment().attest_live_instance(info) {
        require_same_segment_evidence(expected, live.instance_id(), live.state())?;
        return Ok(RecoverableNatsSegmentObservation::Live(live));
    }
    Err(RecoverableNatsTransportError::SealContractDrift)
}

fn classify_seal_readback(
    update_succeeded: bool,
    observed: RecoverableNatsSegmentObservation,
) -> Result<RecoverableNatsSealOutcome, RecoverableNatsTransportError> {
    let RecoverableNatsSegmentObservation::Sealed(sealed) = observed else {
        return Err(RecoverableNatsTransportError::SealNotApplied);
    };
    Ok(RecoverableNatsSealOutcome {
        sealed,
        disposition: if update_succeeded {
            RecoverableNatsSealDisposition::Applied
        } else {
            RecoverableNatsSealDisposition::ReconciledAfterResponseLoss
        },
    })
}

fn require_same_segment_evidence(
    expected: &LiveRecoverableNatsStreamInstance,
    observed_instance: crate::recoverable_segment::RecoverableNatsStreamInstanceId,
    observed_state: crate::recoverable_segment::RecoverableNatsStreamStateSnapshot,
) -> Result<(), RecoverableNatsTransportError> {
    if observed_instance != expected.instance_id() {
        return Err(RecoverableNatsTransportError::SealRecreatedInstance);
    }
    if observed_state != expected.state() {
        return Err(RecoverableNatsTransportError::SealEvidenceChanged);
    }
    Ok(())
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
    WholeStreamScanChanged,
    ConsumerInventoryMismatch,
    ConsumerInventoryChanged,
    ConsumerNotQuiescent,
    ConsumerInstanceChanged,
    ConsumerProvisioningIndeterminate(String),
    SealNotApplied,
    SealRecreatedInstance,
    SealEvidenceChanged,
    SealContractDrift,
    SealIndeterminate(String),
    DeleteNotApplied,
    DeleteRecreatedInstance,
    DeleteEvidenceChanged,
    DeleteContractDrift,
    DeleteIndeterminate(String),
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
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Coordinator,
        );
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
        envelope_for_segment(segment)
    }

    fn envelope_for_segment(
        segment: RecoverableNatsStreamSegment,
    ) -> (RecoverableNatsStreamSegment, PendingQueuePublishEnvelope) {
        let (segment, _, envelope) = fixture_for_segment(segment);
        (segment, envelope)
    }

    #[test]
    fn typed_seal_readback_is_exact_and_response_loss_safe() {
        let segment = envelope().0;
        let state = crate::recoverable_segment::RecoverableNatsStreamStateSnapshot::try_new(
            1, 100, 1, 1, 0, 1,
        )
        .unwrap();
        let expected = segment.model_live_instance(1_700_000_000_000_000_000, state);
        let sealed = segment.model_sealed_instance(1_700_000_000_000_000_000, state);

        let applied = classify_seal_readback(
            true,
            RecoverableNatsSegmentObservation::Sealed(sealed.clone()),
        )
        .unwrap();
        assert_eq!(applied.disposition(), RecoverableNatsSealDisposition::Applied);
        assert_eq!(applied.sealed(), &sealed);
        assert_eq!(
            classify_seal_readback(
                false,
                RecoverableNatsSegmentObservation::Sealed(sealed),
            )
            .unwrap()
            .disposition(),
            RecoverableNatsSealDisposition::ReconciledAfterResponseLoss,
        );
        assert_eq!(
            classify_seal_readback(
                false,
                RecoverableNatsSegmentObservation::Live(expected.clone()),
            ),
            Err(RecoverableNatsTransportError::SealNotApplied),
        );

        let recreated = segment.model_live_instance(1_700_000_000_000_000_001, state);
        assert_eq!(
            require_same_segment_evidence(
                &expected,
                recreated.instance_id(),
                recreated.state(),
            ),
            Err(RecoverableNatsTransportError::SealRecreatedInstance),
        );
        let changed = crate::recoverable_segment::RecoverableNatsStreamStateSnapshot::try_new(
            1, 101, 1, 1, 0, 1,
        )
        .unwrap();
        assert_eq!(
            require_same_segment_evidence(&expected, expected.instance_id(), changed),
            Err(RecoverableNatsTransportError::SealEvidenceChanged),
        );
    }

    #[test]
    fn typed_delete_identity_and_disposition_are_exact() {
        let segment = envelope().0;
        let state = crate::recoverable_segment::RecoverableNatsStreamStateSnapshot::try_new(
            1, 100, 1, 1, 0, 1,
        )
        .unwrap();
        let sealed = segment.model_sealed_instance(1_700_000_000_000_000_000, state);
        assert_eq!(
            RecoverableNatsStreamInstanceId::try_from_bytes(*sealed.instance_id().as_bytes())
                .unwrap(),
            sealed.instance_id(),
        );
        assert!(RecoverableNatsStreamInstanceId::try_from_bytes([0; 32]).is_err());
        let expected = RecoverableNatsDeleteExpectation::from_sealed(&sealed);
        assert_eq!(require_same_delete_instance(&expected, &sealed), Ok(()));

        let recreated = segment.model_sealed_instance(1_700_000_000_000_000_001, state);
        assert_eq!(
            require_same_delete_instance(&expected, &recreated),
            Err(RecoverableNatsTransportError::DeleteRecreatedInstance),
        );
        let changed_state =
            crate::recoverable_segment::RecoverableNatsStreamStateSnapshot::try_new(
                1, 101, 1, 1, 0, 1,
            )
            .unwrap();
        let changed =
            segment.model_sealed_instance(1_700_000_000_000_000_000, changed_state);
        assert_eq!(
            require_same_delete_instance(&expected, &changed),
            Err(RecoverableNatsTransportError::DeleteEvidenceChanged),
        );

        for disposition in [
            RecoverableNatsDeleteDisposition::Applied,
            RecoverableNatsDeleteDisposition::AlreadyAbsent,
            RecoverableNatsDeleteDisposition::ReconciledAfterResponseLoss,
        ] {
            let outcome = RecoverableNatsDeleteOutcome {
                instance_id: expected.instance_id(),
                disposition,
            };
            assert_eq!(outcome.instance_id(), expected.instance_id());
            assert_eq!(outcome.disposition(), disposition);
        }
    }

    #[test]
    fn consumer_manifest_and_inventory_commit_exact_identity_and_config() {
        let segment = envelope().0;
        let subject = segment
            .exact_subject("coord.r0.rs0.p100.topic1.g0")
            .unwrap();
        let spec = RecoverableNatsCaptureSpec::for_segment(
            segment.clone(),
            subject.clone(),
            16,
        )
        .unwrap();
        let state = crate::recoverable_segment::RecoverableNatsStreamStateSnapshot::try_new(
            1, 100, 1, 1, 1, 1,
        )
        .unwrap();
        let sealed = segment.model_sealed_instance(
            1_700_000_000_000_000_000,
            state,
        );
        let expected = RecoverableNatsExpectedConsumer::try_new(
            subject.clone(),
            spec.consumer_digest(),
        )
        .unwrap();
        let manifest = RecoverableNatsExpectedConsumerManifest::try_new(
            sealed.clone(),
            vec![expected.clone()],
        )
        .unwrap();
        assert_eq!(
            manifest,
            RecoverableNatsExpectedConsumerManifest::try_new(
                sealed.clone(),
                vec![expected],
            )
            .unwrap(),
        );
        assert!(RecoverableNatsExpectedConsumerManifest::try_new(
            sealed.clone(),
            Vec::new(),
        )
        .is_err());
        assert!(RecoverableNatsExpectedConsumerManifest::try_new(
            sealed,
            vec![
                RecoverableNatsExpectedConsumer::try_new(
                    subject.clone(),
                    spec.consumer_digest(),
                )
                .unwrap(),
                RecoverableNatsExpectedConsumer::try_new(
                    subject,
                    spec.consumer_digest(),
                )
                .unwrap(),
            ],
        )
        .is_err());

        let config = spec.pull_config().into_consumer_config();
        let first_config = recoverable_consumer_config_digest(&spec, &config);
        let mut server_annotated = spec.pull_config().into_consumer_config();
        server_annotated
            .metadata
            .insert("_nats.req.level".into(), "0".into());
        server_annotated
            .metadata
            .insert("_nats.level".into(), "2".into());
        server_annotated
            .metadata
            .insert("_nats.ver".into(), "2.12.1".into());
        assert_eq!(
            first_config,
            recoverable_consumer_config_digest(&spec, &server_annotated),
        );
        let mut different_operation = server_annotated.clone();
        different_operation.description = Some(consumer_operation_description(
            RecoverableNatsConsumerProvisioningOperationId::try_new([91; 32]).unwrap(),
        ));
        assert_ne!(
            first_config,
            recoverable_consumer_config_digest(&spec, &different_operation),
        );

        let observed = RecoverableNatsObservedConsumer {
            subject: spec.subject().to_owned(),
            name: spec.durable().to_owned(),
            consumer_digest: spec.consumer_digest(),
            config_digest: first_config,
            created_nanos: 1_700_000_000_000_000_000,
            delivered_consumer_sequence: 1,
            delivered_stream_sequence: 1,
            delivered_last_active_nanos: None,
            ack_floor_consumer_sequence: 1,
            ack_floor_stream_sequence: 1,
            ack_floor_last_active_nanos: None,
            num_redelivered: 0,
        };
        let first = consumer_inventory_digest(manifest.digest(), &[observed.clone()]).unwrap();
        let mut recreated = observed;
        recreated.created_nanos += 1;
        let second = consumer_inventory_digest(manifest.digest(), &[recreated]).unwrap();
        assert_ne!(first, second);
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
    fn provisioning_operation_is_committed_in_the_physical_consumer_config() {
        let spec = capture_spec();
        let first = RecoverableNatsConsumerProvisioningOperationId::try_new([41; 32]).unwrap();
        let second = RecoverableNatsConsumerProvisioningOperationId::try_new([42; 32]).unwrap();
        let first_config = spec.pull_config_for_operation(first).into_consumer_config();

        assert_eq!(
            first_config.description.as_deref(),
            Some(consumer_operation_description(first).as_str()),
        );
        assert!(spec.attest_consumer(&first_config).is_ok());
        assert_ne!(
            first_config.description.as_deref(),
            Some(consumer_operation_description(second).as_str()),
        );
        assert!(is_consumer_operation_description(
            first_config.description.as_deref().unwrap()
        ));

        let mut malformed = first_config;
        malformed.description = Some("psy-recoverable-operation-v1:XYZ".to_owned());
        assert!(spec.attest_consumer(&malformed).is_err());
    }

    #[test]
    fn inherited_and_explicit_stream_replica_counts_share_one_physical_identity() {
        let spec = capture_spec();
        let operation =
            RecoverableNatsConsumerProvisioningOperationId::try_new([41; 32]).unwrap();
        let mut inherited = spec
            .pull_config_for_operation(operation)
            .into_consumer_config();
        inherited.num_replicas = 0;
        let mut explicit = inherited.clone();
        explicit.num_replicas = spec.minimum_stream_replicas;
        assert_eq!(
            recoverable_consumer_config_digest(&spec, &inherited),
            recoverable_consumer_config_digest(&spec, &explicit),
        );

        explicit.num_replicas += 1;
        assert_ne!(
            recoverable_consumer_config_digest(&spec, &inherited),
            recoverable_consumer_config_digest(&spec, &explicit),
        );
    }

    #[test]
    fn exact_set_rejects_a_consumer_added_or_deleted_after_enumeration() {
        assert!(require_exact_consumer_count_value(2, 2).is_ok());
        assert_eq!(
            require_exact_consumer_count_value(3, 2),
            Err(RecoverableNatsTransportError::ConsumerInventoryMismatch)
        );
        assert_eq!(
            require_exact_consumer_count_value(1, 2),
            Err(RecoverableNatsTransportError::ConsumerInventoryMismatch)
        );
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
            segment.generation_key(),
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
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Coordinator,
            ),
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
        let live = client
            .observe_recoverable_segment_instance(segment.clone())
            .await
            .unwrap();
        let operation_id =
            RecoverableNatsConsumerProvisioningOperationId::try_new([71; 32]).unwrap();
        let provisioned = client
            .provision_recoverable_capture_consumer(&live, spec.clone(), operation_id)
            .await
            .unwrap();
        let binding = RecoverableNatsExistingConsumerBinding::try_from_durable(
            live.instance_id(),
            &spec,
            operation_id,
            provisioned.consumer_instance_id(),
        )
        .unwrap();
        let mut consumer = client
            .open_existing_recoverable_capture(spec, &binding)
            .await
            .unwrap();
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
            data_committed
                .seal_summary(PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap())
                .unwrap(),
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
        let live_instance = client
            .observe_recoverable_segment_instance(segment.clone())
            .await
            .unwrap();
        let seal_outcome = client
            .seal_recoverable_segment_instance(&live_instance)
            .await
            .unwrap();
        assert_eq!(
            seal_outcome.disposition(),
            RecoverableNatsSealDisposition::Applied
        );
        let sealed_instance = seal_outcome.sealed().clone();
        assert_eq!(sealed_instance.instance_id(), live_instance.instance_id());
        assert_eq!(sealed_instance.state().messages(), 2);
        let whole = client
            .scan_recoverable_sealed_segment(
                PendingQueueNatsWholeStreamExpectedManifest::try_new(
                    sealed_instance.clone(),
                    vec![assignment.clone()],
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(whole.instance_id(), sealed_instance.instance_id());
        assert_eq!(whole.state(), sealed_instance.state());
        assert!(publisher.publish(&seal).await.is_err());
        assert_eq!(
            client
                .delete_recoverable_sealed_segment_instance(
                    &RecoverableNatsDeleteExpectation::from_sealed(&sealed_instance),
                )
                .await
                .unwrap()
                .disposition(),
            RecoverableNatsDeleteDisposition::Applied,
        );
    }
}
