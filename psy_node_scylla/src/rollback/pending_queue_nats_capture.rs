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

use async_nats::jetstream::{
    self,
    consumer::{
        AckPolicy, DeliverPolicy, PullConsumer, ReplayPolicy,
        pull::Config as PullConfig,
    },
    stream::{Config as StreamConfig, RetentionPolicy, StorageType},
};
use futures::StreamExt;
use psy_node_core::queue::recoverable_ephemeral::{
    MAX_RECOVERABLE_QUEUE_BATCH_ITEMS, PendingQueueArtifactIdentity,
    PendingQueueCaptureCandidate, PendingQueueCaptureContext,
    PendingQueueSourceCursor, PendingQueueSourceCursorView,
    PendingQueueSourceIdentity,
};
use psy_node_nats::queue::NatsJetStreamClient;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::{
    DurablySelectedPendingQueueBatchReceipt, PendingQueueArtifactStoreError,
    PendingQueueArtifactOwnerPermit, ScyllaPendingQueueArtifactStore,
};

const CONSUMER_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-nats-consumer/v1";
const DURABLE_PREFIX: &str = "psy_beq_v2_";
const DEFAULT_ACK_WAIT: Duration = Duration::from_secs(30);
const DEFAULT_FETCH_EXPIRES: Duration = Duration::from_millis(250);

/// Exact immutable contract for one recoverable pull consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecoverableNatsConsumerContract {
    namespace: String,
    stream: String,
    subject: String,
    durable: String,
    consumer_digest: [u8; 32],
    minimum_stream_replicas: usize,
    max_batch_items: usize,
    ack_wait: Duration,
}

impl RecoverableNatsConsumerContract {
    pub(super) fn try_new(
        namespace: impl Into<String>,
        stream: impl Into<String>,
        subject: impl Into<String>,
        minimum_stream_replicas: usize,
        max_batch_items: usize,
    ) -> Result<Self, PendingQueueNatsCaptureError> {
        let namespace = namespace.into();
        let stream = stream.into();
        let subject = subject.into();
        if namespace.is_empty() || stream.is_empty() || subject.is_empty() {
            return Err(PendingQueueNatsCaptureError::EmptyAddressComponent);
        }
        if !(1..=5).contains(&minimum_stream_replicas) {
            return Err(PendingQueueNatsCaptureError::InvalidReplicaRequirement(
                minimum_stream_replicas,
            ));
        }
        if max_batch_items == 0
            || max_batch_items > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS
            || max_batch_items > i64::MAX as usize
        {
            return Err(PendingQueueNatsCaptureError::InvalidBatchLimit(
                max_batch_items,
            ));
        }

        // The durable name is derived from the address first; the final cursor
        // digest then binds that durable and every normalized delivery field.
        // Keeping the two derivations separate avoids a digest/name cycle.
        let mut seed = Sha256::new();
        seed.update(b"psy/rollback/recoverable-nats-durable/v1");
        hash_component(&mut seed, namespace.as_bytes());
        hash_component(&mut seed, stream.as_bytes());
        hash_component(&mut seed, subject.as_bytes());
        seed.update((minimum_stream_replicas as u64).to_be_bytes());
        seed.update((max_batch_items as u64).to_be_bytes());
        let durable_seed: [u8; 32] = seed.finalize().into();
        let durable = format!("{DURABLE_PREFIX}{}", hex_prefix(&durable_seed, 16));
        let consumer_digest = canonical_consumer_digest(
            &namespace,
            &stream,
            &subject,
            &durable,
            minimum_stream_replicas,
            max_batch_items,
            DEFAULT_ACK_WAIT,
        );
        if consumer_digest == [0; 32] {
            return Err(PendingQueueNatsCaptureError::EmptyConsumerDigest);
        }
        Ok(Self {
            namespace,
            stream,
            subject,
            durable,
            consumer_digest,
            minimum_stream_replicas,
            max_batch_items,
            ack_wait: DEFAULT_ACK_WAIT,
        })
    }

    pub(super) fn source_identity(
        &self,
    ) -> Result<PendingQueueSourceIdentity, PendingQueueNatsCaptureError> {
        PendingQueueSourceIdentity::nats_jetstream(
            self.namespace.clone(),
            self.stream.clone(),
            self.subject.clone(),
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))
    }

    pub(super) fn pull_config(&self) -> PullConfig {
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
            num_replicas: 0,
            memory_storage: false,
            ..Default::default()
        }
    }

    pub(super) fn durable(&self) -> &str {
        &self.durable
    }

    pub(super) const fn consumer_digest(&self) -> &[u8; 32] {
        &self.consumer_digest
    }

    fn attest_stream(
        &self,
        actual: &StreamConfig,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        if actual.name != self.stream {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "stream name differs".into(),
            ));
        }
        if actual.retention != RetentionPolicy::Limits {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "retention must be Limits".into(),
            ));
        }
        if actual.storage != StorageType::File {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "storage must be File".into(),
            ));
        }
        if actual.num_replicas < self.minimum_stream_replicas {
            return Err(PendingQueueNatsCaptureError::StreamContract(format!(
                "stream replicas {} below required {}",
                actual.num_replicas, self.minimum_stream_replicas,
            )));
        }
        if actual.max_messages != -1
            || actual.max_bytes != -1
            || actual.max_messages_per_subject != -1
            || actual.max_age != Duration::ZERO
        {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "stream history has a finite eviction bound".into(),
            ));
        }
        if actual.no_ack {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "stream disables acknowledgements".into(),
            ));
        }
        if !actual.deny_delete || !actual.deny_purge {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "stream must deny message delete and purge".into(),
            ));
        }
        if !actual
            .subjects
            .iter()
            .any(|filter| subject_matches(filter, &self.subject))
        {
            return Err(PendingQueueNatsCaptureError::StreamContract(
                "stream subjects do not contain the exact queue subject".into(),
            ));
        }
        Ok(())
    }

    fn attest_consumer(
        &self,
        actual: &jetstream::consumer::Config,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        let expected = self.pull_config();
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
            || actual.priority_policy
                != jetstream::consumer::PriorityPolicy::None
            || !actual.priority_groups.is_empty()
            || actual.pause_until.is_some()
        {
            return Err(PendingQueueNatsCaptureError::ConsumerContract);
        }
        let normalized_digest = canonical_consumer_digest(
            &self.namespace,
            &self.stream,
            &actual.filter_subject,
            actual
                .durable_name
                .as_deref()
                .ok_or(PendingQueueNatsCaptureError::ConsumerContract)?,
            self.minimum_stream_replicas,
            usize::try_from(actual.max_batch)
                .map_err(|_| PendingQueueNatsCaptureError::ConsumerContract)?,
            actual.ack_wait,
        );
        if normalized_digest != self.consumer_digest {
            return Err(PendingQueueNatsCaptureError::ConsumerDigestMismatch);
        }
        Ok(())
    }

    fn verify_candidate<'candidate>(
        &self,
        candidate: &'candidate PendingQueueCaptureCandidate,
    ) -> Result<&'candidate [u64], PendingQueueNatsCaptureError> {
        if candidate.source_identity() != &self.source_identity()? {
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
        if consumer_digest != &self.consumer_digest {
            return Err(PendingQueueNatsCaptureError::ConsumerDigestMismatch);
        }
        Ok(stream_sequences)
    }
}

struct NatsUnackedBatchToken {
    messages: Vec<jetstream::Message>,
    stream_sequences: Vec<u64>,
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
        if client.base_namespace != contract.namespace
            || client.stream_name != contract.stream
        {
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
    /// NATS ACK, and the durable header advances only after ACK is confirmed.
    pub(super) async fn capture_one(
        &self,
        context: PendingQueueCaptureContext,
    ) -> Result<Option<PendingQueueCaptureCandidate>, PendingQueueNatsCaptureError> {
        let _serial = self.serial.lock().await;
        let identity = PendingQueueArtifactIdentity::try_new(
            context,
            self.contract.source_identity()?,
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
            self.contract.verify_candidate(&selected)?;
            if self.ack_floor_covers(&mut consumer, &selected).await? {
                self.confirm_after_ack(receipt, &selected).await?;
                return Ok(Some(selected));
            }
            let token = self
                .fetch_exact_candidate(&mut consumer, &selected)
                .await?;
            self.ack_and_confirm(token, receipt, &selected, &mut consumer)
                .await?;
            return Ok(Some(selected));
        }

        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        let Some((token, candidate)) = self.fetch_new(&mut consumer, context).await? else {
            return Ok(None);
        };
        let receipt = self
            .store
            .persist_selected_batch(&self.owner, &candidate)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        self.ack_and_confirm(token, receipt, &candidate, &mut consumer)
            .await?;
        Ok(Some(candidate))
    }

    async fn ensure_attested_consumer(
        &self,
    ) -> Result<PullConsumer, PendingQueueNatsCaptureError> {
        let stream = self
            .client
            .jetstream
            .get_stream(&self.contract.stream)
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        let stream_info = stream
            .get_info()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        self.contract.attest_stream(&stream_info.config)?;
        let mut consumer = stream
            .create_consumer_strict(self.contract.pull_config())
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        let info = consumer
            .info()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?
            .clone();
        if info.stream_name != self.contract.stream || info.name != self.contract.durable {
            return Err(PendingQueueNatsCaptureError::ConsumerContract);
        }
        self.contract.attest_consumer(&info.config)?;
        Ok(consumer)
    }

    async fn fetch_new(
        &self,
        consumer: &mut PullConsumer,
        context: PendingQueueCaptureContext,
    ) -> Result<
        Option<(NatsUnackedBatchToken, PendingQueueCaptureCandidate)>,
        PendingQueueNatsCaptureError,
    > {
        let token = self.fetch_token(consumer, self.contract.max_batch_items).await?;
        let Some(token) = token else {
            return Ok(None);
        };
        let items = token
            .messages
            .iter()
            .map(|message| message.message.payload.to_vec())
            .collect();
        let cursor = PendingQueueSourceCursor::nats_jetstream(
            self.contract.consumer_digest,
            &token.stream_sequences,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        let candidate = PendingQueueCaptureCandidate::try_new(
            context,
            self.contract.source_identity()?,
            cursor,
            items,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        Ok(Some((token, candidate)))
    }

    async fn fetch_exact_candidate(
        &self,
        consumer: &mut PullConsumer,
        selected: &PendingQueueCaptureCandidate,
    ) -> Result<NatsUnackedBatchToken, PendingQueueNatsCaptureError> {
        let expected_sequences = self.contract.verify_candidate(selected)?;
        let info = consumer
            .info()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        self.contract.attest_consumer(&info.config)?;
        let ack_floor_stream_sequence = info.ack_floor.stream_sequence;
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
            &token.stream_sequences,
            token
                .messages
                .iter()
                .map(|message| message.message.payload.as_ref()),
        )
        .map_err(|_| PendingQueueNatsCaptureError::RedeliveryMismatch)?;
        Ok(token)
    }

    async fn fetch_token(
        &self,
        consumer: &PullConsumer,
        max_items: usize,
    ) -> Result<Option<NatsUnackedBatchToken>, PendingQueueNatsCaptureError> {
        let mut stream = consumer
            .fetch()
            .max_messages(max_items)
            .expires(self.fetch_expires)
            .messages()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        let mut messages = Vec::with_capacity(max_items);
        let mut sequences = Vec::with_capacity(max_items);
        while let Some(message) = stream.next().await {
            let message = message
                .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
            let info = message
                .info()
                .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
            if info.stream != self.contract.stream
                || info.consumer != self.contract.durable
                || message.message.subject.as_str() != self.contract.subject
                || info.stream_sequence == 0
                || sequences
                    .last()
                    .is_some_and(|previous| *previous >= info.stream_sequence)
            {
                return Err(PendingQueueNatsCaptureError::DeliveryContract);
            }
            sequences.push(info.stream_sequence);
            messages.push(message);
        }
        if messages.is_empty() {
            return Ok(None);
        }
        Ok(Some(NatsUnackedBatchToken {
            messages,
            stream_sequences: sequences,
        }))
    }

    async fn ack_and_confirm(
        &self,
        token: NatsUnackedBatchToken,
        receipt: DurablySelectedPendingQueueBatchReceipt,
        candidate: &PendingQueueCaptureCandidate,
        consumer: &mut PullConsumer,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        let expected = self.contract.verify_candidate(candidate)?;
        let before = consumer
            .info()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        self.contract.attest_consumer(&before.config)?;
        verify_unacked_prefix(
            expected,
            candidate.items(),
            before.ack_floor.stream_sequence,
            &token.stream_sequences,
            token
                .messages
                .iter()
                .map(|message| message.message.payload.as_ref()),
        )
        .map_err(|_| PendingQueueNatsCaptureError::AckTokenMismatch)?;
        for (message, stream_sequence) in token
            .messages
            .into_iter()
            .zip(token.stream_sequences.into_iter())
        {
            if let Err(error) = message.double_ack().await {
                let info = consumer
                    .info()
                    .await
                    .map_err(|read_error| {
                        PendingQueueNatsCaptureError::AckIndeterminate(format!(
                            "double_ack={error}; consumer_info={read_error}"
                        ))
                    })?;
                if info.ack_floor.stream_sequence < stream_sequence {
                    return Err(PendingQueueNatsCaptureError::AckIndeterminate(
                        error.to_string(),
                    ));
                }
            }
        }
        if !self.ack_floor_covers(consumer, candidate).await? {
            return Err(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery);
        }
        self.confirm_after_ack(receipt, candidate).await
    }

    async fn ack_floor_covers(
        &self,
        consumer: &mut PullConsumer,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<bool, PendingQueueNatsCaptureError> {
        let sequences = self.contract.verify_candidate(candidate)?;
        let last = *sequences
            .last()
            .ok_or(PendingQueueNatsCaptureError::SourceCursorMismatch)?;
        let info = consumer
            .info()
            .await
            .map_err(|error| PendingQueueNatsCaptureError::Nats(error.to_string()))?;
        self.contract.attest_consumer(&info.config)?;
        Ok(info.ack_floor.consumer_sequence > 0
            && info.ack_floor.stream_sequence >= last)
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

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn canonical_consumer_digest(
    namespace: &str,
    stream: &str,
    subject: &str,
    durable: &str,
    minimum_stream_replicas: usize,
    max_batch_items: usize,
    ack_wait: Duration,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_DIGEST_DOMAIN);
    hasher.update(1_u16.to_be_bytes());
    for component in [namespace, stream, subject, durable] {
        hash_component(&mut hasher, component.as_bytes());
    }
    hasher.update((minimum_stream_replicas as u64).to_be_bytes());
    // Stable protocol tags, deliberately independent of async-nats' Rust enum
    // layout (DeliverPolicy also has data-carrying variants).
    hasher.update([1_u8]); // DeliverPolicy::All
    hasher.update([2_u8]); // AckPolicy::Explicit
    hasher.update((ack_wait.as_nanos() as u64).to_be_bytes());
    hasher.update((-1_i64).to_be_bytes());
    hasher.update((max_batch_items as u64).to_be_bytes());
    hasher.update((max_batch_items as u64).to_be_bytes());
    hasher.update([1_u8]); // ReplayPolicy::Instant
    hasher.update(1_i64.to_be_bytes()); // max_waiting: exactly one pull waiter
    hasher.update(0_u64.to_be_bytes());
    // All remaining behavior-affecting fields are fixed at the v1 zero/empty
    // contract: no headers-only/flow-control/heartbeat/rate/sample/expiry/
    // inactive deletion/backoff/priority/pause, and inherited durable storage.
    hasher.update([0_u8; 12]);
    hasher.finalize().into()
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
        if subject_index == subject.len() || (*token != "*" && *token != subject[subject_index]) {
            return false;
        }
        subject_index += 1;
    }
    subject_index == subject.len()
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

#[derive(Debug)]
pub(super) enum PendingQueueNatsCaptureError {
    EmptyAddressComponent,
    InvalidReplicaRequirement(usize),
    InvalidBatchLimit(usize),
    EmptyConsumerDigest,
    ClientContractMismatch,
    OwnerPermitMismatch,
    StreamContract(String),
    ConsumerContract,
    SourceIdentityMismatch,
    SourceCursorMismatch,
    ConsumerDigestMismatch,
    DeliveryContract,
    SelectedAwaitingRedelivery,
    RedeliveryMismatch,
    AckTokenMismatch,
    AckFloorAlreadyComplete,
    AckIndeterminate(String),
    Core(String),
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
            Self::StreamContract(reason) => write!(formatter, "unsafe stream contract: {reason}"),
            Self::ConsumerContract => formatter.write_str("dedicated consumer contract mismatch"),
            Self::SourceIdentityMismatch => formatter.write_str("source identity mismatch"),
            Self::SourceCursorMismatch => formatter.write_str("source cursor mismatch"),
            Self::ConsumerDigestMismatch => formatter.write_str("consumer digest mismatch"),
            Self::DeliveryContract => formatter.write_str("NATS delivery contract mismatch"),
            Self::SelectedAwaitingRedelivery => formatter.write_str("selected batch awaits redelivery"),
            Self::RedeliveryMismatch => formatter.write_str("redelivery differs from durable selection"),
            Self::AckTokenMismatch => formatter.write_str("ACK token differs from durable selection"),
            Self::AckFloorAlreadyComplete => formatter.write_str("ACK floor already covers selected batch"),
            Self::AckIndeterminate(reason) => write!(formatter, "NATS ACK is indeterminate: {reason}"),
            Self::Core(reason) => write!(formatter, "core queue contract failed: {reason}"),
            Self::Nats(reason) => write!(formatter, "NATS operation failed: {reason}"),
            Self::Store(error) => write!(formatter, "artifact store failed: {error}"),
        }
    }
}

impl Error for PendingQueueNatsCaptureError {}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::consumer::IntoConsumerConfig;

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

    #[test]
    fn dedicated_contract_is_deterministic_and_explicit_ack() {
        let first = contract();
        let second = contract();
        assert_eq!(first, second);
        assert_eq!(first.durable(), second.durable());
        assert_eq!(first.durable().len(), DURABLE_PREFIX.len() + 32);
        let config = first.pull_config();
        assert_eq!(config.ack_policy, AckPolicy::Explicit);
        assert_eq!(config.max_deliver, -1);
        assert_eq!(config.deliver_policy, DeliverPolicy::All);
        assert_eq!(config.filter_subject, first.subject);
        assert_eq!(config.max_ack_pending, 1024);
        assert_eq!(config.max_batch, 1024);
        assert!(!config.memory_storage);
    }

    #[test]
    fn consumer_digest_binds_every_recovery_dimension() {
        let baseline = contract();
        for changed in [
            RecoverableNatsConsumerContract::try_new(
                "other", &baseline.stream, &baseline.subject, 3, 1024,
            )
            .unwrap(),
            RecoverableNatsConsumerContract::try_new(
                &baseline.namespace, "other", &baseline.subject, 3, 1024,
            )
            .unwrap(),
            RecoverableNatsConsumerContract::try_new(
                &baseline.namespace, &baseline.stream, "psy.other", 3, 1024,
            )
            .unwrap(),
            RecoverableNatsConsumerContract::try_new(
                &baseline.namespace, &baseline.stream, &baseline.subject, 2, 1024,
            )
            .unwrap(),
            RecoverableNatsConsumerContract::try_new(
                &baseline.namespace, &baseline.stream, &baseline.subject, 3, 512,
            )
            .unwrap(),
        ] {
            assert_ne!(changed.consumer_digest(), baseline.consumer_digest());
            assert_ne!(changed.durable(), baseline.durable());
        }
    }

    #[test]
    fn stream_attestation_is_fail_closed() {
        let contract = contract();
        let safe = safe_stream();
        contract.attest_stream(&safe).unwrap();

        let mut unsafe_cases = Vec::new();
        let mut value = safe.clone();
        value.retention = RetentionPolicy::Interest;
        unsafe_cases.push(value);
        let mut value = safe.clone();
        value.storage = StorageType::Memory;
        unsafe_cases.push(value);
        let mut value = safe.clone();
        value.num_replicas = 2;
        unsafe_cases.push(value);
        let mut value = safe.clone();
        value.max_messages = 1;
        unsafe_cases.push(value);
        let mut value = safe.clone();
        value.max_age = Duration::from_secs(1);
        unsafe_cases.push(value);
        let mut value = safe.clone();
        value.deny_delete = false;
        unsafe_cases.push(value);
        let mut value = safe;
        value.subjects = vec!["other.>".into()];
        unsafe_cases.push(value);

        for unsafe_stream in unsafe_cases {
            assert!(contract.attest_stream(&unsafe_stream).is_err());
        }
    }

    #[test]
    fn subject_filter_matching_is_exact_and_wildcard_aware() {
        assert!(subject_matches("psy.>", "psy.a.b"));
        assert!(subject_matches("psy.*.b", "psy.a.b"));
        assert!(subject_matches("psy.a.b", "psy.a.b"));
        assert!(!subject_matches("psy.>", "psy"));
        assert!(!subject_matches("psy.*", "psy.a.b"));
        assert!(!subject_matches("psy.a", "psy.b"));
        assert!(!subject_matches("psy.>.bad", "psy.a.bad"));
    }

    #[test]
    fn invalid_replica_and_batch_limits_are_rejected() {
        assert!(RecoverableNatsConsumerContract::try_new("n", "s", "q", 0, 1).is_err());
        assert!(RecoverableNatsConsumerContract::try_new("n", "s", "q", 6, 1).is_err());
        assert!(RecoverableNatsConsumerContract::try_new("n", "s", "q", 1, 0).is_err());
        assert!(RecoverableNatsConsumerContract::try_new(
            "n",
            "s",
            "q",
            1,
            MAX_RECOVERABLE_QUEUE_BATCH_ITEMS + 1,
        )
        .is_err());
    }

    #[test]
    fn every_normalized_recovery_field_is_attested() {
        let contract = contract();
        let actual = contract.pull_config().into_consumer_config();
        contract.attest_consumer(&actual).unwrap();

        let mut drifts = Vec::new();
        let mut value = actual.clone();
        value.headers_only = true;
        drifts.push(value);
        let mut value = actual.clone();
        value.inactive_threshold = Duration::from_secs(1);
        drifts.push(value);
        let mut value = actual.clone();
        value.backoff = vec![Duration::from_secs(1)];
        drifts.push(value);
        let mut value = actual.clone();
        value.num_replicas = 1;
        drifts.push(value);
        let mut value = actual.clone();
        value.max_waiting = 2;
        drifts.push(value);
        let mut value = actual.clone();
        value.max_bytes = 1;
        drifts.push(value);
        let mut value = actual.clone();
        value.max_expires = Duration::from_secs(1);
        drifts.push(value);
        let mut value = actual.clone();
        value.metadata.insert("caller.override".into(), "1".into());
        drifts.push(value);
        let mut value = actual;
        value.rate_limit = 1;
        drifts.push(value);

        for drift in drifts {
            assert!(contract.attest_consumer(&drift).is_err());
        }
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

    #[tokio::test]
    #[ignore = "requires PSY_TEST_NATS_URL and a disposable JetStream server"]
    async fn real_nats_strict_consumer_and_double_ack_contract() {
        let url = std::env::var("PSY_TEST_NATS_URL").expect("PSY_TEST_NATS_URL is required");
        let client = async_nats::connect(url).await.unwrap();
        let jetstream = jetstream::new(client);
        let nonce = format!("{}_{}", std::process::id(), monotonic_test_nonce());
        let namespace = format!("psy_c2a_{nonce}");
        let stream_name = format!("{namespace}_stream");
        let subject = format!("{namespace}.pq.r0.rs0.u1.qt1.g0");
        jetstream
            .create_stream(StreamConfig {
                name: stream_name.clone(),
                subjects: vec![format!("{namespace}.>")],
                max_messages: -1,
                max_bytes: -1,
                max_messages_per_subject: -1,
                retention: RetentionPolicy::Limits,
                storage: StorageType::File,
                num_replicas: 1,
                deny_delete: true,
                deny_purge: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let contract = RecoverableNatsConsumerContract::try_new(
            namespace,
            stream_name.clone(),
            subject.clone(),
            1,
            8,
        )
        .unwrap();
        let stream = jetstream.get_stream(stream_name).await.unwrap();
        let mut consumer = stream
            .create_consumer_strict(contract.pull_config())
            .await
            .unwrap();
        let first_info = consumer.info().await.unwrap().clone();
        contract
            .attest_consumer(&first_info.config)
            .unwrap_or_else(|error| panic!("{error}: {:#?}", first_info.config));
        // Strict recreation with exactly the same config must be idempotent.
        let mut same = stream
            .create_consumer_strict(contract.pull_config())
            .await
            .unwrap();
        let same_info = same.info().await.unwrap().clone();
        contract
            .attest_consumer(&same_info.config)
            .unwrap_or_else(|error| panic!("{error}: {:#?}", same_info.config));

        for payload in ["first", "second"] {
            jetstream
                .publish(subject.clone(), payload.into())
                .await
                .unwrap()
                .await
                .unwrap();
        }
        let mut messages = same
            .fetch()
            .max_messages(2)
            .expires(Duration::from_secs(1))
            .messages()
            .await
            .unwrap();
        let mut sequences = Vec::new();
        while let Some(message) = messages.next().await {
            let message = message.unwrap();
            sequences.push(message.info().unwrap().stream_sequence);
            message.double_ack().await.unwrap();
        }
        assert_eq!(sequences.len(), 2);
        assert!(sequences[0] < sequences[1]);
        let info = same.info().await.unwrap();
        assert!(info.ack_floor.consumer_sequence >= 2);
        assert!(info.ack_floor.stream_sequence >= sequences[1]);
    }

    fn monotonic_test_nonce() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
