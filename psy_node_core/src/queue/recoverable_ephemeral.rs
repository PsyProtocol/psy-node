//! Driver-independent two-phase contract for recoverable ephemeral queues.
//!
//! The legacy queue trait returns payload bytes only after the backend has
//! already ACKed or removed them.  That API cannot participate in a durable
//! branch-exact generation.  This module therefore separates:
//!
//! `fetch/stage unacked -> persist/read back artifact chunk -> acknowledge exact batch`.
//!
//! It deliberately does not implement a backend or mint a terminal queue
//! seal or an ACK-authorizing durable receipt.  Those capabilities deliberately
//! remain absent until a concrete durable store and queue backend are composed;
//! an arbitrary trait implementation must not be able to claim persistence.
//! A complete artifact scanner and a linearizable producer fence are both
//! required before `WorkCaptured` or stable-empty evidence can exist.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::{
    QCoreProcCheckpointUniqueId,
    data::queue::queue_key::PCoreStandardQueueKeyForRealm,
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use super::infrastructure::QStandardQueueBase;
use crate::store::{
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::PendingQueueCloseIntentDigest,
};

const CONTEXT_DOMAIN: &[u8] = b"psy/rollback/recoverable-queue-context/v1";
const BATCH_DOMAIN: &[u8] = b"psy/rollback/recoverable-queue-batch/v1";
const PAYLOAD_DOMAIN: &[u8] = b"psy/rollback/recoverable-queue-payload/v1";
const BOUNDARY_DOMAIN: &[u8] = b"psy/rollback/recoverable-queue-boundary/v1";
const NATS_SEQUENCE_SET_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-queue-nats-sequences/v1";
const SOURCE_IDENTITY_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-queue-source-identity/v1";

pub const MAX_RECOVERABLE_QUEUE_BATCH_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECOVERABLE_QUEUE_BATCH_ITEMS: usize = 50_000;
pub const MAX_RECOVERABLE_QUEUE_SOURCE_COMPONENT_BYTES: usize = 512;

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(bytes: [u8; 32]) -> Result<Self, RecoverableQueueError> {
                if bytes == [0; 32] {
                    Err(RecoverableQueueError::EmptyDerivedDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueCaptureContext {
    key: PendingGenerationLedgerKey,
    activation: PendingGenerationActivationDigest,
    processing: PendingGenerationContext,
    digest: PendingQueueCaptureContextDigest,
}

impl PendingQueueCaptureContext {
    pub fn try_new(
        key: PendingGenerationLedgerKey,
        activation: PendingGenerationActivationDigest,
        processing: PendingGenerationContext,
    ) -> Result<Self, RecoverableQueueError> {
        if processing.pending_id().get() == 0
            || processing.proc_checkpoint_id().as_u128() == 0
        {
            return Err(RecoverableQueueError::ZeroProcessingContext);
        }
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_DOMAIN);
        encode_ledger_key(&mut hasher, key);
        hasher.update(activation.as_bytes());
        encode_processing(&mut hasher, processing);
        let digest = nonzero_digest(
            hasher.finalize().into(),
            RecoverableQueueError::EmptyDerivedDigest,
        )?;
        Ok(Self {
            key,
            activation,
            processing,
            digest: PendingQueueCaptureContextDigest(digest),
        })
    }

    pub const fn key(self) -> PendingGenerationLedgerKey {
        self.key
    }

    pub const fn activation(self) -> PendingGenerationActivationDigest {
        self.activation
    }

    pub const fn processing(self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn digest(self) -> PendingQueueCaptureContextDigest {
        self.digest
    }
}

digest_type!(PendingQueueCaptureContextDigest);
digest_type!(PendingQueueSourceIdentityDigest);
digest_type!(PendingQueuePayloadDigest);
digest_type!(PendingQueueBatchDigest);
digest_type!(PendingQueueBoundaryDigest);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RecoverableQueueBackendKind {
    NatsJetStream = 1,
    InMemory = 2,
    Redis = 3,
}

/// Stable address of the exact queue source. Delivery-consumer identity is
/// intentionally separate because a JetStream consumer may be recreated while
/// stream/subject sequence identity remains stable.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSourceIdentity {
    address: PendingQueueSourceAddress,
    digest: PendingQueueSourceIdentityDigest,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PendingQueueSourceAddress {
    NatsJetStream {
        namespace: String,
        stream: String,
        subject: String,
    },
    InMemory {
        namespace: String,
        queue: String,
    },
    Redis {
        namespace: String,
        list_key: String,
    },
}

impl PendingQueueSourceIdentity {
    pub fn nats_jetstream(
        namespace: impl Into<String>,
        stream: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, RecoverableQueueError> {
        Self::try_new(PendingQueueSourceAddress::NatsJetStream {
            namespace: namespace.into(),
            stream: stream.into(),
            subject: subject.into(),
        })
    }

    pub fn in_memory(
        namespace: impl Into<String>,
        queue: impl Into<String>,
    ) -> Result<Self, RecoverableQueueError> {
        Self::try_new(PendingQueueSourceAddress::InMemory {
            namespace: namespace.into(),
            queue: queue.into(),
        })
    }

    pub fn redis(
        namespace: impl Into<String>,
        list_key: impl Into<String>,
    ) -> Result<Self, RecoverableQueueError> {
        Self::try_new(PendingQueueSourceAddress::Redis {
            namespace: namespace.into(),
            list_key: list_key.into(),
        })
    }

    fn try_new(address: PendingQueueSourceAddress) -> Result<Self, RecoverableQueueError> {
        let mut encoded = Vec::with_capacity(128);
        encode_source_address(&address, &mut encoded)?;
        let mut hasher = Sha256::new();
        hasher.update(SOURCE_IDENTITY_DOMAIN);
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(&encoded);
        let digest = PendingQueueSourceIdentityDigest(nonzero_digest(
            hasher.finalize().into(),
            RecoverableQueueError::EmptyDerivedDigest,
        )?);
        Ok(Self { address, digest })
    }

    pub const fn address(&self) -> &PendingQueueSourceAddress {
        &self.address
    }

    pub const fn digest(&self) -> PendingQueueSourceIdentityDigest {
        self.digest
    }

    pub const fn backend(&self) -> RecoverableQueueBackendKind {
        match self.address {
            PendingQueueSourceAddress::NatsJetStream { .. } => {
                RecoverableQueueBackendKind::NatsJetStream
            }
            PendingQueueSourceAddress::InMemory { .. } => {
                RecoverableQueueBackendKind::InMemory
            }
            PendingQueueSourceAddress::Redis { .. } => RecoverableQueueBackendKind::Redis,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecoverableQueueError> {
        encode_source_address(&self.address, out)
    }
}

/// Stable identity for one fetched, still-unacknowledged source range.
///
/// NATS uses stream sequence, which survives consumer recreation. Memory and
/// Redis must first move the prefix into a unique staging generation. A prefix
/// digest alone is deliberately insufficient because identical bytes can
/// reappear after an indeterminate ACK (ABA).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSourceCursor {
    value: PendingQueueSourceCursorValue,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PendingQueueSourceCursorValue {
    NatsJetStream {
        consumer_digest: [u8; 32],
        sequence_set_digest: [u8; 32],
        stream_sequences: Vec<u64>,
    },
    InMemory {
        staging_capture_id: [u8; 32],
        source_revision: u64,
        item_count: u64,
        exact_prefix_digest: [u8; 32],
    },
    Redis {
        staging_capture_id: [u8; 32],
        source_revision: u64,
        item_count: u64,
        exact_prefix_digest: [u8; 32],
    },
}

impl PendingQueueSourceCursor {
    pub fn nats_jetstream(
        consumer_digest: [u8; 32],
        stream_sequences: &[u64],
    ) -> Result<Self, RecoverableQueueError> {
        require_nonzero_source_digest(consumer_digest)?;
        if stream_sequences.is_empty()
            || stream_sequences.len() > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS
        {
            return Err(RecoverableQueueError::InvalidNatsSequenceCount(
                stream_sequences.len(),
            ));
        }
        let mut previous = None;
        let mut hasher = Sha256::new();
        hasher.update(NATS_SEQUENCE_SET_DOMAIN);
        hasher.update((stream_sequences.len() as u64).to_be_bytes());
        for sequence in stream_sequences {
            if *sequence == 0 || previous.is_some_and(|value| value >= *sequence) {
                return Err(RecoverableQueueError::InvalidNatsSequenceOrder {
                    previous,
                    current: *sequence,
                });
            }
            hasher.update(sequence.to_be_bytes());
            previous = Some(*sequence);
        }
        let sequence_set_digest = nonzero_digest(
            hasher.finalize().into(),
            RecoverableQueueError::EmptyDerivedDigest,
        )?;
        Ok(Self {
            value: PendingQueueSourceCursorValue::NatsJetStream {
                consumer_digest,
                sequence_set_digest,
                stream_sequences: stream_sequences.to_vec(),
            },
        })
    }

    pub fn in_memory(
        staging_capture_id: [u8; 32],
        source_revision: u64,
        item_count: u64,
        exact_prefix_digest: [u8; 32],
    ) -> Result<Self, RecoverableQueueError> {
        validate_staged_cursor(staging_capture_id, source_revision, item_count)?;
        require_nonzero_source_digest(exact_prefix_digest)?;
        Ok(Self {
            value: PendingQueueSourceCursorValue::InMemory {
                staging_capture_id,
                source_revision,
                item_count,
                exact_prefix_digest,
            },
        })
    }

    pub fn redis(
        staging_capture_id: [u8; 32],
        source_revision: u64,
        item_count: u64,
        exact_prefix_digest: [u8; 32],
    ) -> Result<Self, RecoverableQueueError> {
        validate_staged_cursor(staging_capture_id, source_revision, item_count)?;
        require_nonzero_source_digest(exact_prefix_digest)?;
        Ok(Self {
            value: PendingQueueSourceCursorValue::Redis {
                staging_capture_id,
                source_revision,
                item_count,
                exact_prefix_digest,
            },
        })
    }

    pub const fn backend(&self) -> RecoverableQueueBackendKind {
        match self.value {
            PendingQueueSourceCursorValue::NatsJetStream { .. } => {
                RecoverableQueueBackendKind::NatsJetStream
            }
            PendingQueueSourceCursorValue::InMemory { .. } => {
                RecoverableQueueBackendKind::InMemory
            }
            PendingQueueSourceCursorValue::Redis { .. } => {
                RecoverableQueueBackendKind::Redis
            }
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match &self.value {
            PendingQueueSourceCursorValue::NatsJetStream {
                consumer_digest,
                sequence_set_digest,
                stream_sequences,
            } => {
                out.push(RecoverableQueueBackendKind::NatsJetStream as u8);
                out.extend_from_slice(consumer_digest);
                out.extend_from_slice(sequence_set_digest);
                out.extend_from_slice(&(stream_sequences.len() as u32).to_be_bytes());
                for sequence in stream_sequences {
                    out.extend_from_slice(&sequence.to_be_bytes());
                }
                out.extend_from_slice(&stream_sequences[0].to_be_bytes());
                out.extend_from_slice(
                    &stream_sequences.last().unwrap().to_be_bytes(),
                );
            }
            PendingQueueSourceCursorValue::InMemory {
                staging_capture_id,
                source_revision,
                item_count,
                exact_prefix_digest,
            } => {
                out.push(RecoverableQueueBackendKind::InMemory as u8);
                out.extend_from_slice(staging_capture_id);
                out.extend_from_slice(&source_revision.to_be_bytes());
                out.extend_from_slice(&item_count.to_be_bytes());
                out.extend_from_slice(exact_prefix_digest);
            }
            PendingQueueSourceCursorValue::Redis {
                staging_capture_id,
                source_revision,
                item_count,
                exact_prefix_digest,
            } => {
                out.push(RecoverableQueueBackendKind::Redis as u8);
                out.extend_from_slice(staging_capture_id);
                out.extend_from_slice(&source_revision.to_be_bytes());
                out.extend_from_slice(&item_count.to_be_bytes());
                out.extend_from_slice(exact_prefix_digest);
            }
        }
    }
}

/// Canonical payload handed to a durable artifact sink before source ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueCaptureCandidate {
    context: PendingQueueCaptureContext,
    source_identity: PendingQueueSourceIdentity,
    source: PendingQueueSourceCursor,
    items: Vec<Vec<u8>>,
    payload_digest: PendingQueuePayloadDigest,
    batch_digest: PendingQueueBatchDigest,
}

impl PendingQueueCaptureCandidate {
    pub fn try_new(
        context: PendingQueueCaptureContext,
        source_identity: PendingQueueSourceIdentity,
        source: PendingQueueSourceCursor,
        items: Vec<Vec<u8>>,
    ) -> Result<Self, RecoverableQueueError> {
        validate_items(&items)?;
        if source_identity.backend() != source.backend() {
            return Err(RecoverableQueueError::SourceBackendMismatch);
        }
        if let PendingQueueSourceCursorValue::NatsJetStream {
            stream_sequences, ..
        } = &source.value
        {
            if stream_sequences.len() != items.len() {
                return Err(
                    RecoverableQueueError::NatsSequenceItemCountMismatch {
                        sequences: stream_sequences.len(),
                        items: items.len(),
                    },
                );
            }
        }
        if let PendingQueueSourceCursorValue::InMemory { item_count, .. }
        | PendingQueueSourceCursorValue::Redis { item_count, .. } = &source.value
        {
            if *item_count != items.len() as u64 {
                return Err(RecoverableQueueError::StagedItemCountMismatch {
                    cursor: *item_count,
                    items: items.len(),
                });
            }
        }
        let payload_digest = payload_digest(&items)?;
        let batch_digest = batch_digest(
            context,
            &source_identity,
            &source,
            items.len(),
            payload_digest,
        )?;
        Ok(Self {
            context,
            source_identity,
            source,
            items,
            payload_digest,
            batch_digest,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn source(&self) -> &PendingQueueSourceCursor {
        &self.source
    }

    pub const fn source_identity(&self) -> &PendingQueueSourceIdentity {
        &self.source_identity
    }

    pub fn items(&self) -> &[Vec<u8>] {
        &self.items
    }

    pub fn into_items(self) -> Vec<Vec<u8>> {
        self.items
    }

    pub fn item_count(&self) -> u64 {
        self.items.len() as u64
    }

    pub fn total_payload_bytes(&self) -> usize {
        self.items.iter().map(Vec::len).sum()
    }

    pub const fn payload_digest(&self) -> PendingQueuePayloadDigest {
        self.payload_digest
    }

    pub const fn batch_digest(&self) -> PendingQueueBatchDigest {
        self.batch_digest
    }

    /// Deterministic artifact payload. It is not a backend ACK token.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_payload_bytes() + 192);
        out.extend_from_slice(b"PSYQCAPT");
        out.extend_from_slice(&1_u16.to_be_bytes());
        encode_context_bytes(self.context, &mut out);
        self.source_identity
            .encode(&mut out)
            .expect("validated source identity must remain canonical");
        self.source.encode(&mut out);
        out.extend_from_slice(&(self.items.len() as u32).to_be_bytes());
        for item in &self.items {
            out.extend_from_slice(&(item.len() as u32).to_be_bytes());
            out.extend_from_slice(item);
        }
        out.extend_from_slice(self.payload_digest.as_bytes());
        out.extend_from_slice(self.batch_digest.as_bytes());
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RecoverableQueueError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != b"PSYQCAPT" {
            return Err(RecoverableQueueError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != 1 {
            return Err(RecoverableQueueError::UnknownCodecVersion(version));
        }
        let network_chain_id = decoder.u32()?;
        let network = NetworkId::try_from_chain_id(network_chain_id)
            .map_err(|_| RecoverableQueueError::UnknownNetwork(network_chain_id))?;
        let authority_kind = decoder.u8()?;
        let realm_id = decoder.u32()?;
        let realm_sub_id = decoder.u16()?;
        let authority = match authority_kind {
            1 if realm_id == 0 && realm_sub_id == 0 => AuthorityScope::Coordinator,
            1 => return Err(RecoverableQueueError::InvalidCoordinatorPadding),
            2 => AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            value => return Err(RecoverableQueueError::UnknownAuthority(value)),
        };
        let activation = PendingGenerationActivationDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| RecoverableQueueError::EmptyActivationDigest)?;
        let pending_id = decoder.u64()?;
        let proc_id = decoder.u128()?;
        let processing = PendingGenerationContext::try_from_legacy(
            pending_id,
            proc_id,
        )
        .map_err(|_| RecoverableQueueError::InvalidProcessingContext)?;
        let context = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(network, authority),
            activation,
            processing,
        )?;

        let source_identity = decode_source_identity(&mut decoder)?;

        let backend = decoder.u8()?;
        let primary_digest = decoder.array32()?;
        let source = match backend {
            1 => {
                let secondary_digest = decoder.array32()?;
                let sequence_count = decoder.u32()? as usize;
                if sequence_count == 0
                    || sequence_count > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS
                {
                    return Err(RecoverableQueueError::InvalidPersistedNatsCursor);
                }
                let mut sequences = Vec::with_capacity(sequence_count);
                for _ in 0..sequence_count {
                    sequences.push(decoder.u64()?);
                }
                let first = decoder.u64()?;
                let last = decoder.u64()?;
                require_nonzero_source_digest(primary_digest)?;
                require_nonzero_source_digest(secondary_digest)?;
                let reconstructed = PendingQueueSourceCursor::nats_jetstream(
                    primary_digest,
                    &sequences,
                )?;
                let PendingQueueSourceCursorValue::NatsJetStream {
                    sequence_set_digest,
                    stream_sequences,
                    ..
                } = reconstructed.value
                else {
                    unreachable!()
                };
                if sequence_set_digest != secondary_digest
                    || stream_sequences[0] != first
                    || *stream_sequences.last().unwrap() != last
                {
                    return Err(RecoverableQueueError::InvalidPersistedNatsCursor);
                }
                PendingQueueSourceCursor {
                    value: PendingQueueSourceCursorValue::NatsJetStream {
                        consumer_digest: primary_digest,
                        sequence_set_digest: secondary_digest,
                        stream_sequences,
                    },
                }
            }
            2 | 3 => {
                let source_revision = decoder.u64()?;
                let staged_item_count = decoder.u64()?;
                let exact_prefix_digest = decoder.array32()?;
                if backend == 2 {
                    PendingQueueSourceCursor::in_memory(
                        primary_digest,
                        source_revision,
                        staged_item_count,
                        exact_prefix_digest,
                    )?
                } else {
                    PendingQueueSourceCursor::redis(
                        primary_digest,
                        source_revision,
                        staged_item_count,
                        exact_prefix_digest,
                    )?
                }
            }
            value => return Err(RecoverableQueueError::UnknownBackend(value)),
        };
        let item_count = decoder.u32()? as usize;
        if item_count > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS {
            return Err(RecoverableQueueError::TooManyItems {
                actual: item_count,
                maximum: MAX_RECOVERABLE_QUEUE_BATCH_ITEMS,
            });
        }
        let mut items = Vec::with_capacity(item_count);
        let mut total_payload_bytes = 0usize;
        for index in 0..item_count {
            let len = decoder.u32()? as usize;
            if len == 0 {
                return Err(RecoverableQueueError::EmptyItem { index });
            }
            if len > MAX_RECOVERABLE_QUEUE_BATCH_BYTES {
                return Err(RecoverableQueueError::ItemTooLarge {
                    index,
                    actual: len,
                });
            }
            total_payload_bytes = total_payload_bytes.checked_add(len).ok_or(
                RecoverableQueueError::BatchTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
                },
            )?;
            if total_payload_bytes > MAX_RECOVERABLE_QUEUE_BATCH_BYTES {
                return Err(RecoverableQueueError::BatchTooLarge {
                    actual: total_payload_bytes,
                    maximum: MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
                });
            }
            items.push(decoder.take(len)?.to_vec());
        }
        let encoded_payload = PendingQueuePayloadDigest::try_new(
            decoder.array32()?,
        )?;
        let encoded_batch = PendingQueueBatchDigest::try_new(decoder.array32()?)?;
        if !decoder.is_done() {
            return Err(RecoverableQueueError::TrailingBytes);
        }
        let candidate = Self::try_new(context, source_identity, source, items)?;
        if candidate.payload_digest != encoded_payload {
            return Err(RecoverableQueueError::PayloadDigestMismatch);
        }
        if candidate.batch_digest != encoded_batch {
            return Err(RecoverableQueueError::BatchDigestMismatch);
        }
        Ok(candidate)
    }
}

/// Separate recoverable fetch/stage capability. Legacy destructive dump methods
/// are intentionally not inherited. This trait deliberately has no ACK method:
/// h22d3b1c1/c2 must compose a concrete Scylla receipt with the concrete
/// backend token without accepting caller-supplied routing arguments.
#[async_trait]
pub trait QRecoverableEphemeralQueueSubscriber: QStandardQueueBase {
    type UnackedBatchToken: Send + Sync;

    async fn fetch_unacked_ephemeral_queue_batch<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        context: PendingQueueCaptureContext,
        max_items: usize,
    ) -> anyhow::Result<Option<UnackedPendingQueueBatch<Self::UnackedBatchToken>>>;
}

/// Backend-private delivery token plus the canonical candidate visible to the
/// artifact sink. The token must own the exact source address/staging handle;
/// later ACK composition must consume this value and must not accept another
/// caller-provided queue key.
pub struct UnackedPendingQueueBatch<Token> {
    token: Token,
    candidate: PendingQueueCaptureCandidate,
}

impl<Token> UnackedPendingQueueBatch<Token> {
    pub fn new(token: Token, candidate: PendingQueueCaptureCandidate) -> Self {
        Self { token, candidate }
    }

    pub fn candidate(&self) -> &PendingQueueCaptureCandidate {
        &self.candidate
    }

    pub fn into_parts(self) -> (Token, PendingQueueCaptureCandidate) {
        (self.token, self.candidate)
    }
}

/// Backend-specific close observation. This value is structurally bound to an
/// exact source, but is not itself authoritative: the concrete backend must
/// obtain it from a linearizable producer fence and the artifact scanner must
/// still prove all chunks through the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueGenerationBoundary {
    context: PendingQueueCaptureContext,
    close_intent: PendingQueueCloseIntentDigest,
    source_identity: PendingQueueSourceIdentity,
    observation: PendingQueueBoundaryObservation,
    digest: PendingQueueBoundaryDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueBoundaryObservation {
    NatsJetStream {
        seal_marker_stream_sequence: u64,
        last_data_stream_sequence: u64,
        seal_marker_digest: [u8; 32],
    },
    InMemory {
        closed_generation_revision: u64,
        staging_capture_id: [u8; 32],
        seal_digest: [u8; 32],
    },
    Redis {
        closed_generation_revision: u64,
        staging_capture_id: [u8; 32],
        seal_digest: [u8; 32],
    },
}

impl PendingQueueGenerationBoundary {
    pub fn try_from_backend_observation(
        context: PendingQueueCaptureContext,
        close_intent: PendingQueueCloseIntentDigest,
        source_identity: PendingQueueSourceIdentity,
        observation: PendingQueueBoundaryObservation,
    ) -> Result<Self, RecoverableQueueError> {
        if source_identity.backend() != observation.backend() {
            return Err(RecoverableQueueError::SourceBackendMismatch);
        }
        let mut observation_bytes = Vec::with_capacity(80);
        observation.encode(&mut observation_bytes)?;
        let mut hasher = Sha256::new();
        hasher.update(BOUNDARY_DOMAIN);
        hasher.update(context.digest.as_bytes());
        hasher.update(close_intent.as_bytes());
        hasher.update(source_identity.digest.as_bytes());
        hasher.update((observation_bytes.len() as u64).to_be_bytes());
        hasher.update(observation_bytes);
        let digest = PendingQueueBoundaryDigest(nonzero_digest(
            hasher.finalize().into(),
            RecoverableQueueError::EmptyDerivedDigest,
        )?);
        Ok(Self {
            context,
            close_intent,
            source_identity,
            observation,
            digest,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn close_intent(&self) -> PendingQueueCloseIntentDigest {
        self.close_intent
    }

    pub const fn source_identity(&self) -> &PendingQueueSourceIdentity {
        &self.source_identity
    }

    pub const fn observation(&self) -> &PendingQueueBoundaryObservation {
        &self.observation
    }

    pub const fn digest(&self) -> PendingQueueBoundaryDigest {
        self.digest
    }
}

impl PendingQueueBoundaryObservation {
    pub const fn backend(&self) -> RecoverableQueueBackendKind {
        match self {
            Self::NatsJetStream { .. } => RecoverableQueueBackendKind::NatsJetStream,
            Self::InMemory { .. } => RecoverableQueueBackendKind::InMemory,
            Self::Redis { .. } => RecoverableQueueBackendKind::Redis,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecoverableQueueError> {
        match self {
            Self::NatsJetStream {
                seal_marker_stream_sequence,
                last_data_stream_sequence,
                seal_marker_digest,
            } => {
                if *seal_marker_stream_sequence == 0
                    || *last_data_stream_sequence >= *seal_marker_stream_sequence
                {
                    return Err(RecoverableQueueError::InvalidNatsBoundary {
                        last_data: *last_data_stream_sequence,
                        seal_marker: *seal_marker_stream_sequence,
                    });
                }
                require_nonzero_source_digest(*seal_marker_digest)?;
                out.push(RecoverableQueueBackendKind::NatsJetStream as u8);
                out.extend_from_slice(&seal_marker_stream_sequence.to_be_bytes());
                out.extend_from_slice(&last_data_stream_sequence.to_be_bytes());
                out.extend_from_slice(seal_marker_digest);
            }
            Self::InMemory {
                closed_generation_revision,
                staging_capture_id,
                seal_digest,
            }
            | Self::Redis {
                closed_generation_revision,
                staging_capture_id,
                seal_digest,
            } => {
                if *closed_generation_revision == 0 {
                    return Err(RecoverableQueueError::ZeroSourceRevision);
                }
                require_nonzero_source_digest(*staging_capture_id)?;
                require_nonzero_source_digest(*seal_digest)?;
                out.push(self.backend() as u8);
                out.extend_from_slice(&closed_generation_revision.to_be_bytes());
                out.extend_from_slice(staging_capture_id);
                out.extend_from_slice(seal_digest);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoverableQueueError {
    ZeroProcessingContext,
    EmptyBatch,
    EmptyItem { index: usize },
    TooManyItems { actual: usize, maximum: usize },
    BatchTooLarge { actual: usize, maximum: usize },
    ItemTooLarge { index: usize, actual: usize },
    EmptySourceDigest,
    EmptyDerivedDigest,
    InvalidNatsSequenceCount(usize),
    InvalidNatsSequenceOrder { previous: Option<u64>, current: u64 },
    NatsSequenceItemCountMismatch { sequences: usize, items: usize },
    SourceBackendMismatch,
    InvalidSourceComponentLength(usize),
    InvalidSourceUtf8,
    ZeroSourceRevision,
    InvalidStagedItemCount(u64),
    StagedItemCountMismatch { cursor: u64, items: usize },
    InvalidNatsBoundary { last_data: u64, seal_marker: u64 },
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownNetwork(u32),
    UnknownAuthority(u8),
    InvalidCoordinatorPadding,
    EmptyActivationDigest,
    InvalidProcessingContext,
    UnknownBackend(u8),
    InvalidPersistedNatsCursor,
    TruncatedPayload,
    TrailingBytes,
    PayloadDigestMismatch,
    BatchDigestMismatch,
}

impl fmt::Display for RecoverableQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RecoverableQueueError {}

fn validate_items(items: &[Vec<u8>]) -> Result<(), RecoverableQueueError> {
    if items.is_empty() {
        return Err(RecoverableQueueError::EmptyBatch);
    }
    if items.len() > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS {
        return Err(RecoverableQueueError::TooManyItems {
            actual: items.len(),
            maximum: MAX_RECOVERABLE_QUEUE_BATCH_ITEMS,
        });
    }
    let mut total = 0usize;
    for (index, item) in items.iter().enumerate() {
        if item.is_empty() {
            return Err(RecoverableQueueError::EmptyItem { index });
        }
        if item.len() > u32::MAX as usize {
            return Err(RecoverableQueueError::ItemTooLarge {
                index,
                actual: item.len(),
            });
        }
        total = total
            .checked_add(item.len())
            .ok_or(RecoverableQueueError::BatchTooLarge {
                actual: usize::MAX,
                maximum: MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
            })?;
    }
    if total > MAX_RECOVERABLE_QUEUE_BATCH_BYTES {
        return Err(RecoverableQueueError::BatchTooLarge {
            actual: total,
            maximum: MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
        });
    }
    Ok(())
}

fn payload_digest(
    items: &[Vec<u8>],
) -> Result<PendingQueuePayloadDigest, RecoverableQueueError> {
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update((items.len() as u64).to_be_bytes());
    for item in items {
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item);
    }
    Ok(PendingQueuePayloadDigest(nonzero_digest(
        hasher.finalize().into(),
        RecoverableQueueError::EmptyDerivedDigest,
    )?))
}

fn batch_digest(
    context: PendingQueueCaptureContext,
    source_identity: &PendingQueueSourceIdentity,
    source: &PendingQueueSourceCursor,
    item_count: usize,
    payload: PendingQueuePayloadDigest,
) -> Result<PendingQueueBatchDigest, RecoverableQueueError> {
    let mut source_bytes = Vec::with_capacity(96);
    source.encode(&mut source_bytes);
    let mut hasher = Sha256::new();
    hasher.update(BATCH_DOMAIN);
    hasher.update(context.digest.as_bytes());
    hasher.update(source_identity.digest.as_bytes());
    hasher.update((source_bytes.len() as u64).to_be_bytes());
    hasher.update(source_bytes);
    hasher.update((item_count as u64).to_be_bytes());
    hasher.update(payload.as_bytes());
    Ok(PendingQueueBatchDigest(nonzero_digest(
        hasher.finalize().into(),
        RecoverableQueueError::EmptyDerivedDigest,
    )?))
}

fn validate_staged_cursor(
    staging_capture_id: [u8; 32],
    source_revision: u64,
    item_count: u64,
) -> Result<(), RecoverableQueueError> {
    require_nonzero_source_digest(staging_capture_id)?;
    if source_revision == 0 {
        return Err(RecoverableQueueError::ZeroSourceRevision);
    }
    if item_count == 0 || item_count > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS as u64 {
        return Err(RecoverableQueueError::InvalidStagedItemCount(item_count));
    }
    Ok(())
}

fn encode_source_address(
    address: &PendingQueueSourceAddress,
    out: &mut Vec<u8>,
) -> Result<(), RecoverableQueueError> {
    match address {
        PendingQueueSourceAddress::NatsJetStream {
            namespace,
            stream,
            subject,
        } => {
            out.push(RecoverableQueueBackendKind::NatsJetStream as u8);
            encode_source_component(namespace, out)?;
            encode_source_component(stream, out)?;
            encode_source_component(subject, out)?;
        }
        PendingQueueSourceAddress::InMemory { namespace, queue } => {
            out.push(RecoverableQueueBackendKind::InMemory as u8);
            encode_source_component(namespace, out)?;
            encode_source_component(queue, out)?;
        }
        PendingQueueSourceAddress::Redis {
            namespace,
            list_key,
        } => {
            out.push(RecoverableQueueBackendKind::Redis as u8);
            encode_source_component(namespace, out)?;
            encode_source_component(list_key, out)?;
        }
    }
    Ok(())
}

fn encode_source_component(
    value: &str,
    out: &mut Vec<u8>,
) -> Result<(), RecoverableQueueError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_RECOVERABLE_QUEUE_SOURCE_COMPONENT_BYTES
        || bytes.contains(&0)
    {
        return Err(RecoverableQueueError::InvalidSourceComponentLength(
            bytes.len(),
        ));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_source_identity(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueSourceIdentity, RecoverableQueueError> {
    let backend = decoder.u8()?;
    let namespace = decoder.source_component()?;
    match backend {
        1 => PendingQueueSourceIdentity::nats_jetstream(
            namespace,
            decoder.source_component()?,
            decoder.source_component()?,
        ),
        2 => PendingQueueSourceIdentity::in_memory(
            namespace,
            decoder.source_component()?,
        ),
        3 => PendingQueueSourceIdentity::redis(
            namespace,
            decoder.source_component()?,
        ),
        value => Err(RecoverableQueueError::UnknownBackend(value)),
    }
}

fn require_nonzero_source_digest(digest: [u8; 32]) -> Result<(), RecoverableQueueError> {
    if digest == [0; 32] {
        Err(RecoverableQueueError::EmptySourceDigest)
    } else {
        Ok(())
    }
}

fn nonzero_digest(
    digest: [u8; 32],
    error: RecoverableQueueError,
) -> Result<[u8; 32], RecoverableQueueError> {
    if digest == [0; 32] {
        Err(error)
    } else {
        Ok(digest)
    }
}

fn encode_context_bytes(context: PendingQueueCaptureContext, out: &mut Vec<u8>) {
    out.extend_from_slice(&context.key.network().chain_id().to_be_bytes());
    match context.key.authority() {
        AuthorityScope::Coordinator => {
            out.push(1);
            out.extend_from_slice(&0_u32.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    out.extend_from_slice(context.activation.as_bytes());
    out.extend_from_slice(&context.processing.pending_id().get().to_be_bytes());
    out.extend_from_slice(
        &context
            .processing
            .proc_checkpoint_id()
            .as_u128()
            .to_be_bytes(),
    );
}

fn encode_ledger_key(hasher: &mut Sha256, key: PendingGenerationLedgerKey) {
    hasher.update(key.network().chain_id().to_be_bytes());
    match key.authority() {
        AuthorityScope::Coordinator => {
            hasher.update([1]);
            hasher.update(0_u32.to_be_bytes());
            hasher.update(0_u16.to_be_bytes());
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

fn encode_processing(hasher: &mut Sha256, processing: PendingGenerationContext) {
    hasher.update(processing.pending_id().get().to_be_bytes());
    hasher.update(processing.proc_checkpoint_id().as_u128().to_be_bytes());
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RecoverableQueueError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RecoverableQueueError::TruncatedPayload)?;
        if end > self.bytes.len() {
            return Err(RecoverableQueueError::TruncatedPayload);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RecoverableQueueError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RecoverableQueueError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().unwrap(),
        ))
    }

    fn u32(&mut self) -> Result<u32, RecoverableQueueError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().unwrap(),
        ))
    }

    fn u64(&mut self) -> Result<u64, RecoverableQueueError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().unwrap(),
        ))
    }

    fn u128(&mut self) -> Result<u128, RecoverableQueueError> {
        Ok(u128::from_be_bytes(
            self.take(16)?.try_into().unwrap(),
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], RecoverableQueueError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn source_component(&mut self) -> Result<String, RecoverableQueueError> {
        let len = self.u16()? as usize;
        if len == 0 || len > MAX_RECOVERABLE_QUEUE_SOURCE_COMPONENT_BYTES {
            return Err(RecoverableQueueError::InvalidSourceComponentLength(len));
        }
        let bytes = self.take(len)?;
        if bytes.contains(&0) {
            return Err(RecoverableQueueError::InvalidSourceComponentLength(len));
        }
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| RecoverableQueueError::InvalidSourceUtf8)
    }

    const fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::pending_generation_identity::PendingGenerationContext;

    fn context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 2,
                },
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(101, 9001).unwrap(),
        )
        .unwrap()
    }

    fn candidate() -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            context(),
            PendingQueueSourceIdentity::nats_jetstream(
                "psy",
                "psy_stream",
                "psy.pq.r7.rs2.u65.qt9.g0",
            )
            .unwrap(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], &[10, 11])
                .unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()],
        )
        .unwrap()
    }

    fn nats_source() -> PendingQueueSourceIdentity {
        PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "psy_stream",
            "psy.pq.r7.rs2.u65.qt9.g0",
        )
        .unwrap()
    }

    #[test]
    fn exact_context_and_source_identity_are_typed() {
        let context = context();
        assert_eq!(context.key().network().chain_id(), 1337);
        assert_eq!(context.processing().pending_id().get(), 101);
        assert!(PendingQueueCaptureContext::try_new(
            context.key(),
            context.activation(),
            PendingGenerationContext::try_from_legacy(0, 0).unwrap(),
        )
        .is_err());
        assert!(PendingQueueSourceCursor::nats_jetstream([4; 32], &[11, 10])
            .is_err());
        assert!(PendingQueueSourceCursor::redis([0; 32], 1, 1, [5; 32]).is_err());
        assert!(PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "psy_stream",
            "",
        )
        .is_err());
        assert_eq!(
            PendingQueueCaptureCandidate::try_new(
                context,
                nats_source(),
                PendingQueueSourceCursor::redis([6; 32], 1, 1, [5; 32])
                    .unwrap(),
                vec![b"one".to_vec()],
            ),
            Err(RecoverableQueueError::SourceBackendMismatch),
        );
        assert!(matches!(
            PendingQueueCaptureCandidate::try_new(
                context,
                PendingQueueSourceIdentity::redis("psy", "queue:7").unwrap(),
                PendingQueueSourceCursor::redis([6; 32], 1, 2, [5; 32])
                    .unwrap(),
                vec![b"one".to_vec()],
            ),
            Err(RecoverableQueueError::StagedItemCountMismatch {
                cursor: 2,
                items: 1
            })
        ));
    }

    #[test]
    fn ordered_payload_and_source_cursor_change_batch_digest() {
        let first = candidate();
        assert_eq!(
            PendingQueueCaptureCandidate::decode_canonical(
                &first.to_canonical_bytes(),
            )
            .unwrap(),
            first,
        );
        let reordered = PendingQueueCaptureCandidate::try_new(
            context(),
            first.source_identity().clone(),
            first.source().clone(),
            vec![b"second".to_vec(), b"first".to_vec()],
        )
        .unwrap();
        let redelivered_elsewhere = PendingQueueCaptureCandidate::try_new(
            context(),
            first.source_identity().clone(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], &[12, 13])
                .unwrap(),
            first.items().to_vec(),
        )
        .unwrap();
        assert_ne!(first.batch_digest(), reordered.batch_digest());
        assert_ne!(first.batch_digest(), redelivered_elsewhere.batch_digest());
        let same_bounds_a = PendingQueueCaptureCandidate::try_new(
            context(),
            nats_source(),
            PendingQueueSourceCursor::nats_jetstream(
                [4; 32],
                &[10, 15, 20],
            )
            .unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        )
        .unwrap();
        let same_bounds_b = PendingQueueCaptureCandidate::try_new(
            context(),
            nats_source(),
            PendingQueueSourceCursor::nats_jetstream(
                [4; 32],
                &[10, 16, 20],
            )
            .unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        )
        .unwrap();
        assert_ne!(same_bounds_a.batch_digest(), same_bounds_b.batch_digest());
        let different_subject = PendingQueueCaptureCandidate::try_new(
            context(),
            PendingQueueSourceIdentity::nats_jetstream(
                "psy",
                "psy_stream",
                "psy.pq.r7.rs2.u65.qt10.g0",
            )
            .unwrap(),
            first.source().clone(),
            first.items().to_vec(),
        )
        .unwrap();
        assert_ne!(first.batch_digest(), different_subject.batch_digest());
        assert_eq!(first.to_canonical_bytes(), candidate().to_canonical_bytes());
    }

    #[test]
    fn canonical_codec_is_strict_and_digest_checked() {
        let candidate = candidate();
        let bytes = candidate.to_canonical_bytes();
        assert_eq!(
            PendingQueueCaptureCandidate::decode_canonical(
                &bytes[..bytes.len() - 1],
            ),
            Err(RecoverableQueueError::TruncatedPayload),
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            PendingQueueCaptureCandidate::decode_canonical(&trailing),
            Err(RecoverableQueueError::TrailingBytes),
        );
        let mut unknown_version = bytes.clone();
        unknown_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            PendingQueueCaptureCandidate::decode_canonical(&unknown_version),
            Err(RecoverableQueueError::UnknownCodecVersion(2)),
        );
        let mut changed_payload = bytes;
        let payload_offset = changed_payload
            .windows(b"first".len())
            .position(|window| window == b"first")
            .unwrap();
        changed_payload[payload_offset] ^= 1;
        assert_eq!(
            PendingQueueCaptureCandidate::decode_canonical(&changed_payload),
            Err(RecoverableQueueError::PayloadDigestMismatch),
        );

        let mut oversized_item = candidate.to_canonical_bytes();
        let first_payload = oversized_item
            .windows(b"first".len())
            .position(|window| window == b"first")
            .unwrap();
        oversized_item[first_payload - 4..first_payload]
            .copy_from_slice(&((MAX_RECOVERABLE_QUEUE_BATCH_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            PendingQueueCaptureCandidate::decode_canonical(&oversized_item),
            Err(RecoverableQueueError::ItemTooLarge {
                index: 0,
                actual
            }) if actual == MAX_RECOVERABLE_QUEUE_BATCH_BYTES + 1
        ));
    }

    #[test]
    fn empty_oversized_and_malformed_batches_fail_closed() {
        assert_eq!(
            PendingQueueCaptureCandidate::try_new(
                context(),
                PendingQueueSourceIdentity::in_memory("test", "q").unwrap(),
                PendingQueueSourceCursor::in_memory([6; 32], 1, 1, [5; 32])
                    .unwrap(),
                Vec::new(),
            ),
            Err(RecoverableQueueError::EmptyBatch),
        );
        assert!(matches!(
            PendingQueueCaptureCandidate::try_new(
                context(),
                PendingQueueSourceIdentity::in_memory("test", "q").unwrap(),
                PendingQueueSourceCursor::in_memory([6; 32], 1, 1, [5; 32])
                    .unwrap(),
                vec![Vec::new()],
            ),
            Err(RecoverableQueueError::EmptyItem { index: 0 })
        ));
        assert!(matches!(
            PendingQueueCaptureCandidate::try_new(
                context(),
                nats_source(),
                PendingQueueSourceCursor::nats_jetstream(
                    [4; 32],
                    &[10, 11],
                )
                .unwrap(),
                vec![b"one".to_vec()],
            ),
            Err(RecoverableQueueError::NatsSequenceItemCountMismatch {
                sequences: 2,
                items: 1,
            })
        ));
        let too_many = vec![vec![1]; MAX_RECOVERABLE_QUEUE_BATCH_ITEMS + 1];
        assert!(matches!(
            PendingQueueCaptureCandidate::try_new(
                context(),
                PendingQueueSourceIdentity::redis("test", "list").unwrap(),
                PendingQueueSourceCursor::redis([6; 32], 1, 1, [5; 32])
                    .unwrap(),
                too_many,
            ),
            Err(RecoverableQueueError::TooManyItems { .. })
        ));
    }

    #[test]
    fn staged_cursor_identity_prevents_prefix_digest_aba() {
        let initial = candidate();
        let source = PendingQueueSourceIdentity::redis("psy", "queue:7").unwrap();
        let a = PendingQueueCaptureCandidate::try_new(
            context(),
            source.clone(),
            PendingQueueSourceCursor::redis([1; 32], 10, 1, [5; 32]).unwrap(),
            vec![b"same".to_vec()],
        )
        .unwrap();
        let b = PendingQueueCaptureCandidate::try_new(
            context(),
            source,
            PendingQueueSourceCursor::redis([2; 32], 11, 1, [5; 32]).unwrap(),
            vec![b"same".to_vec()],
        )
        .unwrap();
        assert_ne!(a.batch_digest(), b.batch_digest());
        let (token, captured) = UnackedPendingQueueBatch::new(77_u64, initial)
            .into_parts();
        assert_eq!(token, 77);
        assert_eq!(captured, candidate());
    }

    #[test]
    fn backend_specific_boundary_is_not_an_empty_poll() {
        let close = PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap();
        assert!(matches!(
            PendingQueueGenerationBoundary::try_from_backend_observation(
                context(),
                close,
                nats_source(),
                PendingQueueBoundaryObservation::NatsJetStream {
                    seal_marker_stream_sequence: 99,
                    last_data_stream_sequence: 99,
                    seal_marker_digest: [6; 32],
                },
            ),
            Err(RecoverableQueueError::InvalidNatsBoundary { .. })
        ));
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context(),
            close,
            nats_source(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 100,
                last_data_stream_sequence: 99,
                seal_marker_digest: [6; 32],
            },
        )
        .unwrap();
        assert_eq!(boundary.source_identity().backend(), RecoverableQueueBackendKind::NatsJetStream);
        assert_ne!(boundary.digest().as_bytes(), &[0; 32]);
    }
}
