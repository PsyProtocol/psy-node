//! Driver-independent immutable Coordinator GUTA submission record.
//!
//! The stable slot selects exactly one submitted Realm contribution inside
//! one complete pending/proc namespace.  The record retains everything needed
//! to reconstruct the exact proof cache entry and queue item after a process
//! restart; neither Redis nor an in-memory actor is durable authority.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::{
    data::queue::queue_key::PCoreQueueItemBase,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    protocol::chain_context::{AuthorityScope, PendingContext, PENDING_CONTEXT_V1_LEN},
};
use psy_data::protocol::canonical_chain::NetworkId;
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata};
use sha2::{Digest, Sha256};

use crate::psy_temp_db::CoordinatorGutaSubmissionDigest;

const MAGIC: &[u8; 8] = b"PSYCGUTA";
const CODEC_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy/coordinator-guta-durable-submission-slot/v1";
const RECORD_DOMAIN: &[u8] = b"psy/coordinator-guta-durable-submission-record/v1";
const QUEUE_POINTER_MAGIC: &[u8; 8] = b"PSYCGQPT";
const QUEUE_POINTER_CODEC_VERSION: u16 = 1;

pub const MAX_COORDINATOR_GUTA_CANONICAL_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_COORDINATOR_GUTA_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COORDINATOR_GUTA_QUEUE_ITEM_BYTES: usize = 64 * 1024;
pub const MAX_COORDINATOR_GUTA_RECORD_BYTES: usize = PENDING_CONTEXT_V1_LEN
    + MAX_COORDINATOR_GUTA_CANONICAL_INPUT_BYTES
    + MAX_COORDINATOR_GUTA_PROOF_BYTES
    + MAX_COORDINATOR_GUTA_QUEUE_ITEM_BYTES
    + 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorGutaDurableSubmissionSlot([u8; 32]);

impl CoordinatorGutaDurableSubmissionSlot {
    pub fn for_submission<Hash: Q256BitHash>(
        pending: &PendingContext<Hash>,
        submitted_realm_id: u64,
    ) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        require_coordinator(pending)?;
        if submitted_realm_id > u32::MAX as u64 {
            return Err(CoordinatorGutaDurableSubmissionError::RealmIdOutOfRange);
        }
        let mut hasher = Sha256::new();
        hasher.update(SLOT_DOMAIN);
        hasher.update(pending.to_canonical_bytes());
        hasher.update(submitted_realm_id.to_be_bytes());
        Self::try_from_bytes(hasher.finalize().into())
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        if bytes == [0; 32] {
            Err(CoordinatorGutaDurableSubmissionError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorGutaDurableRecordDigest([u8; 32]);

impl CoordinatorGutaDurableRecordDigest {
    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        if bytes == [0; 32] {
            Err(CoordinatorGutaDurableSubmissionError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Queue transport for one Coordinator GUTA contribution.
///
/// Legacy payloads remain decodable so a disabled deployment can drain an old
/// queue. A durable deployment must require the `Durable` variant: its slot
/// and record digest let a restarted Processor select the immutable Scylla row
/// without consulting Redis for the pending context first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorGutaQueueItem<F, Hash> {
    Legacy(GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>),
    Durable {
        slot: CoordinatorGutaDurableSubmissionSlot,
        record_digest: CoordinatorGutaDurableRecordDigest,
        item: GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    },
}

impl<F: QFelt64, Hash: Q256BitHash> CoordinatorGutaQueueItem<F, Hash> {
    pub const DURABLE_FIXED_SIZE: usize = 10
        + 32
        + 32
        + GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE;

    pub const fn legacy(
        item: GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> Self {
        Self::Legacy(item)
    }

    pub fn durable(
        submission: &CoordinatorGutaDurableSubmission<Hash>,
        item: GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>,
    ) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        let item_bytes = item
            .psy_ser_to_bytes_vec()
            .map_err(|error| CoordinatorGutaDurableSubmissionError::Codec(error.to_string()))?;
        if submission.queue_item() != item_bytes.as_slice() {
            return Err(CoordinatorGutaDurableSubmissionError::QueueItemMismatch);
        }
        if submission.submitted_realm_id()
            != item
                .header
                .header
                .state_transition
                .node_index
                .to_u64_value()
        {
            return Err(CoordinatorGutaDurableSubmissionError::RealmMismatch);
        }
        Ok(Self::Durable {
            slot: submission.slot(),
            record_digest: submission.record_digest(),
            item,
        })
    }

    pub const fn item(
        &self,
    ) -> &GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
        match self {
            Self::Legacy(item) | Self::Durable { item, .. } => item,
        }
    }

    pub const fn durable_pointer(
        &self,
    ) -> Option<(
        CoordinatorGutaDurableSubmissionSlot,
        CoordinatorGutaDurableRecordDigest,
    )> {
        match self {
            Self::Legacy(_) => None,
            Self::Durable {
                slot,
                record_digest,
                ..
            } => Some((*slot, *record_digest)),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PCoreQueueItemBase
    for CoordinatorGutaQueueItem<F, Hash>
{
    fn is_queue_item(data: &[u8]) -> bool {
        Self::decode_queue_item_ref(data).is_ok()
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        if data.len()
            == GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE
        {
            return Ok(Self::Legacy(
                GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::
                    psy_ser_from_slice(data)?,
            ));
        }
        if data.len() != Self::DURABLE_FIXED_SIZE {
            anyhow::bail!("invalid Coordinator GUTA queue item length {}", data.len());
        }
        if &data[..8] != QUEUE_POINTER_MAGIC {
            anyhow::bail!("unknown Coordinator GUTA queue pointer magic");
        }
        if u16::from_be_bytes(data[8..10].try_into().expect("fixed slice"))
            != QUEUE_POINTER_CODEC_VERSION
        {
            anyhow::bail!("unknown Coordinator GUTA queue pointer codec");
        }
        let slot = CoordinatorGutaDurableSubmissionSlot::try_from_bytes(
            data[10..42].try_into().expect("fixed slice"),
        )?;
        let record_digest = CoordinatorGutaDurableRecordDigest::try_from_bytes(
            data[42..74].try_into().expect("fixed slice"),
        )?;
        let item = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::
            psy_ser_from_slice(&data[74..])?;
        Ok(Self::Durable {
            slot,
            record_digest,
            item,
        })
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Legacy(item) => item.psy_ser_to_bytes_vec(),
            Self::Durable {
                slot,
                record_digest,
                item,
            } => {
                let mut out = Vec::with_capacity(Self::DURABLE_FIXED_SIZE);
                out.extend_from_slice(QUEUE_POINTER_MAGIC);
                out.extend_from_slice(&QUEUE_POINTER_CODEC_VERSION.to_be_bytes());
                out.extend_from_slice(slot.as_bytes());
                out.extend_from_slice(record_digest.as_bytes());
                out.extend_from_slice(&item.psy_ser_to_bytes_vec()?);
                Ok(out)
            }
        }
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.item().get_restorable_job_id()
    }

    fn get_size_hint() -> usize {
        Self::DURABLE_FIXED_SIZE
    }

    fn has_fixed_size() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorGutaDurableSubmission<Hash> {
    slot: CoordinatorGutaDurableSubmissionSlot,
    pending: PendingContext<Hash>,
    submitted_realm_id: u64,
    canonical_input: Vec<u8>,
    proof_bytes: Vec<u8>,
    queue_item: Vec<u8>,
    submission_digest: CoordinatorGutaSubmissionDigest,
    record_digest: CoordinatorGutaDurableRecordDigest,
}

impl<Hash: Q256BitHash> CoordinatorGutaDurableSubmission<Hash> {
    pub fn try_new(
        pending: PendingContext<Hash>,
        submitted_realm_id: u64,
        canonical_input: Vec<u8>,
        proof_bytes: Vec<u8>,
        queue_item: Vec<u8>,
    ) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        require_coordinator(&pending)?;
        validate_component("canonical_input", &canonical_input, MAX_COORDINATOR_GUTA_CANONICAL_INPUT_BYTES)?;
        validate_component("proof_bytes", &proof_bytes, MAX_COORDINATOR_GUTA_PROOF_BYTES)?;
        validate_component("queue_item", &queue_item, MAX_COORDINATOR_GUTA_QUEUE_ITEM_BYTES)?;
        let slot = CoordinatorGutaDurableSubmissionSlot::for_submission(
            &pending,
            submitted_realm_id,
        )?;
        let submission_digest = CoordinatorGutaSubmissionDigest::from_submission(
            submitted_realm_id,
            &canonical_input,
            &proof_bytes,
        )
        .map_err(|error| CoordinatorGutaDurableSubmissionError::Codec(error.to_string()))?;
        let record_digest = record_digest(
            slot,
            &pending,
            submitted_realm_id,
            &canonical_input,
            &proof_bytes,
            &queue_item,
            submission_digest,
        )?;
        Ok(Self {
            slot,
            pending,
            submitted_realm_id,
            canonical_input,
            proof_bytes,
            queue_item,
            submission_digest,
            record_digest,
        })
    }

    pub const fn slot(&self) -> CoordinatorGutaDurableSubmissionSlot { self.slot }
    pub const fn pending(&self) -> &PendingContext<Hash> { &self.pending }
    pub const fn submitted_realm_id(&self) -> u64 { self.submitted_realm_id }
    pub fn canonical_input(&self) -> &[u8] { &self.canonical_input }
    pub fn proof_bytes(&self) -> &[u8] { &self.proof_bytes }
    pub fn queue_item(&self) -> &[u8] { &self.queue_item }
    pub const fn submission_digest(&self) -> CoordinatorGutaSubmissionDigest { self.submission_digest }
    pub const fn record_digest(&self) -> CoordinatorGutaDurableRecordDigest { self.record_digest }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            10 + 32 + PENDING_CONTEXT_V1_LEN + 8 + 4 * 3
                + self.canonical_input.len()
                + self.proof_bytes.len()
                + self.queue_item.len()
                + 64,
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.pending.to_canonical_bytes());
        out.extend_from_slice(&self.submitted_realm_id.to_be_bytes());
        put_bytes(&mut out, &self.canonical_input);
        put_bytes(&mut out, &self.proof_bytes);
        put_bytes(&mut out, &self.queue_item);
        out.extend_from_slice(self.submission_digest.as_bytes());
        out.extend_from_slice(self.record_digest.as_bytes());
        out
    }

    pub fn decode_selected(
        selected_slot: CoordinatorGutaDurableSubmissionSlot,
        bytes: &[u8],
    ) -> Result<Self, CoordinatorGutaDurableSubmissionError> {
        if bytes.len() > MAX_COORDINATOR_GUTA_RECORD_BYTES {
            return Err(CoordinatorGutaDurableSubmissionError::RecordTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(CoordinatorGutaDurableSubmissionError::UnknownMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(CoordinatorGutaDurableSubmissionError::UnknownCodecVersion);
        }
        let encoded_slot = CoordinatorGutaDurableSubmissionSlot::try_from_bytes(decoder.array32()?)?;
        if encoded_slot != selected_slot {
            return Err(CoordinatorGutaDurableSubmissionError::SlotMismatch);
        }
        let pending = PendingContext::<Hash>::from_canonical_bytes(decoder.take(PENDING_CONTEXT_V1_LEN)?)
            .map_err(|error| CoordinatorGutaDurableSubmissionError::Codec(error.to_string()))?;
        let submitted_realm_id = decoder.u64()?;
        let canonical_input = decoder.bytes(MAX_COORDINATOR_GUTA_CANONICAL_INPUT_BYTES)?;
        let proof_bytes = decoder.bytes(MAX_COORDINATOR_GUTA_PROOF_BYTES)?;
        let queue_item = decoder.bytes(MAX_COORDINATOR_GUTA_QUEUE_ITEM_BYTES)?;
        let submission_digest = CoordinatorGutaSubmissionDigest::try_from_bytes(&decoder.array32()?)
            .map_err(|error| CoordinatorGutaDurableSubmissionError::Codec(error.to_string()))?;
        let record_digest = CoordinatorGutaDurableRecordDigest::try_from_bytes(decoder.array32()?)?;
        decoder.finish()?;
        let decoded = Self::try_new(
            pending,
            submitted_realm_id,
            canonical_input,
            proof_bytes,
            queue_item,
        )?;
        if decoded.submission_digest != submission_digest || decoded.record_digest != record_digest {
            return Err(CoordinatorGutaDurableSubmissionError::DigestMismatch);
        }
        Ok(decoded)
    }
}

#[async_trait]
pub trait CoordinatorGutaDurableSubmissionStore<Hash>: Send + Sync
where
    Hash: Q256BitHash + Send + Sync,
{
    fn network(&self) -> NetworkId;

    fn authority(&self) -> AuthorityScope;

    fn readiness_digest(&self) -> [u8; 32];

    async fn persist_and_readback(
        &self,
        submission: CoordinatorGutaDurableSubmission<Hash>,
    ) -> anyhow::Result<CoordinatorGutaDurableSubmission<Hash>>;

    async fn read_selected(
        &self,
        slot: CoordinatorGutaDurableSubmissionSlot,
    ) -> anyhow::Result<Option<CoordinatorGutaDurableSubmission<Hash>>>;
}

fn require_coordinator<Hash>(pending: &PendingContext<Hash>) -> Result<(), CoordinatorGutaDurableSubmissionError> {
    if pending.authority() == AuthorityScope::Coordinator {
        Ok(())
    } else {
        Err(CoordinatorGutaDurableSubmissionError::CoordinatorOnly)
    }
}

fn validate_component(
    name: &'static str,
    bytes: &[u8],
    max: usize,
) -> Result<(), CoordinatorGutaDurableSubmissionError> {
    if bytes.is_empty() {
        return Err(CoordinatorGutaDurableSubmissionError::EmptyComponent(name));
    }
    if bytes.len() > max {
        return Err(CoordinatorGutaDurableSubmissionError::ComponentTooLarge(name));
    }
    Ok(())
}

fn record_digest<Hash: Q256BitHash>(
    slot: CoordinatorGutaDurableSubmissionSlot,
    pending: &PendingContext<Hash>,
    submitted_realm_id: u64,
    canonical_input: &[u8],
    proof_bytes: &[u8],
    queue_item: &[u8],
    submission_digest: CoordinatorGutaSubmissionDigest,
) -> Result<CoordinatorGutaDurableRecordDigest, CoordinatorGutaDurableSubmissionError> {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(slot.as_bytes());
    hasher.update(pending.to_canonical_bytes());
    hasher.update(submitted_realm_id.to_be_bytes());
    hash_bytes(&mut hasher, canonical_input)?;
    hash_bytes(&mut hasher, proof_bytes)?;
    hash_bytes(&mut hasher, queue_item)?;
    hasher.update(submission_digest.as_bytes());
    CoordinatorGutaDurableRecordDigest::try_from_bytes(hasher.finalize().into())
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), CoordinatorGutaDurableSubmissionError> {
    let len = u64::try_from(bytes.len()).map_err(|_| CoordinatorGutaDurableSubmissionError::RecordTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorGutaDurableSubmissionError> {
        let end = self.offset.checked_add(len).ok_or(CoordinatorGutaDurableSubmissionError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(CoordinatorGutaDurableSubmissionError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CoordinatorGutaDurableSubmissionError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorGutaDurableSubmissionError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorGutaDurableSubmissionError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }

    fn array32(&mut self) -> Result<[u8; 32], CoordinatorGutaDurableSubmissionError> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, CoordinatorGutaDurableSubmissionError> {
        let len = usize::try_from(self.u32()?).map_err(|_| CoordinatorGutaDurableSubmissionError::RecordTooLarge)?;
        if len == 0 {
            return Err(CoordinatorGutaDurableSubmissionError::EmptyDecodedComponent);
        }
        if len > max {
            return Err(CoordinatorGutaDurableSubmissionError::RecordTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), CoordinatorGutaDurableSubmissionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CoordinatorGutaDurableSubmissionError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorGutaDurableSubmissionError {
    CoordinatorOnly,
    RealmIdOutOfRange,
    EmptyDigest,
    EmptyComponent(&'static str),
    EmptyDecodedComponent,
    ComponentTooLarge(&'static str),
    RecordTooLarge,
    UnknownMagic,
    UnknownCodecVersion,
    SlotMismatch,
    DigestMismatch,
    QueueItemMismatch,
    RealmMismatch,
    Truncated,
    TrailingBytes,
    Codec(String),
}

impl fmt::Display for CoordinatorGutaDurableSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorGutaDurableSubmissionError {}

#[cfg(test)]
mod tests {
    use parth_core::{felt::FromPrimitiveValuesFelt, PHash, PF, QJobIdBase};
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::{
        guta::{
            header::GlobalUserTreeAggregatorHeader,
            header_extended::{
                GlobalUserTreeAggregatorHeaderWithTagValue,
                GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
            },
            stats::GUTAStats,
            sub_tree_transition::SubTreeNodeStateTransition,
        },
        protocol::{
            canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId},
            chain_context::{AuthorityScope, PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId},
        },
    };

    use super::*;

    fn pending(authority: AuthorityScope, pending: u64) -> PendingContext<PHash> {
        PendingContext::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
                ChainEpoch::new(2),
                CheckpointRef::new(CheckpointId::new(10), CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4))),
            ),
            authority,
            WorkUniquePendingId::new(pending),
            WorkProcCheckpointUniqueId::from_u128(99),
        )
    }

    fn queue_item(realm_id: u64) -> GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<PF, PHash> {
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: PHash::from_values(1, 2, 3, 4),
                    checkpoint_tree_root: PHash::from_values(5, 6, 7, 8),
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: PHash::from_values(9, 10, 11, 12),
                        new_node_value: PHash::from_values(13, 14, 15, 16),
                        node_index: PF::from_u64_value(realm_id),
                        node_level: PF::from_u64_value(8),
                    },
                    stats: GUTAStats {
                        guta_fees_collected: PF::from_u64_value(1),
                        da_fees_collected: PF::from_u64_value(2),
                        user_ops_processed: PF::from_u64_value(3),
                        total_transactions: PF::from_u64_value(4),
                        slots_modified: PF::from_u64_value(5),
                    },
                    total_aggregation_proofs_generated: PF::from_u64_value(6),
                },
                new_tag_tree_node_value: PHash::from_values(17, 18, 19, 20),
            },
            job_id: QProvingJobDataID::new_invalid_job_id(),
        }
    }

    #[test]
    fn durable_queue_pointer_roundtrip_binds_record_and_preserves_legacy_decode() {
        let item = queue_item(3);
        let item_bytes = item.psy_ser_to_bytes_vec().unwrap();
        let record = CoordinatorGutaDurableSubmission::try_new(
            pending(AuthorityScope::Coordinator, 7),
            3,
            vec![1, 2],
            vec![3, 4, 5],
            item_bytes.clone(),
        )
        .unwrap();

        let legacy = CoordinatorGutaQueueItem::<PF, PHash>::legacy(item);
        assert_eq!(legacy.encode_queue_item_vec().unwrap(), item_bytes);
        assert!(matches!(
            CoordinatorGutaQueueItem::<PF, PHash>::decode_queue_item_ref(&item_bytes).unwrap(),
            CoordinatorGutaQueueItem::Legacy(_),
        ));

        let durable = CoordinatorGutaQueueItem::durable(&record, item).unwrap();
        let bytes = durable.encode_queue_item_vec().unwrap();
        assert_eq!(bytes.len(), CoordinatorGutaQueueItem::<PF, PHash>::DURABLE_FIXED_SIZE);
        assert_eq!(
            CoordinatorGutaQueueItem::<PF, PHash>::decode_queue_item_ref(&bytes).unwrap(),
            durable,
        );
        assert_eq!(
            durable.durable_pointer(),
            Some((record.slot(), record.record_digest())),
        );

        let wrong_record = CoordinatorGutaDurableSubmission::try_new(
            record.pending,
            3,
            vec![1, 2],
            vec![3, 4, 5],
            vec![9],
        )
        .unwrap();
        assert_eq!(
            CoordinatorGutaQueueItem::durable(&wrong_record, item),
            Err(CoordinatorGutaDurableSubmissionError::QueueItemMismatch),
        );
    }

    #[test]
    fn canonical_roundtrip_binds_complete_identity_and_content() {
        let record = CoordinatorGutaDurableSubmission::try_new(
            pending(AuthorityScope::Coordinator, 7),
            3,
            vec![1, 2],
            vec![3, 4, 5],
            vec![6, 7],
        )
        .unwrap();
        let bytes = record.to_canonical_bytes();
        assert_eq!(
            CoordinatorGutaDurableSubmission::<PHash>::decode_selected(record.slot(), &bytes).unwrap(),
            record,
        );

        let other_realm = CoordinatorGutaDurableSubmission::try_new(
            record.pending,
            4,
            vec![1, 2],
            vec![3, 4, 5],
            vec![6, 7],
        )
        .unwrap();
        assert_ne!(record.slot(), other_realm.slot());
        assert_ne!(record.record_digest(), other_realm.record_digest());

        let other_generation = CoordinatorGutaDurableSubmission::try_new(
            pending(AuthorityScope::Coordinator, 8),
            3,
            vec![1, 2],
            vec![3, 4, 5],
            vec![6, 7],
        )
        .unwrap();
        assert_ne!(record.slot(), other_generation.slot());
    }

    #[test]
    fn same_slot_different_content_conflicts_by_digest_and_tamper_fails_closed() {
        let pending = pending(AuthorityScope::Coordinator, 7);
        let winner = CoordinatorGutaDurableSubmission::try_new(
            pending,
            3,
            vec![1],
            vec![2],
            vec![3],
        )
        .unwrap();
        let contender = CoordinatorGutaDurableSubmission::try_new(
            pending,
            3,
            vec![1],
            vec![9],
            vec![3],
        )
        .unwrap();
        assert_eq!(winner.slot(), contender.slot());
        assert_ne!(winner.record_digest(), contender.record_digest());

        let mut bytes = winner.to_canonical_bytes();
        bytes[10 + 32 + PENDING_CONTEXT_V1_LEN + 8 + 4] ^= 1;
        assert_eq!(
            CoordinatorGutaDurableSubmission::<PHash>::decode_selected(winner.slot(), &bytes),
            Err(CoordinatorGutaDurableSubmissionError::DigestMismatch),
        );
        let mut trailing = winner.to_canonical_bytes();
        trailing.push(0);
        assert_eq!(
            CoordinatorGutaDurableSubmission::<PHash>::decode_selected(winner.slot(), &trailing),
            Err(CoordinatorGutaDurableSubmissionError::TrailingBytes),
        );
    }

    #[test]
    fn rejects_wrong_authority_empty_and_oversized_components_before_persistence() {
        assert_eq!(
            CoordinatorGutaDurableSubmission::try_new(
                pending(AuthorityScope::Realm { realm_id: 1, realm_sub_id: 0 }, 7),
                3,
                vec![1],
                vec![2],
                vec![3],
            ),
            Err(CoordinatorGutaDurableSubmissionError::CoordinatorOnly),
        );
        assert_eq!(
            CoordinatorGutaDurableSubmission::try_new(
                pending(AuthorityScope::Coordinator, 7),
                3,
                vec![],
                vec![2],
                vec![3],
            ),
            Err(CoordinatorGutaDurableSubmissionError::EmptyComponent("canonical_input")),
        );
        assert_eq!(
            CoordinatorGutaDurableSubmission::try_new(
                pending(AuthorityScope::Coordinator, 7),
                3,
                vec![1],
                vec![2; MAX_COORDINATOR_GUTA_PROOF_BYTES + 1],
                vec![3],
            ),
            Err(CoordinatorGutaDurableSubmissionError::ComponentTooLarge("proof_bytes")),
        );
    }
}
