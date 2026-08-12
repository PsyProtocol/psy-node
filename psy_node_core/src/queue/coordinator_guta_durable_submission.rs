//! Driver-independent immutable Coordinator GUTA submission record.
//!
//! The stable slot selects exactly one submitted Realm contribution inside
//! one complete pending/proc namespace.  The record retains everything needed
//! to reconstruct the exact proof cache entry and queue item after a process
//! restart; neither Redis nor an in-memory actor is durable authority.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityScope, PendingContext, PENDING_CONTEXT_V1_LEN};
use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

use crate::psy_temp_db::CoordinatorGutaSubmissionDigest;

const MAGIC: &[u8; 8] = b"PSYCGUTA";
const CODEC_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy/coordinator-guta-durable-submission-slot/v1";
const RECORD_DOMAIN: &[u8] = b"psy/coordinator-guta-durable-submission-record/v1";

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
    use parth_core::PHash;
    use psy_data::protocol::{
        canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId},
        chain_context::{AuthorityScope, PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId},
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
