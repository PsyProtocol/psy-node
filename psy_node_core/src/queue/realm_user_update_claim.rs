//! Durable, driver-independent admission state for one Realm user update.
//!
//! The slot deliberately includes the complete branch and proc identity. A
//! new branch or generation therefore gets an isolated namespace, while one
//! exact generation/user coordinate still has a single full-request winner.
//! The complete [`PendingContext`] and request digest remain in the canonical
//! payload and are compared on every retry.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityScope, PendingContext};
use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    typed::UserId,
};

use super::{
    realm_user_update_publish::{
        RealmUserUpdatePublishAdmission, RealmUserUpdateRequestDigest,
    },
    recoverable_ephemeral::PendingQueueCaptureContext,
};

const MAGIC: &[u8; 8] = b"PSYRUCIM";
const CODEC_VERSION: u16 = 2;
const SLOT_DOMAIN: &[u8] = b"psy/rollback/realm-user-update-claim-slot/v1";
const STATE_DOMAIN: &[u8] = b"psy/rollback/realm-user-update-claim-state/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateClaimSlot([u8; 32]);

impl RealmUserUpdateClaimSlot {
    fn for_admission<Hash: Q256BitHash>(
        admission: &RealmUserUpdatePublishAdmission<Hash>,
    ) -> Result<Self, RealmUserUpdateClaimError> {
        Self::from_components(
            admission.pending(),
            admission.capture_digest().as_bytes(),
            admission.digest(),
        )
    }

    fn from_components<Hash: Q256BitHash>(
        pending: &PendingContext<Hash>,
        capture_digest: &[u8; 32],
        admission_digest: &[u8; 32],
    ) -> Result<Self, RealmUserUpdateClaimError> {
        let AuthorityScope::Realm { .. } = pending.authority()
        else {
            return Err(RealmUserUpdateClaimError::RealmOnly);
        };
        let mut hasher = Sha256::new();
        hasher.update(SLOT_DOMAIN);
        hasher.update(pending.to_canonical_bytes());
        hasher.update(capture_digest);
        hasher.update(admission_digest);
        let bytes = hasher.finalize().into();
        if bytes == [0; 32] {
            return Err(RealmUserUpdateClaimError::EmptyDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, RealmUserUpdateClaimError> {
        if bytes == [0; 32] {
            Err(RealmUserUpdateClaimError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }
}

/// Fixed bucket inside one exact generation slot. It distributes per-user LWT
/// traffic, but is not by itself a startup index: a scanner must first obtain
/// the opaque generation slot from a separate durable locator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateClaimBucket(u16);

impl RealmUserUpdateClaimBucket {
    pub const COUNT: u16 = 256;

    pub fn for_user(user_id: UserId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"psy/rollback/realm-user-update-claim-bucket/v1");
        hasher.update(user_id.get().to_be_bytes());
        Self(u16::from_be_bytes(
            hasher.finalize()[..2].try_into().expect("fixed digest"),
        ) % Self::COUNT)
    }

    pub fn try_new(value: u16) -> Result<Self, RealmUserUpdateClaimError> {
        if value < Self::COUNT {
            Ok(Self(value))
        } else {
            Err(RealmUserUpdateClaimError::InvalidBucket(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub fn as_i16(self) -> Result<i16, RealmUserUpdateClaimError> {
        i16::try_from(self.0).map_err(|_| RealmUserUpdateClaimError::InvalidBucket(self.0))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateClaimRevision(u64);

impl RealmUserUpdateClaimRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn as_i64(self) -> Result<i64, RealmUserUpdateClaimError> {
        i64::try_from(self.0).map_err(|_| RealmUserUpdateClaimError::RevisionOutOfRange)
    }

    fn next(self) -> Result<Self, RealmUserUpdateClaimError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(RealmUserUpdateClaimError::RevisionOverflow)?;
        if next > i64::MAX as u64 {
            return Err(RealmUserUpdateClaimError::RevisionOutOfRange);
        }
        Ok(Self(next))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateCreatedAtSeconds(u32);

impl RealmUserUpdateCreatedAtSeconds {
    pub fn try_new(value: u32) -> Result<Self, RealmUserUpdateClaimError> {
        if value == 0 {
            Err(RealmUserUpdateClaimError::InvalidCreatedAt)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateDependencyDigest([u8; 32]);

impl RealmUserUpdateDependencyDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmUserUpdateClaimError> {
        if bytes == [0; 32] {
            Err(RealmUserUpdateClaimError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdatePublishReceiptDigest([u8; 32]);

impl RealmUserUpdatePublishReceiptDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmUserUpdateClaimError> {
        if bytes == [0; 32] {
            Err(RealmUserUpdateClaimError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RealmUserUpdateClaimPhase {
    Claimed = 1,
    DependenciesPlanned = 2,
    DependenciesReady = 3,
    Published = 4,
}

impl RealmUserUpdateClaimPhase {
    fn decode(value: u8) -> Result<Self, RealmUserUpdateClaimError> {
        match value {
            1 => Ok(Self::Claimed),
            2 => Ok(Self::DependenciesPlanned),
            3 => Ok(Self::DependenciesReady),
            4 => Ok(Self::Published),
            _ => Err(RealmUserUpdateClaimError::UnknownPhase(value)),
        }
    }
}

/// One immutable request identity plus its monotonic persistence phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRealmUserUpdateClaim<Hash> {
    slot: RealmUserUpdateClaimSlot,
    bucket: RealmUserUpdateClaimBucket,
    revision: RealmUserUpdateClaimRevision,
    pending: PendingContext<Hash>,
    capture_activation_digest: [u8; 32],
    capture_digest: [u8; 32],
    admission_digest: [u8; 32],
    user_id: UserId,
    request_digest: RealmUserUpdateRequestDigest,
    stable_status: u64,
    created_at: RealmUserUpdateCreatedAtSeconds,
    phase: RealmUserUpdateClaimPhase,
    dependency_digest: Option<RealmUserUpdateDependencyDigest>,
    publish_receipt_digest: Option<RealmUserUpdatePublishReceiptDigest>,
    state_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredRealmUserUpdateClaim<Hash> {
    pub fn claimed(
        admission: RealmUserUpdatePublishAdmission<Hash>,
        user_id: UserId,
        request_digest: RealmUserUpdateRequestDigest,
        created_at: RealmUserUpdateCreatedAtSeconds,
    ) -> Result<Self, RealmUserUpdateClaimError> {
        let slot = RealmUserUpdateClaimSlot::for_admission(&admission)?;
        let bucket = RealmUserUpdateClaimBucket::for_user(user_id);
        let pending = admission.pending().clone();
        let capture_activation_digest =
            *admission.capture().activation().as_bytes();
        let mut value = Self {
            slot,
            bucket,
            revision: RealmUserUpdateClaimRevision::INITIAL,
            pending,
            capture_activation_digest,
            capture_digest: *admission.capture_digest().as_bytes(),
            admission_digest: *admission.digest(),
            user_id,
            request_digest,
            stable_status: request_digest.stable_status(),
            created_at,
            phase: RealmUserUpdateClaimPhase::Claimed,
            dependency_digest: None,
            publish_receipt_digest: None,
            state_digest: [1; 32],
        };
        value.state_digest = value.compute_state_digest();
        Ok(value)
    }

    pub fn dependencies_planned(
        expected: &Self,
        dependency_digest: RealmUserUpdateDependencyDigest,
    ) -> Result<Self, RealmUserUpdateClaimError> {
        if expected.phase != RealmUserUpdateClaimPhase::Claimed {
            return Err(RealmUserUpdateClaimError::InvalidTransition);
        }
        let mut candidate = expected.clone();
        candidate.revision = expected.revision.next()?;
        candidate.phase = RealmUserUpdateClaimPhase::DependenciesPlanned;
        candidate.dependency_digest = Some(dependency_digest);
        candidate.state_digest = candidate.compute_state_digest();
        Ok(candidate)
    }

    pub fn dependencies_ready(
        expected: &Self,
    ) -> Result<Self, RealmUserUpdateClaimError> {
        if expected.phase != RealmUserUpdateClaimPhase::DependenciesPlanned
            || expected.dependency_digest.is_none()
        {
            return Err(RealmUserUpdateClaimError::InvalidTransition);
        }
        let mut candidate = expected.clone();
        candidate.revision = expected.revision.next()?;
        candidate.phase = RealmUserUpdateClaimPhase::DependenciesReady;
        candidate.state_digest = candidate.compute_state_digest();
        Ok(candidate)
    }

    pub fn published(
        expected: &Self,
        receipt_digest: RealmUserUpdatePublishReceiptDigest,
    ) -> Result<Self, RealmUserUpdateClaimError> {
        if expected.phase != RealmUserUpdateClaimPhase::DependenciesReady
            || expected.dependency_digest.is_none()
        {
            return Err(RealmUserUpdateClaimError::InvalidTransition);
        }
        let mut candidate = expected.clone();
        candidate.revision = expected.revision.next()?;
        candidate.phase = RealmUserUpdateClaimPhase::Published;
        candidate.publish_receipt_digest = Some(receipt_digest);
        candidate.state_digest = candidate.compute_state_digest();
        Ok(candidate)
    }

    pub fn same_request_as(&self, candidate: &Self) -> bool {
        self.slot == candidate.slot
            && self.bucket == candidate.bucket
            && self.pending == candidate.pending
            && self.capture_activation_digest
                == candidate.capture_activation_digest
            && self.capture_digest == candidate.capture_digest
            && self.admission_digest == candidate.admission_digest
            && self.user_id == candidate.user_id
            && self.request_digest == candidate.request_digest
            && self.stable_status == candidate.stable_status
    }

    pub const fn slot(&self) -> RealmUserUpdateClaimSlot {
        self.slot
    }

    pub const fn revision(&self) -> RealmUserUpdateClaimRevision {
        self.revision
    }

    pub const fn bucket(&self) -> RealmUserUpdateClaimBucket {
        self.bucket
    }

    pub const fn pending(&self) -> &PendingContext<Hash> {
        &self.pending
    }

    pub const fn capture_digest(&self) -> &[u8; 32] {
        &self.capture_digest
    }

    pub const fn capture_activation_digest(&self) -> &[u8; 32] {
        &self.capture_activation_digest
    }

    /// Rebuild the exact admission required by a startup retry. The compact
    /// claim stores the activation digest because it cannot be recovered from
    /// the derived capture/admission digests.
    pub fn reconstruct_admission(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdateClaimError> {
        let generation = PendingGenerationContext::try_from_legacy(
            self.pending.unique_pending_id().get(),
            self.pending.proc_checkpoint_unique_id().as_u128(),
        )
        .map_err(|error| RealmUserUpdateClaimError::Capture(error.to_string()))?;
        let capture = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                self.pending.chain().network_id(),
                self.pending.authority(),
            ),
            PendingGenerationActivationDigest::try_new(
                self.capture_activation_digest,
            )
            .map_err(|error| RealmUserUpdateClaimError::Capture(error.to_string()))?,
            generation,
        )
        .map_err(|error| RealmUserUpdateClaimError::Capture(error.to_string()))?;
        if capture.digest().as_bytes() != &self.capture_digest {
            return Err(RealmUserUpdateClaimError::DigestMismatch);
        }
        let admission = RealmUserUpdatePublishAdmission::try_from_pipeline(
            self.pending.clone(),
            capture,
        )
        .map_err(|error| RealmUserUpdateClaimError::Request(error.to_string()))?;
        if admission.digest() != &self.admission_digest {
            return Err(RealmUserUpdateClaimError::DigestMismatch);
        }
        Ok(admission)
    }

    pub const fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn request_digest(&self) -> RealmUserUpdateRequestDigest {
        self.request_digest
    }

    pub const fn stable_status(&self) -> u64 {
        self.stable_status
    }

    pub const fn created_at(&self) -> RealmUserUpdateCreatedAtSeconds {
        self.created_at
    }

    pub const fn phase(&self) -> RealmUserUpdateClaimPhase {
        self.phase
    }

    pub const fn dependency_digest(&self) -> Option<RealmUserUpdateDependencyDigest> {
        self.dependency_digest
    }

    pub const fn publish_receipt_digest(&self) -> Option<RealmUserUpdatePublishReceiptDigest> {
        self.publish_receipt_digest
    }

    pub const fn state_digest(&self) -> &[u8; 32] {
        &self.state_digest
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_digest();
        bytes.extend_from_slice(&self.state_digest);
        bytes
    }

    pub fn decode_selected(
        selected_slot: RealmUserUpdateClaimSlot,
        selected_bucket: i16,
        selected_user_id: i64,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, RealmUserUpdateClaimError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmUserUpdateClaimError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(RealmUserUpdateClaimError::UnknownCodecVersion);
        }
        let slot = RealmUserUpdateClaimSlot::try_from_bytes(decoder.array32()?)?;
        let bucket = RealmUserUpdateClaimBucket::try_new(decoder.u16()?)?;
        let revision = RealmUserUpdateClaimRevision(decoder.u64()?);
        if revision.get() == 0 || revision.get() > i64::MAX as u64 {
            return Err(RealmUserUpdateClaimError::RevisionOutOfRange);
        }
        let pending = PendingContext::from_canonical_bytes(decoder.take(
            psy_data::protocol::chain_context::PENDING_CONTEXT_V1_LEN,
        )?)
        .map_err(|error| RealmUserUpdateClaimError::PendingCodec(error.to_string()))?;
        let capture_activation_digest = decoder.array32()?;
        let capture_digest = decoder.array32()?;
        let admission_digest = decoder.array32()?;
        if capture_digest == [0; 32] || admission_digest == [0; 32] {
            return Err(RealmUserUpdateClaimError::EmptyDigest);
        }
        let user_id = UserId::new(decoder.u64()?);
        let request_digest = RealmUserUpdateRequestDigest::try_new(decoder.array32()?)
            .map_err(|error| RealmUserUpdateClaimError::Request(error.to_string()))?;
        let stable_status = decoder.u64()?;
        let created_at = RealmUserUpdateCreatedAtSeconds::try_new(decoder.u32()?)?;
        let phase = RealmUserUpdateClaimPhase::decode(decoder.u8()?)?;
        let dependency_digest = decode_optional_digest(&mut decoder)?
            .map(RealmUserUpdateDependencyDigest::try_new)
            .transpose()?;
        let publish_receipt_digest = decode_optional_digest(&mut decoder)?
            .map(RealmUserUpdatePublishReceiptDigest::try_new)
            .transpose()?;
        let state_digest = decoder.array32()?;
        if !decoder.done() {
            return Err(RealmUserUpdateClaimError::TrailingBytes);
        }
        let value = Self {
            slot,
            bucket,
            revision,
            pending,
            capture_activation_digest,
            capture_digest,
            admission_digest,
            user_id,
            request_digest,
            stable_status,
            created_at,
            phase,
            dependency_digest,
            publish_receipt_digest,
            state_digest,
        };
        if selected_slot != value.slot
            || selected_bucket != value.bucket.as_i16()?
            || selected_user_id
                != i64::try_from(value.user_id.get())
                    .map_err(|_| RealmUserUpdateClaimError::UserOutOfRange)?
            || selected_revision != value.revision.as_i64()?
            || RealmUserUpdateClaimBucket::for_user(value.user_id) != value.bucket
            || RealmUserUpdateClaimSlot::from_components(
                &value.pending,
                &value.capture_digest,
                &value.admission_digest,
            )? != value.slot
        {
            return Err(RealmUserUpdateClaimError::SelectedIdentityMismatch);
        }
        if value.capture_activation_digest == [0; 32]
            || value.stable_status == 0
            || value.stable_status != value.request_digest.stable_status()
            || !value.phase_shape_is_valid()
        {
            return Err(RealmUserUpdateClaimError::MalformedPayload);
        }
        if value.compute_state_digest() != value.state_digest {
            return Err(RealmUserUpdateClaimError::DigestMismatch);
        }
        value.reconstruct_admission()?;
        Ok(value)
    }

    fn phase_shape_is_valid(&self) -> bool {
        matches!(
            (self.phase, self.dependency_digest, self.publish_receipt_digest),
            (RealmUserUpdateClaimPhase::Claimed, None, None)
                | (RealmUserUpdateClaimPhase::DependenciesPlanned, Some(_), None)
                | (RealmUserUpdateClaimPhase::DependenciesReady, Some(_), None)
                | (RealmUserUpdateClaimPhase::Published, Some(_), Some(_))
        )
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.slot.as_bytes());
        bytes.extend_from_slice(&self.bucket.get().to_be_bytes());
        bytes.extend_from_slice(&self.revision.get().to_be_bytes());
        bytes.extend_from_slice(&self.pending.to_canonical_bytes());
        bytes.extend_from_slice(&self.capture_activation_digest);
        bytes.extend_from_slice(&self.capture_digest);
        bytes.extend_from_slice(&self.admission_digest);
        bytes.extend_from_slice(&self.user_id.get().to_be_bytes());
        bytes.extend_from_slice(self.request_digest.as_bytes());
        bytes.extend_from_slice(&self.stable_status.to_be_bytes());
        bytes.extend_from_slice(&self.created_at.get().to_be_bytes());
        bytes.push(self.phase as u8);
        encode_optional_digest(&mut bytes, self.dependency_digest.map(|value| *value.as_bytes()));
        encode_optional_digest(
            &mut bytes,
            self.publish_receipt_digest.map(|value| *value.as_bytes()),
        );
        bytes
    }

    fn compute_state_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(STATE_DOMAIN);
        hasher.update(self.encode_without_digest());
        hasher.finalize().into()
    }
}

fn encode_optional_digest(bytes: &mut Vec<u8>, digest: Option<[u8; 32]>) {
    match digest {
        Some(digest) => {
            bytes.push(1);
            bytes.extend_from_slice(&digest);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
    }
}

fn decode_optional_digest(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; 32]>, RealmUserUpdateClaimError> {
    let present = decoder.u8()?;
    let digest = decoder.array32()?;
    match (present, digest) {
        (0, digest) if digest == [0; 32] => Ok(None),
        (1, digest) if digest != [0; 32] => Ok(Some(digest)),
        _ => Err(RealmUserUpdateClaimError::MalformedPayload),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmUserUpdateClaimError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealmUserUpdateClaimError::MalformedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealmUserUpdateClaimError::MalformedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RealmUserUpdateClaimError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RealmUserUpdateClaimError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RealmUserUpdateClaimError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RealmUserUpdateClaimError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], RealmUserUpdateClaimError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateClaimError {
    EmptyDigest,
    InvalidCreatedAt,
    RealmOnly,
    InvalidBucket(u16),
    UserOutOfRange,
    RevisionOverflow,
    RevisionOutOfRange,
    InvalidTransition,
    InvalidMagic,
    UnknownCodecVersion,
    UnknownPhase(u8),
    MalformedPayload,
    TrailingBytes,
    SelectedIdentityMismatch,
    DigestMismatch,
    PendingCodec(String),
    Capture(String),
    Request(String),
}

impl fmt::Display for RealmUserUpdateClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateClaimError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{WorkProcCheckpointUniqueId, WorkUniquePendingId},
    };

    use super::*;
    use crate::store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        typed::UniquePendingId,
    };
    use super::super::recoverable_ephemeral::PendingQueueCaptureContext;

    fn pending(epoch: u64, proc: u128) -> PendingContext<PHash> {
        PendingContext::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(10),
                    CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                        epoch as u8;
                        32
                    ])),
                ),
            ),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            WorkUniquePendingId::new(11),
            WorkProcCheckpointUniqueId::from_u128(proc),
        )
    }

    fn admission(epoch: u64, proc: u128) -> RealmUserUpdatePublishAdmission<PHash> {
        let pending = pending(epoch, proc);
        let key = PendingGenerationLedgerKey::new(
            pending.chain().network_id(),
            pending.authority(),
        );
        let activation = PendingGenerationActivationDigest::try_new([9; 32]).unwrap();
        let generation = PendingGenerationContext::try_from_legacy(
            UniquePendingId::try_new(pending.unique_pending_id().get())
                .unwrap()
                .get(),
            pending.proc_checkpoint_unique_id().as_u128(),
        )
        .unwrap();
        RealmUserUpdatePublishAdmission::try_from_pipeline(
            pending,
            PendingQueueCaptureContext::try_new(key, activation, generation).unwrap(),
        )
        .unwrap()
    }

    fn claimed() -> StoredRealmUserUpdateClaim<PHash> {
        StoredRealmUserUpdateClaim::claimed(
            admission(1, 12),
            UserId::new(13),
            RealmUserUpdateRequestDigest::derive(b"canonical-input", b"proof").unwrap(),
            RealmUserUpdateCreatedAtSeconds::try_new(1234).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn codec_and_monotonic_phases_are_exact() {
        let claimed = claimed();
        let bytes = claimed.to_canonical_bytes();
        assert_eq!(
            StoredRealmUserUpdateClaim::decode_selected(
                claimed.slot(),
                claimed.bucket().as_i16().unwrap(),
                i64::try_from(claimed.user_id().get()).unwrap(),
                claimed.revision().as_i64().unwrap(),
                &bytes,
            )
            .unwrap(),
            claimed
        );
        assert_eq!(claimed.reconstruct_admission().unwrap(), admission(1, 12));
        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &claimed,
            RealmUserUpdateDependencyDigest::try_new([7; 32]).unwrap(),
        )
        .unwrap();
        let dependencies =
            StoredRealmUserUpdateClaim::dependencies_ready(&planned).unwrap();
        let published = StoredRealmUserUpdateClaim::published(
            &dependencies,
            RealmUserUpdatePublishReceiptDigest::try_new([8; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(planned.revision().get(), 2);
        assert_eq!(dependencies.revision().get(), 3);
        assert_eq!(published.revision().get(), 4);
        assert_eq!(published.phase(), RealmUserUpdateClaimPhase::Published);
        assert!(StoredRealmUserUpdateClaim::published(
            &claimed,
            RealmUserUpdatePublishReceiptDigest::try_new([8; 32]).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn exact_generation_namespace_separates_branch_or_proc() {
        let claimed = claimed();
        let same_digest = claimed.request_digest();
        for changed in [admission(2, 12), admission(1, 99)] {
            let other = StoredRealmUserUpdateClaim::claimed(
                changed,
                claimed.user_id(),
                same_digest,
                RealmUserUpdateCreatedAtSeconds::try_new(9999).unwrap(),
            )
            .unwrap();
            assert_ne!(other.slot(), claimed.slot());
            assert!(!claimed.same_request_as(&other));
        }
    }

    #[test]
    fn retry_uses_winner_time_and_full_digest_identity() {
        let claimed = claimed();
        let same = StoredRealmUserUpdateClaim::claimed(
            admission(1, 12),
            claimed.user_id(),
            claimed.request_digest(),
            RealmUserUpdateCreatedAtSeconds::try_new(9999).unwrap(),
        )
        .unwrap();
        assert_ne!(same, claimed);
        assert!(claimed.same_request_as(&same));
        assert_eq!(claimed.created_at().get(), 1234);

        let mut malformed = claimed.to_canonical_bytes();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        assert!(StoredRealmUserUpdateClaim::<PHash>::decode_selected(
            claimed.slot(),
            claimed.bucket().as_i16().unwrap(),
            i64::try_from(claimed.user_id().get()).unwrap(),
            1,
            &malformed,
        )
        .is_err());
    }
}
