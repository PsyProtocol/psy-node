//! Immutable post-delete completion for one Realm rollback participant.
//!
//! This row binds the exact global barrier, pre-delete archive completion,
//! physical catalog, and verified post-state.  It is only constructible from
//! the Realm executor's non-Clone result and has no head-publication API.

#![allow(dead_code)]

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use super::realm_rollback_delete_restore_executor::ExecutedRealmRollbackSuffix;

pub(super) const REALM_DELETE_COMPLETION_KEY_DOMAIN: i16 = -6;
const MAGIC: &[u8; 8] = b"PSYRRDC1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 16 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-delete-completion-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-delete-completion.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackDeleteCompletion<Hash> {
    network: NetworkId,
    old_chain_epoch: u64,
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    barrier_digest: [u8; 32],
    archive_completion_slot: [u8; 32],
    archive_completion_digest: [u8; 32],
    catalog_digest: [u8; 32],
    post_state_digest: [u8; 32],
    physical_delete_count: u64,
    restored_row_count: u64,
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackDeleteCompletion<Hash> {
    pub(super) fn try_from_executed(
        executed: &ExecutedRealmRollbackSuffix<Hash>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackDeleteCompletionError> {
        Self::try_from_fields(
            executed.authority(),
            *executed.target(),
            *executed.participant_plan_digest(),
            *executed.barrier_digest(),
            *executed.archive_completion_slot(),
            *executed.archive_completion_digest(),
            *executed.catalog_digest(),
            *executed.post_state_digest(),
            executed.physical_delete_count(),
            executed.restored_row_count(),
            store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        authority: AuthorityScope,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        barrier_digest: [u8; 32],
        archive_completion_slot: [u8; 32],
        archive_completion_digest: [u8; 32],
        catalog_digest: [u8; 32],
        post_state_digest: [u8; 32],
        physical_delete_count: u64,
        restored_row_count: u64,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackDeleteCompletionError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmRollbackDeleteCompletionError::RealmRequired);
        };
        if physical_delete_count == 0
            || restored_row_count > physical_delete_count
            || [
                participant_plan_digest,
                barrier_digest,
                archive_completion_slot,
                archive_completion_digest,
                catalog_digest,
                post_state_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(RealmRollbackDeleteCompletionError::BindingMismatch);
        }
        let network = target.network_id();
        let old_chain_epoch = target.chain_epoch().get();
        let slot = completion_slot(
            network,
            old_chain_epoch,
            authority,
            &participant_plan_digest,
            &barrier_digest,
            &archive_completion_slot,
            &store_fingerprint,
        );
        let mut completion = Self {
            network,
            old_chain_epoch,
            authority,
            target,
            participant_plan_digest,
            barrier_digest,
            archive_completion_slot,
            archive_completion_digest,
            catalog_digest,
            post_state_digest,
            physical_delete_count,
            restored_row_count,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = completion.encode_body();
        completion.digest = completion_digest(&body);
        completion.canonical_bytes = body;
        completion.canonical_bytes.extend_from_slice(&completion.digest);
        if completion.canonical_bytes.len() > MAX_BYTES {
            return Err(RealmRollbackDeleteCompletionError::RowTooLarge);
        }
        Ok(completion)
    }

    pub(super) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackDeleteCompletionError> {
        if bytes.len() > MAX_BYTES || bytes.len() < 32 {
            return Err(RealmRollbackDeleteCompletionError::InvalidLength);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackDeleteCompletionError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RealmRollbackDeleteCompletionError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)?;
        let old_chain_epoch = cursor.u64()?;
        let authority = AuthorityScope::Realm {
            realm_id: cursor.u32()?,
            realm_sub_id: cursor.u16()?,
        };
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )?;
        let participant_plan_digest = cursor.array_32()?;
        let barrier_digest = cursor.array_32()?;
        let archive_completion_slot = cursor.array_32()?;
        let archive_completion_digest = cursor.array_32()?;
        let catalog_digest = cursor.array_32()?;
        let post_state_digest = cursor.array_32()?;
        let physical_delete_count = cursor.u64()?;
        let restored_row_count = cursor.u64()?;
        let store_fingerprint = cursor.array_32()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackDeleteCompletionError::TrailingBytes);
        }
        let decoded = Self::try_from_fields(
            authority,
            target,
            participant_plan_digest,
            barrier_digest,
            archive_completion_slot,
            archive_completion_digest,
            catalog_digest,
            post_state_digest,
            physical_delete_count,
            restored_row_count,
            store_fingerprint,
        )?;
        if decoded.network != network
            || decoded.old_chain_epoch != old_chain_epoch
            || decoded.slot != slot
            || decoded.digest != digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RealmRollbackDeleteCompletionError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Vec<u8> {
        let AuthorityScope::Realm { realm_id, realm_sub_id } = self.authority else {
            unreachable!()
        };
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.network.chain_id().to_le_bytes());
        bytes.extend_from_slice(&self.old_chain_epoch.to_le_bytes());
        bytes.extend_from_slice(&realm_id.to_le_bytes());
        bytes.extend_from_slice(&realm_sub_id.to_le_bytes());
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.participant_plan_digest);
        bytes.extend_from_slice(&self.barrier_digest);
        bytes.extend_from_slice(&self.archive_completion_slot);
        bytes.extend_from_slice(&self.archive_completion_digest);
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.post_state_digest);
        bytes.extend_from_slice(&self.physical_delete_count.to_le_bytes());
        bytes.extend_from_slice(&self.restored_row_count.to_le_bytes());
        bytes.extend_from_slice(&self.store_fingerprint);
        bytes.extend_from_slice(&self.slot);
        bytes
    }

    pub(super) const fn network(&self) -> NetworkId { self.network }
    pub(super) const fn old_chain_epoch(&self) -> u64 { self.old_chain_epoch }
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn barrier_digest(&self) -> &[u8; 32] { &self.barrier_digest }
    pub(super) const fn archive_completion_slot(&self) -> &[u8; 32] { &self.archive_completion_slot }
    pub(super) const fn archive_completion_digest(&self) -> &[u8; 32] { &self.archive_completion_digest }
    pub(super) const fn catalog_digest(&self) -> &[u8; 32] { &self.catalog_digest }
    pub(super) const fn post_state_digest(&self) -> &[u8; 32] { &self.post_state_digest }
    pub(super) const fn physical_delete_count(&self) -> u64 { self.physical_delete_count }
    pub(super) const fn restored_row_count(&self) -> u64 { self.restored_row_count }
    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] { &self.store_fingerprint }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(super) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }
}

#[allow(clippy::too_many_arguments)]
fn completion_slot(
    network: NetworkId,
    old_chain_epoch: u64,
    authority: AuthorityScope,
    participant_plan_digest: &[u8; 32],
    barrier_digest: &[u8; 32],
    archive_completion_slot: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else { unreachable!() };
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(old_chain_epoch.to_be_bytes());
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(barrier_digest);
    hasher.update(archive_completion_slot);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn completion_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RealmRollbackDeleteCompletionError> {
        let end = self.offset.checked_add(length)
            .ok_or(RealmRollbackDeleteCompletionError::InvalidLength)?;
        let value = self.bytes.get(self.offset..end)
            .ok_or(RealmRollbackDeleteCompletionError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackDeleteCompletionError> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmRollbackDeleteCompletionError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackDeleteCompletionError> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn array_32(&mut self) -> Result<[u8; 32], RealmRollbackDeleteCompletionError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackDeleteCompletionError {
    RealmRequired,
    BindingMismatch,
    RowTooLarge,
    InvalidLength,
    InvalidMagic,
    UnknownVersion(u16),
    Truncated,
    TrailingBytes,
    NonCanonicalEncoding,
    CanonicalChain(psy_data::protocol::canonical_chain::CanonicalChainRefCodecError),
}
impl From<psy_data::protocol::canonical_chain::CanonicalChainRefCodecError>
    for RealmRollbackDeleteCompletionError
{
    fn from(value: psy_data::protocol::canonical_chain::CanonicalChainRefCodecError) -> Self {
        Self::CanonicalChain(value)
    }
}
impl fmt::Display for RealmRollbackDeleteCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm rollback delete completion error: {self:?}")
    }
}
impl Error for RealmRollbackDeleteCompletionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };

    fn completion() -> RealmRollbackDeleteCompletion<PHash> {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let checkpoint = CheckpointRef::new(
            CheckpointId::new(7),
            CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
        );
        RealmRollbackDeleteCompletion::try_from_fields(
            AuthorityScope::Realm { realm_id: 3, realm_sub_id: 4 },
            CanonicalChainRef::new(network, ChainEpoch::new(6), checkpoint),
            [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32],
            11, 3, [7; 32],
        ).unwrap()
    }

    #[test]
    fn completion_roundtrips_and_rejects_tamper() {
        let expected = completion();
        assert_eq!(
            RealmRollbackDeleteCompletion::decode_canonical(expected.canonical_bytes()).unwrap(),
            expected,
        );
        let mut tampered = expected.canonical_bytes().to_vec();
        tampered[100] ^= 1;
        assert!(RealmRollbackDeleteCompletion::<PHash>::decode_canonical(&tampered).is_err());
    }

    #[test]
    fn completion_is_inert_and_content_addressed() {
        let source = include_str!("realm_rollback_delete_completion.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["publish_head", "complete_rollback(", "DELETE FROM", "UPDATE "] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
        let first = completion();
        let second = completion();
        assert_eq!(first.slot(), second.slot());
        assert_eq!(first.digest(), second.digest());
    }
}
