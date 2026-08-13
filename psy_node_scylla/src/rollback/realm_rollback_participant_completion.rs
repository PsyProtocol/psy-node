//! Canonical durable completion for one Realm rollback archive participant.
//!
//! The completion is immutable evidence that one exact Realm-local committed
//! suffix and its physical before-images were selected and revalidated. It is
//! deliberately pre-barrier: no API here can delete, restore, or publish a
//! head.

#![allow(dead_code)]

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CANONICAL_CHAIN_REF_V1_LEN, CanonicalChainRef, NetworkId},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    authority_local_head::{AUTHORITY_LOCAL_HEAD_V1_LEN, StoredAuthorityLocalHead},
};
use sha2::{Digest, Sha256};

pub(super) const REALM_PARTICIPANT_COMPLETION_KEY_DOMAIN: i16 = -2;
const MAGIC: &[u8; 8] = b"PSYRRPC1";
const VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-participant-completion-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-participant-completion.v1\0";
const MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackParticipantCompletion<Hash> {
    network: NetworkId,
    old_chain_epoch: u64,
    authority: AuthorityScope,
    participant_plan_digest: [u8; 32],
    source_head: StoredAuthorityLocalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    catalog_digest: [u8; 32],
    entry_count: u64,
    delete_count: u64,
    restore_count: u64,
    dataset_digest: [u8; 32],
    archive_store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackParticipantCompletion<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_from_selected(
        participant_plan_digest: [u8; 32],
        authority: AuthorityScope,
        source_head: StoredAuthorityLocalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        catalog_digest: [u8; 32],
        entry_count: u64,
        delete_count: u64,
        restore_count: u64,
        dataset_digest: [u8; 32],
        archive_store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackParticipantCompletionError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmRollbackParticipantCompletionError::RealmRequired);
        };
        let network = target.network_id();
        let old_chain_epoch = target.chain_epoch().get();
        if source_head.head().key() != AuthorityTimestampKey::new(network, authority)
            || source_head.head().chain().network_id() != network
            || source_head.head().chain().chain_epoch().get() != old_chain_epoch
            || source_head.head().chain().checkpoint().checkpoint_id().get()
                < target.checkpoint().checkpoint_id().get()
            || participant_plan_digest == [0; 32]
            || catalog_digest == [0; 32]
            || dataset_digest == [0; 32]
            || archive_store_fingerprint == [0; 32]
            || entry_count != delete_count.checked_add(restore_count)
                .ok_or(RealmRollbackParticipantCompletionError::CountOverflow)?
        {
            return Err(RealmRollbackParticipantCompletionError::BindingMismatch);
        }
        let source_head_canonical = source_head.encode_canonical();
        let target_canonical = target.to_canonical_bytes();
        let slot = completion_slot(
            network,
            old_chain_epoch,
            authority,
            &participant_plan_digest,
            source_head.revision().as_i64(),
            &source_head_canonical,
            &target_canonical,
            &catalog_digest,
            &archive_store_fingerprint,
        );
        let mut selected = Self {
            network,
            old_chain_epoch,
            authority,
            participant_plan_digest,
            source_head,
            target,
            catalog_digest,
            entry_count,
            delete_count,
            restore_count,
            dataset_digest,
            archive_store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = selected.encode_without_digest();
        selected.digest = completion_digest(&body);
        selected.canonical_bytes = body;
        selected.canonical_bytes.extend_from_slice(&selected.digest);
        if selected.canonical_bytes.len() > MAX_BYTES {
            return Err(RealmRollbackParticipantCompletionError::RowTooLarge);
        }
        Ok(selected)
    }

    pub(super) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackParticipantCompletionError> {
        if bytes.len() > MAX_BYTES || bytes.len() < 32 {
            return Err(RealmRollbackParticipantCompletionError::InvalidLength);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackParticipantCompletionError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RealmRollbackParticipantCompletionError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)?;
        let old_chain_epoch = cursor.u64()?;
        let authority = AuthorityScope::Realm {
            realm_id: cursor.u32()?,
            realm_sub_id: cursor.u16()?,
        };
        let participant_plan_digest = cursor.array_32()?;
        let source_revision = cursor.i64()?;
        let source_head = StoredAuthorityLocalHead::decode_persisted(
            AuthorityTimestampKey::new(network, authority),
            source_revision,
            cursor.take(AUTHORITY_LOCAL_HEAD_V1_LEN)?,
        )?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )?;
        let catalog_digest = cursor.array_32()?;
        let entry_count = cursor.u64()?;
        let delete_count = cursor.u64()?;
        let restore_count = cursor.u64()?;
        let dataset_digest = cursor.array_32()?;
        let archive_store_fingerprint = cursor.array_32()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackParticipantCompletionError::TrailingBytes);
        }
        let decoded = Self::try_from_selected(
            participant_plan_digest,
            authority,
            source_head,
            target,
            catalog_digest,
            entry_count,
            delete_count,
            restore_count,
            dataset_digest,
            archive_store_fingerprint,
        )?;
        if decoded.network != network
            || decoded.old_chain_epoch != old_chain_epoch
            || decoded.slot != slot
            || decoded.digest != digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RealmRollbackParticipantCompletionError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let AuthorityScope::Realm { realm_id, realm_sub_id } = self.authority else { unreachable!() };
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.network.chain_id().to_le_bytes());
        bytes.extend_from_slice(&self.old_chain_epoch.to_le_bytes());
        bytes.extend_from_slice(&realm_id.to_le_bytes());
        bytes.extend_from_slice(&realm_sub_id.to_le_bytes());
        bytes.extend_from_slice(&self.participant_plan_digest);
        bytes.extend_from_slice(&self.source_head.revision().as_i64().to_le_bytes());
        bytes.extend_from_slice(&self.source_head.encode_canonical());
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.entry_count.to_le_bytes());
        bytes.extend_from_slice(&self.delete_count.to_le_bytes());
        bytes.extend_from_slice(&self.restore_count.to_le_bytes());
        bytes.extend_from_slice(&self.dataset_digest);
        bytes.extend_from_slice(&self.archive_store_fingerprint);
        bytes.extend_from_slice(&self.slot);
        bytes
    }

    pub(super) const fn network(&self) -> NetworkId { self.network }
    pub(super) const fn old_chain_epoch(&self) -> u64 { self.old_chain_epoch }
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn source_head(&self) -> &StoredAuthorityLocalHead<Hash> { &self.source_head }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn catalog_digest(&self) -> &[u8; 32] { &self.catalog_digest }
    pub(super) const fn entry_count(&self) -> u64 { self.entry_count }
    pub(super) const fn delete_count(&self) -> u64 { self.delete_count }
    pub(super) const fn restore_count(&self) -> u64 { self.restore_count }
    pub(super) const fn dataset_digest(&self) -> &[u8; 32] { &self.dataset_digest }
    pub(super) const fn archive_store_fingerprint(&self) -> &[u8; 32] { &self.archive_store_fingerprint }
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
    source_revision: i64,
    source_head_canonical: &[u8],
    target_canonical: &[u8],
    catalog_digest: &[u8; 32],
    archive_store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else { unreachable!() };
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(old_chain_epoch.to_be_bytes());
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(source_revision.to_be_bytes());
    hasher.update(source_head_canonical);
    hasher.update(target_canonical);
    hasher.update(catalog_digest);
    hasher.update(archive_store_fingerprint);
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
    fn take(&mut self, length: usize) -> Result<&'a [u8], RealmRollbackParticipantCompletionError> {
        let end = self.offset.checked_add(length).ok_or(RealmRollbackParticipantCompletionError::InvalidLength)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackParticipantCompletionError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackParticipantCompletionError> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmRollbackParticipantCompletionError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackParticipantCompletionError> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackParticipantCompletionError> { Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn array_32(&mut self) -> Result<[u8; 32], RealmRollbackParticipantCompletionError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackParticipantCompletionError {
    RealmRequired,
    BindingMismatch,
    CountOverflow,
    RowTooLarge,
    InvalidLength,
    InvalidMagic,
    UnknownVersion(u16),
    Truncated,
    TrailingBytes,
    NonCanonicalEncoding,
    CanonicalChain(psy_data::protocol::canonical_chain::CanonicalChainRefCodecError),
    LocalHead(psy_node_core::store::authority_local_head::AuthorityLocalHeadModelError),
}
impl From<psy_data::protocol::canonical_chain::CanonicalChainRefCodecError> for RealmRollbackParticipantCompletionError {
    fn from(value: psy_data::protocol::canonical_chain::CanonicalChainRefCodecError) -> Self { Self::CanonicalChain(value) }
}
impl From<psy_node_core::store::authority_local_head::AuthorityLocalHeadModelError> for RealmRollbackParticipantCompletionError {
    fn from(value: psy_node_core::store::authority_local_head::AuthorityLocalHeadModelError) -> Self { Self::LocalHead(value) }
}
impl fmt::Display for RealmRollbackParticipantCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "Realm rollback participant completion error: {self:?}") }
}
impl Error for RealmRollbackParticipantCompletionError {}

#[cfg(test)]
mod tests {
    use super::{completion_digest, completion_slot};
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};

    #[test]
    fn slot_is_stable_but_content_digest_is_separate() {
        let network = NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet);
        let authority = AuthorityScope::Realm { realm_id: 3, realm_sub_id: 4 };
        let first = completion_slot(network, 9, authority, &[1; 32], 7, &[2; 10], &[3; 65], &[4; 32], &[5; 32]);
        let second = completion_slot(network, 9, authority, &[1; 32], 7, &[2; 10], &[3; 65], &[4; 32], &[5; 32]);
        assert_eq!(first, second);
        assert_ne!(completion_digest(b"first"), completion_digest(b"second"));
    }
}
