//! Canonical before-image copied from one exact Realm hot row.
//!
//! The object binds a global participant plan, one storage-selected Realm
//! suffix catalog entry, the source value/writetime, and the target action.
//! It is inert evidence: durable persistence, the global archive barrier,
//! deletion, restoration, and head publication are separate capabilities.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::CanonicalChainRef,
    chain_context::AuthorityScope,
};
use psy_node_core::store::branch_exact_dual_write::BranchExactDualWriteMutationKind;
use sha2::{Digest, Sha256};

use super::{
    SealedTimestampedPut, decode_locator_canonical,
    branch_exact_dual_write_executor::RealmRollbackNarrowObservedRow,
    realm_full_commit_execution::RealmFullCommitObservedRow,
    realm_rollback_physical_catalog::{
        RealmRollbackPhysicalAction, RealmRollbackPhysicalCatalog,
        RealmRollbackPhysicalCatalogEntry, RealmRollbackPhysicalKey,
        RealmRollbackTargetRestore,
    },
};

const MAGIC: &[u8; 8] = b"PSYRRBI1";
const VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-physical-before-image-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-physical-before-image.v1\0";
const MAX_ROW_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 32 * 1024 * 1024;
const NARROW_KEY_DOMAIN_BASE: i16 = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackPhysicalSourceObservation {
    logical_value: Vec<u8>,
    stored_value: Vec<u8>,
    writetime_us: i64,
}

impl RealmRollbackPhysicalSourceObservation {
    pub(super) fn logical_value(&self) -> &[u8] { &self.logical_value }
    pub(super) fn stored_value(&self) -> &[u8] { &self.stored_value }
    pub(super) const fn writetime_us(&self) -> i64 { self.writetime_us }
}

/// Strict, content-addressed before-image for one physical hot row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackPhysicalBeforeImage<Hash> {
    participant_plan_digest: [u8; 32],
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    source_head: CanonicalChainRef<Hash>,
    catalog_digest: [u8; 32],
    source_index: u64,
    action: RealmRollbackPhysicalAction,
    key: RealmRollbackPhysicalKey,
    source: RealmRollbackPhysicalSourceObservation,
    target_restore: Option<RealmRollbackTargetRestore>,
    key_domain: i16,
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackPhysicalBeforeImage<Hash> {
    pub(super) fn try_from_typed(
        participant_plan_digest: [u8; 32],
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
        observed: &RealmFullCommitObservedRow,
    ) -> Result<Self, RealmRollbackPhysicalBeforeImageError> {
        let RealmRollbackPhysicalKey::Typed(key) = entry.key() else {
            return Err(RealmRollbackPhysicalBeforeImageError::KeyKindMismatch);
        };
        let current = entry
            .current_put()
            .ok_or(RealmRollbackPhysicalBeforeImageError::MissingCurrentPut)?;
        if observed.physical_table() != key.physical_table()
            || observed.locator() != key.locator_bytes()
            || current.resolved().locator_bytes() != key.locator_bytes()
            || observed.writetime_us() != current.timestamp().as_i64()
        {
            return Err(RealmRollbackPhysicalBeforeImageError::SourceMismatch);
        }
        Self::try_new(
            participant_plan_digest,
            catalog,
            entry,
            RealmRollbackPhysicalSourceObservation {
                logical_value: observed.value().to_vec(),
                stored_value: observed.stored_value().to_vec(),
                writetime_us: observed.writetime_us(),
            },
        )
    }

    pub(super) fn try_from_narrow(
        participant_plan_digest: [u8; 32],
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
        observed: &RealmRollbackNarrowObservedRow,
    ) -> Result<Self, RealmRollbackPhysicalBeforeImageError> {
        let RealmRollbackPhysicalKey::Narrow {
            kind,
            primary_key,
            ..
        } = entry.key()
        else {
            return Err(RealmRollbackPhysicalBeforeImageError::KeyKindMismatch);
        };
        if observed.kind() != *kind || observed.primary_key() != primary_key {
            return Err(RealmRollbackPhysicalBeforeImageError::SourceMismatch);
        }
        Self::try_new(
            participant_plan_digest,
            catalog,
            entry,
            RealmRollbackPhysicalSourceObservation {
                logical_value: observed.logical_value().to_vec(),
                stored_value: observed.stored_value().to_vec(),
                writetime_us: observed.writetime_us(),
            },
        )
    }

    fn try_new(
        participant_plan_digest: [u8; 32],
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
        source: RealmRollbackPhysicalSourceObservation,
    ) -> Result<Self, RealmRollbackPhysicalBeforeImageError> {
        if participant_plan_digest == [0; 32]
            || catalog.digest() == &[0; 32]
            || source.logical_value.len() > MAX_FIELD_BYTES
            || source.stored_value.len() > MAX_FIELD_BYTES
        {
            return Err(RealmRollbackPhysicalBeforeImageError::InvalidCommitment);
        }
        validate_action(entry.action(), entry.target_restore(), entry.key())?;
        let authority = catalog.suffix().authority();
        let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
            return Err(RealmRollbackPhysicalBeforeImageError::RealmRequired);
        };
        let target = *catalog.suffix().target();
        let source_head = *catalog.suffix().source_head();
        let key_domain = archive_key_domain(entry.key())?;
        let slot = before_image_slot(
            participant_plan_digest,
            realm_id,
            realm_sub_id,
            entry.key().locator_bytes(),
        );
        let mut image = Self {
            participant_plan_digest,
            authority,
            target,
            source_head,
            catalog_digest: *catalog.digest(),
            source_index: u64::try_from(entry.source_index())
                .map_err(|_| RealmRollbackPhysicalBeforeImageError::LengthOverflow)?,
            action: entry.action(),
            key: entry.key().clone(),
            source,
            target_restore: entry.target_restore().cloned(),
            key_domain,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = image.encode_without_digest()?;
        image.digest = before_image_digest(&body);
        image.canonical_bytes = body;
        image.canonical_bytes.extend_from_slice(&image.digest);
        if image.canonical_bytes.len() > MAX_ROW_BYTES {
            return Err(RealmRollbackPhysicalBeforeImageError::RowTooLarge);
        }
        Ok(image)
    }

    pub(super) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackPhysicalBeforeImageError> {
        if bytes.len() > MAX_ROW_BYTES {
            return Err(RealmRollbackPhysicalBeforeImageError::RowTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackPhysicalBeforeImageError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RealmRollbackPhysicalBeforeImageError::UnknownVersion(version));
        }
        let participant_plan_digest = cursor.array_32()?;
        let authority = decode_authority(&mut cursor)?;
        let target = CanonicalChainRef::from_canonical_bytes(cursor.bytes()?)
            .map_err(|_| RealmRollbackPhysicalBeforeImageError::InvalidChainRef)?;
        let source_head = CanonicalChainRef::from_canonical_bytes(cursor.bytes()?)
            .map_err(|_| RealmRollbackPhysicalBeforeImageError::InvalidChainRef)?;
        let catalog_digest = cursor.array_32()?;
        let source_index = cursor.u64()?;
        let action = decode_action(cursor.u8()?)?;
        let key = decode_key(&mut cursor)?;
        let source = RealmRollbackPhysicalSourceObservation {
            logical_value: cursor.bytes()?.to_vec(),
            stored_value: cursor.bytes()?.to_vec(),
            writetime_us: cursor.i64()?,
        };
        let target_restore = decode_target_restore(&mut cursor)?;
        let key_domain = cursor.i16()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackPhysicalBeforeImageError::TrailingBytes);
        }
        if participant_plan_digest == [0; 32]
            || catalog_digest == [0; 32]
            || source.logical_value.len() > MAX_FIELD_BYTES
            || source.stored_value.len() > MAX_FIELD_BYTES
        {
            return Err(RealmRollbackPhysicalBeforeImageError::InvalidCommitment);
        }
        let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
            return Err(RealmRollbackPhysicalBeforeImageError::RealmRequired);
        };
        if target.network_id() != source_head.network_id()
            || target.chain_epoch() != source_head.chain_epoch()
            || target.checkpoint().checkpoint_id().get()
                >= source_head.checkpoint().checkpoint_id().get()
        {
            return Err(RealmRollbackPhysicalBeforeImageError::InvalidChainRange);
        }
        validate_action(action, target_restore.as_ref(), &key)?;
        if archive_key_domain(&key)? != key_domain
            || before_image_slot(
                participant_plan_digest,
                realm_id,
                realm_sub_id,
                key.locator_bytes(),
            ) != slot
            || bytes.len() < 32
            || before_image_digest(&bytes[..bytes.len() - 32]) != digest
        {
            return Err(RealmRollbackPhysicalBeforeImageError::DigestOrSlotMismatch);
        }
        let decoded = Self {
            participant_plan_digest,
            authority,
            target,
            source_head,
            catalog_digest,
            source_index,
            action,
            key,
            source,
            target_restore,
            key_domain,
            slot,
            digest,
            canonical_bytes: bytes.to_vec(),
        };
        if decoded.encode_without_digest()? != bytes[..bytes.len() - 32] {
            return Err(RealmRollbackPhysicalBeforeImageError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] {
        &self.participant_plan_digest
    }
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn source_head(&self) -> &CanonicalChainRef<Hash> { &self.source_head }
    pub(super) const fn catalog_digest(&self) -> &[u8; 32] { &self.catalog_digest }
    pub(super) const fn action(&self) -> RealmRollbackPhysicalAction { self.action }
    pub(super) const fn key(&self) -> &RealmRollbackPhysicalKey { &self.key }
    pub(super) const fn source(&self) -> &RealmRollbackPhysicalSourceObservation { &self.source }
    pub(super) const fn target_restore(&self) -> Option<&RealmRollbackTargetRestore> {
        self.target_restore.as_ref()
    }
    pub(super) const fn key_domain(&self) -> i16 { self.key_domain }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(super) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }

    fn encode_without_digest(&self) -> Result<Vec<u8>, RealmRollbackPhysicalBeforeImageError> {
        let mut out = Vec::with_capacity(
            256 + self.key.locator_bytes().len()
                + self.source.logical_value.len()
                + self.source.stored_value.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.participant_plan_digest);
        encode_authority(self.authority, &mut out)?;
        put_bytes(&mut out, &self.target.to_canonical_bytes())?;
        put_bytes(&mut out, &self.source_head.to_canonical_bytes())?;
        out.extend_from_slice(&self.catalog_digest);
        out.extend_from_slice(&self.source_index.to_be_bytes());
        out.push(self.action as u8);
        encode_key(&self.key, &mut out)?;
        put_bytes(&mut out, &self.source.logical_value)?;
        put_bytes(&mut out, &self.source.stored_value)?;
        out.extend_from_slice(&self.source.writetime_us.to_be_bytes());
        encode_target_restore(self.target_restore.as_ref(), &mut out)?;
        out.extend_from_slice(&self.key_domain.to_be_bytes());
        out.extend_from_slice(&self.slot);
        Ok(out)
    }
}

fn validate_action(
    action: RealmRollbackPhysicalAction,
    target: Option<&RealmRollbackTargetRestore>,
    key: &RealmRollbackPhysicalKey,
) -> Result<(), RealmRollbackPhysicalBeforeImageError> {
    match (action, target) {
        (RealmRollbackPhysicalAction::ArchiveThenDelete, None) => Ok(()),
        (RealmRollbackPhysicalAction::ArchiveThenRestoreTarget, Some(target)) => {
            match target {
                RealmRollbackTargetRestore::ExactPut(put) => {
                    let RealmRollbackPhysicalKey::Typed(key) = key else {
                        return Err(RealmRollbackPhysicalBeforeImageError::TargetMismatch);
                    };
                    if put.resolved().locator_bytes() != key.locator_bytes() {
                        return Err(RealmRollbackPhysicalBeforeImageError::TargetMismatch);
                    }
                }
                RealmRollbackTargetRestore::ImtCursorBefore(_) => {
                    let RealmRollbackPhysicalKey::Typed(key) = key else {
                        return Err(RealmRollbackPhysicalBeforeImageError::TargetMismatch);
                    };
                    if key.physical_table() != super::ScyllaPhysicalTableId::ImtNextAppendIndex {
                        return Err(RealmRollbackPhysicalBeforeImageError::TargetMismatch);
                    }
                }
            }
            Ok(())
        }
        _ => Err(RealmRollbackPhysicalBeforeImageError::TargetMismatch),
    }
}

fn archive_key_domain(key: &RealmRollbackPhysicalKey) -> Result<i16, RealmRollbackPhysicalBeforeImageError> {
    match key {
        RealmRollbackPhysicalKey::Narrow { kind, .. } => NARROW_KEY_DOMAIN_BASE
            .checked_add(i16::from(*kind as u8))
            .ok_or(RealmRollbackPhysicalBeforeImageError::LengthOverflow),
        RealmRollbackPhysicalKey::Typed(key) => i16::try_from(key.physical_table().stable_id())
            .map_err(|_| RealmRollbackPhysicalBeforeImageError::LengthOverflow),
    }
}

fn before_image_slot(
    participant_plan_digest: [u8; 32],
    realm_id: u32,
    realm_sub_id: u16,
    locator: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(participant_plan_digest);
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update((locator.len() as u64).to_be_bytes());
    hasher.update(locator);
    hasher.finalize().into()
}

fn before_image_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_authority(
    authority: AuthorityScope,
    out: &mut Vec<u8>,
) -> Result<(), RealmRollbackPhysicalBeforeImageError> {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
        return Err(RealmRollbackPhysicalBeforeImageError::RealmRequired);
    };
    out.extend_from_slice(&realm_id.to_be_bytes());
    out.extend_from_slice(&realm_sub_id.to_be_bytes());
    Ok(())
}

fn decode_authority(cursor: &mut Cursor<'_>) -> Result<AuthorityScope, RealmRollbackPhysicalBeforeImageError> {
    Ok(AuthorityScope::Realm {
        realm_id: cursor.u32()?,
        realm_sub_id: cursor.u16()?,
    })
}

fn encode_key(key: &RealmRollbackPhysicalKey, out: &mut Vec<u8>) -> Result<(), RealmRollbackPhysicalBeforeImageError> {
    match key {
        RealmRollbackPhysicalKey::Narrow { kind, primary_key, locator } => {
            out.push(1);
            out.push(*kind as u8);
            put_bytes(out, primary_key)?;
            put_bytes(out, locator)?;
        }
        RealmRollbackPhysicalKey::Typed(key) => {
            out.push(2);
            put_bytes(out, key.locator_bytes())?;
        }
    }
    Ok(())
}

fn decode_key(cursor: &mut Cursor<'_>) -> Result<RealmRollbackPhysicalKey, RealmRollbackPhysicalBeforeImageError> {
    match cursor.u8()? {
        1 => {
            let kind = decode_narrow_kind(cursor.u8()?)?;
            let primary_key = cursor.bytes()?.to_vec();
            let locator = cursor.bytes()?.to_vec();
            if locator.get(..8) != Some(b"PSYRRNK1")
                || locator.get(8) != Some(&(kind as u8))
                || locator.get(9..) != Some(primary_key.as_slice())
            {
                return Err(RealmRollbackPhysicalBeforeImageError::InvalidKey);
            }
            Ok(RealmRollbackPhysicalKey::Narrow { kind, primary_key, locator })
        }
        2 => Ok(RealmRollbackPhysicalKey::Typed(
            decode_locator_canonical(cursor.bytes()?)
                .map_err(|_| RealmRollbackPhysicalBeforeImageError::InvalidKey)?,
        )),
        value => Err(RealmRollbackPhysicalBeforeImageError::UnknownKeyKind(value)),
    }
}

fn decode_narrow_kind(value: u8) -> Result<BranchExactDualWriteMutationKind, RealmRollbackPhysicalBeforeImageError> {
    use BranchExactDualWriteMutationKind as K;
    match value {
        1 => Ok(K::LegacyCheckpointToPending),
        2 => Ok(K::LegacyPendingToCheckpoint),
        3 => Ok(K::LegacyPendingToProc),
        4 => Ok(K::LegacyProcToPending),
        5 => Ok(K::TargetBranchToPending),
        6 => Ok(K::TargetPendingToBranch),
        7 => Ok(K::LegacyPendingRewardProof),
        8 => Ok(K::TargetPendingRewardProof),
        other => Err(RealmRollbackPhysicalBeforeImageError::UnknownNarrowKind(other)),
    }
}

fn decode_action(value: u8) -> Result<RealmRollbackPhysicalAction, RealmRollbackPhysicalBeforeImageError> {
    match value {
        1 => Ok(RealmRollbackPhysicalAction::ArchiveThenDelete),
        2 => Ok(RealmRollbackPhysicalAction::ArchiveThenRestoreTarget),
        other => Err(RealmRollbackPhysicalBeforeImageError::UnknownAction(other)),
    }
}

fn encode_target_restore(target: Option<&RealmRollbackTargetRestore>, out: &mut Vec<u8>) -> Result<(), RealmRollbackPhysicalBeforeImageError> {
    match target {
        None => out.push(0),
        Some(RealmRollbackTargetRestore::ExactPut(put)) => {
            out.push(1);
            put_bytes(out, put.canonical_bytes())?;
        }
        Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => {
            out.push(2);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

fn decode_target_restore(cursor: &mut Cursor<'_>) -> Result<Option<RealmRollbackTargetRestore>, RealmRollbackPhysicalBeforeImageError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => Ok(Some(RealmRollbackTargetRestore::ExactPut(
            SealedTimestampedPut::decode_realm_commit_inventory_canonical(cursor.bytes()?)
                .map_err(|_| RealmRollbackPhysicalBeforeImageError::InvalidTargetPut)?,
        ))),
        2 => Ok(Some(RealmRollbackTargetRestore::ImtCursorBefore(cursor.u64()?))),
        other => Err(RealmRollbackPhysicalBeforeImageError::UnknownTargetKind(other)),
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RealmRollbackPhysicalBeforeImageError> {
    if bytes.len() > MAX_FIELD_BYTES {
        return Err(RealmRollbackPhysicalBeforeImageError::FieldTooLarge);
    }
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| RealmRollbackPhysicalBeforeImageError::LengthOverflow)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackPhysicalBeforeImageError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackPhysicalBeforeImageError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackPhysicalBeforeImageError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, RealmRollbackPhysicalBeforeImageError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, RealmRollbackPhysicalBeforeImageError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn i16(&mut self) -> Result<i16, RealmRollbackPhysicalBeforeImageError> { Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmRollbackPhysicalBeforeImageError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackPhysicalBeforeImageError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackPhysicalBeforeImageError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array_32(&mut self) -> Result<[u8; 32], RealmRollbackPhysicalBeforeImageError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn bytes(&mut self) -> Result<&'a [u8], RealmRollbackPhysicalBeforeImageError> { let len = self.u32()? as usize; self.take(len) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackPhysicalBeforeImageError {
    RealmRequired,
    InvalidCommitment,
    InvalidChainRef,
    InvalidChainRange,
    KeyKindMismatch,
    MissingCurrentPut,
    SourceMismatch,
    TargetMismatch,
    InvalidTargetPut,
    InvalidKey,
    UnknownVersion(u16),
    UnknownKeyKind(u8),
    UnknownNarrowKind(u8),
    UnknownAction(u8),
    UnknownTargetKind(u8),
    InvalidMagic,
    DigestOrSlotMismatch,
    NonCanonicalEncoding,
    FieldTooLarge,
    RowTooLarge,
    LengthOverflow,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for RealmRollbackPhysicalBeforeImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm rollback physical before-image: {self:?}")
    }
}
impl Error for RealmRollbackPhysicalBeforeImageError {}

#[cfg(test)]
mod tests {
    #[test]
    fn before_image_has_no_barrier_delete_restore_or_head_api() {
        let source = include_str!("realm_rollback_physical_before_image.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "execute_delete",
            "execute_restore",
            "cross_archive_barrier",
            "publish_head",
            "compare_and_set",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
