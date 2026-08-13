//! Canonical raw before-image for one floor-bound Coordinator physical key.
//!
//! This module freezes the bytes a future Scylla reader must archive. It does
//! not execute CQL, persist an archive row, cross the participant barrier, or
//! authorize a delete. In particular, key-only rows carry explicit presence
//! and no invented writetime.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN,
};
use sha2::{Digest, Sha256};

use super::{
    decode_locator_canonical, CoordinatorCommitInventoryAction,
    CoordinatorCommitPhysicalCatalog, physical_descriptor, CqlKeyspaceName,
    ResolvedScyllaKey, ScyllaSchemaFamily,
};

const BEFORE_IMAGE_MAGIC: &[u8; 8] = b"PSYCCIMG";
const BEFORE_IMAGE_CODEC_VERSION: u16 = 1;
const BEFORE_IMAGE_SLOT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-before-image-slot.v1\0";
const BEFORE_IMAGE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-before-image.v1\0";
const MAX_CANONICAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_CELL_BYTES: usize = 64 * 1024 * 1024;

/// Closed exact-read contract for one Coordinator inventory row. It is kept
/// separate from driver values so a later prepared-statement adapter cannot
/// silently change which physical columns are archived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalReadSpec {
    cql: String,
    bind_shape: &'static [&'static str],
    result_shape: &'static [&'static str],
    key_only: bool,
}

impl CoordinatorCommitPhysicalReadSpec {
    pub(crate) fn try_for_key(
        keyspace: &CqlKeyspaceName,
        key: &ResolvedScyllaKey,
    ) -> Result<Self, CoordinatorCommitPhysicalBeforeImageError> {
        let table = physical_descriptor(key.physical_table()).physical_name;
        let qualified = format!("{}.{table}", keyspace.as_str());
        use ScyllaSchemaFamily as F;
        let (select, where_clause, bind_shape, result_shape, key_only) =
            match key.schema_family() {
                F::Kiv => (
                    "value, writetime(value)",
                    "obj_id = ?",
                    &["obj_id:BIGINT"][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::Blob => (
                    "value, writetime(value)",
                    "obj_id = ?",
                    &["obj_id:BLOB"][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::U64 => (
                    "value, writetime(value)",
                    "obj_id = ?",
                    &["obj_id:BIGINT"][..],
                    &["value:BIGINT", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::U64ToU128 => (
                    "value, writetime(value)",
                    "obj_id = ?",
                    &["obj_id:BIGINT"][..],
                    &["value:UUID", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::U128ToU64 => (
                    "value, writetime(value)",
                    "obj_id = ?",
                    &["obj_id:UUID"][..],
                    &["value:BIGINT", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::ObjectSingle => (
                    "value, writetime(value)",
                    "obj_id = ? AND checkpoint_id = ?",
                    &["obj_id:BIGINT", "checkpoint_id:BIGINT"][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::HashToMany => (
                    "value_u64",
                    "hash_id = ? AND value_u64 = ?",
                    &["hash_id:BLOB", "value_u64:BIGINT"][..],
                    &["value_u64:BIGINT"][..],
                    true,
                ),
                F::MerkleZero => (
                    "value, writetime(value)",
                    "level = ? AND node_index = ? AND checkpoint_id = ?",
                    &["level:TINYINT", "node_index:BIGINT", "checkpoint_id:BIGINT"][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::MerkleSingle => (
                    "value, writetime(value)",
                    "tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?",
                    &[
                        "tree_id:BIGINT",
                        "level:TINYINT",
                        "node_index:BIGINT",
                        "checkpoint_id:BIGINT",
                    ][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::MerkleDouble => (
                    "value, writetime(value)",
                    "tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?",
                    &[
                        "tree_id:BIGINT",
                        "tree_sub_id:BIGINT",
                        "level:TINYINT",
                        "node_index:BIGINT",
                        "checkpoint_id:BIGINT",
                    ][..],
                    &["value:BLOB", "writetime(value):BIGINT"][..],
                    false,
                ),
                F::Counter | F::TagTree | F::ImtLeaf | F::ImtKeyIndex | F::ImtCursor => {
                    return Err(
                        CoordinatorCommitPhysicalBeforeImageError::UnsupportedSchemaFamily,
                    );
                }
            };
        Ok(Self {
            cql: format!("SELECT {select} FROM {qualified} WHERE {where_clause}"),
            bind_shape,
            result_shape,
            key_only,
        })
    }

    pub(crate) fn cql(&self) -> &str {
        &self.cql
    }

    pub(crate) const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }

    pub(crate) const fn result_shape(&self) -> &'static [&'static str] {
        self.result_shape
    }

    pub(crate) const fn key_only(&self) -> bool {
        self.key_only
    }
}

/// Stable physical value-column identity. Coordinator commit inventories use
/// one ordinary value column or a key-only row; multi-column TagTree/IMT rows
/// do not occur in this catalog and remain fail-closed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub(crate) enum CoordinatorCommitPhysicalCellKind {
    Value = 1,
}

impl TryFrom<u8> for CoordinatorCommitPhysicalCellKind {
    type Error = CoordinatorCommitPhysicalBeforeImageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Value),
            value => Err(CoordinatorCommitPhysicalBeforeImageError::UnknownCellKind(value)),
        }
    }
}

/// Canonical bytes for the exact CQL cell value and the cell writetime observed
/// before PONR. BLOB values remain byte-for-byte unchanged (including existing
/// compression); BIGINT and UUID values use fixed-width canonical bytes so the
/// restore adapter can reconstruct the same typed CQL value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalSourceCell {
    kind: CoordinatorCommitPhysicalCellKind,
    bytes: Vec<u8>,
    writetime_us: i64,
}

impl CoordinatorCommitPhysicalSourceCell {
    pub(crate) fn value(bytes: Vec<u8>, writetime_us: i64) -> Self {
        Self {
            kind: CoordinatorCommitPhysicalCellKind::Value,
            bytes,
            writetime_us,
        }
    }

    pub(crate) const fn kind(&self) -> CoordinatorCommitPhysicalCellKind {
        self.kind
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn writetime_us(&self) -> i64 {
        self.writetime_us
    }
}

/// Exact source observation. Absence is represented as an error by the future
/// reader because every catalog entry was derived from a committed write.
/// Key-only presence is explicit and must not be confused with a missing row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitPhysicalSourceObservation {
    Value(CoordinatorCommitPhysicalSourceCell),
    KeyOnlyPresent,
}

/// Non-clone canonical before-image bound to one exact catalog entry.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalBeforeImage<Hash> {
    catalog_digest: [u8; 32],
    floor_digest: [u8; 32],
    target: CanonicalChainRef<Hash>,
    old_head: CanonicalChainRef<Hash>,
    source_candidate: CanonicalChainRef<Hash>,
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    inventory_digest: [u8; 32],
    action: CoordinatorCommitInventoryAction,
    key: ResolvedScyllaKey,
    observation: CoordinatorCommitPhysicalSourceObservation,
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalBeforeImage<Hash> {
    pub(crate) fn try_from_catalog_entry(
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        entry_index: usize,
        observation: CoordinatorCommitPhysicalSourceObservation,
    ) -> Result<Self, CoordinatorCommitPhysicalBeforeImageError> {
        let entry = catalog
            .entries()
            .get(entry_index)
            .ok_or(CoordinatorCommitPhysicalBeforeImageError::CatalogEntryMissing)?;
        validate_observation(entry.key(), &observation)?;
        let slot = before_image_slot(catalog.digest(), entry.key().locator_bytes());
        let mut row = Self {
            catalog_digest: *catalog.digest(),
            floor_digest: *catalog.floor().digest(),
            target: *catalog.target(),
            old_head: *catalog.old_head(),
            source_candidate: *entry.source_candidate(),
            source_slot: *entry.source_slot(),
            source_digest: *entry.source_digest(),
            inventory_digest: *entry.inventory_digest(),
            action: entry.action(),
            key: entry.key().clone(),
            observation,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let commitment = row.encode_without_digest()?;
        row.digest = digest(&commitment);
        row.canonical_bytes = commitment;
        row.canonical_bytes.extend_from_slice(&row.digest);
        if row.canonical_bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CoordinatorCommitPhysicalBeforeImageError::RowTooLarge(
                row.canonical_bytes.len(),
            ));
        }
        Ok(row)
    }

    pub(crate) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitPhysicalBeforeImageError> {
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CoordinatorCommitPhysicalBeforeImageError::RowTooLarge(bytes.len()));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != BEFORE_IMAGE_MAGIC {
            return Err(CoordinatorCommitPhysicalBeforeImageError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != BEFORE_IMAGE_CODEC_VERSION {
            return Err(CoordinatorCommitPhysicalBeforeImageError::UnknownVersion(version));
        }
        let catalog_digest = cursor.array_32()?;
        let floor_digest = cursor.array_32()?;
        let target = decode_ref(&mut cursor)?;
        let old_head = decode_ref(&mut cursor)?;
        let source_candidate = decode_ref(&mut cursor)?;
        let source_slot = cursor.array_32()?;
        let source_digest = cursor.array_32()?;
        let inventory_digest = cursor.array_32()?;
        let action = CoordinatorCommitInventoryAction::try_from(cursor.u8()?)
            .map_err(|_| CoordinatorCommitPhysicalBeforeImageError::InvalidAction)?;
        let locator = cursor.bytes()?;
        let key = decode_locator_canonical(locator)
            .map_err(CoordinatorCommitPhysicalBeforeImageError::InvalidLocator)?;
        let observation = match cursor.u8()? {
            1 => {
                let kind = CoordinatorCommitPhysicalCellKind::try_from(cursor.u8()?)?;
                let writetime_us = cursor.i64()?;
                let cell = cursor.bytes()?.to_vec();
                if cell.len() > MAX_CELL_BYTES {
                    return Err(CoordinatorCommitPhysicalBeforeImageError::CellTooLarge(
                        cell.len(),
                    ));
                }
                CoordinatorCommitPhysicalSourceObservation::Value(
                    CoordinatorCommitPhysicalSourceCell {
                        kind,
                        bytes: cell,
                        writetime_us,
                    },
                )
            }
            2 => CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent,
            value => {
                return Err(CoordinatorCommitPhysicalBeforeImageError::InvalidPresence(value));
            }
        };
        let slot = cursor.array_32()?;
        let row_digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorCommitPhysicalBeforeImageError::TrailingBytes);
        }
        validate_observation(&key, &observation)?;
        if before_image_slot(&catalog_digest, key.locator_bytes()) != slot {
            return Err(CoordinatorCommitPhysicalBeforeImageError::SlotMismatch);
        }
        if digest(&bytes[..bytes.len() - 32]) != row_digest {
            return Err(CoordinatorCommitPhysicalBeforeImageError::DigestMismatch);
        }
        let decoded = Self {
            catalog_digest,
            floor_digest,
            target,
            old_head,
            source_candidate,
            source_slot,
            source_digest,
            inventory_digest,
            action,
            key,
            observation,
            slot,
            digest: row_digest,
            canonical_bytes: bytes.to_vec(),
        };
        if decoded.encode_without_digest()? != bytes[..bytes.len() - 32] {
            return Err(CoordinatorCommitPhysicalBeforeImageError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    /// Strict persisted-object readback. Decoding a self-consistent frame is
    /// insufficient: the frame must also be the unique row selected by the
    /// floor-bound catalog used for this rollback request.
    pub(crate) fn decode_for_catalog(
        bytes: &[u8],
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalBeforeImageError> {
        let decoded = Self::decode_canonical(bytes)?;
        decoded.validate_catalog(catalog)?;
        Ok(decoded)
    }

    pub(crate) fn validate_catalog(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalBeforeImageError> {
        if self.catalog_digest != *catalog.digest()
            || self.floor_digest != *catalog.floor().digest()
            || self.target != *catalog.target()
            || self.old_head != *catalog.old_head()
        {
            return Err(CoordinatorCommitPhysicalBeforeImageError::CatalogMismatch);
        }
        let matches = catalog.entries().iter().filter(|entry| {
            entry.key().locator_bytes() == self.key.locator_bytes()
                && entry.source_candidate() == &self.source_candidate
                && entry.source_slot() == &self.source_slot
                && entry.source_digest() == &self.source_digest
                && entry.inventory_digest() == &self.inventory_digest
                && entry.action() == self.action
        });
        if matches.count() != 1 {
            return Err(CoordinatorCommitPhysicalBeforeImageError::CatalogMismatch);
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn catalog_digest(&self) -> &[u8; 32] {
        &self.catalog_digest
    }

    pub(crate) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) const fn action(&self) -> CoordinatorCommitInventoryAction {
        self.action
    }

    pub(crate) const fn key(&self) -> &ResolvedScyllaKey {
        &self.key
    }

    pub(crate) const fn observation(&self) -> &CoordinatorCommitPhysicalSourceObservation {
        &self.observation
    }

    fn encode_without_digest(
        &self,
    ) -> Result<Vec<u8>, CoordinatorCommitPhysicalBeforeImageError> {
        let locator = self.key.locator_bytes();
        let locator_len = u32::try_from(locator.len())
            .map_err(|_| CoordinatorCommitPhysicalBeforeImageError::LengthOverflow)?;
        let mut bytes = Vec::with_capacity(512 + locator.len());
        bytes.extend_from_slice(BEFORE_IMAGE_MAGIC);
        bytes.extend_from_slice(&BEFORE_IMAGE_CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.floor_digest);
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.old_head.to_canonical_bytes());
        bytes.extend_from_slice(&self.source_candidate.to_canonical_bytes());
        bytes.extend_from_slice(&self.source_slot);
        bytes.extend_from_slice(&self.source_digest);
        bytes.extend_from_slice(&self.inventory_digest);
        bytes.push(self.action as u8);
        bytes.extend_from_slice(&locator_len.to_be_bytes());
        bytes.extend_from_slice(locator);
        match &self.observation {
            CoordinatorCommitPhysicalSourceObservation::Value(cell) => {
                if cell.bytes.len() > MAX_CELL_BYTES {
                    return Err(CoordinatorCommitPhysicalBeforeImageError::CellTooLarge(
                        cell.bytes.len(),
                    ));
                }
                let cell_len = u32::try_from(cell.bytes.len())
                    .map_err(|_| CoordinatorCommitPhysicalBeforeImageError::LengthOverflow)?;
                bytes.push(1);
                bytes.push(cell.kind as u8);
                bytes.extend_from_slice(&cell.writetime_us.to_be_bytes());
                bytes.extend_from_slice(&cell_len.to_be_bytes());
                bytes.extend_from_slice(&cell.bytes);
            }
            CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent => bytes.push(2),
        }
        bytes.extend_from_slice(&self.slot);
        Ok(bytes)
    }
}

fn validate_observation(
    key: &ResolvedScyllaKey,
    observation: &CoordinatorCommitPhysicalSourceObservation,
) -> Result<(), CoordinatorCommitPhysicalBeforeImageError> {
    use ScyllaSchemaFamily as F;
    match (key.schema_family(), observation) {
        (F::HashToMany, CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent) => Ok(()),
        (
            F::Kiv
            | F::Blob
            | F::ObjectSingle
            | F::U64
            | F::U64ToU128
            | F::U128ToU64
            | F::MerkleZero
            | F::MerkleSingle
            | F::MerkleDouble,
            CoordinatorCommitPhysicalSourceObservation::Value(cell),
        ) if cell.kind == CoordinatorCommitPhysicalCellKind::Value => Ok(()),
        (F::HashToMany, CoordinatorCommitPhysicalSourceObservation::Value(_))
        | (_, CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent) => {
            Err(CoordinatorCommitPhysicalBeforeImageError::ObservationSchemaMismatch)
        }
        _ => Err(CoordinatorCommitPhysicalBeforeImageError::UnsupportedSchemaFamily),
    }
}

fn before_image_slot(catalog_digest: &[u8; 32], locator: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BEFORE_IMAGE_SLOT_DOMAIN);
    hasher.update(catalog_digest);
    hasher.update((locator.len() as u64).to_be_bytes());
    hasher.update(locator);
    hasher.finalize().into()
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BEFORE_IMAGE_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn decode_ref<Hash: Q256BitHash>(
    cursor: &mut Cursor<'_>,
) -> Result<CanonicalChainRef<Hash>, CoordinatorCommitPhysicalBeforeImageError> {
    CanonicalChainRef::from_canonical_bytes(cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?)
        .map_err(|error| CoordinatorCommitPhysicalBeforeImageError::CanonicalRef(error.to_string()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitPhysicalBeforeImageError {
    CatalogEntryMissing,
    CatalogMismatch,
    ObservationSchemaMismatch,
    UnsupportedSchemaFamily,
    UnknownCellKind(u8),
    InvalidPresence(u8),
    InvalidAction,
    InvalidLocator(&'static str),
    InvalidMagic,
    UnknownVersion(u16),
    CanonicalRef(String),
    SlotMismatch,
    DigestMismatch,
    NonCanonicalEncoding,
    CellTooLarge(usize),
    RowTooLarge(usize),
    LengthOverflow,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for CoordinatorCommitPhysicalBeforeImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator physical before-image: {self:?}")
    }
}

impl Error for CoordinatorCommitPhysicalBeforeImageError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], CoordinatorCommitPhysicalBeforeImageError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CoordinatorCommitPhysicalBeforeImageError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CoordinatorCommitPhysicalBeforeImageError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorCommitPhysicalBeforeImageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitPhysicalBeforeImageError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed u16"),
        ))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorCommitPhysicalBeforeImageError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed i64"),
        ))
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorCommitPhysicalBeforeImageError> {
        Ok(self.take(32)?.try_into().expect("fixed array"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorCommitPhysicalBeforeImageError> {
        let length = u32::from_be_bytes(self.take(4)?.try_into().expect("fixed u32"));
        self.take(length as usize)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use psy_node_core::store::typed::{
        CheckpointId, MerkleNode, NodeIndex, PublicKeyHash, TypedTableKey, UniquePendingId,
        UserId,
    };

    use super::*;
    use crate::rollback::{describe_existing_key, CqlKeyspaceName};

    #[test]
    fn schema_contract_distinguishes_value_key_only_and_unsupported_rows() {
        let value_key = describe_existing_key(&TypedTableKey::CheckpointLeaf(
            CheckpointId::try_new(7).unwrap(),
        ));
        let value = CoordinatorCommitPhysicalSourceObservation::Value(
            CoordinatorCommitPhysicalSourceCell::value(vec![1], 9),
        );
        assert_eq!(validate_observation(&value_key, &value), Ok(()));
        assert_eq!(
            validate_observation(
                &value_key,
                &CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent,
            ),
            Err(CoordinatorCommitPhysicalBeforeImageError::ObservationSchemaMismatch)
        );

        let key_only = describe_existing_key(&TypedTableKey::PublicKeyToUser {
            public_key_hash: PublicKeyHash::new(vec![2; 32]),
            user: UserId::new(8),
        });
        assert_eq!(
            validate_observation(
                &key_only,
                &CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent,
            ),
            Ok(())
        );
        assert_eq!(
            validate_observation(&key_only, &value),
            Err(CoordinatorCommitPhysicalBeforeImageError::ObservationSchemaMismatch)
        );

        let unsupported = describe_existing_key(&TypedTableKey::RewardTagMerkle {
            pending: UniquePendingId::try_new(9).unwrap(),
            node: MerkleNode::new(1, NodeIndex::new(2)),
        });
        assert_eq!(
            validate_observation(&unsupported, &value),
            Err(CoordinatorCommitPhysicalBeforeImageError::UnsupportedSchemaFamily)
        );
    }

    #[test]
    fn exact_read_contract_preserves_raw_value_writetime_and_key_only_presence() {
        let keyspace = CqlKeyspaceName::try_new("state_data").unwrap();
        let value_key = describe_existing_key(&TypedTableKey::CheckpointLeaf(
            CheckpointId::try_new(7).unwrap(),
        ));
        let value = CoordinatorCommitPhysicalReadSpec::try_for_key(&keyspace, &value_key)
            .unwrap();
        assert_eq!(
            value.cql(),
            "SELECT value, writetime(value) FROM state_data.checkpoint_leaf_table WHERE obj_id = ?"
        );
        assert_eq!(value.bind_shape(), &["obj_id:BIGINT"]);
        assert_eq!(
            value.result_shape(),
            &["value:BLOB", "writetime(value):BIGINT"]
        );
        assert!(!value.key_only());

        let key_only = describe_existing_key(&TypedTableKey::PublicKeyToUser {
            public_key_hash: PublicKeyHash::new(vec![2; 32]),
            user: UserId::new(8),
        });
        let key_only = CoordinatorCommitPhysicalReadSpec::try_for_key(&keyspace, &key_only)
            .unwrap();
        assert_eq!(
            key_only.cql(),
            "SELECT value_u64 FROM state_data.public_key_hash_to_user_ids_table WHERE hash_id = ? AND value_u64 = ?"
        );
        assert_eq!(
            key_only.bind_shape(),
            &["hash_id:BLOB", "value_u64:BIGINT"]
        );
        assert_eq!(key_only.result_shape(), &["value_u64:BIGINT"]);
        assert!(key_only.key_only());

        let unsupported = describe_existing_key(&TypedTableKey::RewardTagMerkle {
            pending: UniquePendingId::try_new(9).unwrap(),
            node: MerkleNode::new(1, NodeIndex::new(2)),
        });
        assert_eq!(
            CoordinatorCommitPhysicalReadSpec::try_for_key(&keyspace, &unsupported),
            Err(CoordinatorCommitPhysicalBeforeImageError::UnsupportedSchemaFamily)
        );
    }
}
