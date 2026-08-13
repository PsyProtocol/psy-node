//! Canonical pre-PONR restore payload for Coordinator mutable singletons.
//!
//! The latest-L2 singleton is restored from the exact stored bytes of the
//! immutable checkpoint-keyed L2 row at the selected target.  The latest
//! checkpoint singleton is restored to the target checkpoint number.  A
//! target above the rollback floor must additionally be backed by its exact
//! normal-commit source and COMMITTED marker. Genesis is the only source-less
//! target accepted here because its L2 singleton value is deterministic. A
//! non-genesis target equal to an upgrade floor remains fail-closed until a
//! floor-time singleton anchor is durably available.

use std::{error::Error, fmt, io::Cursor as IoCursor};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::canonical_chain::{
        CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN,
    },
    v1::qdata::checkpoint::QEDL2BlockState,
};
use psy_node_core::store::{
    canonical_head::StoredCanonicalHead,
    coordinator_commit_source::{
        CoordinatorCommitSource, CoordinatorCommitSourceCommitted,
        CoordinatorCommitSourcePayload, CoordinatorRollbackFloor,
    },
    rollback_control::{RollbackControlState, RollbackExecutionMode},
};
use psy_serialize::{
    PsyCanonicalDatabaseSerializeBaseSingle, PsyIOReadWrite,
};
use sha2::{Digest, Sha256};

use super::{
    CoordinatorCommitPhysicalInventory, CoordinatorCommitPhysicalSourceCell,
};

const PAYLOAD_MAGIC: &[u8; 8] = b"PSYCTRP1";
const PAYLOAD_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-target-restore-payload-slot.v1\0";
const DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-target-restore-payload.v1\0";
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_BINDING_BYTES: usize = 16 * 1024;
const MAX_STORED_L2_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorTargetRestoreSource {
    GenesisAnchor {
        floor_digest: [u8; 32],
    },
    CommittedSource {
        floor_digest: [u8; 32],
        source_slot: [u8; 32],
        source_digest: [u8; 32],
        committed_marker: [u8; 106],
    },
}

/// Immutable payload from which the future post-barrier writer can restore
/// the two mutable Coordinator singleton rows.  This object is evidence only:
/// it has no DELETE, timestamp, singleton-write, or head-mutation API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorCommitTargetRestorePayload<Hash> {
    network_chain_id: i64,
    old_chain_epoch: u64,
    archiving_head_revision: i64,
    archiving_head_canonical: Vec<u8>,
    archiving_control_canonical: Vec<u8>,
    catalog_digest: [u8; 32],
    archive_store_fingerprint: [u8; 32],
    participant_completion_slot: [u8; 32],
    participant_completion_digest: [u8; 32],
    target: CanonicalChainRef<Hash>,
    source: CoordinatorTargetRestoreSource,
    target_l2_source_writetime_us: i64,
    target_l2_stored_value: Vec<u8>,
    latest_checkpoint: u64,
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> CoordinatorCommitTargetRestorePayload<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_from_genesis_anchor(
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        catalog_digest: [u8; 32],
        archive_store_fingerprint: [u8; 32],
        participant_completion_slot: [u8; 32],
        participant_completion_digest: [u8; 32],
        floor: &CoordinatorRollbackFloor<Hash>,
        target_l2: &CoordinatorCommitPhysicalSourceCell,
    ) -> Result<Self, CoordinatorCommitTargetRestoreError> {
        if floor.floor() != &target
            || target.checkpoint().checkpoint_id().get() != 0
            || decode_stored_l2(target_l2)? != QEDL2BlockState::get_genesis_value()
        {
            return Err(CoordinatorCommitTargetRestoreError::FloorTargetMismatch);
        }
        Self::try_from_parts(
            archiving_head,
            target,
            catalog_digest,
            archive_store_fingerprint,
            participant_completion_slot,
            participant_completion_digest,
            CoordinatorTargetRestoreSource::GenesisAnchor {
                floor_digest: *floor.digest(),
            },
            target_l2,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_from_committed_source<F, Hasher>(
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        catalog_digest: [u8; 32],
        archive_store_fingerprint: [u8; 32],
        participant_completion_slot: [u8; 32],
        participant_completion_digest: [u8; 32],
        floor: &CoordinatorRollbackFloor<Hash>,
        source: &CoordinatorCommitSource<Hash>,
        marker: CoordinatorCommitSourceCommitted,
        target_l2: &CoordinatorCommitPhysicalSourceCell,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitTargetRestoreError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        if source.candidate() != &target || !marker.matches(source) {
            return Err(CoordinatorCommitTargetRestoreError::TargetSourceMismatch);
        }
        let floor_checkpoint = floor.floor().checkpoint().checkpoint_id().get();
        let target_checkpoint = target.checkpoint().checkpoint_id().get();
        if floor.floor().network_id() != target.network_id()
            || floor.floor().chain_epoch() != target.chain_epoch()
            || floor_checkpoint >= target_checkpoint
        {
            return Err(CoordinatorCommitTargetRestoreError::FloorTargetMismatch);
        }
        CoordinatorCommitPhysicalInventory::<Hash>::try_from_committed_source::<
            F,
            Hasher,
        >(source, marker, checkpoint_tree_height)
        .map_err(|error| {
            CoordinatorCommitTargetRestoreError::TargetSource(error.to_string())
        })?;
        let prepared = decode_prepared::<F, Hash>(source)?;
        let materialized = decode_stored_l2(target_l2)?;
        if prepared.new_base.block_state != materialized
            || prepared.checkpoint_id != target_checkpoint
            || prepared.new_base.block_state.checkpoint_id != target_checkpoint
        {
            return Err(
                CoordinatorCommitTargetRestoreError::MaterializedTargetMismatch,
            );
        }
        Self::try_from_parts(
            archiving_head,
            target,
            catalog_digest,
            archive_store_fingerprint,
            participant_completion_slot,
            participant_completion_digest,
            CoordinatorTargetRestoreSource::CommittedSource {
                floor_digest: *floor.digest(),
                source_slot: source.slot().as_bytes(),
                source_digest: source.digest().as_bytes(),
                committed_marker: marker.encode_canonical(),
            },
            target_l2,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_parts(
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        catalog_digest: [u8; 32],
        archive_store_fingerprint: [u8; 32],
        participant_completion_slot: [u8; 32],
        participant_completion_digest: [u8; 32],
        source: CoordinatorTargetRestoreSource,
        target_l2: &CoordinatorCommitPhysicalSourceCell,
    ) -> Result<Self, CoordinatorCommitTargetRestoreError> {
        validate_scope(&archiving_head, &target)?;
        if catalog_digest == [0; 32]
            || archive_store_fingerprint == [0; 32]
            || participant_completion_slot == [0; 32]
            || participant_completion_digest == [0; 32]
        {
            return Err(CoordinatorCommitTargetRestoreError::ZeroCommitment);
        }
        let target_checkpoint = target.checkpoint().checkpoint_id().get();
        let materialized = decode_stored_l2(target_l2)?;
        if materialized.checkpoint_id != target_checkpoint {
            return Err(
                CoordinatorCommitTargetRestoreError::MaterializedTargetMismatch,
            );
        }
        let network_chain_id = i64::from(target.network_id().chain_id());
        let old_chain_epoch = target.chain_epoch().get();
        let archiving_head_revision = archiving_head.revision().as_i64();
        let archiving_head_canonical =
            archiving_head.canonical_ref_bytes().to_vec();
        let archiving_control_canonical =
            archiving_head.rollback_control_bytes().to_vec();
        let slot = restore_slot(
            network_chain_id,
            old_chain_epoch,
            archiving_head_revision,
            &archiving_head_canonical,
            &archiving_control_canonical,
            &catalog_digest,
            &archive_store_fingerprint,
            &participant_completion_slot,
            &participant_completion_digest,
            &target,
        )?;
        let mut payload = Self {
            network_chain_id,
            old_chain_epoch,
            archiving_head_revision,
            archiving_head_canonical,
            archiving_control_canonical,
            catalog_digest,
            archive_store_fingerprint,
            participant_completion_slot,
            participant_completion_digest,
            target,
            source,
            target_l2_source_writetime_us: target_l2.writetime_us(),
            target_l2_stored_value: target_l2.bytes().to_vec(),
            latest_checkpoint: target_checkpoint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let commitment = payload.encode_without_digest()?;
        payload.digest = restore_digest(&commitment);
        payload.canonical_bytes = commitment;
        payload.canonical_bytes.extend_from_slice(&payload.digest);
        if payload.canonical_bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CoordinatorCommitTargetRestoreError::PayloadTooLarge);
        }
        Ok(payload)
    }

    pub(super) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitTargetRestoreError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CoordinatorCommitTargetRestoreError::PayloadTooLarge);
        }
        let mut cursor = RestoreCursor::new(bytes);
        if cursor.take(8)? != PAYLOAD_MAGIC {
            return Err(CoordinatorCommitTargetRestoreError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != PAYLOAD_VERSION {
            return Err(CoordinatorCommitTargetRestoreError::UnknownVersion(version));
        }
        let network_chain_id = cursor.i64()?;
        let old_chain_epoch = cursor.u64()?;
        let archiving_head_revision = cursor.i64()?;
        let archiving_head_canonical = cursor.bytes()?.to_vec();
        let archiving_control_canonical = cursor.bytes()?.to_vec();
        let catalog_digest = cursor.array_32()?;
        let archive_store_fingerprint = cursor.array_32()?;
        let participant_completion_slot = cursor.array_32()?;
        let participant_completion_digest = cursor.array_32()?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| {
            CoordinatorCommitTargetRestoreError::CanonicalRef(error.to_string())
        })?;
        let source = match cursor.u8()? {
            1 => CoordinatorTargetRestoreSource::GenesisAnchor {
                floor_digest: cursor.array_32()?,
            },
            2 => {
                let floor_digest = cursor.array_32()?;
                let source_slot = cursor.array_32()?;
                let source_digest = cursor.array_32()?;
                let committed_marker: [u8; 106] = cursor
                    .take(106)?
                    .try_into()
                    .expect("fixed committed marker");
                let marker = CoordinatorCommitSourceCommitted::decode_canonical(
                    &committed_marker,
                )
                .map_err(|error| {
                    CoordinatorCommitTargetRestoreError::TargetSource(
                        error.to_string(),
                    )
                })?;
                if marker.slot().as_bytes() != source_slot
                    || marker.source_digest().as_bytes() != source_digest
                {
                    return Err(CoordinatorCommitTargetRestoreError::TargetSourceMismatch);
                }
                CoordinatorTargetRestoreSource::CommittedSource {
                    floor_digest,
                    source_slot,
                    source_digest,
                    committed_marker,
                }
            }
            value => {
                return Err(CoordinatorCommitTargetRestoreError::UnknownSourceKind(
                    value,
                ));
            }
        };
        let target_l2_source_writetime_us = cursor.i64()?;
        let target_l2_stored_value = cursor.bytes()?.to_vec();
        let latest_checkpoint = cursor.u64()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorCommitTargetRestoreError::TrailingBytes);
        }
        if archiving_head_canonical.len() > MAX_BINDING_BYTES
            || archiving_control_canonical.len() > MAX_BINDING_BYTES
            || target_l2_stored_value.len() > MAX_STORED_L2_BYTES
        {
            return Err(CoordinatorCommitTargetRestoreError::BindingTooLarge);
        }
        if catalog_digest == [0; 32]
            || archive_store_fingerprint == [0; 32]
            || participant_completion_slot == [0; 32]
            || participant_completion_digest == [0; 32]
            || slot == [0; 32]
            || digest == [0; 32]
            || source.floor_digest() == &[0; 32]
        {
            return Err(CoordinatorCommitTargetRestoreError::ZeroCommitment);
        }
        if i64::from(target.network_id().chain_id()) != network_chain_id
            || target.chain_epoch().get() != old_chain_epoch
            || target.checkpoint().checkpoint_id().get() != latest_checkpoint
        {
            return Err(CoordinatorCommitTargetRestoreError::BindingMismatch);
        }
        match &source {
            CoordinatorTargetRestoreSource::GenesisAnchor { .. }
                if latest_checkpoint != 0 =>
            {
                return Err(CoordinatorCommitTargetRestoreError::FloorTargetMismatch);
            }
            CoordinatorTargetRestoreSource::CommittedSource { .. }
                if latest_checkpoint == 0 =>
            {
                return Err(CoordinatorCommitTargetRestoreError::FloorTargetMismatch);
            }
            CoordinatorTargetRestoreSource::GenesisAnchor { .. }
            | CoordinatorTargetRestoreSource::CommittedSource { .. } => {}
        }
        let target_cell = CoordinatorCommitPhysicalSourceCell::value(
            target_l2_stored_value.clone(),
            target_l2_source_writetime_us,
        );
        if decode_stored_l2(&target_cell)?.checkpoint_id != latest_checkpoint {
            return Err(
                CoordinatorCommitTargetRestoreError::MaterializedTargetMismatch,
            );
        }
        let expected_slot = restore_slot(
            network_chain_id,
            old_chain_epoch,
            archiving_head_revision,
            &archiving_head_canonical,
            &archiving_control_canonical,
            &catalog_digest,
            &archive_store_fingerprint,
            &participant_completion_slot,
            &participant_completion_digest,
            &target,
        )?;
        if expected_slot != slot {
            return Err(CoordinatorCommitTargetRestoreError::SlotMismatch);
        }
        if bytes.len() < 32 || restore_digest(&bytes[..bytes.len() - 32]) != digest {
            return Err(CoordinatorCommitTargetRestoreError::DigestMismatch);
        }
        let decoded = Self {
            network_chain_id,
            old_chain_epoch,
            archiving_head_revision,
            archiving_head_canonical,
            archiving_control_canonical,
            catalog_digest,
            archive_store_fingerprint,
            participant_completion_slot,
            participant_completion_digest,
            target,
            source,
            target_l2_source_writetime_us,
            target_l2_stored_value,
            latest_checkpoint,
            slot,
            digest,
            canonical_bytes: bytes.to_vec(),
        };
        if decoded.encode_without_digest()? != bytes[..bytes.len() - 32] {
            return Err(CoordinatorCommitTargetRestoreError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub(super) const fn catalog_digest(&self) -> &[u8; 32] {
        &self.catalog_digest
    }

    pub(super) const fn archive_store_fingerprint(&self) -> &[u8; 32] {
        &self.archive_store_fingerprint
    }

    pub(super) const fn participant_completion_slot(&self) -> &[u8; 32] {
        &self.participant_completion_slot
    }

    pub(super) const fn participant_completion_digest(&self) -> &[u8; 32] {
        &self.participant_completion_digest
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(super) fn validate_selected(
        &self,
        archiving_head: &StoredCanonicalHead<Hash>,
        target: &CanonicalChainRef<Hash>,
        catalog_digest: &[u8; 32],
        archive_store_fingerprint: &[u8; 32],
        participant_completion_slot: &[u8; 32],
        participant_completion_digest: &[u8; 32],
    ) -> Result<(), CoordinatorCommitTargetRestoreError> {
        if self.network_chain_id != i64::from(target.network_id().chain_id())
            || self.old_chain_epoch != target.chain_epoch().get()
            || self.archiving_head_revision != archiving_head.revision().as_i64()
            || self.archiving_head_canonical != archiving_head.canonical_ref_bytes()
            || self.archiving_control_canonical
                != archiving_head.rollback_control_bytes()
            || &self.catalog_digest != catalog_digest
            || &self.archive_store_fingerprint != archive_store_fingerprint
            || &self.participant_completion_slot != participant_completion_slot
            || &self.participant_completion_digest != participant_completion_digest
            || &self.target != target
        {
            return Err(CoordinatorCommitTargetRestoreError::BindingMismatch);
        }
        Ok(())
    }

    fn encode_without_digest(
        &self,
    ) -> Result<Vec<u8>, CoordinatorCommitTargetRestoreError> {
        if self.archiving_head_canonical.len() > MAX_BINDING_BYTES
            || self.archiving_control_canonical.len() > MAX_BINDING_BYTES
            || self.target_l2_stored_value.len() > MAX_STORED_L2_BYTES
        {
            return Err(CoordinatorCommitTargetRestoreError::BindingTooLarge);
        }
        let mut bytes = Vec::with_capacity(
            512 + self.archiving_head_canonical.len()
                + self.archiving_control_canonical.len()
                + self.target_l2_stored_value.len(),
        );
        bytes.extend_from_slice(PAYLOAD_MAGIC);
        bytes.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_chain_id.to_be_bytes());
        bytes.extend_from_slice(&self.old_chain_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.archiving_head_revision.to_be_bytes());
        encode_bytes(&mut bytes, &self.archiving_head_canonical)?;
        encode_bytes(&mut bytes, &self.archiving_control_canonical)?;
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.archive_store_fingerprint);
        bytes.extend_from_slice(&self.participant_completion_slot);
        bytes.extend_from_slice(&self.participant_completion_digest);
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        match &self.source {
            CoordinatorTargetRestoreSource::GenesisAnchor { floor_digest } => {
                bytes.push(1);
                bytes.extend_from_slice(floor_digest);
            }
            CoordinatorTargetRestoreSource::CommittedSource {
                floor_digest,
                source_slot,
                source_digest,
                committed_marker,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(floor_digest);
                bytes.extend_from_slice(source_slot);
                bytes.extend_from_slice(source_digest);
                bytes.extend_from_slice(committed_marker);
            }
        }
        bytes.extend_from_slice(&self.target_l2_source_writetime_us.to_be_bytes());
        encode_bytes(&mut bytes, &self.target_l2_stored_value)?;
        bytes.extend_from_slice(&self.latest_checkpoint.to_be_bytes());
        bytes.extend_from_slice(&self.slot);
        Ok(bytes)
    }
}

impl CoordinatorTargetRestoreSource {
    const fn floor_digest(&self) -> &[u8; 32] {
        match self {
            Self::GenesisAnchor { floor_digest }
            | Self::CommittedSource { floor_digest, .. } => floor_digest,
        }
    }
}

fn validate_scope<Hash: Q256BitHash>(
    head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
) -> Result<(), CoordinatorCommitTargetRestoreError> {
    let RollbackControlState::Archiving(request) = head.rollback_control() else {
        return Err(CoordinatorCommitTargetRestoreError::NotExactArchivingScope);
    };
    let active_epoch = head.canonical_ref().chain_epoch().get();
    let old_epoch = active_epoch
        .checked_sub(1)
        .ok_or(CoordinatorCommitTargetRestoreError::EpochUnderflow)?;
    if request.execution_mode() != RollbackExecutionMode::InPlace
        || head.canonical_ref().checkpoint() != request.requested_head()
        || target.network_id() != head.canonical_ref().network_id()
        || target.chain_epoch().get() != old_epoch
        || target.checkpoint() != request.target()
    {
        return Err(CoordinatorCommitTargetRestoreError::NotExactArchivingScope);
    }
    Ok(())
}

fn decode_prepared<F: QFelt64, Hash: Q256BitHash>(
    source: &CoordinatorCommitSource<Hash>,
) -> Result<PsyPreparedCoordinatorBlockStateUpdates<F, Hash>, CoordinatorCommitTargetRestoreError>
{
    let payload = CoordinatorCommitSourcePayload::decode_canonical(
        source.prepared_update(),
    )
    .map_err(|error| {
        CoordinatorCommitTargetRestoreError::TargetSource(error.to_string())
    })?;
    let mut cursor = IoCursor::new(payload.prepared_update());
    let prepared = PsyPreparedCoordinatorBlockStateUpdates::<F, Hash>::pio_read_from_io(
        &mut cursor,
    )
    .map_err(|error| {
        CoordinatorCommitTargetRestoreError::TargetSource(error.to_string())
    })?;
    if cursor.position() != payload.prepared_update().len() as u64 {
        return Err(CoordinatorCommitTargetRestoreError::TrailingPreparedUpdate);
    }
    Ok(prepared)
}

fn decode_stored_l2(
    cell: &CoordinatorCommitPhysicalSourceCell,
) -> Result<QEDL2BlockState, CoordinatorCommitTargetRestoreError> {
    if cell.bytes().is_empty() || cell.bytes().len() > MAX_STORED_L2_BYTES {
        return Err(CoordinatorCommitTargetRestoreError::InvalidStoredL2);
    }
    let canonical = crate::compression::decompress(cell.bytes())
        .map_err(|error| CoordinatorCommitTargetRestoreError::StoredL2(error.to_string()))?;
    let decoded = QEDL2BlockState::psy_ser_from_owned_bytes_vec(canonical.clone())
        .map_err(|error| CoordinatorCommitTargetRestoreError::StoredL2(error.to_string()))?;
    let rebuilt = decoded
        .psy_ser_to_bytes_vec()
        .map_err(|error| CoordinatorCommitTargetRestoreError::StoredL2(error.to_string()))?;
    if rebuilt != canonical {
        return Err(CoordinatorCommitTargetRestoreError::NonCanonicalStoredL2);
    }
    Ok(decoded)
}

#[allow(clippy::too_many_arguments)]
fn restore_slot<Hash: Q256BitHash>(
    network_chain_id: i64,
    old_chain_epoch: u64,
    archiving_head_revision: i64,
    archiving_head_canonical: &[u8],
    archiving_control_canonical: &[u8],
    catalog_digest: &[u8; 32],
    archive_store_fingerprint: &[u8; 32],
    participant_completion_slot: &[u8; 32],
    participant_completion_digest: &[u8; 32],
    target: &CanonicalChainRef<Hash>,
) -> Result<[u8; 32], CoordinatorCommitTargetRestoreError> {
    if archiving_head_canonical.len() > MAX_BINDING_BYTES
        || archiving_control_canonical.len() > MAX_BINDING_BYTES
    {
        return Err(CoordinatorCommitTargetRestoreError::BindingTooLarge);
    }
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network_chain_id.to_be_bytes());
    hasher.update(old_chain_epoch.to_be_bytes());
    hasher.update(archiving_head_revision.to_be_bytes());
    hash_bytes(&mut hasher, archiving_head_canonical);
    hash_bytes(&mut hasher, archiving_control_canonical);
    hasher.update(catalog_digest);
    hasher.update(archive_store_fingerprint);
    hasher.update(participant_completion_slot);
    hasher.update(participant_completion_digest);
    hasher.update(target.to_canonical_bytes());
    Ok(hasher.finalize().into())
}

fn restore_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CoordinatorCommitTargetRestoreError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CoordinatorCommitTargetRestoreError::LengthOverflow)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct RestoreCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RestoreCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorCommitTargetRestoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CoordinatorCommitTargetRestoreError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoordinatorCommitTargetRestoreError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorCommitTargetRestoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitTargetRestoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorCommitTargetRestoreError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed u32")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorCommitTargetRestoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorCommitTargetRestoreError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("fixed i64")))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorCommitTargetRestoreError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorCommitTargetRestoreError> {
        Ok(self.take(32)?.try_into().expect("fixed digest"))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitTargetRestoreError {
    InvalidMagic,
    UnknownVersion(u16),
    UnknownSourceKind(u8),
    CanonicalRef(String),
    NotExactArchivingScope,
    EpochUnderflow,
    FloorTargetMismatch,
    TargetSourceMismatch,
    TargetSource(String),
    TrailingPreparedUpdate,
    MaterializedTargetMismatch,
    InvalidStoredL2,
    StoredL2(String),
    NonCanonicalStoredL2,
    BindingMismatch,
    BindingTooLarge,
    PayloadTooLarge,
    ZeroCommitment,
    SlotMismatch,
    DigestMismatch,
    NonCanonicalEncoding,
    LengthOverflow,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for CoordinatorCommitTargetRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator target restore payload: {self:?}")
    }
}

impl Error for CoordinatorCommitTargetRestoreError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore,
            traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        pgoldilocks::PoseidonHasher,
        PHash, PF,
    };
    use psy_data::{
        prepared_block::{
            common::PsyCoordinatorPendingCheckpointBase,
            coordinator::PsyPreparedCoordinatorBlockStateUpdates,
        },
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash,
            CheckpointId as ChainCheckpointId, CheckpointRef, NetworkId,
        },
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats,
                QEDL2BlockState,
            },
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };
    use psy_node_core::store::{
        canonical_head::StoredCanonicalHead,
        coordinator_commit_source::{
            CoordinatorCommitSource, CoordinatorCommitSourcePayload,
            CoordinatorRollbackFloor,
        },
        rollback_control::{
            RollbackControlState, RollbackExecutionMode, RollbackPlanDigest,
            RollbackRequest,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;

    const TREE_HEIGHT: u8 = 8;

    fn hash(seed: u64) -> PHash {
        PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            ChainCheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        )
    }

    fn canonical(epoch: u64, height: u64, seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(epoch),
            checkpoint(height, seed),
        )
    }

    fn idle_head(epoch: u64, height: u64, seed: u64) -> StoredCanonicalHead<PHash> {
        let canonical = canonical(epoch, height, seed);
        StoredCanonicalHead::decode_persisted(
            canonical.network_id(),
            1,
            &canonical.to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap()
    }

    fn archiving_head(target: CheckpointRef<PHash>) -> StoredCanonicalHead<PHash> {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let request = RollbackRequest::try_new(
            checkpoint(10, 1_000),
            target,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(20_000).unwrap(),
                20_001,
                20_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap();
        StoredCanonicalHead::decode_persisted(
            network,
            9,
            &CanonicalChainRef::new(
                network,
                ChainEpoch::new(7),
                checkpoint(10, 1_000),
            )
            .to_canonical_bytes(),
            &RollbackControlState::Archiving(request).to_canonical_bytes(),
        )
        .unwrap()
    }

    fn leaf(contract_root: PHash) -> PsyCheckpointLeafPopulated<PF, PHash> {
        PsyCheckpointLeafPopulated {
            global_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: contract_root,
                deposit_tree_root: PHash::get_zero_value(),
                user_tree_root: PHash::get_zero_value(),
                withdrawal_tree_root: PHash::get_zero_value(),
                user_registration_tree_root: PHash::get_zero_value(),
            },
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        }
    }

    fn block_state(checkpoint_id: u64, next_contract_id: u32) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id,
            next_add_withdrawal_id: 11,
            next_process_withdrawal_id: 12,
            next_deposit_id: 13,
            total_deposits_claimed_epoch: 14,
            next_user_id: 15,
            end_balance: 16,
            next_contract_id,
        }
    }

    fn prepared() -> PsyPreparedCoordinatorBlockStateUpdates<PF, PHash> {
        let old_leaf = leaf(PHash::get_zero_value());
        let new_leaf = leaf(hash(900));
        let old_leaf_hash = old_leaf.qfhash::<PoseidonHasher>();
        let new_leaf_hash = new_leaf.qfhash::<PoseidonHasher>();
        let siblings = (0..TREE_HEIGHT as usize)
            .map(PoseidonHasher::get_zero_hash)
            .collect::<Vec<_>>();
        let proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
            8,
            old_leaf_hash,
            new_leaf_hash,
            siblings,
        );
        PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: 0,
            checkpoint_id: 8,
            unique_pending_id: 81,
            proc_checkpoint_unique_id: 82,
            old_base: PsyCoordinatorPendingCheckpointBase {
                block_state: block_state(7, 41),
                checkpoint_leaf: old_leaf,
                checkpoint_leaf_hash: old_leaf_hash,
                checkpoint_tree_root: proof.old_root,
            },
            new_base: PsyCoordinatorPendingCheckpointBase {
                block_state: block_state(8, 42),
                checkpoint_leaf: new_leaf,
                checkpoint_leaf_hash: new_leaf_hash,
                checkpoint_tree_root: proof.new_root,
            },
            update_global_contract_tree_nodes_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            new_contract_leaves_ffs: Vec::new(),
            new_contract_code_definitions: Vec::new(),
            update_user_registration_tree_nodes_ffs: Vec::new(),
            new_user_public_keys_ffs: Vec::new(),
            new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
            update_global_user_tree_nodes_ffs: Vec::new(),
            new_realm_guta_reward_tree_node_keys_ffs: Vec::new(),
            checkpoint_tree_update_proof: proof,
        }
    }

    fn committed_source(
        prepared: &PsyPreparedCoordinatorBlockStateUpdates<PF, PHash>,
    ) -> CoordinatorCommitSource<PHash> {
        let mut prepared_bytes = Vec::new();
        prepared.pio_write_to_io(&mut prepared_bytes).unwrap();
        let payload = CoordinatorCommitSourcePayload::try_new(
            prepared_bytes,
            17,
            vec![3; 64],
        )
        .unwrap();
        CoordinatorCommitSource::try_new(
            idle_head(6, 7, 700),
            canonical(6, 8, 800),
            payload.encode_canonical(),
        )
        .unwrap()
    }

    fn stored_l2(state: &QEDL2BlockState, writetime_us: i64) -> CoordinatorCommitPhysicalSourceCell {
        CoordinatorCommitPhysicalSourceCell::value(
            crate::compression::compress(&state.psy_ser_to_bytes_vec().unwrap()).unwrap(),
            writetime_us,
        )
    }

    #[test]
    fn committed_target_payload_roundtrips_and_rejects_source_or_materialized_drift() {
        let prepared = prepared();
        let source = committed_source(&prepared);
        let marker = source.committed_marker();
        let floor = CoordinatorRollbackFloor::try_new(idle_head(6, 7, 700)).unwrap();
        let target = canonical(6, 8, 800);
        let payload = CoordinatorCommitTargetRestorePayload::try_from_committed_source::<
            PF,
            PoseidonHasher,
        >(
            archiving_head(*target.checkpoint()),
            target,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            &floor,
            &source,
            marker,
            &stored_l2(&prepared.new_base.block_state, 7_001),
            TREE_HEIGHT,
        )
        .unwrap();
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::decode_canonical(
                payload.canonical_bytes(),
            ),
            Ok(payload.clone()),
        );

        let mut drifted = prepared.new_base.block_state;
        drifted.next_contract_id += 1;
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::try_from_committed_source::<
                PF,
                PoseidonHasher,
            >(
                archiving_head(*target.checkpoint()),
                target,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0x44; 32],
                &floor,
                &source,
                marker,
                &stored_l2(&drifted, 7_001),
                TREE_HEIGHT,
            ),
            Err(CoordinatorCommitTargetRestoreError::MaterializedTargetMismatch),
        );

        let foreign = CoordinatorCommitSource::try_new(
            idle_head(6, 7, 701),
            canonical(6, 8, 801),
            source.prepared_update().to_vec(),
        )
        .unwrap();
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::try_from_committed_source::<
                PF,
                PoseidonHasher,
            >(
                archiving_head(*target.checkpoint()),
                target,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0x44; 32],
                &floor,
                &source,
                foreign.committed_marker(),
                &stored_l2(&prepared.new_base.block_state, 7_001),
                TREE_HEIGHT,
            ),
            Err(CoordinatorCommitTargetRestoreError::TargetSourceMismatch),
        );
    }

    #[test]
    fn genesis_target_is_explicit_and_different_observations_conflict_at_one_slot() {
        let target = canonical(6, 0, 700);
        let floor = CoordinatorRollbackFloor::try_new(idle_head(6, 0, 700)).unwrap();
        let first = CoordinatorCommitTargetRestorePayload::try_from_genesis_anchor(
            archiving_head(*target.checkpoint()),
            target,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            &floor,
            &stored_l2(&QEDL2BlockState::get_genesis_value(), 7_001),
        )
        .unwrap();
        let second = CoordinatorCommitTargetRestorePayload::try_from_genesis_anchor(
            archiving_head(*target.checkpoint()),
            target,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            &floor,
            &stored_l2(&QEDL2BlockState::get_genesis_value(), 7_002),
        )
        .unwrap();
        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.digest(), second.digest());
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::decode_canonical(
                first.canonical_bytes(),
            ),
            Ok(first),
        );

        let non_genesis_floor_target = canonical(6, 7, 700);
        let non_genesis_floor =
            CoordinatorRollbackFloor::try_new(idle_head(6, 7, 700)).unwrap();
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::try_from_genesis_anchor(
                archiving_head(*non_genesis_floor_target.checkpoint()),
                non_genesis_floor_target,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0x44; 32],
                &non_genesis_floor,
                &stored_l2(&block_state(7, 41), 7_001),
            ),
            Err(CoordinatorCommitTargetRestoreError::FloorTargetMismatch),
        );
    }

    #[test]
    fn strict_decoder_rejects_rehashed_inner_checkpoint_forgery() {
        let target = canonical(6, 0, 700);
        let floor = CoordinatorRollbackFloor::try_new(idle_head(6, 0, 700)).unwrap();
        let payload = CoordinatorCommitTargetRestorePayload::try_from_genesis_anchor(
            archiving_head(*target.checkpoint()),
            target,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            &floor,
            &stored_l2(&QEDL2BlockState::get_genesis_value(), 7_001),
        )
        .unwrap();
        let mut forged = payload.canonical_bytes().to_vec();
        let latest_checkpoint_offset = forged.len() - 32 - 32 - 8;
        forged[latest_checkpoint_offset + 7] ^= 1;
        let rebuilt = restore_digest(&forged[..forged.len() - 32]);
        let digest_offset = forged.len() - 32;
        forged[digest_offset..].copy_from_slice(&rebuilt);
        assert_eq!(
            CoordinatorCommitTargetRestorePayload::<PHash>::decode_canonical(&forged),
            Err(CoordinatorCommitTargetRestoreError::BindingMismatch),
        );
    }
}
