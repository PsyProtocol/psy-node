//! Strict, non-destructive Coordinator delete/restore execution plan.
//!
//! The plan binds an exact pre-barrier readiness commitment to every archived
//! hot-row identity and to the rollback timestamp window. It is deliberately
//! not an execution capability: no barrier receipt, prepared DELETE, mutable
//! singleton writer, or canonical-head mutation is exposed here.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN,
};
use psy_node_core::store::{
    canonical_head::StoredCanonicalHead,
    rollback_control::{RollbackControlState, RollbackExecutionMode},
    timestamp::{
        CommitWriteTimestampUs, TimestampFenceWindow, TimestampOrderingError,
    },
};
use sha2::{Digest, Sha256};

use super::{
    coordinator_commit_physical_inventory::action_for_key,
    decode_locator_canonical, CoordinatorCommitInventoryAction,
    CoordinatorCommitPhysicalBeforeImage, CoordinatorCommitPhysicalSourceObservation,
    ResolvedScyllaKey,
};

const PLAN_MAGIC: &[u8; 8] = b"PSYCCDP1";
const PLAN_VERSION: u16 = 1;
const PLAN_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-delete-restore-plan.v1\0";
const MAX_PLAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_BINDING_BYTES: usize = 16 * 1024;
const MAX_LOCATOR_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CoordinatorCommitDeleteRestoreAction {
    DeleteHotRow = 1,
    RestoreTargetSingleton = 2,
}

impl TryFrom<u8> for CoordinatorCommitDeleteRestoreAction {
    type Error = CoordinatorCommitDeleteRestorePlanError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DeleteHotRow),
            2 => Ok(Self::RestoreTargetSingleton),
            value => Err(CoordinatorCommitDeleteRestorePlanError::UnknownAction(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorCommitDeleteRestoreEntry {
    action: CoordinatorCommitDeleteRestoreAction,
    key: ResolvedScyllaKey,
    before_image_slot: [u8; 32],
    before_image_digest: [u8; 32],
    source_writetime_us: Option<i64>,
}

impl CoordinatorCommitDeleteRestoreEntry {
    pub(super) fn try_from_before_image<Hash: Q256BitHash>(
        before_image: &CoordinatorCommitPhysicalBeforeImage<Hash>,
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanError> {
        let action = match before_image.action() {
            CoordinatorCommitInventoryAction::ArchiveThenDelete => {
                CoordinatorCommitDeleteRestoreAction::DeleteHotRow
            }
            CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget => {
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton
            }
        };
        let source_writetime_us = match before_image.observation() {
            CoordinatorCommitPhysicalSourceObservation::Value(cell) => {
                Some(cell.writetime_us())
            }
            CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent => None,
        };
        Self::try_new(
            action,
            before_image.key().clone(),
            *before_image.slot(),
            *before_image.digest(),
            source_writetime_us,
        )
    }

    fn try_new(
        action: CoordinatorCommitDeleteRestoreAction,
        key: ResolvedScyllaKey,
        before_image_slot: [u8; 32],
        before_image_digest: [u8; 32],
        source_writetime_us: Option<i64>,
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanError> {
        if key.locator_bytes().is_empty()
            || key.locator_bytes().len() > MAX_LOCATOR_BYTES
            || before_image_slot == [0; 32]
            || before_image_digest == [0; 32]
        {
            return Err(CoordinatorCommitDeleteRestorePlanError::InvalidEntry);
        }
        let expected_action = match action_for_key(key.typed_key()) {
            CoordinatorCommitInventoryAction::ArchiveThenDelete => {
                CoordinatorCommitDeleteRestoreAction::DeleteHotRow
            }
            CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget => {
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton
            }
        };
        if action != expected_action {
            return Err(CoordinatorCommitDeleteRestorePlanError::ActionMismatch);
        }
        Ok(Self {
            action,
            key,
            before_image_slot,
            before_image_digest,
            source_writetime_us,
        })
    }

    pub(crate) const fn action(&self) -> CoordinatorCommitDeleteRestoreAction {
        self.action
    }

    pub(crate) const fn key(&self) -> &ResolvedScyllaKey {
        &self.key
    }
}

/// Content-addressed description of the future Coordinator destructive work.
/// It is non-Clone and has no execute or authorization method.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitDeleteRestorePlan<Hash> {
    archiving_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    old_head: CanonicalChainRef<Hash>,
    catalog_digest: [u8; 32],
    pre_barrier_readiness_digest: [u8; 32],
    target_restore_slot: [u8; 32],
    target_restore_digest: [u8; 32],
    fence_window: TimestampFenceWindow,
    entries: Vec<CoordinatorCommitDeleteRestoreEntry>,
    delete_count: u64,
    restore_count: u64,
    key_only_count: u64,
    max_value_source_writetime_us: Option<i64>,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCommitDeleteRestorePlan<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_from_selected(
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        old_head: CanonicalChainRef<Hash>,
        catalog_digest: [u8; 32],
        pre_barrier_readiness_digest: [u8; 32],
        target_restore_slot: [u8; 32],
        target_restore_digest: [u8; 32],
        fence_window: TimestampFenceWindow,
        entries: Vec<CoordinatorCommitDeleteRestoreEntry>,
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanError> {
        if entries.is_empty() || entries.len() > MAX_ENTRIES {
            return Err(CoordinatorCommitDeleteRestorePlanError::InvalidEntryCount);
        }
        if catalog_digest == [0; 32]
            || pre_barrier_readiness_digest == [0; 32]
            || target_restore_slot == [0; 32]
            || target_restore_digest == [0; 32]
        {
            return Err(CoordinatorCommitDeleteRestorePlanError::ZeroCommitment);
        }
        validate_scope(&archiving_head, &target, &old_head, fence_window)?;
        if entries.windows(2).any(|pair| {
            pair[0].key.locator_bytes() >= pair[1].key.locator_bytes()
        }) {
            return Err(CoordinatorCommitDeleteRestorePlanError::NonCanonicalEntryOrder);
        }

        let orphan_write_max = fence_window
            .delete_fence()
            .orphan_write_max()
            .as_i64();
        let mut delete_count = 0_u64;
        let mut restore_count = 0_u64;
        let mut key_only_count = 0_u64;
        let mut max_value_source_writetime_us: Option<i64> = None;
        for entry in &entries {
            match entry.action {
                CoordinatorCommitDeleteRestoreAction::DeleteHotRow => {
                    delete_count = delete_count.checked_add(1).ok_or(
                        CoordinatorCommitDeleteRestorePlanError::LengthOverflow,
                    )?;
                }
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton => {
                    restore_count = restore_count.checked_add(1).ok_or(
                        CoordinatorCommitDeleteRestorePlanError::LengthOverflow,
                    )?;
                }
            }
            match entry.source_writetime_us {
                Some(writetime_us) => {
                    if writetime_us > orphan_write_max {
                        return Err(
                            CoordinatorCommitDeleteRestorePlanError::SourceWritetimeExceedsFence {
                                writetime_us,
                                orphan_write_max,
                            },
                        );
                    }
                    max_value_source_writetime_us = Some(
                        max_value_source_writetime_us
                            .map_or(writetime_us, |current| current.max(writetime_us)),
                    );
                }
                None => {
                    key_only_count = key_only_count.checked_add(1).ok_or(
                        CoordinatorCommitDeleteRestorePlanError::LengthOverflow,
                    )?;
                }
            }
        }
        if restore_count != 2 {
            return Err(CoordinatorCommitDeleteRestorePlanError::RestoreSetMismatch {
                actual: restore_count,
            });
        }

        let mut plan = Self {
            archiving_head,
            target,
            old_head,
            catalog_digest,
            pre_barrier_readiness_digest,
            target_restore_slot,
            target_restore_digest,
            fence_window,
            entries,
            delete_count,
            restore_count,
            key_only_count,
            max_value_source_writetime_us,
            canonical_bytes: Vec::new(),
            digest: [0; 32],
        };
        let commitment = plan.encode_without_digest()?;
        plan.digest = plan_digest(&commitment);
        plan.canonical_bytes = commitment;
        plan.canonical_bytes.extend_from_slice(&plan.digest);
        if plan.canonical_bytes.len() > MAX_PLAN_BYTES {
            return Err(CoordinatorCommitDeleteRestorePlanError::PlanTooLarge);
        }
        Ok(plan)
    }

    pub(crate) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(CoordinatorCommitDeleteRestorePlanError::PlanTooLarge);
        }
        let mut cursor = PlanCursor::new(bytes);
        if cursor.take(8)? != PLAN_MAGIC {
            return Err(CoordinatorCommitDeleteRestorePlanError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != PLAN_VERSION {
            return Err(CoordinatorCommitDeleteRestorePlanError::UnknownVersion(version));
        }
        let chain_id = u32::try_from(cursor.i64()?).map_err(|error| {
            CoordinatorCommitDeleteRestorePlanError::CanonicalHead(error.to_string())
        })?;
        let network = NetworkId::try_from_chain_id(chain_id).map_err(|error| {
            CoordinatorCommitDeleteRestorePlanError::CanonicalHead(error.to_string())
        })?;
        let head_revision = cursor.i64()?;
        let head_canonical = cursor.bytes()?.to_vec();
        let head_control = cursor.bytes()?.to_vec();
        if head_canonical.len() > MAX_BINDING_BYTES || head_control.len() > MAX_BINDING_BYTES {
            return Err(CoordinatorCommitDeleteRestorePlanError::BindingTooLarge);
        }
        let archiving_head = StoredCanonicalHead::decode_persisted(
            network,
            head_revision,
            &head_canonical,
            &head_control,
        )
        .map_err(|error| {
            CoordinatorCommitDeleteRestorePlanError::CanonicalHead(error.to_string())
        })?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| {
            CoordinatorCommitDeleteRestorePlanError::CanonicalRef(error.to_string())
        })?;
        let old_head = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| {
            CoordinatorCommitDeleteRestorePlanError::CanonicalRef(error.to_string())
        })?;
        let catalog_digest = cursor.array_32()?;
        let pre_barrier_readiness_digest = cursor.array_32()?;
        let target_restore_slot = cursor.array_32()?;
        let target_restore_digest = cursor.array_32()?;
        let orphan_write_max = cursor.i64()?;
        let delete_fence = cursor.i64()?;
        let new_branch_write = cursor.i64()?;
        let fence_window = TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(i128::from(orphan_write_max))?,
            i128::from(delete_fence),
            i128::from(new_branch_write),
        )?;
        let expected_delete_count = cursor.u64()?;
        let expected_restore_count = cursor.u64()?;
        let expected_key_only_count = cursor.u64()?;
        let expected_max_value_source_writetime_us = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.i64()?),
            value => return Err(CoordinatorCommitDeleteRestorePlanError::InvalidPresence(value)),
        };
        let entry_count = cursor.u32()? as usize;
        if entry_count == 0 || entry_count > MAX_ENTRIES {
            return Err(CoordinatorCommitDeleteRestorePlanError::InvalidEntryCount);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let action = CoordinatorCommitDeleteRestoreAction::try_from(cursor.u8()?)?;
            let locator = cursor.bytes()?;
            if locator.len() > MAX_LOCATOR_BYTES {
                return Err(CoordinatorCommitDeleteRestorePlanError::InvalidEntry);
            }
            let key = decode_locator_canonical(locator)
                .map_err(CoordinatorCommitDeleteRestorePlanError::InvalidLocator)?;
            let before_image_slot = cursor.array_32()?;
            let before_image_digest = cursor.array_32()?;
            let source_writetime_us = match cursor.u8()? {
                0 => None,
                1 => Some(cursor.i64()?),
                value => {
                    return Err(CoordinatorCommitDeleteRestorePlanError::InvalidPresence(value));
                }
            };
            entries.push(CoordinatorCommitDeleteRestoreEntry::try_new(
                action,
                key,
                before_image_slot,
                before_image_digest,
                source_writetime_us,
            )?);
        }
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorCommitDeleteRestorePlanError::TrailingBytes);
        }
        if bytes.len() < 32 || plan_digest(&bytes[..bytes.len() - 32]) != digest {
            return Err(CoordinatorCommitDeleteRestorePlanError::DigestMismatch);
        }
        let decoded = Self::try_from_selected(
            archiving_head,
            target,
            old_head,
            catalog_digest,
            pre_barrier_readiness_digest,
            target_restore_slot,
            target_restore_digest,
            fence_window,
            entries,
        )?;
        if decoded.delete_count != expected_delete_count
            || decoded.restore_count != expected_restore_count
            || decoded.key_only_count != expected_key_only_count
            || decoded.max_value_source_writetime_us
                != expected_max_value_source_writetime_us
            || decoded.digest != digest
            || decoded.canonical_bytes != bytes
        {
            return Err(CoordinatorCommitDeleteRestorePlanError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub(crate) const fn fence_window(&self) -> TimestampFenceWindow {
        self.fence_window
    }

    pub(crate) fn entries(&self) -> &[CoordinatorCommitDeleteRestoreEntry] {
        &self.entries
    }

    pub(crate) const fn delete_count(&self) -> u64 {
        self.delete_count
    }

    pub(crate) const fn restore_count(&self) -> u64 {
        self.restore_count
    }

    pub(crate) const fn key_only_count(&self) -> u64 {
        self.key_only_count
    }

    pub(crate) const fn max_value_source_writetime_us(&self) -> Option<i64> {
        self.max_value_source_writetime_us
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn encode_without_digest(&self) -> Result<Vec<u8>, CoordinatorCommitDeleteRestorePlanError> {
        let head_canonical = self.archiving_head.canonical_ref_bytes();
        let head_control = self.archiving_head.rollback_control_bytes();
        let mut bytes = Vec::with_capacity(512 + self.entries.len() * 160);
        bytes.extend_from_slice(PLAN_MAGIC);
        bytes.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&i64::from(self.target.network_id().chain_id()).to_be_bytes());
        bytes.extend_from_slice(&self.archiving_head.revision().as_i64().to_be_bytes());
        encode_bytes(&mut bytes, &head_canonical)?;
        encode_bytes(&mut bytes, &head_control)?;
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.old_head.to_canonical_bytes());
        bytes.extend_from_slice(&self.catalog_digest);
        bytes.extend_from_slice(&self.pre_barrier_readiness_digest);
        bytes.extend_from_slice(&self.target_restore_slot);
        bytes.extend_from_slice(&self.target_restore_digest);
        bytes.extend_from_slice(
            &self
                .fence_window
                .delete_fence()
                .orphan_write_max()
                .as_i64()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.fence_window.delete_fence().as_i64().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .fence_window
                .new_branch_write()
                .as_commit_timestamp()
                .as_i64()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.delete_count.to_be_bytes());
        bytes.extend_from_slice(&self.restore_count.to_be_bytes());
        bytes.extend_from_slice(&self.key_only_count.to_be_bytes());
        match self.max_value_source_writetime_us {
            Some(writetime_us) => {
                bytes.push(1);
                bytes.extend_from_slice(&writetime_us.to_be_bytes());
            }
            None => bytes.push(0),
        }
        let entry_count = u32::try_from(self.entries.len())
            .map_err(|_| CoordinatorCommitDeleteRestorePlanError::LengthOverflow)?;
        bytes.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &self.entries {
            bytes.push(entry.action as u8);
            encode_bytes(&mut bytes, entry.key.locator_bytes())?;
            bytes.extend_from_slice(&entry.before_image_slot);
            bytes.extend_from_slice(&entry.before_image_digest);
            match entry.source_writetime_us {
                Some(writetime_us) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&writetime_us.to_be_bytes());
                }
                None => bytes.push(0),
            }
        }
        Ok(bytes)
    }
}

fn validate_scope<Hash: Q256BitHash>(
    archiving_head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
    old_head: &CanonicalChainRef<Hash>,
    fence_window: TimestampFenceWindow,
) -> Result<(), CoordinatorCommitDeleteRestorePlanError> {
    let RollbackControlState::Archiving(request) = archiving_head.rollback_control() else {
        return Err(CoordinatorCommitDeleteRestorePlanError::NotExactArchivingScope);
    };
    let old_epoch = archiving_head
        .canonical_ref()
        .chain_epoch()
        .get()
        .checked_sub(1)
        .ok_or(CoordinatorCommitDeleteRestorePlanError::EpochUnderflow)?;
    if request.execution_mode() != RollbackExecutionMode::InPlace
        || request.fence_window() != fence_window
        || archiving_head.canonical_ref().checkpoint() != request.requested_head()
        || target.network_id() != archiving_head.canonical_ref().network_id()
        || target.chain_epoch().get() != old_epoch
        || target.checkpoint() != request.target()
        || old_head.network_id() != target.network_id()
        || old_head.chain_epoch() != target.chain_epoch()
        || old_head.checkpoint() != request.requested_head()
    {
        return Err(CoordinatorCommitDeleteRestorePlanError::NotExactArchivingScope);
    }
    Ok(())
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CoordinatorCommitDeleteRestorePlanError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| CoordinatorCommitDeleteRestorePlanError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn plan_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct PlanCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PlanCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CoordinatorCommitDeleteRestorePlanError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CoordinatorCommitDeleteRestorePlanError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CoordinatorCommitDeleteRestorePlanError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorCommitDeleteRestorePlanError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitDeleteRestorePlanError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorCommitDeleteRestorePlanError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed u32")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorCommitDeleteRestorePlanError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorCommitDeleteRestorePlanError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("fixed i64")))
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorCommitDeleteRestorePlanError> {
        Ok(self.take(32)?.try_into().expect("fixed array"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorCommitDeleteRestorePlanError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitDeleteRestorePlanError {
    CanonicalHead(String),
    CanonicalRef(String),
    Timestamp(TimestampOrderingError),
    NotExactArchivingScope,
    EpochUnderflow,
    ZeroCommitment,
    InvalidEntry,
    ActionMismatch,
    InvalidEntryCount,
    NonCanonicalEntryOrder,
    RestoreSetMismatch { actual: u64 },
    SourceWritetimeExceedsFence { writetime_us: i64, orphan_write_max: i64 },
    InvalidMagic,
    UnknownVersion(u16),
    UnknownAction(u8),
    InvalidPresence(u8),
    InvalidLocator(&'static str),
    BindingTooLarge,
    PlanTooLarge,
    LengthOverflow,
    Truncated,
    TrailingBytes,
    DigestMismatch,
    NonCanonicalEncoding,
}

impl From<psy_node_core::store::timestamp::TimestampOutOfCqlRange>
    for CoordinatorCommitDeleteRestorePlanError
{
    fn from(error: psy_node_core::store::timestamp::TimestampOutOfCqlRange) -> Self {
        Self::Timestamp(TimestampOrderingError::OutOfCqlRange(error))
    }
}

impl From<TimestampOrderingError> for CoordinatorCommitDeleteRestorePlanError {
    fn from(error: TimestampOrderingError) -> Self {
        Self::Timestamp(error)
    }
}

impl fmt::Display for CoordinatorCommitDeleteRestorePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator delete/restore plan: {self:?}")
    }
}

impl Error for CoordinatorCommitDeleteRestorePlanError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::{
        rollback_control::{RollbackPlanDigest, RollbackRequest},
        timestamp::CommitWriteTimestampUs,
        typed::{CheckpointId as TypedCheckpointId, LatestInfoSlot, TypedTableKey, U64SingletonSlot},
    };

    use super::*;
    use crate::rollback::describe_existing_key;

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(seed, seed + 1, seed + 2, seed + 3)),
        )
    }

    fn fixture() -> (
        StoredCanonicalHead<PHash>,
        CanonicalChainRef<PHash>,
        CanonicalChainRef<PHash>,
        TimestampFenceWindow,
        Vec<CoordinatorCommitDeleteRestoreEntry>,
    ) {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let requested = checkpoint(10, 10);
        let target_checkpoint = checkpoint(7, 20);
        let fence = TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            1_001,
            1_002,
        )
        .unwrap();
        let request = RollbackRequest::try_new(
            requested,
            target_checkpoint,
            fence,
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap();
        let archiving_head = StoredCanonicalHead::decode_persisted(
            network,
            9,
            &CanonicalChainRef::new(network, ChainEpoch::new(7), requested).to_canonical_bytes(),
            &RollbackControlState::Archiving(request).to_canonical_bytes(),
        )
        .unwrap();
        let target = CanonicalChainRef::new(network, ChainEpoch::new(6), target_checkpoint);
        let old_head = CanonicalChainRef::new(network, ChainEpoch::new(6), requested);
        let mut entries = vec![
            CoordinatorCommitDeleteRestoreEntry::try_new(
                CoordinatorCommitDeleteRestoreAction::DeleteHotRow,
                describe_existing_key(&TypedTableKey::L2BlockState(
                    TypedCheckpointId::try_new(9).unwrap(),
                )),
                [0x11; 32],
                [0x21; 32],
                Some(999),
            )
            .unwrap(),
            CoordinatorCommitDeleteRestoreEntry::try_new(
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton,
                describe_existing_key(&TypedTableKey::LatestInfo(
                    LatestInfoSlot::LatestL2BlockState,
                )),
                [0x12; 32],
                [0x22; 32],
                Some(998),
            )
            .unwrap(),
            CoordinatorCommitDeleteRestoreEntry::try_new(
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton,
                describe_existing_key(&TypedTableKey::U64Singleton(
                    U64SingletonSlot::LatestCheckpoint,
                )),
                [0x13; 32],
                [0x23; 32],
                Some(997),
            )
            .unwrap(),
        ];
        entries.sort_by(|left, right| left.key.locator_bytes().cmp(right.key.locator_bytes()));
        (archiving_head, target, old_head, fence, entries)
    }

    #[test]
    fn plan_roundtrips_and_binds_fence_archive_and_two_restore_singletons() {
        let (head, target, old_head, fence, entries) = fixture();
        let plan = CoordinatorCommitDeleteRestorePlan::try_from_selected(
            head,
            target,
            old_head,
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            [0x34; 32],
            fence,
            entries,
        )
        .unwrap();
        assert_eq!(plan.delete_count(), 1);
        assert_eq!(plan.restore_count(), 2);
        assert_eq!(plan.key_only_count(), 0);
        assert_eq!(plan.max_value_source_writetime_us(), Some(999));
        assert_eq!(plan.fence_window(), fence);
        assert_ne!(plan.digest(), &[0; 32]);
        assert_eq!(
            CoordinatorCommitDeleteRestorePlan::decode_canonical(plan.canonical_bytes()).unwrap(),
            plan,
        );

        let mut corrupt = plan.canonical_bytes().to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            CoordinatorCommitDeleteRestorePlan::<PHash>::decode_canonical(&corrupt),
            Err(CoordinatorCommitDeleteRestorePlanError::DigestMismatch),
        );
    }

    #[test]
    fn plan_rejects_source_timestamp_above_declared_orphan_max_and_bad_restore_set() {
        let (head, target, old_head, fence, mut entries) = fixture();
        entries[0].source_writetime_us = Some(1_001);
        assert_eq!(
            CoordinatorCommitDeleteRestorePlan::try_from_selected(
                head,
                target,
                old_head,
                [0x31; 32],
                [0x32; 32],
                [0x33; 32],
                [0x34; 32],
                fence,
                entries,
            ),
            Err(CoordinatorCommitDeleteRestorePlanError::SourceWritetimeExceedsFence {
                writetime_us: 1_001,
                orphan_write_max: 1_000,
            }),
        );

        let (head, target, old_head, fence, mut entries) = fixture();
        entries.pop();
        assert_eq!(
            CoordinatorCommitDeleteRestorePlan::try_from_selected(
                head,
                target,
                old_head,
                [0x31; 32],
                [0x32; 32],
                [0x33; 32],
                [0x34; 32],
                fence,
                entries,
            ),
            Err(CoordinatorCommitDeleteRestorePlanError::RestoreSetMismatch { actual: 1 }),
        );

        let (_, _, _, _, entries) = fixture();
        let entry = entries
            .iter()
            .find(|entry| entry.action == CoordinatorCommitDeleteRestoreAction::DeleteHotRow)
            .unwrap();
        assert_eq!(
            CoordinatorCommitDeleteRestoreEntry::try_new(
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton,
                entry.key.clone(),
                entry.before_image_slot,
                entry.before_image_digest,
                entry.source_writetime_us,
            ),
            Err(CoordinatorCommitDeleteRestorePlanError::ActionMismatch),
        );
    }

    #[test]
    fn plan_has_no_barrier_delete_restore_or_head_mutation_api() {
        let source = include_str!("coordinator_commit_delete_restore_plan.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains(
            "Clone, Debug, Eq, PartialEq)]\npub(crate) struct CoordinatorCommitDeleteRestorePlan",
        ));
        for forbidden in [
            "restore_target_singletons(",
            "publish_target_head(",
            "advance_archive_barrier(",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
