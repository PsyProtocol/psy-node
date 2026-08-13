//! Exact physical hot-row catalog for one committed Realm rollback suffix.
//!
//! The catalog consumes only storage-selected COMMITTED inventories. It folds
//! repeated mutable locators to the final hot value, derives the target value
//! for singletons/cursors, and keeps suffix-owned rows as delete candidates.
//! It is inert: no archive, barrier, delete, restore, or head API is exposed.

use std::{collections::BTreeMap, error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    branch_exact_dual_write::BranchExactDualWriteMutationKind,
    typed::{
        ImtCursorTransition, ImtKeyIndexRow, MutationOperation, MutationValue,
        StructuredValueSchema,
    },
};
use sha2::{Digest, Sha256};

use super::{
    ResolvedScyllaKey, ScyllaPhysicalTableId, SealedTimestampedPut,
    VersionAxis, describe_existing_key, physical_descriptor,
    realm_rollback_commit_inventory_store::{
        VerifiedRealmRollbackCommittedSuffix,
        VerifiedRealmRollbackCommittedSuffixEntry,
    },
};

const CATALOG_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-physical-catalog.v1\0";
const NARROW_LOCATOR_MAGIC: &[u8; 8] = b"PSYRRNK1";
const MAX_CATALOG_ROWS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum RealmRollbackPhysicalAction {
    ArchiveThenDelete = 1,
    ArchiveThenRestoreTarget = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackPhysicalKey {
    Narrow {
        kind: BranchExactDualWriteMutationKind,
        primary_key: Vec<u8>,
        locator: Vec<u8>,
    },
    Typed(ResolvedScyllaKey),
}

impl RealmRollbackPhysicalKey {
    pub(super) fn locator_bytes(&self) -> &[u8] {
        match self {
            Self::Narrow { locator, .. } => locator,
            Self::Typed(key) => key.locator_bytes(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackTargetRestore {
    ExactPut(SealedTimestampedPut),
    ImtCursorBefore(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackPhysicalCatalogEntry {
    source_index: usize,
    action: RealmRollbackPhysicalAction,
    key: RealmRollbackPhysicalKey,
    current_put: Option<SealedTimestampedPut>,
    target_restore: Option<RealmRollbackTargetRestore>,
}

impl RealmRollbackPhysicalCatalogEntry {
    pub(super) const fn source_index(&self) -> usize { self.source_index }
    pub(super) const fn action(&self) -> RealmRollbackPhysicalAction { self.action }
    pub(super) const fn key(&self) -> &RealmRollbackPhysicalKey { &self.key }
    pub(super) const fn current_put(&self) -> Option<&SealedTimestampedPut> {
        self.current_put.as_ref()
    }
    pub(super) const fn target_restore(&self) -> Option<&RealmRollbackTargetRestore> {
        self.target_restore.as_ref()
    }
}

/// Non-Clone exact Realm suffix catalog. The embedded suffix keeps all source
/// inventories and committed markers available for later fresh revalidation.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackPhysicalCatalog<Hash> {
    suffix: VerifiedRealmRollbackCommittedSuffix<Hash>,
    target_inventory_digest: Option<[u8; 32]>,
    entries: Vec<RealmRollbackPhysicalCatalogEntry>,
    delete_count: u64,
    restore_count: u64,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmRollbackPhysicalCatalog<Hash> {
    pub(super) fn try_from_selected(
        suffix: VerifiedRealmRollbackCommittedSuffix<Hash>,
        target: Option<&VerifiedRealmRollbackCommittedSuffixEntry<Hash>>,
    ) -> Result<Self, RealmRollbackPhysicalCatalogError> {
        if suffix.entries().is_empty() {
            return Err(RealmRollbackPhysicalCatalogError::EmptySuffix);
        }
        let target_inventory_digest = match target {
            Some(target) => {
                if target.inventory().authority() != suffix.authority()
                    || target.inventory().candidate().canonical_chain() != suffix.target()
                {
                    return Err(RealmRollbackPhysicalCatalogError::TargetMismatch);
                }
                Some(*target.inventory().digest())
            }
            None => None,
        };
        let target_puts = target
            .map(|target| canonical_target_puts(target.inventory().typed_puts()))
            .transpose()?
            .unwrap_or_default();

        let mut entries = Vec::new();
        let mut typed = BTreeMap::<Vec<u8>, TypedAccumulator>::new();
        for (source_index, source) in suffix.entries().iter().enumerate() {
            push_narrow_entries(source_index, source, &mut entries)?;
            for put in source.inventory().typed_puts() {
                let key = describe_existing_key(put.resolved().mutation().key());
                if key.locator_bytes() != put.resolved().locator_bytes() {
                    return Err(RealmRollbackPhysicalCatalogError::LocatorMismatch);
                }
                let locator = key.locator_bytes().to_vec();
                match typed.get_mut(&locator) {
                    Some(current) => current.observe(source_index, key, put.clone())?,
                    None => {
                        typed.insert(
                            locator,
                            TypedAccumulator::new(source_index, key, put.clone())?,
                        );
                    }
                }
            }
        }
        for (locator, accumulated) in typed {
            entries.push(accumulated.finish(
                suffix.target().checkpoint().checkpoint_id().get(),
                target_puts.get(&locator),
            )?);
        }
        if entries.is_empty() || entries.len() > MAX_CATALOG_ROWS {
            return Err(RealmRollbackPhysicalCatalogError::InvalidRowCount(entries.len()));
        }
        entries.sort_by(|left, right| left.key.locator_bytes().cmp(right.key.locator_bytes()));
        if entries
            .windows(2)
            .any(|pair| pair[0].key.locator_bytes() >= pair[1].key.locator_bytes())
        {
            return Err(RealmRollbackPhysicalCatalogError::DuplicatePhysicalKey);
        }
        let delete_count = entries
            .iter()
            .filter(|entry| entry.action == RealmRollbackPhysicalAction::ArchiveThenDelete)
            .count() as u64;
        let restore_count = entries.len() as u64 - delete_count;
        let mut catalog = Self {
            suffix,
            target_inventory_digest,
            entries,
            delete_count,
            restore_count,
            digest: [0; 32],
        };
        catalog.digest = catalog_digest(&catalog);
        Ok(catalog)
    }

    pub(super) const fn suffix(&self) -> &VerifiedRealmRollbackCommittedSuffix<Hash> {
        &self.suffix
    }
    pub(super) fn entries(&self) -> &[RealmRollbackPhysicalCatalogEntry] { &self.entries }
    pub(super) const fn delete_count(&self) -> u64 { self.delete_count }
    pub(super) const fn restore_count(&self) -> u64 { self.restore_count }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

fn canonical_target_puts(
    puts: &[SealedTimestampedPut],
) -> Result<BTreeMap<Vec<u8>, SealedTimestampedPut>, RealmRollbackPhysicalCatalogError> {
    let mut selected = BTreeMap::new();
    for put in puts {
        let key = describe_existing_key(put.resolved().mutation().key());
        if key.locator_bytes() != put.resolved().locator_bytes()
            || selected
                .insert(key.locator_bytes().to_vec(), put.clone())
                .is_some()
        {
            return Err(RealmRollbackPhysicalCatalogError::DuplicateTargetKey);
        }
    }
    Ok(selected)
}

fn push_narrow_entries<Hash: Q256BitHash>(
    source_index: usize,
    source: &VerifiedRealmRollbackCommittedSuffixEntry<Hash>,
    entries: &mut Vec<RealmRollbackPhysicalCatalogEntry>,
) -> Result<(), RealmRollbackPhysicalCatalogError> {
    let intent = source.inventory().narrow_intent();
    let observed = intent
        .mutations()
        .iter()
        .map(|mutation| mutation.kind())
        .collect::<Vec<_>>();
    if observed != BranchExactDualWriteMutationKind::REALM {
        return Err(RealmRollbackPhysicalCatalogError::NarrowMutationSetMismatch);
    }
    let checkpoint = intent
        .candidate()
        .canonical_chain()
        .checkpoint()
        .checkpoint_id()
        .get();
    let pending = intent.candidate().pending_id().get();
    let proc_checkpoint_id = intent.proc_checkpoint_id();
    let proc_id = proc_checkpoint_id.as_bytes();
    let canonical = intent.candidate().canonical_chain_bytes();
    for kind in BranchExactDualWriteMutationKind::REALM {
        let primary_key = match kind {
            BranchExactDualWriteMutationKind::LegacyCheckpointToPending => {
                checkpoint.to_be_bytes().to_vec()
            }
            BranchExactDualWriteMutationKind::LegacyPendingToCheckpoint
            | BranchExactDualWriteMutationKind::LegacyPendingToProc
            | BranchExactDualWriteMutationKind::TargetPendingToBranch
            | BranchExactDualWriteMutationKind::TargetPendingRewardProof => {
                pending.to_be_bytes().to_vec()
            }
            BranchExactDualWriteMutationKind::LegacyProcToPending => proc_id.to_vec(),
            BranchExactDualWriteMutationKind::TargetBranchToPending => canonical.to_vec(),
            BranchExactDualWriteMutationKind::LegacyPendingRewardProof => {
                [2_i64.to_be_bytes().as_slice(), pending.to_be_bytes().as_slice()].concat()
            }
        };
        let mut locator = Vec::with_capacity(9 + primary_key.len());
        locator.extend_from_slice(NARROW_LOCATOR_MAGIC);
        locator.push(kind as u8);
        locator.extend_from_slice(&primary_key);
        entries.push(RealmRollbackPhysicalCatalogEntry {
            source_index,
            action: RealmRollbackPhysicalAction::ArchiveThenDelete,
            key: RealmRollbackPhysicalKey::Narrow {
                kind,
                primary_key,
                locator,
            },
            current_put: None,
            target_restore: None,
        });
    }
    Ok(())
}

struct TypedAccumulator {
    first_source_index: usize,
    last_source_index: usize,
    key: ResolvedScyllaKey,
    first_put: SealedTimestampedPut,
    last_put: SealedTimestampedPut,
}

impl TypedAccumulator {
    fn new(
        source_index: usize,
        key: ResolvedScyllaKey,
        put: SealedTimestampedPut,
    ) -> Result<Self, RealmRollbackPhysicalCatalogError> {
        validate_supported_put(&put)?;
        Ok(Self {
            first_source_index: source_index,
            last_source_index: source_index,
            key,
            first_put: put.clone(),
            last_put: put,
        })
    }

    fn observe(
        &mut self,
        source_index: usize,
        key: ResolvedScyllaKey,
        put: SealedTimestampedPut,
    ) -> Result<(), RealmRollbackPhysicalCatalogError> {
        validate_supported_put(&put)?;
        if source_index <= self.last_source_index || key != self.key {
            return Err(RealmRollbackPhysicalCatalogError::NonCanonicalSourceOrder);
        }
        if self.key.physical_table() == ScyllaPhysicalTableId::ImtKeyIndex
            && self.last_put.resolved().mutation().operation()
                != put.resolved().mutation().operation()
        {
            return Err(RealmRollbackPhysicalCatalogError::MutableImtBirthRow);
        }
        self.last_source_index = source_index;
        self.last_put = put;
        Ok(())
    }

    fn finish(
        self,
        target_checkpoint: u64,
        target_put: Option<&SealedTimestampedPut>,
    ) -> Result<RealmRollbackPhysicalCatalogEntry, RealmRollbackPhysicalCatalogError> {
        let axis = physical_descriptor(self.key.physical_table()).version_axis;
        let target_restore = match axis {
            VersionAxis::Singleton => Some(RealmRollbackTargetRestore::ExactPut(
                target_put
                    .cloned()
                    .ok_or(RealmRollbackPhysicalCatalogError::MissingTargetSingleton)?,
            )),
            VersionAxis::MutableCursor => {
                if let Some(target_put) = target_put {
                    let target_after = cursor_transition(target_put)?.after();
                    let first_before = cursor_transition(&self.first_put)?.before();
                    if target_after != first_before {
                        return Err(RealmRollbackPhysicalCatalogError::CursorTargetMismatch);
                    }
                }
                Some(RealmRollbackTargetRestore::ImtCursorBefore(
                    cursor_transition(&self.first_put)?.before(),
                ))
            }
            VersionAxis::ImtBirthOrdinaryColumn => {
                let birth = imt_birth(&self.last_put)?;
                if birth <= target_checkpoint {
                    Some(RealmRollbackTargetRestore::ExactPut(self.last_put.clone()))
                } else {
                    None
                }
            }
            _ => target_put.cloned().map(RealmRollbackTargetRestore::ExactPut),
        };
        let action = if target_restore.is_some() {
            RealmRollbackPhysicalAction::ArchiveThenRestoreTarget
        } else {
            RealmRollbackPhysicalAction::ArchiveThenDelete
        };
        Ok(RealmRollbackPhysicalCatalogEntry {
            source_index: self.last_source_index,
            action,
            key: RealmRollbackPhysicalKey::Typed(self.key),
            current_put: Some(self.last_put),
            target_restore,
        })
    }
}

fn validate_supported_put(
    put: &SealedTimestampedPut,
) -> Result<(), RealmRollbackPhysicalCatalogError> {
    if !matches!(put.resolved().mutation().operation(), MutationOperation::Put(_)) {
        return Err(RealmRollbackPhysicalCatalogError::DeleteInCommitInventory);
    }
    Ok(())
}

fn cursor_transition(
    put: &SealedTimestampedPut,
) -> Result<ImtCursorTransition, RealmRollbackPhysicalCatalogError> {
    match put.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::Structured {
            schema: StructuredValueSchema::ImtCursorTransitionV1,
            canonical_bytes,
        }) if put.resolved().mutation().physical_table()
            == ScyllaPhysicalTableId::ImtNextAppendIndex =>
        {
            ImtCursorTransition::decode_canonical(canonical_bytes)
                .map_err(|_| RealmRollbackPhysicalCatalogError::InvalidCursorTransition)
        }
        _ => Err(RealmRollbackPhysicalCatalogError::InvalidCursorTransition),
    }
}

fn imt_birth(put: &SealedTimestampedPut) -> Result<u64, RealmRollbackPhysicalCatalogError> {
    match put.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::Structured {
            schema: StructuredValueSchema::ImtKeyIndexRowV2,
            canonical_bytes,
        }) if put.resolved().mutation().physical_table() == ScyllaPhysicalTableId::ImtKeyIndex => {
            Ok(ImtKeyIndexRow::decode_canonical(canonical_bytes)
                .map_err(|_| RealmRollbackPhysicalCatalogError::InvalidImtBirthRow)?
                .birth_checkpoint()
                .get())
        }
        _ => Err(RealmRollbackPhysicalCatalogError::InvalidImtBirthRow),
    }
}

fn catalog_digest<Hash: Q256BitHash>(catalog: &RealmRollbackPhysicalCatalog<Hash>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_DIGEST_DOMAIN);
    hasher.update(catalog.suffix.digest());
    hasher.update(catalog.target_inventory_digest.unwrap_or([0; 32]));
    hasher.update((catalog.entries.len() as u64).to_be_bytes());
    for entry in &catalog.entries {
        hasher.update((entry.source_index as u64).to_be_bytes());
        hasher.update([entry.action as u8]);
        hasher.update((entry.key.locator_bytes().len() as u64).to_be_bytes());
        hasher.update(entry.key.locator_bytes());
        match &entry.target_restore {
            None => hasher.update([0]),
            Some(RealmRollbackTargetRestore::ExactPut(put)) => {
                hasher.update([1]);
                hasher.update((put.canonical_bytes().len() as u64).to_be_bytes());
                hasher.update(put.canonical_bytes());
            }
            Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => {
                hasher.update([2]);
                hasher.update(value.to_be_bytes());
            }
        }
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackPhysicalCatalogError {
    EmptySuffix,
    TargetMismatch,
    LocatorMismatch,
    NarrowMutationSetMismatch,
    DuplicateTargetKey,
    InvalidRowCount(usize),
    DuplicatePhysicalKey,
    NonCanonicalSourceOrder,
    MutableImtBirthRow,
    MissingTargetSingleton,
    CursorTargetMismatch,
    DeleteInCommitInventory,
    InvalidCursorTransition,
    InvalidImtBirthRow,
}

impl fmt::Display for RealmRollbackPhysicalCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmRollbackPhysicalCatalogError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_no_execution_or_caller_selected_row_api() {
        let source = include_str!("realm_rollback_physical_catalog.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "execute_delete",
            "execute_restore",
            "cross_archive_barrier",
            "publish_head",
            "caller_rows",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
