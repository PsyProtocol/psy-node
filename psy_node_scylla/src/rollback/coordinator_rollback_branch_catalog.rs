//! Exact, read-only Coordinator branch catalog for an in-place rollback.
//!
//! `start_rollback` opens a new chain epoch before archive copying begins. The
//! rows in `(target, requested_head]`, however, belong to the immediately
//! preceding epoch. This module reconstructs that discarded branch from the
//! canonical checkpoint transition/proof rows and requires the legacy and
//! branch-exact pending mappings to agree in both directions. It is strictly
//! pre-PONR: the returned summary is metrics/evidence only and cannot archive
//! a row, cross the global barrier, delete hot state, or publish a head.

#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    marker::PhantomData,
    sync::Arc,
};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::{
        Q256BitHash, QFHashBase, QZKProofPublicInputsHasherReader,
    },
};
use psy_data::protocol::{
    canonical_chain::{
        checkpoint_hash_from_saved_proof_bytes, genesis_checkpoint_hash,
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef,
    },
    verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
};
use psy_node_core::store::{
    branch_pending_mapping::BranchPendingMapping,
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use crate::compression;

use super::{
    BranchExactCheckpointChainConfig, BRANCH_TO_PENDING_TABLE,
    CqlKeyspaceName, CoordinatorRollbackArchivePlan, PENDING_TO_BRANCH_TABLE,
    ScyllaCanonicalHeadStore,
};
use super::coordinator_rollback_archive_store::{
    CoordinatorRollbackArchivedMappingBundle,
    ScyllaCoordinatorRollbackArchiveStore,
};

const CHECKPOINT_TRANSITION_TABLE: &str =
    "checkpoint_zk_proof_and_transition_table";
const LEGACY_FORWARD_TABLE: &str = "checkpoint_id_to_pending_id_table";
const LEGACY_REVERSE_TABLE: &str = "pending_id_to_checkpoint_id_table";
const MAX_SUFFIX_ROWS: u64 = 1_048_576;
const CATALOG_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-branch-catalog/v1";
const SOURCE_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-branch-catalog-source/v1";
const CATALOG_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-branch-catalog-store/v1";
const MAPPING_ARCHIVE_DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-mapping-archive-dataset/v1";

const READ_TRANSITION_TEMPLATE: &str =
    "SELECT value, WRITETIME(value) FROM {table} WHERE obj_id = ?";
const READ_LEGACY_TEMPLATE: &str =
    "SELECT value, WRITETIME(value) FROM {table} WHERE obj_id = ?";
const READ_TARGET_FORWARD_TEMPLATE: &str =
    "SELECT pending_id, mapping_digest, WRITETIME(mapping_digest) FROM {table} WHERE canonical_ref = ? LIMIT 2";
const READ_TARGET_REVERSE_TEMPLATE: &str =
    "SELECT canonical_ref, mapping_digest, WRITETIME(mapping_digest) FROM {table} WHERE pending_id = ? LIMIT 2";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorRollbackBranchCatalogQueries {
    transition: String,
    legacy_forward: String,
    legacy_reverse: String,
    target_forward: String,
    target_reverse: String,
}

impl CoordinatorRollbackBranchCatalogQueries {
    fn new(
        canonical: &CqlKeyspaceName,
        authority: &CqlKeyspaceName,
        branch_exact: &CqlKeyspaceName,
    ) -> Self {
        Self {
            transition: READ_TRANSITION_TEMPLATE.replace(
                "{table}",
                &format!(
                    "{}.{}",
                    canonical.as_str(),
                    CHECKPOINT_TRANSITION_TABLE
                ),
            ),
            legacy_forward: READ_LEGACY_TEMPLATE.replace(
                "{table}",
                &format!("{}.{}", authority.as_str(), LEGACY_FORWARD_TABLE),
            ),
            legacy_reverse: READ_LEGACY_TEMPLATE.replace(
                "{table}",
                &format!("{}.{}", authority.as_str(), LEGACY_REVERSE_TABLE),
            ),
            target_forward: READ_TARGET_FORWARD_TEMPLATE.replace(
                "{table}",
                &format!("{}.{}", branch_exact.as_str(), BRANCH_TO_PENDING_TABLE),
            ),
            target_reverse: READ_TARGET_REVERSE_TEMPLATE.replace(
                "{table}",
                &format!("{}.{}", branch_exact.as_str(), PENDING_TO_BRANCH_TABLE),
            ),
        }
    }

    fn golden(&self) -> String {
        format!(
            "transition\n{}\nlegacy_forward\n{}\nlegacy_reverse\n{}\ntarget_forward\n{}\ntarget_reverse\n{}\n",
            self.transition,
            self.legacy_forward,
            self.legacy_reverse,
            self.target_forward,
            self.target_reverse,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PointValue {
    value: Vec<u8>,
    writetime_us: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyMappingPair {
    pending_id: UniquePendingId,
    forward_writetime_us: i64,
    reverse_writetime_us: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetForwardRow {
    pending_id: UniquePendingId,
    mapping_digest: [u8; 32],
    pending_writetime_us: i64,
    digest_writetime_us: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetReverseRow {
    canonical_ref: Vec<u8>,
    mapping_digest: [u8; 32],
    canonical_writetime_us: i64,
    digest_writetime_us: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorRollbackMappingSourceKind {
    LegacyCheckpointToPending = 1,
    LegacyPendingToCheckpoint = 2,
    BranchExactCanonicalToPending = 3,
    BranchExactPendingToCanonical = 4,
}

impl CoordinatorRollbackMappingSourceKind {
    pub(super) const fn stable_id(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedCoordinatorRollbackMappingColumn {
    column_id: u8,
    value: Vec<u8>,
    writetime_us: i64,
}

impl VerifiedCoordinatorRollbackMappingColumn {
    pub(super) const fn column_id(&self) -> u8 {
        self.column_id
    }

    pub(super) fn value(&self) -> &[u8] {
        &self.value
    }

    pub(super) const fn writetime_us(&self) -> i64 {
        self.writetime_us
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedCoordinatorRollbackMappingSource {
    kind: CoordinatorRollbackMappingSourceKind,
    primary_key: Vec<u8>,
    columns: Vec<VerifiedCoordinatorRollbackMappingColumn>,
}

impl VerifiedCoordinatorRollbackMappingSource {
    pub(super) const fn kind(&self) -> CoordinatorRollbackMappingSourceKind {
        self.kind
    }

    pub(super) fn primary_key(&self) -> &[u8] {
        &self.primary_key
    }

    pub(super) fn columns(&self) -> &[VerifiedCoordinatorRollbackMappingColumn] {
        &self.columns
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedCoordinatorRollbackMappingBundle {
    catalog_fingerprint: [u8; 32],
    network: psy_data::protocol::canonical_chain::NetworkId,
    rollback_epoch: u64,
    source_epoch: u64,
    checkpoint: u64,
    pending: UniquePendingId,
    sources: [VerifiedCoordinatorRollbackMappingSource; 4],
}

impl VerifiedCoordinatorRollbackMappingBundle {
    pub(super) const fn catalog_fingerprint(&self) -> [u8; 32] {
        self.catalog_fingerprint
    }

    pub(super) const fn network(
        &self,
    ) -> psy_data::protocol::canonical_chain::NetworkId {
        self.network
    }

    pub(super) const fn rollback_epoch(&self) -> u64 {
        self.rollback_epoch
    }

    pub(super) const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    pub(super) const fn checkpoint(&self) -> u64 {
        self.checkpoint
    }

    pub(super) const fn pending(&self) -> UniquePendingId {
        self.pending
    }

    pub(super) fn sources(&self) -> &[VerifiedCoordinatorRollbackMappingSource; 4] {
        &self.sources
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct CoordinatorRollbackBranchCatalogDigest([u8; 32]);

impl CoordinatorRollbackBranchCatalogDigest {
    pub(super) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Inert read-only catalog evidence. It is not accepted by archive, barrier,
/// delete, timestamp, or head mutation APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorRollbackBranchCatalogSummary {
    catalog_fingerprint: [u8; 32],
    source_chain_epoch: u64,
    suffix_rows: u64,
    catalog_digest: CoordinatorRollbackBranchCatalogDigest,
    source_digest: [u8; 32],
}

impl CoordinatorRollbackBranchCatalogSummary {
    pub(super) const fn catalog_fingerprint(self) -> [u8; 32] {
        self.catalog_fingerprint
    }

    pub(super) const fn source_chain_epoch(self) -> u64 {
        self.source_chain_epoch
    }

    pub(super) const fn suffix_rows(self) -> u64 {
        self.suffix_rows
    }

    pub(super) const fn catalog_digest(
        self,
    ) -> CoordinatorRollbackBranchCatalogDigest {
        self.catalog_digest
    }

    pub(super) const fn source_digest(self) -> [u8; 32] {
        self.source_digest
    }
}

/// Inert progress evidence for mapping rows copied by the catalog-owned path.
/// It is not a participant archive receipt and cannot cross the global barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorRollbackMappingArchiveSummary {
    catalog: CoordinatorRollbackBranchCatalogSummary,
    archive_rows: u64,
    archive_bytes: u64,
    archive_digest: [u8; 32],
}

/// Storage-selected pending coordinates for the discarded checkpoint suffix.
///
/// This is deliberately not a participant receipt.  It exists so pending-keyed
/// legacy tables can be scanned without treating checkpoint height as pending
/// identity or trusting a caller-provided pending list.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedCoordinatorRollbackSuffixSelection {
    summary: CoordinatorRollbackBranchCatalogSummary,
    pending_to_checkpoint: BTreeMap<UniquePendingId, u64>,
}

impl VerifiedCoordinatorRollbackSuffixSelection {
    pub(super) const fn summary(&self) -> CoordinatorRollbackBranchCatalogSummary {
        self.summary
    }

    pub(super) fn checkpoint_for_pending(
        &self,
        pending: UniquePendingId,
    ) -> Option<u64> {
        self.pending_to_checkpoint.get(&pending).copied()
    }

    pub(super) fn pending_rows(&self) -> usize {
        self.pending_to_checkpoint.len()
    }
}

impl CoordinatorRollbackMappingArchiveSummary {
    pub(super) const fn catalog(self) -> CoordinatorRollbackBranchCatalogSummary {
        self.catalog
    }

    pub(super) const fn archive_rows(self) -> u64 {
        self.archive_rows
    }

    pub(super) const fn archive_bytes(self) -> u64 {
        self.archive_bytes
    }

    pub(super) const fn archive_digest(self) -> [u8; 32] {
        self.archive_digest
    }
}

/// Affine streaming verifier for the target anchor and discarded suffix.
/// Any failed row poisons the accumulator so a caller cannot skip it.
struct CoordinatorRollbackBranchCatalogAccumulator<
    F,
    Hash,
    Hasher,
    Proof,
    Verifier,
> {
    config: BranchExactCheckpointChainConfig<Hash>,
    catalog_fingerprint: [u8; 32],
    network: psy_data::protocol::canonical_chain::NetworkId,
    rollback_epoch: u64,
    source_epoch: u64,
    target: CheckpointRef<Hash>,
    requested_head: CheckpointRef<Hash>,
    orphan_write_max_us: i64,
    next_checkpoint: u64,
    previous_hash: Option<Hash>,
    previous_root_leaf: Option<(Hash, Hash)>,
    pending_to_checkpoint: BTreeMap<UniquePendingId, u64>,
    suffix_rows: u64,
    catalog_hasher: Sha256,
    source_hasher: Sha256,
    poisoned: bool,
    marker: PhantomData<(F, Hasher, Proof, Verifier)>,
}

impl<F, Hash, Hasher, Proof, Verifier>
    CoordinatorRollbackBranchCatalogAccumulator<F, Hash, Hasher, Proof, Verifier>
where
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
    PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
        PsyCanonicalDatabaseSerializeBaseSingle,
{
    fn try_new(
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
        catalog_fingerprint: [u8; 32],
    ) -> Result<Self, CoordinatorRollbackBranchCatalogError> {
        validate_archiving_head(expected_head, plan)?;
        let rollback_epoch = expected_head.canonical_ref().chain_epoch().get();
        let source_epoch = rollback_epoch
            .checked_sub(1)
            .ok_or(CoordinatorRollbackBranchCatalogError::MissingSourceEpoch)?;
        let target = *plan.request().target();
        let requested_head = *plan.request().requested_head();
        let suffix_rows = requested_head
            .checkpoint_id()
            .get()
            .checked_sub(target.checkpoint_id().get())
            .ok_or(CoordinatorRollbackBranchCatalogError::InvalidCheckpointRange)?;
        if suffix_rows == 0 || suffix_rows > MAX_SUFFIX_ROWS {
            return Err(CoordinatorRollbackBranchCatalogError::SuffixRowLimit {
                actual: suffix_rows,
                max: MAX_SUFFIX_ROWS,
            });
        }
        let next_checkpoint = target.checkpoint_id().get();
        let mut catalog_hasher = Sha256::new();
        catalog_hasher.update(CATALOG_DIGEST_DOMAIN);
        catalog_hasher.update(catalog_fingerprint);
        catalog_hasher.update(plan.digest().as_bytes());
        catalog_hasher.update(
            expected_head
                .canonical_ref()
                .network_id()
                .chain_id()
                .to_be_bytes(),
        );
        catalog_hasher.update(source_epoch.to_be_bytes());
        catalog_hasher.update(target.checkpoint_id().get().to_be_bytes());
        catalog_hasher.update(
            target.checkpoint_hash().as_inner().into_owned_32bytes(),
        );
        catalog_hasher.update(requested_head.checkpoint_id().get().to_be_bytes());
        catalog_hasher.update(
            requested_head
                .checkpoint_hash()
                .as_inner()
                .into_owned_32bytes(),
        );
        let mut source_hasher = Sha256::new();
        source_hasher.update(SOURCE_DIGEST_DOMAIN);
        source_hasher.update(catalog_fingerprint);
        source_hasher.update(plan.digest().as_bytes());
        source_hasher.update(
            expected_head
                .canonical_ref()
                .network_id()
                .chain_id()
                .to_be_bytes(),
        );
        source_hasher.update(rollback_epoch.to_be_bytes());
        source_hasher.update(source_epoch.to_be_bytes());
        Ok(Self {
            config,
            catalog_fingerprint,
            network: expected_head.canonical_ref().network_id(),
            rollback_epoch,
            source_epoch,
            target,
            requested_head,
            orphan_write_max_us: plan
                .request()
                .fence_window()
                .delete_fence()
                .orphan_write_max()
                .as_i64(),
            next_checkpoint,
            previous_hash: None,
            previous_root_leaf: None,
            pending_to_checkpoint: BTreeMap::new(),
            suffix_rows: 0,
            catalog_hasher,
            source_hasher,
            poisoned: false,
            marker: PhantomData,
        })
    }

    fn observe_anchor(
        &mut self,
        checkpoint_id: u64,
        transition: PointValue,
    ) -> Result<(), CoordinatorRollbackBranchCatalogError> {
        self.observe_guarded(|this| {
            if checkpoint_id != this.target.checkpoint_id().get()
                || checkpoint_id != this.next_checkpoint
            {
                return Err(CoordinatorRollbackBranchCatalogError::CheckpointGap {
                    expected: this.next_checkpoint,
                    actual: checkpoint_id,
                });
            }
            this.require_before_fence(transition.writetime_us)?;
            let canonical = this.verify_transition(checkpoint_id, &transition.value, true)?;
            if canonical.checkpoint() != &this.target {
                return Err(CoordinatorRollbackBranchCatalogError::TargetAnchorMismatch);
            }
            this.source_hasher.update(checkpoint_id.to_be_bytes());
            this.source_hasher.update(transition.writetime_us.to_be_bytes());
            this.source_hasher.update((transition.value.len() as u64).to_be_bytes());
            this.source_hasher.update(&transition.value);
            this.next_checkpoint = this
                .next_checkpoint
                .checked_add(1)
                .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
            Ok(())
        })
    }

    fn observe_suffix(
        &mut self,
        checkpoint_id: u64,
        transition: PointValue,
        legacy: LegacyMappingPair,
        target_forward: Vec<TargetForwardRow>,
        target_reverse: Vec<TargetReverseRow>,
    ) -> Result<VerifiedCoordinatorRollbackMappingBundle, CoordinatorRollbackBranchCatalogError> {
        self.observe_guarded(|this| {
            if checkpoint_id != this.next_checkpoint
                || checkpoint_id > this.requested_head.checkpoint_id().get()
            {
                return Err(CoordinatorRollbackBranchCatalogError::CheckpointGap {
                    expected: this.next_checkpoint,
                    actual: checkpoint_id,
                });
            }
            for writetime in [
                transition.writetime_us,
                legacy.forward_writetime_us,
                legacy.reverse_writetime_us,
            ] {
                this.require_before_fence(writetime)?;
            }
            let canonical = this.verify_transition(checkpoint_id, &transition.value, false)?;
            if this
                .pending_to_checkpoint
                .insert(legacy.pending_id, checkpoint_id)
                .is_some()
            {
                return Err(CoordinatorRollbackBranchCatalogError::PendingMappedTwice(
                    legacy.pending_id.get(),
                ));
            }
            let mapping = BranchPendingMapping::new(canonical, legacy.pending_id);
            hash_target_source(
                &mut this.source_hasher,
                &target_forward,
                &target_reverse,
            );
            verify_target_mapping(
                &mapping,
                &target_forward,
                &target_reverse,
                this.orphan_write_max_us(),
            )?;
            let forward = &target_forward[0];
            let reverse = &target_reverse[0];
            let canonical_bytes = mapping.canonical_chain_bytes();
            let mapping_digest = mapping.digest().as_bytes();
            let bundle = VerifiedCoordinatorRollbackMappingBundle {
                catalog_fingerprint: this.catalog_fingerprint,
                network: this.network,
                rollback_epoch: this.rollback_epoch,
                source_epoch: this.source_epoch,
                checkpoint: checkpoint_id,
                pending: legacy.pending_id,
                sources: [
                    VerifiedCoordinatorRollbackMappingSource {
                        kind: CoordinatorRollbackMappingSourceKind::LegacyCheckpointToPending,
                        primary_key: checkpoint_id.to_be_bytes().to_vec(),
                        columns: vec![VerifiedCoordinatorRollbackMappingColumn {
                            column_id: 1,
                            value: legacy.pending_id.get().to_be_bytes().to_vec(),
                            writetime_us: legacy.forward_writetime_us,
                        }],
                    },
                    VerifiedCoordinatorRollbackMappingSource {
                        kind: CoordinatorRollbackMappingSourceKind::LegacyPendingToCheckpoint,
                        primary_key: legacy.pending_id.get().to_be_bytes().to_vec(),
                        columns: vec![VerifiedCoordinatorRollbackMappingColumn {
                            column_id: 1,
                            value: checkpoint_id.to_be_bytes().to_vec(),
                            writetime_us: legacy.reverse_writetime_us,
                        }],
                    },
                    VerifiedCoordinatorRollbackMappingSource {
                        kind: CoordinatorRollbackMappingSourceKind::BranchExactCanonicalToPending,
                        primary_key: canonical_bytes.to_vec(),
                        columns: vec![
                            VerifiedCoordinatorRollbackMappingColumn {
                                column_id: 1,
                                value: legacy.pending_id.get().to_be_bytes().to_vec(),
                                writetime_us: forward.pending_writetime_us,
                            },
                            VerifiedCoordinatorRollbackMappingColumn {
                                column_id: 2,
                                value: mapping_digest.to_vec(),
                                writetime_us: forward.digest_writetime_us,
                            },
                        ],
                    },
                    VerifiedCoordinatorRollbackMappingSource {
                        kind: CoordinatorRollbackMappingSourceKind::BranchExactPendingToCanonical,
                        primary_key: legacy.pending_id.get().to_be_bytes().to_vec(),
                        columns: vec![
                            VerifiedCoordinatorRollbackMappingColumn {
                                column_id: 1,
                                value: reverse.canonical_ref.clone(),
                                writetime_us: reverse.canonical_writetime_us,
                            },
                            VerifiedCoordinatorRollbackMappingColumn {
                                column_id: 2,
                                value: mapping_digest.to_vec(),
                                writetime_us: reverse.digest_writetime_us,
                            },
                        ],
                    },
                ],
            };
            this.catalog_hasher.update(checkpoint_id.to_be_bytes());
            this.catalog_hasher.update(mapping.canonical_chain_bytes());
            this.catalog_hasher
                .update(mapping.pending_id().get().to_be_bytes());
            this.catalog_hasher.update(mapping.digest().as_bytes());
            this.source_hasher.update(checkpoint_id.to_be_bytes());
            this.source_hasher.update(transition.writetime_us.to_be_bytes());
            this.source_hasher.update((transition.value.len() as u64).to_be_bytes());
            this.source_hasher.update(&transition.value);
            this.source_hasher
                .update(mapping.pending_id().get().to_be_bytes());
            this.source_hasher
                .update(legacy.forward_writetime_us.to_be_bytes());
            this.source_hasher
                .update(legacy.reverse_writetime_us.to_be_bytes());
            this.suffix_rows = this
                .suffix_rows
                .checked_add(1)
                .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
            this.next_checkpoint = this
                .next_checkpoint
                .checked_add(1)
                .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
            Ok(bundle)
        })
    }

    fn finish(
        self,
    ) -> Result<CoordinatorRollbackBranchCatalogSummary, CoordinatorRollbackBranchCatalogError> {
        self.finish_selection().map(|selection| selection.summary)
    }

    fn finish_selection(
        self,
    ) -> Result<VerifiedCoordinatorRollbackSuffixSelection, CoordinatorRollbackBranchCatalogError> {
        if self.poisoned {
            return Err(CoordinatorRollbackBranchCatalogError::Poisoned);
        }
        let expected_next = self
            .requested_head
            .checkpoint_id()
            .get()
            .checked_add(1)
            .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        if self.next_checkpoint != expected_next {
            return Err(CoordinatorRollbackBranchCatalogError::IncompleteCatalog {
                expected: expected_next,
                actual: self.next_checkpoint,
            });
        }
        if self.suffix_rows != self.pending_to_checkpoint.len() as u64 {
            return Err(CoordinatorRollbackBranchCatalogError::IncompleteCatalog {
                expected: self.suffix_rows,
                actual: self.pending_to_checkpoint.len() as u64,
            });
        }
        let last_hash = self
            .previous_hash
            .ok_or(CoordinatorRollbackBranchCatalogError::IncompleteCatalog {
                expected: expected_next,
                actual: 0,
            })?;
        if CheckpointHash::from_last_chain_hash(last_hash)
            != *self.requested_head.checkpoint_hash()
        {
            return Err(CoordinatorRollbackBranchCatalogError::RecoveredHeadMismatch);
        }
        let mut catalog_hasher = self.catalog_hasher;
        catalog_hasher.update(self.suffix_rows.to_be_bytes());
        let mut source_hasher = self.source_hasher;
        source_hasher.update(self.suffix_rows.to_be_bytes());
        Ok(VerifiedCoordinatorRollbackSuffixSelection {
            summary: CoordinatorRollbackBranchCatalogSummary {
                catalog_fingerprint: self.catalog_fingerprint,
                source_chain_epoch: self.source_epoch,
                suffix_rows: self.suffix_rows,
                catalog_digest: CoordinatorRollbackBranchCatalogDigest(
                    catalog_hasher.finalize().into(),
                ),
                source_digest: source_hasher.finalize().into(),
            },
            pending_to_checkpoint: self.pending_to_checkpoint,
        })
    }

    fn observe_guarded<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, CoordinatorRollbackBranchCatalogError>,
    ) -> Result<T, CoordinatorRollbackBranchCatalogError> {
        if self.poisoned {
            return Err(CoordinatorRollbackBranchCatalogError::Poisoned);
        }
        let result = operation(self);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn orphan_write_max_us(&self) -> i64 {
        self.orphan_write_max_us
    }

    fn require_before_fence(
        &self,
        writetime_us: i64,
    ) -> Result<(), CoordinatorRollbackBranchCatalogError> {
        if writetime_us <= self.orphan_write_max_us {
            Ok(())
        } else {
            Err(CoordinatorRollbackBranchCatalogError::WriteAfterFence {
                writetime_us,
                orphan_write_max_us: self.orphan_write_max_us,
            })
        }
    }

    fn verify_transition(
        &mut self,
        checkpoint_id: u64,
        canonical_transition: &[u8],
        anchor: bool,
    ) -> Result<CanonicalChainRef<Hash>, CoordinatorRollbackBranchCatalogError> {
        let (canonical, checkpoint_hash, root_leaf) =
            self.decode_transition(checkpoint_id, canonical_transition, anchor)?;
        self.previous_hash = Some(checkpoint_hash);
        self.previous_root_leaf = Some(root_leaf);
        Ok(canonical)
    }

    fn decode_transition(
        &self,
        checkpoint_id: u64,
        canonical_transition: &[u8],
        anchor: bool,
    ) -> Result<(CanonicalChainRef<Hash>, Hash, (Hash, Hash)), CoordinatorRollbackBranchCatalogError> {
        let transition = PsyVerifiableCheckpointTransitionWithProof::<F, Hash>::
            psy_ser_from_owned_bytes_vec(canonical_transition.to_vec())
            .map_err(|error| CoordinatorRollbackBranchCatalogError::MalformedTransition {
                checkpoint_id,
                reason: error.to_string(),
            })?;
        let rebuilt = transition.psy_ser_to_bytes_vec().map_err(|error| {
            CoordinatorRollbackBranchCatalogError::MalformedTransition {
                checkpoint_id,
                reason: error.to_string(),
            }
        })?;
        if rebuilt.as_slice() != canonical_transition {
            return Err(CoordinatorRollbackBranchCatalogError::NonCanonicalTransition(
                checkpoint_id,
            ));
        }
        if &transition
            .info
            .state_transition
            .genesis_checkpoint_state_transition_hash
            != self.config.genesis_checkpoint_state_transition_hash()
        {
            return Err(CoordinatorRollbackBranchCatalogError::GenesisHashMismatch(
                checkpoint_id,
            ));
        }
        if &transition
            .info
            .state_transition
            .checkpoint_state_transition_circuit_fingerprint
            != self.config.checkpoint_state_transition_circuit_fingerprint()
        {
            return Err(CoordinatorRollbackBranchCatalogError::CircuitFingerprintMismatch(
                checkpoint_id,
            ));
        }
        let state = &transition.info.state_transition.checkpoint_transition;
        if transition.info.checkpoint_leaf.qfhash::<Hasher>()
            != state.new_checkpoint_leaf_hash
        {
            return Err(CoordinatorRollbackBranchCatalogError::LeafHashMismatch(
                checkpoint_id,
            ));
        }
        if !anchor
            && self.previous_root_leaf
                != Some((
                    state.old_checkpoint_tree_root,
                    state.old_checkpoint_leaf_hash,
                ))
        {
            return Err(CoordinatorRollbackBranchCatalogError::PredecessorMismatch(
                checkpoint_id,
            ));
        }
        let checkpoint_hash = if checkpoint_id == 0 {
            if !transition.zk_proof.is_empty()
                || state.old_checkpoint_tree_root != state.new_checkpoint_tree_root
                || state.old_checkpoint_leaf_hash != state.new_checkpoint_leaf_hash
            {
                return Err(CoordinatorRollbackBranchCatalogError::InvalidGenesis);
            }
            genesis_checkpoint_hash::<_, Hasher>(
                state.new_checkpoint_tree_root,
                state.new_checkpoint_leaf_hash,
                *self.config.genesis_checkpoint_state_transition_fingerprint(),
            )
        } else {
            if transition.zk_proof.is_empty() {
                return Err(CoordinatorRollbackBranchCatalogError::MissingProof(
                    checkpoint_id,
                ));
            }
            let extracted = checkpoint_hash_from_saved_proof_bytes::<Hash, Proof, Verifier>(
                &transition.zk_proof,
            )
            .map_err(|error| CoordinatorRollbackBranchCatalogError::MalformedProof {
                checkpoint_id,
                reason: error.to_string(),
            })?;
            if !anchor {
                let expected = CheckpointHash::from_last_chain_hash(
                    transition
                        .info
                        .state_transition
                        .get_chain_hash_from_previous::<Hasher>(
                            self.previous_hash.as_ref().ok_or(
                                CoordinatorRollbackBranchCatalogError::AnchorMissing,
                            )?,
                        ),
                );
                if extracted != expected {
                    return Err(CoordinatorRollbackBranchCatalogError::ChainMismatch(
                        checkpoint_id,
                    ));
                }
            }
            extracted
        };
        let checkpoint_hash_inner = *checkpoint_hash.as_inner();
        Ok((
            CanonicalChainRef::new(
                self.network,
                ChainEpoch::new(self.source_epoch),
                CheckpointRef::new(CheckpointId::new(checkpoint_id), checkpoint_hash),
            ),
            checkpoint_hash_inner,
            (
                state.new_checkpoint_tree_root,
                state.new_checkpoint_leaf_hash,
            ),
        ))
    }
}

fn hash_target_source(
    hasher: &mut Sha256,
    forward: &[TargetForwardRow],
    reverse: &[TargetReverseRow],
) {
    hasher.update((forward.len() as u64).to_be_bytes());
    for row in forward {
        hasher.update(row.pending_id.get().to_be_bytes());
        hasher.update(row.mapping_digest);
        hasher.update(row.pending_writetime_us.to_be_bytes());
        hasher.update(row.digest_writetime_us.to_be_bytes());
    }
    hasher.update((reverse.len() as u64).to_be_bytes());
    for row in reverse {
        hasher.update((row.canonical_ref.len() as u64).to_be_bytes());
        hasher.update(&row.canonical_ref);
        hasher.update(row.mapping_digest);
        hasher.update(row.canonical_writetime_us.to_be_bytes());
        hasher.update(row.digest_writetime_us.to_be_bytes());
    }
}

fn verify_target_mapping<Hash: Q256BitHash>(
    expected: &BranchPendingMapping<Hash>,
    forward: &[TargetForwardRow],
    reverse: &[TargetReverseRow],
    orphan_write_max_us: i64,
) -> Result<(), CoordinatorRollbackBranchCatalogError> {
    let expected_digest = expected.digest().as_bytes();
    let forward = match forward {
        [row] => row,
        [] => return Err(CoordinatorRollbackBranchCatalogError::MissingTargetForward),
        _ => return Err(CoordinatorRollbackBranchCatalogError::TargetForwardConflict),
    };
    if forward.pending_id != expected.pending_id()
        || forward.mapping_digest != expected_digest
    {
        return Err(CoordinatorRollbackBranchCatalogError::TargetForwardConflict);
    }
    for writetime_us in [
        forward.pending_writetime_us,
        forward.digest_writetime_us,
    ] {
        if writetime_us > orphan_write_max_us {
            return Err(CoordinatorRollbackBranchCatalogError::WriteAfterFence {
                writetime_us,
                orphan_write_max_us,
            });
        }
    }
    let reverse = match reverse {
        [row] => row,
        [] => return Err(CoordinatorRollbackBranchCatalogError::MissingTargetReverse),
        _ => return Err(CoordinatorRollbackBranchCatalogError::TargetReverseConflict),
    };
    if reverse.canonical_ref.as_slice() != expected.canonical_chain_bytes()
        || reverse.mapping_digest != expected_digest
    {
        return Err(CoordinatorRollbackBranchCatalogError::TargetReverseConflict);
    }
    for writetime_us in [
        reverse.canonical_writetime_us,
        reverse.digest_writetime_us,
    ] {
        if writetime_us > orphan_write_max_us {
            return Err(CoordinatorRollbackBranchCatalogError::WriteAfterFence {
                writetime_us,
                orphan_write_max_us,
            });
        }
    }
    Ok(())
}

struct PreparedCatalogReads {
    transition: PreparedStatement,
    legacy_forward: PreparedStatement,
    legacy_reverse: PreparedStatement,
    target_forward: PreparedStatement,
    target_reverse: PreparedStatement,
}

struct MappingArchiveAccumulator {
    rows: u64,
    bytes: u64,
    hasher: Sha256,
}

impl MappingArchiveAccumulator {
    fn new<Hash: Q256BitHash>(plan: &CoordinatorRollbackArchivePlan<Hash>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MAPPING_ARCHIVE_DATASET_DIGEST_DOMAIN);
        hasher.update(plan.digest().as_bytes());
        Self { rows: 0, bytes: 0, hasher }
    }

    fn observe(
        &mut self,
        persisted: CoordinatorRollbackArchivedMappingBundle,
    ) -> Result<(), CoordinatorRollbackBranchCatalogError> {
        self.rows = self
            .rows
            .checked_add(persisted.rows())
            .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        self.bytes = self
            .bytes
            .checked_add(persisted.canonical_bytes())
            .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        self.hasher.update(persisted.digest());
        Ok(())
    }

    fn finish(mut self) -> MappingArchiveFinished {
        self.hasher.update(self.rows.to_be_bytes());
        self.hasher.update(self.bytes.to_be_bytes());
        MappingArchiveFinished {
            rows: self.rows,
            bytes: self.bytes,
            digest: self.hasher.finalize().into(),
        }
    }
}

struct MappingArchiveFinished {
    rows: u64,
    bytes: u64,
    digest: [u8; 32],
}

pub(super) struct ScyllaCoordinatorRollbackBranchCatalog {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    prepared: PreparedCatalogReads,
}

impl ScyllaCoordinatorRollbackBranchCatalog {
    pub(super) async fn prepare(
        session: Arc<Session>,
        canonical_keyspace: CqlKeyspaceName,
        authority_keyspace: CqlKeyspaceName,
        branch_exact_keyspace: CqlKeyspaceName,
    ) -> Result<Self, CoordinatorRollbackBranchCatalogError> {
        let queries = CoordinatorRollbackBranchCatalogQueries::new(
            &canonical_keyspace,
            &authority_keyspace,
            &branch_exact_keyspace,
        );
        let fingerprint = catalog_fingerprint(
            &canonical_keyspace,
            &authority_keyspace,
            &branch_exact_keyspace,
            &queries,
        );
        Ok(Self {
            prepared: PreparedCatalogReads {
                transition: prepare_read(&session, queries.transition).await?,
                legacy_forward: prepare_read(&session, queries.legacy_forward).await?,
                legacy_reverse: prepare_read(&session, queries.legacy_reverse).await?,
                target_forward: prepare_read(&session, queries.target_forward).await?,
                target_reverse: prepare_read(&session, queries.target_reverse).await?,
            },
            session,
            fingerprint,
        })
    }

    pub(super) async fn verify_suffix<F, Hash, Hasher, Proof, Verifier>(
        &self,
        canonical_head_store: &ScyllaCanonicalHeadStore,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
    ) -> Result<CoordinatorRollbackBranchCatalogSummary, CoordinatorRollbackBranchCatalogError>
    where
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        self.require_current_head(canonical_head_store, expected_head).await?;
        let (first, _) = self
            .scan_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
                None,
            )
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;
        let (second, _) = self
            .scan_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
                None,
            )
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;
        if first != second {
            return Err(CoordinatorRollbackBranchCatalogError::SourceChanged);
        }
        Ok(second.summary)
    }

    /// Verify, copy and re-verify all four mapping rows for every discarded
    /// checkpoint. Any archive written before a later failure is immutable,
    /// unselected evidence; no participant receipt or destructive capability
    /// is produced here.
    pub(super) async fn archive_verified_suffix<F, Hash, Hasher, Proof, Verifier>(
        &self,
        archive_store: &ScyllaCoordinatorRollbackArchiveStore,
        canonical_head_store: &ScyllaCanonicalHeadStore,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
    ) -> Result<CoordinatorRollbackMappingArchiveSummary, CoordinatorRollbackBranchCatalogError>
    where
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        self.require_current_head(canonical_head_store, expected_head).await?;
        let (first, _) = self
            .scan_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
                None,
            )
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;
        let (second, archived) = self
            .scan_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
                Some(archive_store),
            )
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;
        let (third, _) = self
            .scan_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
                None,
            )
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;
        if first != second || second != third {
            return Err(CoordinatorRollbackBranchCatalogError::SourceChanged);
        }
        let archived = archived.ok_or(
            CoordinatorRollbackBranchCatalogError::ArchiveSummaryMissing,
        )?;
        let expected_rows = first
            .summary
            .suffix_rows()
            .checked_mul(4)
            .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        if archived.rows != expected_rows {
            return Err(CoordinatorRollbackBranchCatalogError::ArchiveRowCountMismatch {
                expected: expected_rows,
                actual: archived.rows,
            });
        }
        Ok(CoordinatorRollbackMappingArchiveSummary {
            catalog: first.summary,
            archive_rows: archived.rows,
            archive_bytes: archived.bytes,
            archive_digest: archived.digest,
        })
    }

    async fn scan_once<F, Hash, Hasher, Proof, Verifier>(
        &self,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
        archive_store: Option<&ScyllaCoordinatorRollbackArchiveStore>,
    ) -> Result<
        (VerifiedCoordinatorRollbackSuffixSelection, Option<MappingArchiveFinished>),
        CoordinatorRollbackBranchCatalogError,
    >
    where
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        let mut catalog = CoordinatorRollbackBranchCatalogAccumulator::<
            F, Hash, Hasher, Proof, Verifier,
        >::try_new(expected_head, plan, config, self.fingerprint)?;
        let mut archived = archive_store.map(|_| MappingArchiveAccumulator::new(plan));
        let target = plan.suffix_start_exclusive();
        let anchor = self
            .read_point(&self.prepared.transition, target)
            .await?
            .ok_or(CoordinatorRollbackBranchCatalogError::MissingTransition(target))?;
        catalog.observe_anchor(target, PointValue {
            value: compression::decompress(&anchor.value).map_err(|error| {
                CoordinatorRollbackBranchCatalogError::MalformedTransition {
                    checkpoint_id: target,
                    reason: error.to_string(),
                }
            })?,
            writetime_us: anchor.writetime_us,
        })?;
        let mut checkpoint = target
            .checked_add(1)
            .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        while checkpoint <= plan.suffix_end_inclusive() {
            let transition = self
                .read_point(&self.prepared.transition, checkpoint)
                .await?
                .ok_or(CoordinatorRollbackBranchCatalogError::MissingTransition(checkpoint))?;
            let forward = self
                .read_u64_point(&self.prepared.legacy_forward, checkpoint)
                .await?
                .ok_or(CoordinatorRollbackBranchCatalogError::MissingLegacyForward(checkpoint))?;
            let pending = UniquePendingId::try_new(forward.0).map_err(|_| {
                CoordinatorRollbackBranchCatalogError::InvalidPending(forward.0)
            })?;
            let reverse = self
                .read_u64_point(&self.prepared.legacy_reverse, pending.get())
                .await?
                .ok_or(CoordinatorRollbackBranchCatalogError::MissingLegacyReverse(
                    pending.get(),
                ))?;
            if reverse.0 != checkpoint {
                return Err(CoordinatorRollbackBranchCatalogError::LegacyPairMismatch {
                    checkpoint,
                    pending: pending.get(),
                    reverse_checkpoint: reverse.0,
                });
            }
            let expected_chain = catalog.preview_transition(
                checkpoint,
                &compression::decompress(&transition.value).map_err(|error| {
                    CoordinatorRollbackBranchCatalogError::MalformedTransition {
                        checkpoint_id: checkpoint,
                        reason: error.to_string(),
                    }
                })?,
            )?;
            let expected_mapping = BranchPendingMapping::new(expected_chain, pending);
            let target_forward = self
                .read_target_forward(expected_mapping.canonical_chain_bytes())
                .await?;
            let target_reverse = self.read_target_reverse(pending).await?;
            let verified = catalog.observe_suffix(
                checkpoint,
                PointValue {
                    value: compression::decompress(&transition.value).map_err(|error| {
                        CoordinatorRollbackBranchCatalogError::MalformedTransition {
                            checkpoint_id: checkpoint,
                            reason: error.to_string(),
                        }
                    })?,
                    writetime_us: transition.writetime_us,
                },
                LegacyMappingPair {
                    pending_id: pending,
                    forward_writetime_us: forward.1,
                    reverse_writetime_us: reverse.1,
                },
                target_forward,
                target_reverse,
            )?;
            if let Some(store) = archive_store {
                let persisted = store
                    .persist_verified_mapping_bundle(expected_head, plan, &verified)
                    .await
                    .map_err(|error| {
                        CoordinatorRollbackBranchCatalogError::Archive(error.to_string())
                    })?;
                archived
                    .as_mut()
                    .expect("archive accumulator exists with store")
                    .observe(persisted)?;
            }
            if checkpoint == plan.suffix_end_inclusive() {
                break;
            }
            checkpoint = checkpoint
                .checked_add(1)
                .ok_or(CoordinatorRollbackBranchCatalogError::CheckpointOverflow)?;
        }
        Ok((
            catalog.finish_selection()?,
            archived.map(MappingArchiveAccumulator::finish),
        ))
    }

    /// One complete storage-derived branch selection for a sibling scanner.
    /// The caller must bracket this with exact canonical-head reads and compare
    /// multiple selections before treating any copied rows as complete.
    pub(super) async fn select_verified_suffix_once<
        F,
        Hash,
        Hasher,
        Proof,
        Verifier,
    >(
        &self,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
    ) -> Result<VerifiedCoordinatorRollbackSuffixSelection, CoordinatorRollbackBranchCatalogError>
    where
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        self.scan_once::<F, Hash, Hasher, Proof, Verifier>(
            expected_head,
            plan,
            config,
            None,
        )
        .await
        .map(|(selection, _)| selection)
    }

    async fn require_current_head<Hash: Q256BitHash>(
        &self,
        store: &ScyllaCanonicalHeadStore,
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<(), CoordinatorRollbackBranchCatalogError> {
        match store
            .read(expected.canonical_ref().network_id())
            .await
            .map_err(|error| CoordinatorRollbackBranchCatalogError::Head(error.to_string()))?
        {
            CanonicalHeadReadState::Current(current) if current == expected => Ok(()),
            _ => Err(CoordinatorRollbackBranchCatalogError::HeadChanged),
        }
    }

    async fn read_point(
        &self,
        statement: &PreparedStatement,
        key: u64,
    ) -> Result<Option<PointValue>, CoordinatorRollbackBranchCatalogError> {
        let row = self
            .session
            .execute_unpaged(
                statement,
                (i64::try_from(key)
                    .map_err(|_| CoordinatorRollbackBranchCatalogError::IntegerOutOfRange)?,),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
            .map_err(driver)?;
        row.map(|(value, writetime_us)| {
            Ok(PointValue {
                value: value.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
                writetime_us: writetime_us
                    .ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
            })
        })
        .transpose()
    }

    async fn read_u64_point(
        &self,
        statement: &PreparedStatement,
        key: u64,
    ) -> Result<Option<(u64, i64)>, CoordinatorRollbackBranchCatalogError> {
        let row = self
            .session
            .execute_unpaged(
                statement,
                (i64::try_from(key)
                    .map_err(|_| CoordinatorRollbackBranchCatalogError::IntegerOutOfRange)?,),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(Option<i64>, Option<i64>)>()
            .map_err(driver)?;
        row.map(|(value, writetime)| {
            let value = value.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?;
            Ok((
                u64::try_from(value)
                    .map_err(|_| CoordinatorRollbackBranchCatalogError::IntegerOutOfRange)?,
                writetime.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
            ))
        })
        .transpose()
    }

    async fn read_target_forward(
        &self,
        canonical: [u8; 65],
    ) -> Result<Vec<TargetForwardRow>, CoordinatorRollbackBranchCatalogError> {
        let rows_result = self
            .session
            .execute_unpaged(&self.prepared.target_forward, (canonical.as_slice(),))
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?;
        let rows = rows_result
            .rows::<(Option<i64>, Option<Vec<u8>>, Option<i64>)>()
            .map_err(driver)?;
        rows.map(|row| {
            let (pending, digest, row_writetime) = row.map_err(driver)?;
            let pending = pending.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?;
            let pending = u64::try_from(pending)
                .map_err(|_| CoordinatorRollbackBranchCatalogError::IntegerOutOfRange)?;
            let row_writetime = row_writetime
                .ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?;
            Ok(TargetForwardRow {
                pending_id: UniquePendingId::try_new(pending)
                    .map_err(|_| CoordinatorRollbackBranchCatalogError::InvalidPending(pending))?,
                mapping_digest: array_32(
                    digest.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
                )?,
                // Primary-key cells have no independent CQL writetime.  The
                // mapping digest is the row's sole non-key value and is
                // written in the same mutation as the complete key.
                pending_writetime_us: row_writetime,
                digest_writetime_us: row_writetime,
            })
        })
        .collect()
    }

    async fn read_target_reverse(
        &self,
        pending: UniquePendingId,
    ) -> Result<Vec<TargetReverseRow>, CoordinatorRollbackBranchCatalogError> {
        let rows_result = self
            .session
            .execute_unpaged(
                &self.prepared.target_reverse,
                (i64::try_from(pending.get())
                    .map_err(|_| CoordinatorRollbackBranchCatalogError::IntegerOutOfRange)?,),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?;
        let rows = rows_result
            .rows::<(Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>)>()
            .map_err(driver)?;
        rows.map(|row| {
            let (canonical_ref, digest, row_writetime) = row.map_err(driver)?;
            let row_writetime = row_writetime
                .ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?;
            Ok(TargetReverseRow {
                canonical_ref: canonical_ref
                    .ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
                mapping_digest: array_32(
                    digest.ok_or(CoordinatorRollbackBranchCatalogError::MissingColumn)?,
                )?,
                canonical_writetime_us: row_writetime,
                digest_writetime_us: row_writetime,
            })
        })
        .collect()
    }
}

impl<F, Hash, Hasher, Proof, Verifier>
    CoordinatorRollbackBranchCatalogAccumulator<F, Hash, Hasher, Proof, Verifier>
where
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
    PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
        PsyCanonicalDatabaseSerializeBaseSingle,
{
    fn preview_transition(
        &self,
        checkpoint_id: u64,
        canonical_transition: &[u8],
    ) -> Result<CanonicalChainRef<Hash>, CoordinatorRollbackBranchCatalogError> {
        self.decode_transition(checkpoint_id, canonical_transition, false)
            .map(|(canonical, _, _)| canonical)
    }
}

fn validate_archiving_head<Hash: Q256BitHash>(
    head: StoredCanonicalHead<Hash>,
    plan: &CoordinatorRollbackArchivePlan<Hash>,
) -> Result<(), CoordinatorRollbackBranchCatalogError> {
    match head.rollback_control() {
        RollbackControlState::Archiving(request)
            if request == plan.request()
                && head.canonical_ref().checkpoint() == request.requested_head() => Ok(()),
        _ => Err(CoordinatorRollbackBranchCatalogError::NotExactArchivingHead),
    }
}

async fn prepare_read(
    session: &Session,
    query: String,
) -> Result<PreparedStatement, CoordinatorRollbackBranchCatalogError> {
    let mut statement = session.prepare(query).await.map_err(driver)?;
    statement.set_consistency(Consistency::Quorum);
    Ok(statement)
}

fn catalog_fingerprint(
    canonical: &CqlKeyspaceName,
    authority: &CqlKeyspaceName,
    branch_exact: &CqlKeyspaceName,
    queries: &CoordinatorRollbackBranchCatalogQueries,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_FINGERPRINT_DOMAIN);
    for keyspace in [canonical, authority, branch_exact] {
        hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
        hasher.update(keyspace.as_str().as_bytes());
    }
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    hasher.finalize().into()
}

fn array_32(bytes: Vec<u8>) -> Result<[u8; 32], CoordinatorRollbackBranchCatalogError> {
    bytes
        .try_into()
        .map_err(|_| CoordinatorRollbackBranchCatalogError::InvalidDigestLength)
}

fn driver(error: impl ToString) -> CoordinatorRollbackBranchCatalogError {
    CoordinatorRollbackBranchCatalogError::Driver(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorRollbackBranchCatalogError {
    NotExactArchivingHead,
    MissingSourceEpoch,
    InvalidCheckpointRange,
    SuffixRowLimit { actual: u64, max: u64 },
    CheckpointOverflow,
    CheckpointGap { expected: u64, actual: u64 },
    IncompleteCatalog { expected: u64, actual: u64 },
    AnchorMissing,
    MissingTransition(u64),
    MalformedTransition { checkpoint_id: u64, reason: String },
    NonCanonicalTransition(u64),
    GenesisHashMismatch(u64),
    CircuitFingerprintMismatch(u64),
    LeafHashMismatch(u64),
    PredecessorMismatch(u64),
    InvalidGenesis,
    MissingProof(u64),
    MalformedProof { checkpoint_id: u64, reason: String },
    ChainMismatch(u64),
    TargetAnchorMismatch,
    RecoveredHeadMismatch,
    MissingLegacyForward(u64),
    MissingLegacyReverse(u64),
    LegacyPairMismatch { checkpoint: u64, pending: u64, reverse_checkpoint: u64 },
    InvalidPending(u64),
    PendingMappedTwice(u64),
    MissingTargetForward,
    MissingTargetReverse,
    TargetForwardConflict,
    TargetReverseConflict,
    WriteAfterFence { writetime_us: i64, orphan_write_max_us: i64 },
    MissingColumn,
    InvalidDigestLength,
    IntegerOutOfRange,
    Head(String),
    HeadChanged,
    SourceChanged,
    Archive(String),
    ArchiveSummaryMissing,
    ArchiveRowCountMismatch { expected: u64, actual: u64 },
    Driver(String),
    Poisoned,
}

impl fmt::Display for CoordinatorRollbackBranchCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator rollback branch-catalog failure: {self:?}")
    }
}

impl Error for CoordinatorRollbackBranchCatalogError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::traits::{QFieldHashable, ZeroableHash},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader},
        PHash, PF,
    };
    use psy_data::{
        protocol::{
            canonical_chain::{
                checkpoint_hash_from_previous, NetworkId,
            },
            checkpoint_transition_hash::{
                CheckpointStateHashTransition,
                CheckpointStateTransitionPublicInputs,
            },
            verifiable_checkpoint_transition::PsyVerifiableCheckpointTransition,
        },
        v1::qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats},
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };
    use psy_node_core::store::{
        canonical_head::StoredCanonicalHead,
        rollback_control::{
            RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;
    use super::super::coordinator_rollback_archive_store::{
        CoordinatorRollbackMappingArchiveRow,
        CoordinatorRollbackMappingArchiveRowError, mapping_row_digest,
        qualification_reconstruct_mapping_archive_row,
    };

    #[derive(Clone, Copy, Debug)]
    struct HashProofVerifier;

    impl QZKProofPublicInputsHasherReader<PHash, PHash> for HashProofVerifier {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }

        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            Ok(PHash::from_owned_32bytes(bytes.try_into()?))
        }
    }

    fn hash(seed: u64) -> PHash {
        PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn transitions(
        head: u64,
    ) -> (
        Vec<Vec<u8>>,
        BranchExactCheckpointChainConfig<PHash>,
        Vec<CheckpointRef<PHash>>,
    ) {
        let genesis_fingerprint = hash(100);
        let genesis_transition_hash = hash(200);
        let checkpoint_fingerprint = hash(300);
        let config = BranchExactCheckpointChainConfig::new(
            genesis_fingerprint,
            genesis_transition_hash,
            checkpoint_fingerprint,
        );
        let leaf = PsyCheckpointLeafPopulated {
            global_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: PHash::get_zero_value(),
                deposit_tree_root: PHash::get_zero_value(),
                user_tree_root: PHash::get_zero_value(),
                withdrawal_tree_root: PHash::get_zero_value(),
                user_registration_tree_root: PHash::get_zero_value(),
            },
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        };
        let leaf_hash = leaf.qfhash::<PoseidonHasher>();
        let mut previous_root = hash(400);
        let mut previous_leaf = leaf_hash;
        let mut previous_chain = None;
        let mut rows = Vec::new();
        let mut refs = Vec::new();
        for checkpoint_id in 0..=head {
            let new_root = hash(500 + checkpoint_id * 10);
            let state = CheckpointStateHashTransition {
                old_checkpoint_tree_root: if checkpoint_id == 0 { new_root } else { previous_root },
                new_checkpoint_tree_root: new_root,
                old_checkpoint_leaf_hash: if checkpoint_id == 0 { leaf_hash } else { previous_leaf },
                new_checkpoint_leaf_hash: leaf_hash,
            };
            let chain_hash = if checkpoint_id == 0 {
                genesis_checkpoint_hash::<_, PoseidonHasher>(
                    new_root,
                    leaf_hash,
                    genesis_fingerprint,
                )
            } else {
                checkpoint_hash_from_previous::<_, PoseidonHasher>(
                    CheckpointHash::from_last_chain_hash(previous_chain.unwrap()),
                    new_root,
                    leaf_hash,
                    checkpoint_fingerprint,
                )
            };
            let transition = PsyVerifiableCheckpointTransitionWithProof {
                info: PsyVerifiableCheckpointTransition {
                    state_transition: CheckpointStateTransitionPublicInputs {
                        checkpoint_transition: state,
                        genesis_checkpoint_state_transition_hash: genesis_transition_hash,
                        checkpoint_state_transition_circuit_fingerprint: checkpoint_fingerprint,
                    },
                    checkpoint_leaf: leaf,
                },
                circuit_type: 7,
                zk_proof: if checkpoint_id == 0 {
                    Vec::new()
                } else {
                    chain_hash.as_inner().into_owned_32bytes().to_vec()
                },
            };
            rows.push(transition.psy_ser_to_bytes_vec().unwrap());
            refs.push(CheckpointRef::new(CheckpointId::new(checkpoint_id), chain_hash));
            previous_root = new_root;
            previous_leaf = leaf_hash;
            previous_chain = Some(*chain_hash.as_inner());
        }
        (rows, config, refs)
    }

    fn plan_and_head(
        refs: &[CheckpointRef<PHash>],
        target: u64,
    ) -> (CoordinatorRollbackArchivePlan<PHash>, StoredCanonicalHead<PHash>) {
        let request = RollbackRequest::try_new(
            refs[refs.len() - 1],
            refs[target as usize],
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(10_000).unwrap(),
                10_001,
                10_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([9; 32]).unwrap(),
        )
        .unwrap();
        let plan = CoordinatorRollbackArchivePlan::resolve(request);
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let canonical = CanonicalChainRef::new(
            network,
            ChainEpoch::new(4),
            refs[refs.len() - 1],
        );
        let control = RollbackControlState::Archiving(request);
        let head = StoredCanonicalHead::decode_persisted(
            network,
            8,
            &canonical.to_canonical_bytes(),
            &control.to_canonical_bytes(),
        )
        .unwrap();
        (plan, head)
    }

    fn target_rows(
        mapping: &BranchPendingMapping<PHash>,
    ) -> (Vec<TargetForwardRow>, Vec<TargetReverseRow>) {
        let digest = mapping.digest().as_bytes();
        (
            vec![TargetForwardRow {
                pending_id: mapping.pending_id(),
                mapping_digest: digest,
                pending_writetime_us: 9_000,
                digest_writetime_us: 9_000,
            }],
            vec![TargetReverseRow {
                canonical_ref: mapping.canonical_chain_bytes().to_vec(),
                mapping_digest: digest,
                canonical_writetime_us: 9_000,
                digest_writetime_us: 9_000,
            }],
        )
    }

    #[test]
    fn suffix_catalog_uses_old_epoch_and_requires_all_four_mapping_directions() {
        let (rows, config, refs) = transitions(4);
        let (plan, head) = plan_and_head(&refs, 1);
        let mut catalog = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        catalog.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 9_000 }).unwrap();
        for checkpoint in 2..=4 {
            let pending = UniquePendingId::try_new(100 + checkpoint).unwrap();
            let mapping = BranchPendingMapping::new(
                CanonicalChainRef::new(
                    NetworkId::try_from_chain_id(1).unwrap(),
                    ChainEpoch::new(3),
                    refs[checkpoint as usize],
                ),
                pending,
            );
            let (forward, reverse) = target_rows(&mapping);
            let mut bundle = catalog.observe_suffix(
                checkpoint,
                PointValue { value: rows[checkpoint as usize].clone(), writetime_us: 9_000 },
                LegacyMappingPair { pending_id: pending, forward_writetime_us: 9_000, reverse_writetime_us: 9_000 },
                forward,
                reverse,
            ).unwrap();
            if checkpoint == 2 {
                assert_eq!(bundle.catalog_fingerprint(), [7; 32]);
                assert_eq!(bundle.rollback_epoch(), 4);
                assert_eq!(bundle.source_epoch(), 3);
                assert_eq!(bundle.checkpoint(), 2);
                assert_eq!(bundle.pending(), pending);
                assert_eq!(
                    bundle
                        .sources()
                        .iter()
                        .map(VerifiedCoordinatorRollbackMappingSource::kind)
                        .collect::<Vec<_>>(),
                    [
                        CoordinatorRollbackMappingSourceKind::LegacyCheckpointToPending,
                        CoordinatorRollbackMappingSourceKind::LegacyPendingToCheckpoint,
                        CoordinatorRollbackMappingSourceKind::BranchExactCanonicalToPending,
                        CoordinatorRollbackMappingSourceKind::BranchExactPendingToCanonical,
                    ]
                    .to_vec()
                );
                assert_eq!(
                    bundle
                        .sources()
                        .iter()
                        .map(|source| source.columns().len())
                        .collect::<Vec<_>>(),
                    vec![1, 1, 2, 2]
                );

                let original = CoordinatorRollbackMappingArchiveRow::try_from_verified(
                    head, &plan, &bundle, 0,
                )
                .unwrap();
                assert_eq!(
                    CoordinatorRollbackMappingArchiveRow::decode_canonical::<PHash>(
                        original.canonical_bytes(),
                    )
                    .unwrap(),
                    original
                );
                assert_eq!(
                    qualification_reconstruct_mapping_archive_row::<PHash>(&original)
                        .unwrap(),
                    original
                );

                bundle.sources[0].columns[0].writetime_us -= 1;
                let same_physical_source =
                    CoordinatorRollbackMappingArchiveRow::try_from_verified(
                        head, &plan, &bundle, 0,
                    )
                    .unwrap();
                assert_eq!(original.slot(), same_physical_source.slot());
                assert_ne!(original.digest(), same_physical_source.digest());

                bundle.sources[0].columns[0].writetime_us = 10_001;
                assert!(matches!(
                    CoordinatorRollbackMappingArchiveRow::try_from_verified(
                        head, &plan, &bundle, 0,
                    ),
                    Err(
                        CoordinatorRollbackMappingArchiveRowError::WriteAfterOrphanFence {
                            writetime_us: 10_001,
                            orphan_write_max_us: 10_000,
                        }
                    )
                ));

                let mut rehashed = original.canonical_bytes().to_vec();
                let slot_start = rehashed.len() - 64;
                rehashed[slot_start] ^= 0x80;
                let digest = mapping_row_digest(&rehashed[..rehashed.len() - 32]);
                let digest_start = rehashed.len() - 32;
                rehashed[digest_start..].copy_from_slice(digest.as_bytes());
                assert_eq!(
                    CoordinatorRollbackMappingArchiveRow::decode_canonical::<PHash>(&rehashed),
                    Err(CoordinatorRollbackMappingArchiveRowError::RowSlotMismatch)
                );
            }
        }
        let selection = catalog.finish_selection().unwrap();
        assert_eq!(selection.pending_rows(), 3);
        for checkpoint in 2..=4 {
            assert_eq!(
                selection.checkpoint_for_pending(
                    UniquePendingId::try_new(100 + checkpoint).unwrap(),
                ),
                Some(checkpoint),
            );
        }
        assert_eq!(
            selection.checkpoint_for_pending(
                UniquePendingId::try_new(999).unwrap(),
            ),
            None,
        );
        let summary = selection.summary();
        assert_eq!(summary.source_chain_epoch(), 3);
        assert_eq!(summary.suffix_rows(), 3);
        assert_ne!(summary.catalog_digest().as_bytes(), [0; 32]);
        assert_ne!(summary.source_digest(), [0; 32]);
    }

    #[test]
    fn missing_target_pair_and_pending_reuse_poison_the_stream() {
        let (rows, config, refs) = transitions(3);
        let (plan, head) = plan_and_head(&refs, 1);
        let mut catalog = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        catalog.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 9_000 }).unwrap();
        let pending = UniquePendingId::try_new(102).unwrap();
        assert_eq!(
            catalog.observe_suffix(
                2,
                PointValue { value: rows[2].clone(), writetime_us: 9_000 },
                LegacyMappingPair { pending_id: pending, forward_writetime_us: 9_000, reverse_writetime_us: 9_000 },
                Vec::new(),
                Vec::new(),
            ),
            Err(CoordinatorRollbackBranchCatalogError::MissingTargetForward)
        );
        assert_eq!(
            catalog.observe_anchor(2, PointValue { value: rows[2].clone(), writetime_us: 9_000 }),
            Err(CoordinatorRollbackBranchCatalogError::Poisoned)
        );

        let mut reused = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        reused.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 9_000 }).unwrap();
        for checkpoint in 2..=3 {
            let mapping = BranchPendingMapping::new(
                CanonicalChainRef::new(
                    NetworkId::try_from_chain_id(1).unwrap(),
                    ChainEpoch::new(3),
                    refs[checkpoint as usize],
                ),
                pending,
            );
            let (forward, reverse) = target_rows(&mapping);
            let result = reused.observe_suffix(
                checkpoint,
                PointValue { value: rows[checkpoint as usize].clone(), writetime_us: 9_000 },
                LegacyMappingPair { pending_id: pending, forward_writetime_us: 9_000, reverse_writetime_us: 9_000 },
                forward,
                reverse,
            );
            if checkpoint == 2 {
                result.unwrap();
            } else {
                assert_eq!(
                    result,
                    Err(CoordinatorRollbackBranchCatalogError::PendingMappedTwice(
                        pending.get(),
                    ))
                );
            }
        }
    }

    #[test]
    fn chain_gap_fence_and_rehashed_target_mapping_fail_closed() {
        let (rows, config, refs) = transitions(3);
        let (plan, head) = plan_and_head(&refs, 1);
        let mut gap = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        gap.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 9_000 }).unwrap();
        let pending = UniquePendingId::try_new(103).unwrap();
        assert!(matches!(
            gap.observe_suffix(
                3,
                PointValue { value: rows[3].clone(), writetime_us: 9_000 },
                LegacyMappingPair { pending_id: pending, forward_writetime_us: 9_000, reverse_writetime_us: 9_000 },
                Vec::new(),
                Vec::new(),
            ),
            Err(CoordinatorRollbackBranchCatalogError::CheckpointGap { .. })
        ));

        let mut fenced = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        assert_eq!(
            fenced.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 10_001 }),
            Err(CoordinatorRollbackBranchCatalogError::WriteAfterFence {
                writetime_us: 10_001,
                orphan_write_max_us: 10_000,
            })
        );

        let mut rehashed = CoordinatorRollbackBranchCatalogAccumulator::<
            PF, PHash, PoseidonHasher, PHash, HashProofVerifier,
        >::try_new(head, &plan, config, [7; 32])
        .unwrap();
        rehashed.observe_anchor(1, PointValue { value: rows[1].clone(), writetime_us: 9_000 }).unwrap();
        let mapping = BranchPendingMapping::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1).unwrap(),
                ChainEpoch::new(3),
                refs[2],
            ),
            UniquePendingId::try_new(102).unwrap(),
        );
        let (mut forward, reverse) = target_rows(&mapping);
        let mut after_fence = forward.clone();
        after_fence[0].pending_writetime_us = 10_001;
        assert_eq!(
            verify_target_mapping(&mapping, &after_fence, &reverse, 10_000),
            Err(CoordinatorRollbackBranchCatalogError::WriteAfterFence {
                writetime_us: 10_001,
                orphan_write_max_us: 10_000,
            })
        );
        forward[0].mapping_digest[0] ^= 1;
        assert_eq!(
            rehashed.observe_suffix(
                2,
                PointValue { value: rows[2].clone(), writetime_us: 9_000 },
                LegacyMappingPair { pending_id: mapping.pending_id(), forward_writetime_us: 9_000, reverse_writetime_us: 9_000 },
                forward,
                reverse,
            ),
            Err(CoordinatorRollbackBranchCatalogError::TargetForwardConflict)
        );

        let queries = CoordinatorRollbackBranchCatalogQueries::new(
            &CqlKeyspaceName::try_new("canonical").unwrap(),
            &CqlKeyspaceName::try_new("authority").unwrap(),
            &CqlKeyspaceName::try_new("branch_exact").unwrap(),
        );
        let golden = queries.golden();
        assert!(golden.contains("checkpoint_zk_proof_and_transition_table"));
        assert!(golden.contains("checkpoint_id_to_pending_id_table"));
        assert!(golden.contains("pending_id_to_checkpoint_id_table"));
        assert!(golden.contains(BRANCH_TO_PENDING_TABLE));
        assert!(golden.contains(PENDING_TO_BRANCH_TABLE));
        assert_eq!(golden.matches("LIMIT 2").count(), 2);
        assert!(!golden.contains("WRITETIME(pending_id)"));
        assert!(!golden.contains("WRITETIME(canonical_ref)"));
        assert_eq!(golden.matches("WRITETIME(mapping_digest)").count(), 2);
    }
}
