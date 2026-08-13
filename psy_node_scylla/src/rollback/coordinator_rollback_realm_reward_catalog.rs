//! Storage-selected archive scanner for Coordinator Realm reward nodes.
//!
//! The legacy table is partitioned by Realm and clustered by unique-pending;
//! production reads select the latest row at or below a pending coordinate.
//! A checkpoint rollback therefore cannot guess a checkpoint range in this
//! table.  This scanner first obtains the exact old-branch checkpoint→pending
//! selection from the verified branch catalog, then streams the whole physical
//! table and archives only rows whose pending coordinate belongs to the
//! discarded suffix.  It remains pre-PONR and cannot delete or publish state.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use futures::TryStreamExt;
use parth_core::{
    crypto::hash::traits::FieldQHasher,
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::QFelt64,
    protocol::core_types::{
        Q256BitHash, QFHashBase, QZKProofPublicInputsHasherReader,
    },
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    typed::{RealmId, UniquePendingId},
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactCheckpointChainConfig, CoordinatorRollbackArchivePlan,
    CqlKeyspaceName, ScyllaCanonicalHeadStore,
};
use super::coordinator_rollback_archive_store::ScyllaCoordinatorRollbackArchiveStore;
use super::coordinator_rollback_branch_catalog::{
    CoordinatorRollbackBranchCatalogSummary,
    CoordinatorRollbackMappingArchiveSummary,
    ScyllaCoordinatorRollbackBranchCatalog,
    VerifiedCoordinatorRollbackSuffixSelection,
};

const REALM_REWARD_TABLE: &str = "realm_rewards_tree_node_key_table";
const READ_ALL_TEMPLATE: &str =
    "SELECT obj_id, checkpoint_id, value, WRITETIME(value) FROM {table}";
const READ_POINT_TEMPLATE: &str =
    "SELECT value, WRITETIME(value) FROM {table} WHERE obj_id = ? AND checkpoint_id = ?";
const CATALOG_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-realm-reward-catalog/v1";
const ROW_COMMITMENT_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-realm-reward-source-row/v1";
const DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-realm-reward-source-dataset/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RewardCatalogQueries {
    read_all: String,
    read_point: String,
}

impl RewardCatalogQueries {
    fn new(source: &CqlKeyspaceName) -> Self {
        let table = format!("{}.{}", source.as_str(), REALM_REWARD_TABLE);
        Self {
            read_all: READ_ALL_TEMPLATE.replace("{table}", &table),
            read_point: READ_POINT_TEMPLATE.replace("{table}", &table),
        }
    }

    fn golden(&self) -> String {
        format!(
            "read_all\n{}\nread_point\n{}\n",
            self.read_all, self.read_point,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RewardSourceRow {
    realm: RealmId,
    pending: UniquePendingId,
    value: Vec<u8>,
    writetime_us: i64,
}

/// Non-constructible source evidence passed directly to the archive store.
/// It cannot authorize deletion or cross the global participant barrier.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedCoordinatorRollbackRealmRewardRow {
    catalog_fingerprint: [u8; 32],
    network: NetworkId,
    rollback_epoch: u64,
    source_epoch: u64,
    mapping_catalog_fingerprint: [u8; 32],
    mapping_catalog_digest: [u8; 32],
    mapping_source_digest: [u8; 32],
    source_checkpoint: u64,
    source: RewardSourceRow,
}

impl VerifiedCoordinatorRollbackRealmRewardRow {
    pub(super) const fn catalog_fingerprint(&self) -> [u8; 32] {
        self.catalog_fingerprint
    }

    pub(super) const fn network(&self) -> NetworkId {
        self.network
    }

    pub(super) const fn rollback_epoch(&self) -> u64 {
        self.rollback_epoch
    }

    pub(super) const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    pub(super) const fn mapping_catalog_fingerprint(&self) -> [u8; 32] {
        self.mapping_catalog_fingerprint
    }

    pub(super) const fn mapping_catalog_digest(&self) -> [u8; 32] {
        self.mapping_catalog_digest
    }

    pub(super) const fn mapping_source_digest(&self) -> [u8; 32] {
        self.mapping_source_digest
    }

    pub(super) const fn source_checkpoint(&self) -> u64 {
        self.source_checkpoint
    }

    pub(super) const fn realm(&self) -> RealmId {
        self.source.realm
    }

    pub(super) const fn pending(&self) -> UniquePendingId {
        self.source.pending
    }

    pub(super) fn source_value(&self) -> &[u8] {
        &self.source.value
    }

    pub(super) const fn source_writetime_us(&self) -> i64 {
        self.source.writetime_us
    }
}

#[cfg(test)]
pub(super) fn qualification_verified_reward_row(
    network: NetworkId,
    rollback_epoch: u64,
    source_epoch: u64,
    source_checkpoint: u64,
    realm: u64,
    pending: u64,
    value: Vec<u8>,
    writetime_us: i64,
) -> VerifiedCoordinatorRollbackRealmRewardRow {
    VerifiedCoordinatorRollbackRealmRewardRow {
        catalog_fingerprint: [0x11; 32],
        network,
        rollback_epoch,
        source_epoch,
        mapping_catalog_fingerprint: [0x22; 32],
        mapping_catalog_digest: [0x33; 32],
        mapping_source_digest: [0x44; 32],
        source_checkpoint,
        source: RewardSourceRow {
            realm: RealmId::new(realm),
            pending: UniquePendingId::try_new(pending).unwrap(),
            value,
            writetime_us,
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RewardDatasetSnapshot {
    selected_rows: u64,
    source_bytes: u64,
    xor_commitment: [u8; 32],
    sum_commitment: [u8; 32],
    digest: [u8; 32],
}

/// Inert progress evidence only.  The plan remains blocked until the later
/// participant assembler proves every required Coordinator domain complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorRollbackRealmRewardArchiveSummary {
    mapping: CoordinatorRollbackMappingArchiveSummary,
    selected_rows: u64,
    archive_bytes: u64,
    archive_digest: [u8; 32],
}

impl CoordinatorRollbackRealmRewardArchiveSummary {
    pub(super) const fn mapping(self) -> CoordinatorRollbackMappingArchiveSummary {
        self.mapping
    }

    pub(super) const fn selected_rows(self) -> u64 {
        self.selected_rows
    }

    pub(super) const fn archive_bytes(self) -> u64 {
        self.archive_bytes
    }

    pub(super) const fn archive_digest(self) -> [u8; 32] {
        self.archive_digest
    }
}

pub(super) struct ScyllaCoordinatorRollbackRealmRewardCatalog {
    session: Arc<Session>,
    read_all: PreparedStatement,
    read_point: PreparedStatement,
    fingerprint: [u8; 32],
}

impl ScyllaCoordinatorRollbackRealmRewardCatalog {
    pub(super) async fn prepare(
        session: Arc<Session>,
        source_keyspace: CqlKeyspaceName,
    ) -> Result<Self, CoordinatorRollbackRealmRewardCatalogError> {
        let queries = RewardCatalogQueries::new(&source_keyspace);
        let fingerprint = catalog_fingerprint(&source_keyspace, &queries);
        Ok(Self {
            read_all: prepare_read(&session, queries.read_all).await?,
            read_point: prepare_read(&session, queries.read_point).await?,
            session,
            fingerprint,
        })
    }

    /// Archive all reward-node rows selected by exact old-branch pending IDs.
    /// Mapping rows are first copied by their existing catalog-owned path.  All
    /// resulting rows remain immutable orphan-safe evidence; this method emits
    /// no participant receipt and exposes no destructive operation.
    pub(super) async fn archive_verified_suffix<
        F,
        Hash,
        Hasher,
        Proof,
        Verifier,
    >(
        &self,
        branch_catalog: &ScyllaCoordinatorRollbackBranchCatalog,
        archive_store: &ScyllaCoordinatorRollbackArchiveStore,
        canonical_head_store: &ScyllaCanonicalHeadStore,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        config: BranchExactCheckpointChainConfig<Hash>,
    ) -> Result<CoordinatorRollbackRealmRewardArchiveSummary, CoordinatorRollbackRealmRewardCatalogError>
    where
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        let mapping = branch_catalog
            .archive_verified_suffix::<F, Hash, Hasher, Proof, Verifier>(
                archive_store,
                canonical_head_store,
                expected_head,
                plan,
                config,
            )
            .await
            .map_err(|error| {
                CoordinatorRollbackRealmRewardCatalogError::BranchCatalog(
                    error.to_string(),
                )
            })?;

        self.require_current_head(canonical_head_store, expected_head).await?;
        let first_selection = branch_catalog
            .select_verified_suffix_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
            )
            .await
            .map_err(|error| {
                CoordinatorRollbackRealmRewardCatalogError::BranchCatalog(
                    error.to_string(),
                )
            })?;
        if mapping.catalog() != first_selection.summary() {
            return Err(CoordinatorRollbackRealmRewardCatalogError::SourceChanged);
        }
        let (first, _) = self
            .scan_once(expected_head, plan, &first_selection, None)
            .await?;

        self.require_current_head(canonical_head_store, expected_head).await?;
        let second_selection = branch_catalog
            .select_verified_suffix_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
            )
            .await
            .map_err(|error| {
                CoordinatorRollbackRealmRewardCatalogError::BranchCatalog(
                    error.to_string(),
                )
            })?;
        let (second, archived) = self
            .scan_once(expected_head, plan, &second_selection, Some(archive_store))
            .await?;

        self.require_current_head(canonical_head_store, expected_head).await?;
        let third_selection = branch_catalog
            .select_verified_suffix_once::<F, Hash, Hasher, Proof, Verifier>(
                expected_head,
                plan,
                config,
            )
            .await
            .map_err(|error| {
                CoordinatorRollbackRealmRewardCatalogError::BranchCatalog(
                    error.to_string(),
                )
            })?;
        let (third, _) = self
            .scan_once(expected_head, plan, &third_selection, None)
            .await?;
        self.require_current_head(canonical_head_store, expected_head).await?;

        if first_selection != second_selection
            || second_selection != third_selection
            || first != second
            || second != third
        {
            return Err(CoordinatorRollbackRealmRewardCatalogError::SourceChanged);
        }
        let archived = archived.ok_or(
            CoordinatorRollbackRealmRewardCatalogError::ArchiveSummaryMissing,
        )?;
        if archived.rows != second.selected_rows {
            return Err(
                CoordinatorRollbackRealmRewardCatalogError::ArchiveRowCountMismatch {
                    expected: second.selected_rows,
                    actual: archived.rows,
                },
            );
        }
        Ok(CoordinatorRollbackRealmRewardArchiveSummary {
            mapping,
            selected_rows: archived.rows,
            archive_bytes: archived.bytes,
            archive_digest: archived.digest,
        })
    }

    async fn scan_once<Hash: Q256BitHash>(
        &self,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        selection: &VerifiedCoordinatorRollbackSuffixSelection,
        archive_store: Option<&ScyllaCoordinatorRollbackArchiveStore>,
    ) -> Result<(RewardDatasetSnapshot, Option<RewardArchiveFinished>), CoordinatorRollbackRealmRewardCatalogError> {
        validate_selection(expected_head, plan, selection)?;
        let mut stream = self
            .session
            .execute_iter(self.read_all.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(Option<i64>, Option<i64>, Option<Vec<u8>>, Option<i64>)>()
            .map_err(driver)?;
        let mut dataset = RewardDatasetAccumulator::new(plan, selection.summary());
        let mut archived = archive_store.map(|_| RewardArchiveAccumulator::new(plan));
        while let Some((realm, pending, value, writetime_us)) =
            stream.try_next().await.map_err(driver)?
        {
            let pending_i64 = pending.ok_or(
                CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
            )?;
            if pending_i64 < 0 {
                continue;
            }
            let pending_u64 = u64::try_from(pending_i64).map_err(|_| {
                CoordinatorRollbackRealmRewardCatalogError::IntegerOutOfRange
            })?;
            let pending = UniquePendingId::try_new(pending_u64).map_err(|_| {
                CoordinatorRollbackRealmRewardCatalogError::IntegerOutOfRange
            })?;
            let Some(checkpoint) = selection.checkpoint_for_pending(pending) else {
                continue;
            };
            let realm = realm.ok_or(
                CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
            )?;
            let realm = RealmId::new(u64::try_from(realm).map_err(|_| {
                CoordinatorRollbackRealmRewardCatalogError::IntegerOutOfRange
            })?);
            let value = value.ok_or(
                CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
            )?;
            let writetime_us = writetime_us.ok_or(
                CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
            )?;
            validate_source_value(&value)?;
            require_before_fence(plan, writetime_us)?;
            let verified = VerifiedCoordinatorRollbackRealmRewardRow {
                catalog_fingerprint: self.fingerprint,
                network: expected_head.canonical_ref().network_id(),
                rollback_epoch: expected_head.canonical_ref().chain_epoch().get(),
                source_epoch: selection.summary().source_chain_epoch(),
                mapping_catalog_fingerprint: selection.summary().catalog_fingerprint(),
                mapping_catalog_digest: selection.summary().catalog_digest().as_bytes(),
                mapping_source_digest: selection.summary().source_digest(),
                source_checkpoint: checkpoint,
                source: RewardSourceRow {
                    realm,
                    pending,
                    value,
                    writetime_us,
                },
            };
            let row_commitment = source_row_commitment(&verified);
            if let Some(store) = archive_store {
                let persisted = store
                    .persist_verified_realm_reward_row(expected_head, plan, &verified)
                    .await
                    .map_err(|error| {
                        CoordinatorRollbackRealmRewardCatalogError::Archive(
                            error.to_string(),
                        )
                    })?;
                let after = self
                    .read_source_point(verified.realm(), verified.pending())
                    .await?
                    .ok_or(CoordinatorRollbackRealmRewardCatalogError::SourceChanged)?;
                if after != verified.source {
                    return Err(CoordinatorRollbackRealmRewardCatalogError::SourceChanged);
                }
                archived
                    .as_mut()
                    .expect("archive accumulator exists with store")
                    .observe(persisted)?;
            }
            dataset.observe(&verified, row_commitment)?;
        }
        Ok((dataset.finish(), archived.map(RewardArchiveAccumulator::finish)))
    }

    async fn read_source_point(
        &self,
        realm: RealmId,
        pending: UniquePendingId,
    ) -> Result<Option<RewardSourceRow>, CoordinatorRollbackRealmRewardCatalogError> {
        let row = self
            .session
            .execute_unpaged(
                &self.read_point,
                (
                    i64::try_from(realm.get()).map_err(|_| {
                        CoordinatorRollbackRealmRewardCatalogError::IntegerOutOfRange
                    })?,
                    i64::try_from(pending.get()).map_err(|_| {
                        CoordinatorRollbackRealmRewardCatalogError::IntegerOutOfRange
                    })?,
                ),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
            .map_err(driver)?;
        row.map(|(value, writetime_us)| {
            Ok(RewardSourceRow {
                realm,
                pending,
                value: value.ok_or(
                    CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
                )?,
                writetime_us: writetime_us.ok_or(
                    CoordinatorRollbackRealmRewardCatalogError::MissingSourceColumn,
                )?,
            })
        })
        .transpose()
    }

    async fn require_current_head<Hash: Q256BitHash>(
        &self,
        store: &ScyllaCanonicalHeadStore,
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
        match store
            .read(expected.canonical_ref().network_id())
            .await
            .map_err(|error| {
                CoordinatorRollbackRealmRewardCatalogError::Head(error.to_string())
            })?
        {
            CanonicalHeadReadState::Current(current) if current == expected => Ok(()),
            _ => Err(CoordinatorRollbackRealmRewardCatalogError::HeadChanged),
        }
    }
}

struct RewardDatasetAccumulator {
    rows: u64,
    bytes: u64,
    xor: [u8; 32],
    sum: [u8; 32],
    plan_digest: [u8; 32],
    mapping_digest: [u8; 32],
}

impl RewardDatasetAccumulator {
    fn new<Hash: Q256BitHash>(
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        mapping: CoordinatorRollbackBranchCatalogSummary,
    ) -> Self {
        Self {
            rows: 0,
            bytes: 0,
            xor: [0; 32],
            sum: [0; 32],
            plan_digest: plan.digest().as_bytes(),
            mapping_digest: mapping.catalog_digest().as_bytes(),
        }
    }

    fn observe(
        &mut self,
        row: &VerifiedCoordinatorRollbackRealmRewardRow,
        commitment: [u8; 32],
    ) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
        self.rows = self.rows.checked_add(1).ok_or(
            CoordinatorRollbackRealmRewardCatalogError::LengthOverflow,
        )?;
        self.bytes = self
            .bytes
            .checked_add(row.source_value().len() as u64)
            .ok_or(CoordinatorRollbackRealmRewardCatalogError::LengthOverflow)?;
        for (target, value) in self.xor.iter_mut().zip(commitment) {
            *target ^= value;
        }
        add_be_256(&mut self.sum, commitment);
        Ok(())
    }

    fn finish(self) -> RewardDatasetSnapshot {
        let mut hasher = Sha256::new();
        hasher.update(DATASET_DIGEST_DOMAIN);
        hasher.update(self.plan_digest);
        hasher.update(self.mapping_digest);
        hasher.update(self.rows.to_be_bytes());
        hasher.update(self.bytes.to_be_bytes());
        hasher.update(self.xor);
        hasher.update(self.sum);
        RewardDatasetSnapshot {
            selected_rows: self.rows,
            source_bytes: self.bytes,
            xor_commitment: self.xor,
            sum_commitment: self.sum,
            digest: hasher.finalize().into(),
        }
    }
}

struct RewardArchiveAccumulator {
    rows: u64,
    bytes: u64,
    xor: [u8; 32],
    sum: [u8; 32],
    plan_digest: [u8; 32],
}

struct RewardArchiveFinished {
    rows: u64,
    bytes: u64,
    digest: [u8; 32],
}

impl RewardArchiveAccumulator {
    fn new<Hash: Q256BitHash>(plan: &CoordinatorRollbackArchivePlan<Hash>) -> Self {
        Self {
            rows: 0,
            bytes: 0,
            xor: [0; 32],
            sum: [0; 32],
            plan_digest: plan.digest().as_bytes(),
        }
    }

    fn observe(
        &mut self,
        persisted: super::coordinator_rollback_archive_store::CoordinatorRollbackArchivedRealmRewardRow,
    ) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
        self.rows = self.rows.checked_add(1).ok_or(
            CoordinatorRollbackRealmRewardCatalogError::LengthOverflow,
        )?;
        self.bytes = self.bytes.checked_add(persisted.canonical_bytes()).ok_or(
            CoordinatorRollbackRealmRewardCatalogError::LengthOverflow,
        )?;
        let mut hasher = Sha256::new();
        hasher.update(b"psy/coordinator-rollback-realm-reward-archive-member/v1");
        hasher.update(persisted.slot());
        hasher.update(persisted.digest());
        let commitment: [u8; 32] = hasher.finalize().into();
        for (target, value) in self.xor.iter_mut().zip(commitment) {
            *target ^= value;
        }
        add_be_256(&mut self.sum, commitment);
        Ok(())
    }

    fn finish(self) -> RewardArchiveFinished {
        let mut hasher = Sha256::new();
        hasher.update(b"psy/coordinator-rollback-realm-reward-archive-dataset/v1");
        hasher.update(self.plan_digest);
        hasher.update(self.rows.to_be_bytes());
        hasher.update(self.bytes.to_be_bytes());
        hasher.update(self.xor);
        hasher.update(self.sum);
        RewardArchiveFinished {
            rows: self.rows,
            bytes: self.bytes,
            digest: hasher.finalize().into(),
        }
    }
}

fn validate_selection<Hash: Q256BitHash>(
    expected_head: StoredCanonicalHead<Hash>,
    plan: &CoordinatorRollbackArchivePlan<Hash>,
    selection: &VerifiedCoordinatorRollbackSuffixSelection,
) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
    if selection.pending_rows() as u64 != selection.summary().suffix_rows()
        || selection.summary().source_chain_epoch().checked_add(1)
            != Some(expected_head.canonical_ref().chain_epoch().get())
        || expected_head.canonical_ref().checkpoint() != plan.request().requested_head()
    {
        return Err(CoordinatorRollbackRealmRewardCatalogError::SelectionMismatch);
    }
    Ok(())
}

fn validate_source_value(
    compressed: &[u8],
) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
    let canonical = crate::compression::decompress(compressed).map_err(|error| {
        CoordinatorRollbackRealmRewardCatalogError::MalformedSource(error.to_string())
    })?;
    let decoded = SimpleMerkleNodeKey::psy_ser_from_owned_bytes_vec(canonical.clone())
        .map_err(|error| {
            CoordinatorRollbackRealmRewardCatalogError::MalformedSource(
                error.to_string(),
            )
        })?;
    let rebuilt = decoded.psy_ser_to_bytes_vec().map_err(|error| {
        CoordinatorRollbackRealmRewardCatalogError::MalformedSource(error.to_string())
    })?;
    if rebuilt != canonical {
        return Err(CoordinatorRollbackRealmRewardCatalogError::NonCanonicalSource);
    }
    Ok(())
}

fn require_before_fence<Hash: Q256BitHash>(
    plan: &CoordinatorRollbackArchivePlan<Hash>,
    writetime_us: i64,
) -> Result<(), CoordinatorRollbackRealmRewardCatalogError> {
    let maximum = plan
        .request()
        .fence_window()
        .delete_fence()
        .orphan_write_max()
        .as_i64();
    if writetime_us > maximum {
        Err(CoordinatorRollbackRealmRewardCatalogError::WriteAfterFence {
            writetime_us,
            orphan_write_max_us: maximum,
        })
    } else {
        Ok(())
    }
}

fn source_row_commitment(row: &VerifiedCoordinatorRollbackRealmRewardRow) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_COMMITMENT_DOMAIN);
    hasher.update(row.catalog_fingerprint());
    hasher.update(row.network().chain_id().to_be_bytes());
    hasher.update(row.rollback_epoch().to_be_bytes());
    hasher.update(row.source_epoch().to_be_bytes());
    hasher.update(row.mapping_catalog_digest());
    hasher.update(row.mapping_source_digest());
    hasher.update(row.source_checkpoint().to_be_bytes());
    hasher.update(row.realm().get().to_be_bytes());
    hasher.update(row.pending().get().to_be_bytes());
    hasher.update(row.source_writetime_us().to_be_bytes());
    hasher.update((row.source_value().len() as u64).to_be_bytes());
    hasher.update(row.source_value());
    hasher.finalize().into()
}

fn add_be_256(sum: &mut [u8; 32], value: [u8; 32]) {
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let total = u16::from(sum[index]) + u16::from(value[index]) + carry;
        sum[index] = total as u8;
        carry = total >> 8;
    }
}

fn catalog_fingerprint(
    source: &CqlKeyspaceName,
    queries: &RewardCatalogQueries,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_FINGERPRINT_DOMAIN);
    hasher.update((source.as_str().len() as u64).to_be_bytes());
    hasher.update(source.as_str().as_bytes());
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    hasher.finalize().into()
}

async fn prepare_read(
    session: &Session,
    query: String,
) -> Result<PreparedStatement, CoordinatorRollbackRealmRewardCatalogError> {
    let mut statement = session.prepare(query).await.map_err(driver)?;
    statement.set_consistency(Consistency::Quorum);
    Ok(statement)
}

fn driver(error: impl ToString) -> CoordinatorRollbackRealmRewardCatalogError {
    CoordinatorRollbackRealmRewardCatalogError::Driver(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorRollbackRealmRewardCatalogError {
    SelectionMismatch,
    MissingSourceColumn,
    IntegerOutOfRange,
    MalformedSource(String),
    NonCanonicalSource,
    WriteAfterFence { writetime_us: i64, orphan_write_max_us: i64 },
    SourceChanged,
    Head(String),
    HeadChanged,
    BranchCatalog(String),
    Archive(String),
    ArchiveSummaryMissing,
    ArchiveRowCountMismatch { expected: u64, actual: u64 },
    LengthOverflow,
    Driver(String),
}

impl fmt::Display for CoordinatorRollbackRealmRewardCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator reward-catalog failure: {self:?}")
    }
}

impl Error for CoordinatorRollbackRealmRewardCatalogError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn compressed_node(level: u8, index: u64) -> Vec<u8> {
        crate::compression::compress(
            &SimpleMerkleNodeKey::new(level, index)
                .psy_ser_to_bytes_vec()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn query_golden_is_full_scan_plus_exact_point_read() {
        let keyspace = CqlKeyspaceName::try_new("state").unwrap();
        let queries = RewardCatalogQueries::new(&keyspace);
        assert_eq!(
            queries.read_all,
            "SELECT obj_id, checkpoint_id, value, WRITETIME(value) FROM state.realm_rewards_tree_node_key_table"
        );
        assert_eq!(
            queries.read_point,
            "SELECT value, WRITETIME(value) FROM state.realm_rewards_tree_node_key_table WHERE obj_id = ? AND checkpoint_id = ?"
        );
        assert_ne!(catalog_fingerprint(&keyspace, &queries), [0; 32]);
    }

    #[test]
    fn multiset_commitment_is_order_independent_and_count_sensitive() {
        let mut first_xor = [0_u8; 32];
        let mut first_sum = [0_u8; 32];
        let mut second_xor = [0_u8; 32];
        let mut second_sum = [0_u8; 32];
        let a = [0x11; 32];
        let b = [0xF2; 32];
        for value in [a, b] {
            for (target, byte) in first_xor.iter_mut().zip(value) {
                *target ^= byte;
            }
            add_be_256(&mut first_sum, value);
        }
        for value in [b, a] {
            for (target, byte) in second_xor.iter_mut().zip(value) {
                *target ^= byte;
            }
            add_be_256(&mut second_sum, value);
        }
        assert_eq!(first_xor, second_xor);
        assert_eq!(first_sum, second_sum);
        let once = a;
        let mut twice = [0_u8; 32];
        add_be_256(&mut twice, a);
        add_be_256(&mut twice, a);
        assert_ne!(once, twice);
    }

    #[test]
    fn source_commitment_binds_physical_key_value_and_writetime() {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let first = qualification_verified_reward_row(
            network,
            7,
            6,
            95,
            3,
            105,
            compressed_node(4, 8),
            999,
        );
        let same = qualification_verified_reward_row(
            network,
            7,
            6,
            95,
            3,
            105,
            compressed_node(4, 8),
            999,
        );
        assert_eq!(source_row_commitment(&first), source_row_commitment(&same));
        for changed in [
            qualification_verified_reward_row(network, 7, 6, 95, 4, 105, compressed_node(4, 8), 999),
            qualification_verified_reward_row(network, 7, 6, 95, 3, 106, compressed_node(4, 8), 999),
            qualification_verified_reward_row(network, 7, 6, 95, 3, 105, compressed_node(4, 9), 999),
            qualification_verified_reward_row(network, 7, 6, 95, 3, 105, compressed_node(4, 8), 998),
        ] {
            assert_ne!(source_row_commitment(&first), source_row_commitment(&changed));
        }
        assert!(validate_source_value(first.source_value()).is_ok());
        assert!(validate_source_value(b"not-zstd").is_err());
    }
}
