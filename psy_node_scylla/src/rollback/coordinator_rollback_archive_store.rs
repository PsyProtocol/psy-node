//! Append-only Coordinator suffix archive and the first real table scanner.
//!
//! This module is deliberately pre-PONR.  It can copy one rollback-ready
//! Coordinator table into an immutable archive and prove exact readback, but
//! neither its private persistence receipt nor its public scan summary can
//! advance the global archive barrier or authorize a hot-table delete.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CoordinatorRollbackArchiveAction, CoordinatorRollbackArchivePlan,
    CoordinatorRollbackArchivePlanDigest,
    CoordinatorRollbackArchivePlanDigestError, CqlKeyspaceName,
    ScyllaCanonicalHeadStore, ScyllaKeyDomain, ScyllaPhysicalTableId,
    key_domain_descriptor, physical_descriptor,
};

pub(super) const COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE: &str =
    "coordinator_rollback_suffix_archive_v1";

const ROW_MAGIC: [u8; 8] = *b"PSYCRARW";
const ROW_CODEC_VERSION: u16 = 1;
const ROW_DIGEST_DOMAIN: &[u8] = b"psy/coordinator-rollback-archive-row/v1";
const ROW_SLOT_DOMAIN: &[u8] = b"psy/coordinator-rollback-archive-row-slot/v1";
const FRAGMENT_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-archive-fragment/v1";
const DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-archive-dataset/v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/coordinator-rollback-archive-store/v1";
const ARCHIVE_REVISION: i64 = 1;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const MAX_CANONICAL_ROW_BYTES: usize = MAX_FRAGMENT_BYTES * MAX_FRAGMENTS;

const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, chain_epoch bigint, participant_plan_digest blob, key_domain smallint, row_slot blob, fragment_index int, revision bigint, fragment_count int, row_bytes bigint, fragment_payload blob, fragment_digest blob, row_digest blob, PRIMARY KEY ((network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_ROW_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ? AND fragment_index = ?";
const READ_SOURCE_TEMPLATE: &str =
    "SELECT value, WRITETIME(value) FROM {table} WHERE obj_id = ?";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorRollbackArchiveQueries {
    create: String,
    insert: String,
    read_row: String,
    read_fragment: String,
    read_checkpoint_zk_proof: String,
}

impl CoordinatorRollbackArchiveQueries {
    fn new(archive: &CqlKeyspaceName, source: &CqlKeyspaceName) -> Self {
        let archive_table = format!(
            "{}.{}",
            archive.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE
        );
        let source_descriptor =
            physical_descriptor(ScyllaPhysicalTableId::CheckpointZkProofAndTransition);
        let source_table = format!(
            "{}.{}",
            source.as_str(),
            source_descriptor.physical_name
        );
        Self {
            create: CREATE_TEMPLATE.replace("{table}", &archive_table),
            insert: INSERT_TEMPLATE.replace("{table}", &archive_table),
            read_row: READ_ROW_TEMPLATE.replace("{table}", &archive_table),
            read_fragment: READ_FRAGMENT_TEMPLATE.replace("{table}", &archive_table),
            read_checkpoint_zk_proof: READ_SOURCE_TEMPLATE.replace("{table}", &source_table),
        }
    }

    fn golden(&self) -> String {
        format!(
            "create\n{}\n\ninsert\n{}\n\nread_row\n{}\n\nread_fragment\n{}\n\nread_checkpoint_zk_proof\n{}\n",
            self.create,
            self.insert,
            self.read_row,
            self.read_fragment,
            self.read_checkpoint_zk_proof,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CoordinatorRollbackArchiveRowSlot([u8; 32]);

impl CoordinatorRollbackArchiveRowSlot {
    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CoordinatorRollbackArchiveRowDigest([u8; 32]);

impl CoordinatorRollbackArchiveRowDigest {
    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorRollbackArchiveStoreFingerprint([u8; 32]);

/// Canonical archive image of one real checkpoint-keyed KIV row.
///
/// The stable row slot excludes value bytes and writetime.  A delayed writer
/// for the same source primary key therefore conflicts with the first exact
/// image instead of creating a second selectable archive row.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorRollbackCheckpointKivArchiveRow {
    network: NetworkId,
    chain_epoch: u64,
    participant_plan_digest: CoordinatorRollbackArchivePlanDigest,
    global_plan_digest: [u8; 32],
    key_domain: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
    action: CoordinatorRollbackArchiveAction,
    requested_height: u64,
    requested_hash: [u8; 32],
    target_height: u64,
    target_hash: [u8; 32],
    orphan_write_max_us: i64,
    source_checkpoint: u64,
    source_value: Vec<u8>,
    source_writetime_us: i64,
    slot: CoordinatorRollbackArchiveRowSlot,
    canonical_bytes: Vec<u8>,
    digest: CoordinatorRollbackArchiveRowDigest,
}

impl CoordinatorRollbackCheckpointKivArchiveRow {
    fn try_checkpoint_zk_proof<Hash: Q256BitHash>(
        network: NetworkId,
        chain_epoch: u64,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
        source_checkpoint: u64,
        source_value: Vec<u8>,
        source_writetime_us: i64,
    ) -> Result<Self, CoordinatorRollbackArchiveRowError> {
        let domain = plan
            .domains()
            .iter()
            .find(|domain| domain.key_domain() == ScyllaKeyDomain::CheckpointZkProof)
            .copied()
            .ok_or(CoordinatorRollbackArchiveRowError::DomainNotPlanned)?;
        if domain.physical_table()
            != ScyllaPhysicalTableId::CheckpointZkProofAndTransition
            || domain.action()
                != CoordinatorRollbackArchiveAction::ArchiveCheckpointPartitions
        {
            return Err(CoordinatorRollbackArchiveRowError::DomainContractMismatch);
        }
        if source_checkpoint <= plan.suffix_start_exclusive()
            || source_checkpoint > plan.suffix_end_inclusive()
        {
            return Err(CoordinatorRollbackArchiveRowError::SourceOutsideSuffix);
        }
        let orphan_write_max_us = plan
            .request()
            .fence_window()
            .delete_fence()
            .orphan_write_max()
            .as_i64();
        if source_writetime_us > orphan_write_max_us {
            return Err(CoordinatorRollbackArchiveRowError::WriteAfterOrphanFence {
                writetime_us: source_writetime_us,
                orphan_write_max_us,
            });
        }
        let participant_plan_digest = plan.digest();
        let global_plan_digest = *plan.global_plan_digest().as_bytes();
        let requested_height = plan.request().requested_head().checkpoint_id().get();
        let requested_hash = plan
            .request()
            .requested_head()
            .checkpoint_hash()
            .as_inner()
            .into_owned_32bytes();
        let target_height = plan.request().target().checkpoint_id().get();
        let target_hash = plan
            .request()
            .target()
            .checkpoint_hash()
            .as_inner()
            .into_owned_32bytes();
        let slot = row_slot(
            network,
            chain_epoch,
            participant_plan_digest,
            domain.key_domain(),
            source_checkpoint,
        );
        let mut canonical_bytes = encode_row_without_digest(
            network,
            chain_epoch,
            participant_plan_digest,
            global_plan_digest,
            domain.key_domain(),
            domain.physical_table(),
            domain.action(),
            requested_height,
            requested_hash,
            target_height,
            target_hash,
            orphan_write_max_us,
            source_checkpoint,
            &source_value,
            source_writetime_us,
            slot,
        )?;
        let digest = row_digest(&canonical_bytes);
        canonical_bytes.extend_from_slice(digest.as_bytes());
        if canonical_bytes.len() > MAX_CANONICAL_ROW_BYTES {
            return Err(CoordinatorRollbackArchiveRowError::RowTooLarge {
                actual: canonical_bytes.len(),
                maximum: MAX_CANONICAL_ROW_BYTES,
            });
        }
        Ok(Self {
            network,
            chain_epoch,
            participant_plan_digest,
            global_plan_digest,
            key_domain: domain.key_domain(),
            physical_table: domain.physical_table(),
            action: domain.action(),
            requested_height,
            requested_hash,
            target_height,
            target_hash,
            orphan_write_max_us,
            source_checkpoint,
            source_value,
            source_writetime_us,
            slot,
            canonical_bytes,
            digest,
        })
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CoordinatorRollbackArchiveRowError> {
        if bytes.len() < ROW_MIN_BYTES {
            return Err(CoordinatorRollbackArchiveRowError::Truncated);
        }
        if bytes.len() > MAX_CANONICAL_ROW_BYTES {
            return Err(CoordinatorRollbackArchiveRowError::RowTooLarge {
                actual: bytes.len(),
                maximum: MAX_CANONICAL_ROW_BYTES,
            });
        }
        let (body, stored_digest) = bytes.split_at(bytes.len() - 32);
        let expected_digest = row_digest(body);
        if stored_digest != expected_digest.as_bytes().as_slice() {
            return Err(CoordinatorRollbackArchiveRowError::DigestMismatch);
        }
        let mut decoder = Decoder::new(body);
        if decoder.take(8)? != ROW_MAGIC {
            return Err(CoordinatorRollbackArchiveRowError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != ROW_CODEC_VERSION {
            return Err(CoordinatorRollbackArchiveRowError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(|error| CoordinatorRollbackArchiveRowError::Network(error.to_string()))?;
        let chain_epoch = decoder.u64()?;
        if chain_epoch > i64::MAX as u64 {
            return Err(CoordinatorRollbackArchiveRowError::IntegerOutOfCqlRange);
        }
        let participant_plan_digest = CoordinatorRollbackArchivePlanDigest::try_from_archive_bytes(
            decoder.array_32()?,
        )?;
        let global_plan_digest = decoder.array_32()?;
        if global_plan_digest == [0; 32] {
            return Err(CoordinatorRollbackArchiveRowError::ZeroGlobalPlanDigest);
        }
        let key_domain = match decoder.u16()? {
            value if value == ScyllaKeyDomain::CheckpointZkProof.stable_id() => {
                ScyllaKeyDomain::CheckpointZkProof
            }
            value => return Err(CoordinatorRollbackArchiveRowError::UnknownKeyDomain(value)),
        };
        let physical_table = match decoder.u16()? {
            value
                if value
                    == ScyllaPhysicalTableId::CheckpointZkProofAndTransition.stable_id() =>
            {
                ScyllaPhysicalTableId::CheckpointZkProofAndTransition
            }
            value => {
                return Err(CoordinatorRollbackArchiveRowError::UnknownPhysicalTable(
                    value,
                ));
            }
        };
        if key_domain_descriptor(key_domain).physical_table != physical_table {
            return Err(CoordinatorRollbackArchiveRowError::DomainContractMismatch);
        }
        let action = match decoder.u8()? {
            value
                if value
                    == CoordinatorRollbackArchiveAction::ArchiveCheckpointPartitions as u8 =>
            {
                CoordinatorRollbackArchiveAction::ArchiveCheckpointPartitions
            }
            value => return Err(CoordinatorRollbackArchiveRowError::UnknownAction(value)),
        };
        let requested_height = decoder.u64()?;
        let requested_hash = decoder.array_32()?;
        let target_height = decoder.u64()?;
        let target_hash = decoder.array_32()?;
        if target_height >= requested_height {
            return Err(CoordinatorRollbackArchiveRowError::InvalidRollbackRange);
        }
        let orphan_write_max_us = decoder.i64()?;
        let source_checkpoint = decoder.u64()?;
        if source_checkpoint <= target_height || source_checkpoint > requested_height {
            return Err(CoordinatorRollbackArchiveRowError::SourceOutsideSuffix);
        }
        let source_writetime_us = decoder.i64()?;
        if source_writetime_us > orphan_write_max_us {
            return Err(CoordinatorRollbackArchiveRowError::WriteAfterOrphanFence {
                writetime_us: source_writetime_us,
                orphan_write_max_us,
            });
        }
        let source_len = usize::try_from(decoder.u64()?)
            .map_err(|_| CoordinatorRollbackArchiveRowError::LengthOverflow)?;
        let source_value = decoder.take(source_len)?.to_vec();
        let slot = CoordinatorRollbackArchiveRowSlot(decoder.array_32()?);
        if !decoder.is_empty() {
            return Err(CoordinatorRollbackArchiveRowError::TrailingBytes);
        }
        let expected_slot = row_slot(
            network,
            chain_epoch,
            participant_plan_digest,
            key_domain,
            source_checkpoint,
        );
        if slot != expected_slot {
            return Err(CoordinatorRollbackArchiveRowError::RowSlotMismatch);
        }
        Ok(Self {
            network,
            chain_epoch,
            participant_plan_digest,
            global_plan_digest,
            key_domain,
            physical_table,
            action,
            requested_height,
            requested_hash,
            target_height,
            target_hash,
            orphan_write_max_us,
            source_checkpoint,
            source_value,
            source_writetime_us,
            slot,
            canonical_bytes: bytes.to_vec(),
            digest: expected_digest,
        })
    }

    fn fragments(&self) -> Result<Vec<CoordinatorRollbackArchiveFragment>, CoordinatorRollbackArchiveRowError> {
        let fragment_count = self.canonical_bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
        if fragment_count == 0 || fragment_count > MAX_FRAGMENTS {
            return Err(CoordinatorRollbackArchiveRowError::InvalidFragmentCount(
                fragment_count,
            ));
        }
        let row_bytes = i64::try_from(self.canonical_bytes.len())
            .map_err(|_| CoordinatorRollbackArchiveRowError::LengthOverflow)?;
        let count = i32::try_from(fragment_count)
            .map_err(|_| CoordinatorRollbackArchiveRowError::LengthOverflow)?;
        Ok(self
            .canonical_bytes
            .chunks(MAX_FRAGMENT_BYTES)
            .enumerate()
            .map(|(index, payload)| CoordinatorRollbackArchiveFragment {
                index: index as i32,
                count,
                row_bytes,
                payload: payload.to_vec(),
                payload_digest: fragment_digest(index as i32, payload),
                row_digest: self.digest,
            })
            .collect())
    }
}

const ROW_MIN_BYTES: usize = 8 + 2 + 4 + 8 + 32 + 32 + 2 + 2 + 1 + 8 + 32 + 8 + 32 + 8 + 8 + 8 + 8 + 32 + 32;

fn encode_row_without_digest(
    network: NetworkId,
    chain_epoch: u64,
    participant_plan_digest: CoordinatorRollbackArchivePlanDigest,
    global_plan_digest: [u8; 32],
    key_domain: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
    action: CoordinatorRollbackArchiveAction,
    requested_height: u64,
    requested_hash: [u8; 32],
    target_height: u64,
    target_hash: [u8; 32],
    orphan_write_max_us: i64,
    source_checkpoint: u64,
    source_value: &[u8],
    source_writetime_us: i64,
    slot: CoordinatorRollbackArchiveRowSlot,
) -> Result<Vec<u8>, CoordinatorRollbackArchiveRowError> {
    if chain_epoch > i64::MAX as u64 || source_checkpoint > i64::MAX as u64 {
        return Err(CoordinatorRollbackArchiveRowError::IntegerOutOfCqlRange);
    }
    let source_len = u64::try_from(source_value.len())
        .map_err(|_| CoordinatorRollbackArchiveRowError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(ROW_MIN_BYTES + source_value.len());
    bytes.extend_from_slice(&ROW_MAGIC);
    bytes.extend_from_slice(&ROW_CODEC_VERSION.to_be_bytes());
    bytes.extend_from_slice(&network.chain_id().to_be_bytes());
    bytes.extend_from_slice(&chain_epoch.to_be_bytes());
    bytes.extend_from_slice(&participant_plan_digest.as_bytes());
    bytes.extend_from_slice(&global_plan_digest);
    bytes.extend_from_slice(&key_domain.stable_id().to_be_bytes());
    bytes.extend_from_slice(&physical_table.stable_id().to_be_bytes());
    bytes.push(action as u8);
    bytes.extend_from_slice(&requested_height.to_be_bytes());
    bytes.extend_from_slice(&requested_hash);
    bytes.extend_from_slice(&target_height.to_be_bytes());
    bytes.extend_from_slice(&target_hash);
    bytes.extend_from_slice(&orphan_write_max_us.to_be_bytes());
    bytes.extend_from_slice(&source_checkpoint.to_be_bytes());
    bytes.extend_from_slice(&source_writetime_us.to_be_bytes());
    bytes.extend_from_slice(&source_len.to_be_bytes());
    bytes.extend_from_slice(source_value);
    bytes.extend_from_slice(slot.as_bytes());
    Ok(bytes)
}

fn row_slot(
    network: NetworkId,
    chain_epoch: u64,
    participant_plan_digest: CoordinatorRollbackArchivePlanDigest,
    key_domain: ScyllaKeyDomain,
    source_checkpoint: u64,
) -> CoordinatorRollbackArchiveRowSlot {
    let mut hasher = Sha256::new();
    hasher.update(ROW_SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(chain_epoch.to_be_bytes());
    hasher.update(participant_plan_digest.as_bytes());
    hasher.update(key_domain.stable_id().to_be_bytes());
    hasher.update(source_checkpoint.to_be_bytes());
    CoordinatorRollbackArchiveRowSlot(hasher.finalize().into())
}

fn row_digest(bytes: &[u8]) -> CoordinatorRollbackArchiveRowDigest {
    let mut hasher = Sha256::new();
    hasher.update(ROW_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    CoordinatorRollbackArchiveRowDigest(hasher.finalize().into())
}

fn fragment_digest(index: i32, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(index.to_be_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorRollbackArchiveFragment {
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: Vec<u8>,
    payload_digest: [u8; 32],
    row_digest: CoordinatorRollbackArchiveRowDigest,
}

#[derive(Debug)]
struct PersistedCoordinatorRollbackArchiveRowReceipt {
    store_fingerprint: CoordinatorRollbackArchiveStoreFingerprint,
    row: CoordinatorRollbackCheckpointKivArchiveRow,
}

/// Inert evidence for progress/metrics only.  It is intentionally Copy and is
/// not accepted by any barrier, delete, head, or timestamp mutation API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CoordinatorRollbackArchiveScanSummary {
    row_count: u64,
    canonical_bytes: u64,
    dataset_digest: [u8; 32],
}

impl CoordinatorRollbackArchiveScanSummary {
    pub(super) const fn row_count(self) -> u64 {
        self.row_count
    }

    pub(super) const fn canonical_bytes(self) -> u64 {
        self.canonical_bytes
    }

    pub(super) const fn dataset_digest(self) -> [u8; 32] {
        self.dataset_digest
    }
}

pub(super) struct ScyllaCoordinatorRollbackArchiveStore {
    session: Arc<Session>,
    fingerprint: CoordinatorRollbackArchiveStoreFingerprint,
    read_row: PreparedStatement,
    read_fragment: PreparedStatement,
    insert: PreparedStatement,
    read_checkpoint_zk_proof: PreparedStatement,
}

impl ScyllaCoordinatorRollbackArchiveStore {
    pub(super) async fn create_schema(
        session: &Session,
        archive_keyspace: &CqlKeyspaceName,
    ) -> Result<(), CoordinatorRollbackArchiveStoreError> {
        require_standard_keyspace(archive_keyspace)?;
        let queries = CoordinatorRollbackArchiveQueries::new(
            archive_keyspace,
            archive_keyspace,
        );
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        archive_keyspace: CqlKeyspaceName,
        source_keyspace: CqlKeyspaceName,
    ) -> Result<Self, CoordinatorRollbackArchiveStoreError> {
        require_standard_keyspace(&archive_keyspace)?;
        require_standard_keyspace(&source_keyspace)?;
        let queries = CoordinatorRollbackArchiveQueries::new(
            &archive_keyspace,
            &source_keyspace,
        );
        let fingerprint = store_fingerprint(
            &archive_keyspace,
            &source_keyspace,
            &queries,
        );
        Ok(Self {
            read_row: prepare_read(&session, queries.read_row).await?,
            read_fragment: prepare_read(&session, queries.read_fragment).await?,
            insert: prepare_lwt(&session, queries.insert).await?,
            read_checkpoint_zk_proof: prepare_read(
                &session,
                queries.read_checkpoint_zk_proof,
            )
            .await?,
            session,
            fingerprint,
        })
    }

    /// Stream the real checkpoint-proof KIV suffix into the append-only
    /// archive.  This does not require the unrelated participant blockers to
    /// be resolved because copied rows are orphan-safe and cannot cross the
    /// global barrier.  The barrier owner must later revalidate all tables and
    /// prove that every blocker has been closed.
    pub(super) async fn archive_checkpoint_zk_proof_suffix<Hash: Q256BitHash>(
        &self,
        canonical_head_store: &ScyllaCanonicalHeadStore,
        expected_head: StoredCanonicalHead<Hash>,
        plan: &CoordinatorRollbackArchivePlan<Hash>,
    ) -> Result<CoordinatorRollbackArchiveScanSummary, CoordinatorRollbackArchiveStoreError> {
        validate_archiving_head(expected_head, plan)?;
        self.require_current_head(canonical_head_store, expected_head)
            .await?;

        let network = expected_head.canonical_ref().network_id();
        let chain_epoch = expected_head.canonical_ref().chain_epoch().get();
        let mut checkpoint = plan
            .suffix_start_exclusive()
            .checked_add(1)
            .ok_or(CoordinatorRollbackArchiveStoreError::CheckpointOverflow)?;
        let end = plan.suffix_end_inclusive();
        let mut row_count = 0_u64;
        let mut canonical_bytes = 0_u64;
        let mut dataset = Sha256::new();
        dataset.update(DATASET_DIGEST_DOMAIN);
        dataset.update(plan.digest().as_bytes());

        while checkpoint <= end {
            if let Some(source) = self.read_checkpoint_zk_proof(checkpoint).await? {
                let row = CoordinatorRollbackCheckpointKivArchiveRow::try_checkpoint_zk_proof(
                    network,
                    chain_epoch,
                    plan,
                    checkpoint,
                    source.value.clone(),
                    source.writetime_us,
                )?;
                let receipt = self.persist_exact(row).await?;
                self.revalidate_exact(&receipt).await?;
                let after = self
                    .read_checkpoint_zk_proof(checkpoint)
                    .await?
                    .ok_or(CoordinatorRollbackArchiveStoreError::SourceChanged)?;
                if after != source {
                    return Err(CoordinatorRollbackArchiveStoreError::SourceChanged);
                }
                row_count = row_count
                    .checked_add(1)
                    .ok_or(CoordinatorRollbackArchiveStoreError::LengthOverflow)?;
                canonical_bytes = canonical_bytes
                    .checked_add(receipt.row.canonical_bytes.len() as u64)
                    .ok_or(CoordinatorRollbackArchiveStoreError::LengthOverflow)?;
                dataset.update(receipt.row.slot.as_bytes());
                dataset.update(receipt.row.digest.as_bytes());
            }
            if checkpoint == end {
                break;
            }
            checkpoint = checkpoint
                .checked_add(1)
                .ok_or(CoordinatorRollbackArchiveStoreError::CheckpointOverflow)?;
        }

        self.require_current_head(canonical_head_store, expected_head)
            .await?;
        dataset.update(row_count.to_be_bytes());
        dataset.update(canonical_bytes.to_be_bytes());
        Ok(CoordinatorRollbackArchiveScanSummary {
            row_count,
            canonical_bytes,
            dataset_digest: dataset.finalize().into(),
        })
    }

    async fn require_current_head<Hash: Q256BitHash>(
        &self,
        canonical_head_store: &ScyllaCanonicalHeadStore,
        expected: StoredCanonicalHead<Hash>,
    ) -> Result<(), CoordinatorRollbackArchiveStoreError> {
        match canonical_head_store
            .read(expected.canonical_ref().network_id())
            .await
            .map_err(|error| CoordinatorRollbackArchiveStoreError::CanonicalHead(error.to_string()))?
        {
            CanonicalHeadReadState::Current(current) if current == expected => Ok(()),
            _ => Err(CoordinatorRollbackArchiveStoreError::CanonicalHeadChanged),
        }
    }

    async fn read_checkpoint_zk_proof(
        &self,
        checkpoint: u64,
    ) -> Result<Option<CheckpointKivSourceRow>, CoordinatorRollbackArchiveStoreError> {
        let checkpoint = i64::try_from(checkpoint)
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let row = self
            .session
            .execute_unpaged(&self.read_checkpoint_zk_proof, (checkpoint,))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
            .map_err(cql)?;
        let Some((value, writetime_us)) = row else {
            return Ok(None);
        };
        Ok(Some(CheckpointKivSourceRow {
            value: value.ok_or(CoordinatorRollbackArchiveStoreError::MissingSourceColumn)?,
            writetime_us: writetime_us
                .ok_or(CoordinatorRollbackArchiveStoreError::MissingSourceColumn)?,
        }))
    }

    async fn persist_exact(
        &self,
        row: CoordinatorRollbackCheckpointKivArchiveRow,
    ) -> Result<PersistedCoordinatorRollbackArchiveRowReceipt, CoordinatorRollbackArchiveStoreError> {
        let fragments = row.fragments()?;
        let network = i64::from(row.network.chain_id());
        let chain_epoch = i64::try_from(row.chain_epoch)
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let key_domain = i16::try_from(row.key_domain.stable_id())
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let participant = row.participant_plan_digest.as_bytes();
        for fragment in &fragments {
            let execution = self
                .session
                .execute_unpaged(
                    &self.insert,
                    (
                        network,
                        chain_epoch,
                        participant.as_slice(),
                        key_domain,
                        row.slot.as_bytes().as_slice(),
                        fragment.index,
                        ARCHIVE_REVISION,
                        fragment.count,
                        fragment.row_bytes,
                        fragment.payload.as_slice(),
                        fragment.payload_digest.as_slice(),
                        fragment.row_digest.as_bytes().as_slice(),
                    ),
                )
                .await;
            match execution {
                Ok(result) => {
                    if !decode_applied(result)? {
                        let current = self.read_fragment(&row, fragment.index).await?;
                        if current.as_ref() != Some(fragment) {
                            return Err(CoordinatorRollbackArchiveStoreError::Conflict);
                        }
                    }
                }
                Err(error) => {
                    let current = self.read_fragment(&row, fragment.index).await;
                    match current {
                        Ok(Some(current)) if current == *fragment => {}
                        Ok(_) => {
                            return Err(CoordinatorRollbackArchiveStoreError::Indeterminate(
                                error.to_string(),
                            ));
                        }
                        Err(read) => {
                            return Err(CoordinatorRollbackArchiveStoreError::Indeterminate(
                                format!("execute={error}; read={read}"),
                            ));
                        }
                    }
                }
            }
        }
        let current = self
            .read_exact_row(&row)
            .await?
            .ok_or(CoordinatorRollbackArchiveStoreError::MissingAfterPersist)?;
        if current != row {
            return Err(CoordinatorRollbackArchiveStoreError::Conflict);
        }
        Ok(PersistedCoordinatorRollbackArchiveRowReceipt {
            store_fingerprint: self.fingerprint,
            row: current,
        })
    }

    async fn revalidate_exact(
        &self,
        receipt: &PersistedCoordinatorRollbackArchiveRowReceipt,
    ) -> Result<(), CoordinatorRollbackArchiveStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(CoordinatorRollbackArchiveStoreError::ReceiptBindingMismatch);
        }
        match self.read_exact_row(&receipt.row).await? {
            Some(current) if current == receipt.row => Ok(()),
            _ => Err(CoordinatorRollbackArchiveStoreError::ReceiptStale),
        }
    }

    async fn read_fragment(
        &self,
        row: &CoordinatorRollbackCheckpointKivArchiveRow,
        index: i32,
    ) -> Result<Option<CoordinatorRollbackArchiveFragment>, CoordinatorRollbackArchiveStoreError> {
        let network = i64::from(row.network.chain_id());
        let chain_epoch = i64::try_from(row.chain_epoch)
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let key_domain = i16::try_from(row.key_domain.stable_id())
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let participant = row.participant_plan_digest.as_bytes();
        let result = self
            .session
            .execute_unpaged(
                &self.read_fragment,
                (
                    network,
                    chain_epoch,
                    participant.as_slice(),
                    key_domain,
                    row.slot.as_bytes().as_slice(),
                    index,
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(
                Option<i64>,
                Option<i32>,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        result
            .map(|tuple| decode_fragment(index, tuple))
            .transpose()
    }

    async fn read_exact_row(
        &self,
        expected: &CoordinatorRollbackCheckpointKivArchiveRow,
    ) -> Result<Option<CoordinatorRollbackCheckpointKivArchiveRow>, CoordinatorRollbackArchiveStoreError> {
        let network = i64::from(expected.network.chain_id());
        let chain_epoch = i64::try_from(expected.chain_epoch)
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let key_domain = i16::try_from(expected.key_domain.stable_id())
            .map_err(|_| CoordinatorRollbackArchiveStoreError::IntegerOutOfCqlRange)?;
        let participant = expected.participant_plan_digest.as_bytes();
        let rows_result = self
            .session
            .execute_unpaged(
                &self.read_row,
                (
                    network,
                    chain_epoch,
                    participant.as_slice(),
                    key_domain,
                    expected.slot.as_bytes().as_slice(),
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?;
        let rows = rows_result
            .rows::<(
                Option<i32>,
                Option<i64>,
                Option<i32>,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let mut fragments = Vec::new();
        for row in rows {
            let (index, revision, count, row_bytes, payload, payload_digest, row_digest) =
                row.map_err(cql)?;
            let index = index.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?;
            fragments.push(decode_fragment(
                index,
                (revision, count, row_bytes, payload, payload_digest, row_digest),
            )?);
        }
        if fragments.is_empty() {
            return Ok(None);
        }
        let reconstructed = reconstruct_fragments(fragments)?;
        let row = CoordinatorRollbackCheckpointKivArchiveRow::decode_canonical(&reconstructed)?;
        if row.slot != expected.slot
            || row.network != expected.network
            || row.chain_epoch != expected.chain_epoch
            || row.participant_plan_digest != expected.participant_plan_digest
            || row.key_domain != expected.key_domain
        {
            return Err(CoordinatorRollbackArchiveStoreError::SelectedRowMismatch);
        }
        Ok(Some(row))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckpointKivSourceRow {
    value: Vec<u8>,
    writetime_us: i64,
}

fn decode_fragment(
    index: i32,
    tuple: (
        Option<i64>,
        Option<i32>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ),
) -> Result<CoordinatorRollbackArchiveFragment, CoordinatorRollbackArchiveStoreError> {
    let (revision, count, row_bytes, payload, payload_digest, row_digest) = tuple;
    if revision != Some(ARCHIVE_REVISION) {
        return Err(CoordinatorRollbackArchiveStoreError::InvalidArchiveRevision);
    }
    let payload = payload.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?;
    let payload_digest = array_32(
        payload_digest.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?,
    )?;
    if payload_digest != fragment_digest(index, &payload) {
        return Err(CoordinatorRollbackArchiveStoreError::FragmentDigestMismatch);
    }
    Ok(CoordinatorRollbackArchiveFragment {
        index,
        count: count.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?,
        row_bytes: row_bytes.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?,
        payload,
        payload_digest,
        row_digest: CoordinatorRollbackArchiveRowDigest(array_32(
            row_digest.ok_or(CoordinatorRollbackArchiveStoreError::MissingArchiveColumn)?,
        )?),
    })
}

fn reconstruct_fragments(
    mut fragments: Vec<CoordinatorRollbackArchiveFragment>,
) -> Result<Vec<u8>, CoordinatorRollbackArchiveStoreError> {
    fragments.sort_by_key(|fragment| fragment.index);
    let first = fragments
        .first()
        .ok_or(CoordinatorRollbackArchiveStoreError::MissingAfterPersist)?;
    let expected_count = usize::try_from(first.count)
        .map_err(|_| CoordinatorRollbackArchiveStoreError::InvalidFragmentSet)?;
    let expected_bytes = usize::try_from(first.row_bytes)
        .map_err(|_| CoordinatorRollbackArchiveStoreError::InvalidFragmentSet)?;
    if expected_count == 0
        || expected_count > MAX_FRAGMENTS
        || expected_count != fragments.len()
        || expected_bytes > MAX_CANONICAL_ROW_BYTES
    {
        return Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet);
    }
    let expected_digest = first.row_digest;
    let mut bytes = Vec::with_capacity(expected_bytes);
    for (expected_index, fragment) in fragments.iter().enumerate() {
        if fragment.index != expected_index as i32
            || fragment.count != first.count
            || fragment.row_bytes != first.row_bytes
            || fragment.row_digest != expected_digest
            || fragment.payload.is_empty()
            || fragment.payload.len() > MAX_FRAGMENT_BYTES
            || fragment.payload_digest != fragment_digest(fragment.index, &fragment.payload)
        {
            return Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet);
        }
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() != expected_bytes {
        return Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet);
    }
    if bytes.len() < 32
        || row_digest(&bytes[..bytes.len() - 32]) != expected_digest
        || bytes[bytes.len() - 32..] != *expected_digest.as_bytes()
    {
        return Err(CoordinatorRollbackArchiveStoreError::RowDigestMismatch);
    }
    Ok(bytes)
}

fn validate_archiving_head<Hash: Q256BitHash>(
    head: StoredCanonicalHead<Hash>,
    plan: &CoordinatorRollbackArchivePlan<Hash>,
) -> Result<(), CoordinatorRollbackArchiveStoreError> {
    match head.rollback_control() {
        RollbackControlState::Archiving(request)
            if request == plan.request()
                && head.canonical_ref().checkpoint() == request.requested_head() =>
        {
            Ok(())
        }
        _ => Err(CoordinatorRollbackArchiveStoreError::NotExactArchivingHead),
    }
}

fn require_standard_keyspace(
    keyspace: &CqlKeyspaceName,
) -> Result<(), CoordinatorRollbackArchiveStoreError> {
    if keyspace.as_str().ends_with("_nt") || keyspace.as_str().ends_with("_no_tablet") {
        Err(CoordinatorRollbackArchiveStoreError::TabletKeyspaceRequired)
    } else {
        Ok(())
    }
}

fn store_fingerprint(
    archive: &CqlKeyspaceName,
    source: &CqlKeyspaceName,
    queries: &CoordinatorRollbackArchiveQueries,
) -> CoordinatorRollbackArchiveStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((archive.as_str().len() as u64).to_be_bytes());
    hasher.update(archive.as_str().as_bytes());
    hasher.update((source.as_str().len() as u64).to_be_bytes());
    hasher.update(source.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    CoordinatorRollbackArchiveStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorRollbackArchiveStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorRollbackArchiveStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, CoordinatorRollbackArchiveStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorRollbackArchiveStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(CoordinatorRollbackArchiveStoreError::InvalidAppliedColumn),
    }
}

fn array_32(bytes: Vec<u8>) -> Result<[u8; 32], CoordinatorRollbackArchiveStoreError> {
    bytes
        .try_into()
        .map_err(|_| CoordinatorRollbackArchiveStoreError::InvalidDigestLength)
}

fn cql(error: impl fmt::Display) -> CoordinatorRollbackArchiveStoreError {
    CoordinatorRollbackArchiveStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorRollbackArchiveRowError {
    InvalidMagic,
    UnknownVersion(u16),
    Network(String),
    PlanDigest(CoordinatorRollbackArchivePlanDigestError),
    ZeroGlobalPlanDigest,
    UnknownKeyDomain(u16),
    UnknownPhysicalTable(u16),
    UnknownAction(u8),
    DomainNotPlanned,
    DomainContractMismatch,
    InvalidRollbackRange,
    SourceOutsideSuffix,
    WriteAfterOrphanFence {
        writetime_us: i64,
        orphan_write_max_us: i64,
    },
    IntegerOutOfCqlRange,
    LengthOverflow,
    RowTooLarge { actual: usize, maximum: usize },
    InvalidFragmentCount(usize),
    Truncated,
    DigestMismatch,
    RowSlotMismatch,
    TrailingBytes,
}

impl From<CoordinatorRollbackArchivePlanDigestError>
    for CoordinatorRollbackArchiveRowError
{
    fn from(value: CoordinatorRollbackArchivePlanDigestError) -> Self {
        Self::PlanDigest(value)
    }
}

impl fmt::Display for CoordinatorRollbackArchiveRowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator rollback archive row: {self:?}")
    }
}

impl Error for CoordinatorRollbackArchiveRowError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorRollbackArchiveStoreError {
    Cql(String),
    Row(CoordinatorRollbackArchiveRowError),
    CanonicalHead(String),
    CanonicalHeadChanged,
    NotExactArchivingHead,
    TabletKeyspaceRequired,
    CheckpointOverflow,
    IntegerOutOfCqlRange,
    LengthOverflow,
    MissingSourceColumn,
    SourceChanged,
    MissingArchiveColumn,
    InvalidArchiveRevision,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    InvalidDigestLength,
    FragmentDigestMismatch,
    RowDigestMismatch,
    InvalidFragmentSet,
    MissingAfterPersist,
    SelectedRowMismatch,
    Conflict,
    ReceiptBindingMismatch,
    ReceiptStale,
    Indeterminate(String),
}

impl From<CoordinatorRollbackArchiveRowError>
    for CoordinatorRollbackArchiveStoreError
{
    fn from(value: CoordinatorRollbackArchiveRowError) -> Self {
        Self::Row(value)
    }
}

impl fmt::Display for CoordinatorRollbackArchiveStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator rollback archive store error: {self:?}")
    }
}

impl Error for CoordinatorRollbackArchiveStoreError {}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorRollbackArchiveRowError> {
        if self.remaining.len() < len {
            return Err(CoordinatorRollbackArchiveRowError::Truncated);
        }
        let (head, tail) = self.remaining.split_at(len);
        self.remaining = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorRollbackArchiveRowError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorRollbackArchiveRowError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed length"),
        ))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorRollbackArchiveRowError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed length"),
        ))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorRollbackArchiveRowError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed length"),
        ))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorRollbackArchiveRowError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed length"),
        ))
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorRollbackArchiveRowError> {
        Ok(self.take(32)?.try_into().expect("fixed length"))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::{
        rollback_control::{RollbackExecutionMode, RollbackPlanDigest, RollbackRequest},
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
            )),
        )
    }

    fn plan() -> CoordinatorRollbackArchivePlan<PHash> {
        CoordinatorRollbackArchivePlan::resolve(
            RollbackRequest::try_new(
                checkpoint(100, 10),
                checkpoint(90, 20),
                TimestampFenceWindow::try_new(
                    CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                    1_001,
                    1_002,
                )
                .unwrap(),
                RollbackExecutionMode::InPlace,
                RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
            )
            .unwrap(),
        )
    }

    fn row(value: Vec<u8>) -> CoordinatorRollbackCheckpointKivArchiveRow {
        CoordinatorRollbackCheckpointKivArchiveRow::try_checkpoint_zk_proof(
            NetworkId::try_from_chain_id(1).unwrap(),
            7,
            &plan(),
            95,
            value,
            999,
        )
        .unwrap()
    }

    #[test]
    fn archive_row_roundtrip_and_slot_bind_source_pk_not_content() {
        let first = row(vec![7; MAX_FRAGMENT_BYTES + 31]);
        let second = row(vec![8; MAX_FRAGMENT_BYTES + 31]);
        assert_eq!(first.slot, second.slot);
        assert_ne!(first.digest, second.digest);
        assert_eq!(
            CoordinatorRollbackCheckpointKivArchiveRow::decode_canonical(
                &first.canonical_bytes
            )
            .unwrap(),
            first
        );
        assert_eq!(first.fragments().unwrap().len(), 2);
    }

    #[test]
    fn structurally_forged_rehashed_slot_is_rejected() {
        let row = row(vec![1, 2, 3]);
        let mut bytes = row.canonical_bytes.clone();
        let slot_start = bytes.len() - 32 - 32;
        bytes[slot_start] ^= 0x80;
        let digest = row_digest(&bytes[..bytes.len() - 32]);
        let len = bytes.len();
        bytes[len - 32..].copy_from_slice(digest.as_bytes());
        assert_eq!(
            CoordinatorRollbackCheckpointKivArchiveRow::decode_canonical(&bytes),
            Err(CoordinatorRollbackArchiveRowError::RowSlotMismatch)
        );
    }

    #[test]
    fn out_of_suffix_and_post_fence_rows_fail_closed() {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        assert!(matches!(
            CoordinatorRollbackCheckpointKivArchiveRow::try_checkpoint_zk_proof(
                network,
                7,
                &plan(),
                90,
                vec![1],
                999,
            ),
            Err(CoordinatorRollbackArchiveRowError::SourceOutsideSuffix)
        ));
        assert!(matches!(
            CoordinatorRollbackCheckpointKivArchiveRow::try_checkpoint_zk_proof(
                network,
                7,
                &plan(),
                91,
                vec![1],
                1_001,
            ),
            Err(CoordinatorRollbackArchiveRowError::WriteAfterOrphanFence { .. })
        ));
    }

    #[test]
    fn fragment_reconstruction_rejects_missing_extra_and_corrupt() {
        let row = row(vec![3; MAX_FRAGMENT_BYTES + 17]);
        let fragments = row.fragments().unwrap();
        assert_eq!(
            CoordinatorRollbackCheckpointKivArchiveRow::decode_canonical(
                &reconstruct_fragments(fragments.clone()).unwrap()
            )
            .unwrap(),
            row
        );
        assert_eq!(
            reconstruct_fragments(vec![fragments[0].clone()]),
            Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet)
        );
        let mut corrupt = fragments.clone();
        corrupt[1].payload[0] ^= 1;
        assert_eq!(
            reconstruct_fragments(corrupt),
            Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet)
        );
        let mut extra = fragments.clone();
        extra.push(fragments[1].clone());
        assert_eq!(
            reconstruct_fragments(extra),
            Err(CoordinatorRollbackArchiveStoreError::InvalidFragmentSet)
        );
    }

    #[test]
    fn cql_is_append_only_lwt_and_source_read_is_exact_kiv_point_read() {
        let archive = CqlKeyspaceName::try_new("rollback_archive").unwrap();
        let source = CqlKeyspaceName::try_new("coordinator_state").unwrap();
        let queries = CoordinatorRollbackArchiveQueries::new(&archive, &source);
        assert!(queries.create.contains("CREATE TABLE IF NOT EXISTS rollback_archive.coordinator_rollback_suffix_archive_v1"));
        assert!(queries.insert.contains("IF NOT EXISTS"));
        assert!(!queries.insert.contains("USING TIMESTAMP"));
        assert!(!queries.golden().contains("DELETE FROM"));
        assert!(!queries.golden().contains("UPDATE "));
        assert_eq!(
            queries.read_checkpoint_zk_proof,
            "SELECT value, WRITETIME(value) FROM coordinator_state.checkpoint_zk_proof_and_transition_table WHERE obj_id = ?"
        );
    }

    #[test]
    fn archive_store_requires_tablet_keyspaces() {
        assert!(require_standard_keyspace(
            &CqlKeyspaceName::try_new("rollback_archive").unwrap()
        )
        .is_ok());
        assert_eq!(
            require_standard_keyspace(
                &CqlKeyspaceName::try_new("rollback_archive_nt").unwrap()
            ),
            Err(CoordinatorRollbackArchiveStoreError::TabletKeyspaceRequired)
        );
    }
}
