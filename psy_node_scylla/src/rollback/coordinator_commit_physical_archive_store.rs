//! Exact hot-row reader and immutable archive adapter for a floor-bound
//! Coordinator physical catalog.
//!
//! This remains pre-PONR. The row adapter can copy one selected before-image;
//! the affine owner composes the complete storage-selected catalog and returns
//! an in-memory participant receipt only after exact source/archive readback
//! and canonical-head/catalog fencing. Neither receipt is durable barrier
//! authority, and this module cannot delete, restore, or mutate the head.

#![allow(dead_code)]

use std::{
    collections::BTreeMap, error::Error, fmt, sync::Arc,
};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, NetworkId,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::{RollbackControlState, RollbackExecutionMode},
    typed::{CheckpointedObjectKey, TypedTableKey},
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::utils::{u64_to_i64_exact, u8_to_i8_exact};

use super::{
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    CanonicalHeadPrototypeError,
    CoordinatorCommitPhysicalBeforeImage,
    CoordinatorCommitPhysicalBeforeImageError, CoordinatorCommitPhysicalCatalog,
    CoordinatorCommitPhysicalReadSpec, CoordinatorCommitPhysicalSourceCell,
    CoordinatorCommitPhysicalSourceObservation, CqlKeyspaceName,
    ResolvedScyllaKey, ScyllaCanonicalHeadStore,
    ScyllaCoordinatorCommitSourceStore, ScyllaPhysicalTableId,
    ScyllaSchemaFamily,
};

const ARCHIVE_REVISION: i64 = 1;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-archive-store.v1\0";
const FRAGMENT_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-before-image-fragment.v1\0";
const PARTICIPANT_DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-archive-participant.v1\0";

const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, chain_epoch bigint, participant_plan_digest blob, key_domain smallint, row_slot blob, fragment_index int, revision bigint, fragment_count int, row_bytes bigint, fragment_payload blob, fragment_digest blob, row_digest blob, PRIMARY KEY ((network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_ROW_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ? AND fragment_index = ?";

/// Storage-selected scope for the discarded old epoch. The active canonical
/// head is already in the next epoch, while every catalog row belongs to the
/// immediately preceding epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorCommitPhysicalArchiveScope<Hash> {
    archiving_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    old_head: CanonicalChainRef<Hash>,
}

/// Small, non-authoritative commitment fed directly into the participant
/// dataset hash. The full before-image is dropped after each row and
/// reconstructed from storage during the second pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorCommitPhysicalArchivedRow {
    slot: [u8; 32],
    digest: [u8; 32],
}

impl<Hash: Q256BitHash>
    From<&PersistedCoordinatorCommitPhysicalBeforeImage<Hash>>
    for CoordinatorCommitPhysicalArchivedRow
{
    fn from(receipt: &PersistedCoordinatorCommitPhysicalBeforeImage<Hash>) -> Self {
        Self {
            slot: *receipt.slot(),
            digest: *receipt.digest(),
        }
    }
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalArchiveScope<Hash> {
    fn try_from_head(
        head: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalArchiveOwnerError> {
        let request = match head.rollback_control() {
            RollbackControlState::Archiving(request) => *request,
            _ => {
                return Err(
                    CoordinatorCommitPhysicalArchiveOwnerError::NotExactArchivingHead,
                );
            }
        };
        if request.execution_mode() != RollbackExecutionMode::InPlace
            || head.canonical_ref().checkpoint() != request.requested_head()
        {
            return Err(
                CoordinatorCommitPhysicalArchiveOwnerError::NotExactArchivingHead,
            );
        }
        let active_epoch = head.canonical_ref().chain_epoch().get();
        let old_epoch = active_epoch
            .checked_sub(1)
            .ok_or(CoordinatorCommitPhysicalArchiveOwnerError::EpochUnderflow)?;
        let network = head.canonical_ref().network_id();
        Ok(Self {
            archiving_head: head,
            target: CanonicalChainRef::new(
                network,
                ChainEpoch::new(old_epoch),
                *request.target(),
            ),
            old_head: CanonicalChainRef::new(
                network,
                ChainEpoch::new(old_epoch),
                *request.requested_head(),
            ),
        })
    }
}

/// Non-clone, storage-private proof that every row in one exact Coordinator
/// catalog was archived and revalidated while the control head stayed at the
/// same ARCHIVING payload. This remains pre-barrier and grants no deletion.
#[derive(Debug)]
pub(crate) struct CoordinatorCommitPhysicalParticipantArchiveReceipt<Hash> {
    archiving_head: StoredCanonicalHead<Hash>,
    catalog_digest: [u8; 32],
    entry_count: u64,
    dataset_digest: [u8; 32],
    archive_store_fingerprint: [u8; 32],
}

impl<Hash> CoordinatorCommitPhysicalParticipantArchiveReceipt<Hash> {
    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub(crate) const fn dataset_digest(&self) -> &[u8; 32] {
        &self.dataset_digest
    }
}

/// Affine composition boundary for the whole Coordinator catalog. Callers do
/// not provide target/head/catalog entries or row values; all are selected
/// from the canonical head and commit-source stores.
pub(crate) struct ScyllaCoordinatorCommitPhysicalArchiveOwner {
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
    archive_keyspace: CqlKeyspaceName,
    source_keyspace: CqlKeyspaceName,
    checkpoint_tree_height: u8,
}

impl ScyllaCoordinatorCommitPhysicalArchiveOwner {
    pub(crate) fn new(
        session: Arc<Session>,
        canonical_head: Arc<ScyllaCanonicalHeadStore>,
        commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
        archive_keyspace: CqlKeyspaceName,
        source_keyspace: CqlKeyspaceName,
        checkpoint_tree_height: u8,
    ) -> Self {
        Self {
            session,
            canonical_head,
            commit_sources,
            archive_keyspace,
            source_keyspace,
            checkpoint_tree_height,
        }
    }

    pub(crate) async fn archive_current_request<F, Hash, Hasher>(
        &mut self,
        network: NetworkId,
    ) -> Result<
        CoordinatorCommitPhysicalParticipantArchiveReceipt<Hash>,
        CoordinatorCommitPhysicalArchiveOwnerError,
    >
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let scope = self.read_scope::<Hash>(network).await?;
        let catalog = self.scan_catalog::<F, Hash, Hasher>(&scope).await?;
        let store = ScyllaCoordinatorCommitPhysicalArchiveStore::prepare_for_catalog(
            self.session.clone(),
            self.archive_keyspace.clone(),
            self.source_keyspace.clone(),
            &catalog,
        )
        .await?;

        let entry_count = u64::try_from(catalog.entries().len())
            .map_err(|_| CoordinatorCommitPhysicalArchiveOwnerError::LengthOverflow)?;
        let mut first_dataset = participant_dataset_hasher(
            &scope,
            &catalog,
            entry_count,
            &store.fingerprint,
        );
        for index in 0..catalog.entries().len() {
            let receipt = store
                .persist_catalog_entry_and_readback(&catalog, index)
                .await?;
            if receipt.before_image.key().locator_bytes()
                != catalog.entries()[index].key().locator_bytes()
            {
                return Err(
                    CoordinatorCommitPhysicalArchiveOwnerError::EntryReceiptMismatch,
                );
            }
            update_participant_dataset(
                &mut first_dataset,
                index,
                CoordinatorCommitPhysicalArchivedRow::from(&receipt),
            )?;
        }
        let dataset_digest: [u8; 32] = first_dataset.finalize().into();

        self.require_catalog_and_head_unchanged::<F, Hash, Hasher>(
            &scope,
            &catalog,
        )
        .await?;
        let mut second_dataset = participant_dataset_hasher(
            &scope,
            &catalog,
            entry_count,
            &store.fingerprint,
        );
        for index in 0..catalog.entries().len() {
            let row = store.revalidate_catalog_entry(&catalog, index).await?;
            update_participant_dataset(&mut second_dataset, index, row)?;
        }
        if <[u8; 32]>::from(second_dataset.finalize()) != dataset_digest {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::ArchiveRowChanged);
        }
        self.require_catalog_and_head_unchanged::<F, Hash, Hasher>(
            &scope,
            &catalog,
        )
        .await?;

        Ok(CoordinatorCommitPhysicalParticipantArchiveReceipt {
            archiving_head: scope.archiving_head,
            catalog_digest: *catalog.digest(),
            entry_count,
            dataset_digest,
            archive_store_fingerprint: store.fingerprint,
        })
    }

    pub(crate) async fn revalidate_participant_receipt<F, Hash, Hasher>(
        &mut self,
        network: NetworkId,
        receipt: &CoordinatorCommitPhysicalParticipantArchiveReceipt<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveOwnerError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let scope = self.read_scope::<Hash>(network).await?;
        if scope.archiving_head != receipt.archiving_head {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::HeadChanged);
        }
        let catalog = self.scan_catalog::<F, Hash, Hasher>(&scope).await?;
        let entry_count = u64::try_from(catalog.entries().len())
            .map_err(|_| CoordinatorCommitPhysicalArchiveOwnerError::LengthOverflow)?;
        if catalog.digest() != &receipt.catalog_digest
            || entry_count != receipt.entry_count
        {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::CatalogChanged);
        }
        let store = ScyllaCoordinatorCommitPhysicalArchiveStore::prepare_for_catalog(
            self.session.clone(),
            self.archive_keyspace.clone(),
            self.source_keyspace.clone(),
            &catalog,
        )
        .await?;
        if store.fingerprint != receipt.archive_store_fingerprint {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::ReceiptBindingMismatch);
        }
        let mut dataset = participant_dataset_hasher(
            &scope,
            &catalog,
            entry_count,
            &store.fingerprint,
        );
        for index in 0..catalog.entries().len() {
            let row = store.revalidate_catalog_entry(&catalog, index).await?;
            update_participant_dataset(&mut dataset, index, row)?;
        }
        self.require_catalog_and_head_unchanged::<F, Hash, Hasher>(
            &scope,
            &catalog,
        )
        .await?;
        if <[u8; 32]>::from(dataset.finalize()) != receipt.dataset_digest {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::DatasetChanged);
        }
        Ok(())
    }

    async fn read_scope<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
    ) -> Result<CoordinatorCommitPhysicalArchiveScope<Hash>, CoordinatorCommitPhysicalArchiveOwnerError>
    {
        match self.canonical_head.read(network).await? {
            CanonicalHeadReadState::Current(head) => {
                CoordinatorCommitPhysicalArchiveScope::try_from_head(head)
            }
            CanonicalHeadReadState::Uninitialized => {
                Err(CoordinatorCommitPhysicalArchiveOwnerError::HeadMissing)
            }
        }
    }

    async fn scan_catalog<F, Hash, Hasher>(
        &self,
        scope: &CoordinatorCommitPhysicalArchiveScope<Hash>,
    ) -> Result<CoordinatorCommitPhysicalCatalog<Hash>, CoordinatorCommitPhysicalArchiveOwnerError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        self.commit_sources
            .scan_floor_bound_physical_catalog::<F, Hash, Hasher>(
                &scope.target,
                &scope.old_head,
                self.checkpoint_tree_height,
            )
            .await
            .map_err(|error| {
                CoordinatorCommitPhysicalArchiveOwnerError::CommitSource(
                    error.to_string(),
                )
            })
    }

    async fn require_catalog_and_head_unchanged<F, Hash, Hasher>(
        &self,
        scope: &CoordinatorCommitPhysicalArchiveScope<Hash>,
        expected: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveOwnerError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let current_catalog = self.scan_catalog::<F, Hash, Hasher>(scope).await?;
        if &current_catalog != expected {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::CatalogChanged);
        }
        let current_scope = self
            .read_scope::<Hash>(scope.archiving_head.canonical_ref().network_id())
            .await?;
        if current_scope != *scope {
            return Err(CoordinatorCommitPhysicalArchiveOwnerError::HeadChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorCommitPhysicalArchiveQueries {
    create: String,
    insert: String,
    read_row: String,
    read_fragment: String,
    source_reads: BTreeMap<ScyllaPhysicalTableId, CoordinatorCommitPhysicalReadSpec>,
}

impl CoordinatorCommitPhysicalArchiveQueries {
    fn try_for_catalog<Hash: Q256BitHash>(
        archive_keyspace: &CqlKeyspaceName,
        source_keyspace: &CqlKeyspaceName,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalArchiveStoreError> {
        let archive_table = format!(
            "{}.{}",
            archive_keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        let mut source_reads = BTreeMap::new();
        for entry in catalog.entries() {
            let key = entry.key();
            let spec = CoordinatorCommitPhysicalReadSpec::try_for_key(
                source_keyspace,
                key,
            )?;
            let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(key)?;
            if binding.shape() != spec.bind_shape() {
                return Err(
                    CoordinatorCommitPhysicalArchiveStoreError::BindingShapeMismatch,
                );
            }
            match source_reads.entry(key.physical_table()) {
                std::collections::btree_map::Entry::Vacant(vacant) => {
                    vacant.insert(spec);
                }
                std::collections::btree_map::Entry::Occupied(occupied)
                    if occupied.get() != &spec =>
                {
                    return Err(
                        CoordinatorCommitPhysicalArchiveStoreError::QueryShapeConflict,
                    );
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
        Ok(Self {
            create: CREATE_TEMPLATE.replace("{table}", &archive_table),
            insert: INSERT_TEMPLATE.replace("{table}", &archive_table),
            read_row: READ_ROW_TEMPLATE.replace("{table}", &archive_table),
            read_fragment: READ_FRAGMENT_TEMPLATE.replace("{table}", &archive_table),
            source_reads,
        })
    }
}

struct PreparedCoordinatorCommitPhysicalRead {
    table: ScyllaPhysicalTableId,
    spec: CoordinatorCommitPhysicalReadSpec,
    statement: PreparedStatement,
}

/// Catalog-bound storage adapter. Preparing it requires the complete
/// storage-selected catalog, so it cannot be reused with a caller-selected
/// key set or a different rollback floor.
pub(crate) struct ScyllaCoordinatorCommitPhysicalArchiveStore {
    session: Arc<Session>,
    catalog_digest: [u8; 32],
    fingerprint: [u8; 32],
    source_reads: Vec<PreparedCoordinatorCommitPhysicalRead>,
    insert: PreparedStatement,
    read_row: PreparedStatement,
    read_fragment: PreparedStatement,
}

/// Private, non-clone row-level proof of exact immutable persistence. It is
/// deliberately insufficient for participant completion or PONR.
#[derive(Debug)]
pub(crate) struct PersistedCoordinatorCommitPhysicalBeforeImage<Hash> {
    store_fingerprint: [u8; 32],
    before_image: CoordinatorCommitPhysicalBeforeImage<Hash>,
}

impl<Hash: Q256BitHash> PersistedCoordinatorCommitPhysicalBeforeImage<Hash> {
    pub(crate) const fn slot(&self) -> &[u8; 32] {
        self.before_image.slot()
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        self.before_image.digest()
    }
}

impl ScyllaCoordinatorCommitPhysicalArchiveStore {
    pub(crate) async fn create_schema(
        session: &Session,
        archive_keyspace: &CqlKeyspaceName,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveStoreError> {
        let table = format!(
            "{}.{}",
            archive_keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        session
            .query_unpaged(CREATE_TEMPLATE.replace("{table}", &table), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare_for_catalog<Hash: Q256BitHash>(
        session: Arc<Session>,
        archive_keyspace: CqlKeyspaceName,
        source_keyspace: CqlKeyspaceName,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalArchiveStoreError> {
        let queries = CoordinatorCommitPhysicalArchiveQueries::try_for_catalog(
            &archive_keyspace,
            &source_keyspace,
            catalog,
        )?;
        let mut source_reads = Vec::with_capacity(queries.source_reads.len());
        for (table, spec) in &queries.source_reads {
            source_reads.push(PreparedCoordinatorCommitPhysicalRead {
                table: *table,
                spec: spec.clone(),
                statement: prepare_read(&session, spec.cql()).await?,
            });
        }
        Ok(Self {
            fingerprint: store_fingerprint(
                &archive_keyspace,
                &source_keyspace,
                catalog.digest(),
                &queries,
            ),
            catalog_digest: *catalog.digest(),
            source_reads,
            insert: prepare_lwt(&session, &queries.insert).await?,
            read_row: prepare_read(&session, &queries.read_row).await?,
            read_fragment: prepare_read(&session, &queries.read_fragment).await?,
            session,
        })
    }

    /// Read A -> immutable IFNE archive + exact readback -> read B. An error
    /// after the LWT is commit-indeterminate and callers must retry the same
    /// catalog entry; immutable identity makes that retry safe.
    pub(crate) async fn persist_catalog_entry_and_readback<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        entry_index: usize,
    ) -> Result<
        PersistedCoordinatorCommitPhysicalBeforeImage<Hash>,
        CoordinatorCommitPhysicalArchiveStoreError,
    > {
        self.require_catalog(catalog)?;
        let entry = catalog.entries().get(entry_index).ok_or(
            CoordinatorCommitPhysicalArchiveStoreError::CatalogEntryMissing,
        )?;
        let first = self.read_source(entry.key()).await?;
        let expected = CoordinatorCommitPhysicalBeforeImage::try_from_catalog_entry(
            catalog,
            entry_index,
            first.clone(),
        )?;
        self.persist_exact(catalog, &expected).await?;
        let current = self
            .read_archive_exact(catalog, &expected)
            .await?
            .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingAfterPersist)?;
        if current != expected {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::Conflict);
        }
        let second = self.read_source(entry.key()).await?;
        if second != first {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::SourceChanged);
        }
        Ok(PersistedCoordinatorCommitPhysicalBeforeImage {
            store_fingerprint: self.fingerprint,
            before_image: current,
        })
    }

    pub(crate) async fn revalidate_exact<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        receipt: &PersistedCoordinatorCommitPhysicalBeforeImage<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveStoreError> {
        self.require_catalog(catalog)?;
        if receipt.store_fingerprint != self.fingerprint
            || receipt.before_image.catalog_digest() != catalog.digest()
        {
            return Err(
                CoordinatorCommitPhysicalArchiveStoreError::ReceiptBindingMismatch,
            );
        }
        match self
            .read_archive_exact(catalog, &receipt.before_image)
            .await?
        {
            Some(current) if current == receipt.before_image => {}
            _ => return Err(CoordinatorCommitPhysicalArchiveStoreError::ReceiptStale),
        }
        let source = self.read_source(receipt.before_image.key()).await?;
        if &source != receipt.before_image.observation() {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::SourceChanged);
        }
        Ok(())
    }

    async fn revalidate_catalog_entry<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        entry_index: usize,
    ) -> Result<CoordinatorCommitPhysicalArchivedRow, CoordinatorCommitPhysicalArchiveStoreError>
    {
        self.require_catalog(catalog)?;
        let entry = catalog.entries().get(entry_index).ok_or(
            CoordinatorCommitPhysicalArchiveStoreError::CatalogEntryMissing,
        )?;
        let source = self.read_source(entry.key()).await?;
        let expected = CoordinatorCommitPhysicalBeforeImage::try_from_catalog_entry(
            catalog,
            entry_index,
            source,
        )?;
        match self.read_archive_exact(catalog, &expected).await? {
            Some(current) if current == expected => {
                Ok(CoordinatorCommitPhysicalArchivedRow {
                    slot: *current.slot(),
                    digest: *current.digest(),
                })
            }
            Some(_) => Err(CoordinatorCommitPhysicalArchiveStoreError::Conflict),
            None => Err(CoordinatorCommitPhysicalArchiveStoreError::MissingAfterPersist),
        }
    }

    fn require_catalog<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveStoreError> {
        if self.catalog_digest != *catalog.digest() {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::CatalogMismatch);
        }
        Ok(())
    }

    async fn read_source(
        &self,
        key: &ResolvedScyllaKey,
    ) -> Result<CoordinatorCommitPhysicalSourceObservation, CoordinatorCommitPhysicalArchiveStoreError>
    {
        let prepared = self
            .source_reads
            .iter()
            .find(|prepared| prepared.table == key.physical_table())
            .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingPreparedSource)?;
        let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(key)?;
        if binding.shape() != prepared.spec.bind_shape() {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::BindingShapeMismatch);
        }
        match binding {
            CoordinatorCommitPhysicalReadBinding::BigInt(value, _) => {
                self.execute_source(&prepared.statement, (value,), key.schema_family(), None)
                    .await
            }
            CoordinatorCommitPhysicalReadBinding::Blob(value) => {
                self.execute_source(&prepared.statement, (value,), key.schema_family(), None)
                    .await
            }
            CoordinatorCommitPhysicalReadBinding::Uuid(value) => {
                self.execute_source(&prepared.statement, (value,), key.schema_family(), None)
                    .await
            }
            CoordinatorCommitPhysicalReadBinding::ObjectSingle(object, checkpoint) => {
                self.execute_source(
                    &prepared.statement,
                    (object, checkpoint),
                    key.schema_family(),
                    None,
                )
                .await
            }
            CoordinatorCommitPhysicalReadBinding::HashToMany(hash, value) => {
                self.execute_source(
                    &prepared.statement,
                    (hash, value),
                    key.schema_family(),
                    Some(value),
                )
                .await
            }
            CoordinatorCommitPhysicalReadBinding::MerkleZero(
                level,
                node,
                checkpoint,
            ) => {
                self.execute_source(
                    &prepared.statement,
                    (level, node, checkpoint),
                    key.schema_family(),
                    None,
                )
                .await
            }
            CoordinatorCommitPhysicalReadBinding::MerkleSingle(
                tree,
                level,
                node,
                checkpoint,
            ) => {
                self.execute_source(
                    &prepared.statement,
                    (tree, level, node, checkpoint),
                    key.schema_family(),
                    None,
                )
                .await
            }
            CoordinatorCommitPhysicalReadBinding::MerkleDouble(
                tree,
                tree_sub,
                level,
                node,
                checkpoint,
            ) => {
                self.execute_source(
                    &prepared.statement,
                    (tree, tree_sub, level, node, checkpoint),
                    key.schema_family(),
                    None,
                )
                .await
            }
        }
    }

    async fn execute_source<V: scylla::serialize::row::SerializeRow>(
        &self,
        statement: &PreparedStatement,
        bind: V,
        family: ScyllaSchemaFamily,
        expected_key_only: Option<i64>,
    ) -> Result<CoordinatorCommitPhysicalSourceObservation, CoordinatorCommitPhysicalArchiveStoreError>
    {
        let rows = self
            .session
            .execute_unpaged(statement, bind)
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?;
        use ScyllaSchemaFamily as F;
        match family {
            F::Kiv | F::Blob | F::ObjectSingle | F::MerkleZero | F::MerkleSingle
            | F::MerkleDouble => {
                let (value, writetime) = rows
                    .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
                    .map_err(cql)?
                    .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingSource)?;
                Ok(CoordinatorCommitPhysicalSourceObservation::Value(
                    CoordinatorCommitPhysicalSourceCell::value(
                        value.ok_or(
                            CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                        )?,
                        writetime.ok_or(
                            CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                        )?,
                    ),
                ))
            }
            F::U64 | F::U128ToU64 => {
                let (value, writetime) = rows
                    .maybe_first_row::<(Option<i64>, Option<i64>)>()
                    .map_err(cql)?
                    .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingSource)?;
                Ok(CoordinatorCommitPhysicalSourceObservation::Value(
                    CoordinatorCommitPhysicalSourceCell::value(
                        value
                            .ok_or(
                                CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                            )?
                            .to_be_bytes()
                            .to_vec(),
                        writetime.ok_or(
                            CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                        )?,
                    ),
                ))
            }
            F::U64ToU128 => {
                let (value, writetime) = rows
                    .maybe_first_row::<(Option<Uuid>, Option<i64>)>()
                    .map_err(cql)?
                    .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingSource)?;
                Ok(CoordinatorCommitPhysicalSourceObservation::Value(
                    CoordinatorCommitPhysicalSourceCell::value(
                        value
                            .ok_or(
                                CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                            )?
                            .as_bytes()
                            .to_vec(),
                        writetime.ok_or(
                            CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn,
                        )?,
                    ),
                ))
            }
            F::HashToMany => {
                let value = rows
                    .maybe_first_row::<(Option<i64>,)>()
                    .map_err(cql)?
                    .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingSource)?
                    .0
                    .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingSourceColumn)?;
                if Some(value) != expected_key_only {
                    return Err(
                        CoordinatorCommitPhysicalArchiveStoreError::SelectedSourceMismatch,
                    );
                }
                Ok(CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent)
            }
            F::Counter | F::TagTree | F::ImtLeaf | F::ImtKeyIndex | F::ImtCursor => Err(
                CoordinatorCommitPhysicalArchiveStoreError::UnsupportedSchemaFamily,
            ),
        }
    }

    async fn persist_exact<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        before: &CoordinatorCommitPhysicalBeforeImage<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalArchiveStoreError> {
        let fragments = archive_fragments(before.canonical_bytes(), before.digest())?;
        let coordinates = ArchiveCoordinates::try_for(catalog, before)?;
        for fragment in &fragments {
            let execution = self
                .session
                .execute_unpaged(
                    &self.insert,
                    (
                        coordinates.network,
                        coordinates.chain_epoch,
                        coordinates.catalog_digest.as_slice(),
                        coordinates.key_domain,
                        coordinates.row_slot.as_slice(),
                        fragment.index,
                        ARCHIVE_REVISION,
                        fragment.count,
                        fragment.row_bytes,
                        fragment.payload.as_slice(),
                        fragment.digest.as_slice(),
                        fragment.row_digest.as_slice(),
                    ),
                )
                .await;
            match execution {
                Ok(result) => {
                    if !decode_applied(result)? {
                        let current = self
                            .read_archive_fragment(&coordinates, fragment.index)
                            .await?;
                        if current.as_ref() != Some(fragment) {
                            return Err(CoordinatorCommitPhysicalArchiveStoreError::Conflict);
                        }
                    }
                }
                Err(error) => match self
                    .read_archive_fragment(&coordinates, fragment.index)
                    .await
                {
                    Ok(Some(current)) if current == *fragment => {}
                    Ok(_) => {
                        return Err(CoordinatorCommitPhysicalArchiveStoreError::Indeterminate(
                            error.to_string(),
                        ));
                    }
                    Err(read) => {
                        return Err(CoordinatorCommitPhysicalArchiveStoreError::Indeterminate(
                            format!("execute={error}; read={read}"),
                        ));
                    }
                },
            }
        }
        Ok(())
    }

    async fn read_archive_exact<Hash: Q256BitHash>(
        &self,
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        expected: &CoordinatorCommitPhysicalBeforeImage<Hash>,
    ) -> Result<Option<CoordinatorCommitPhysicalBeforeImage<Hash>>, CoordinatorCommitPhysicalArchiveStoreError>
    {
        let coordinates = ArchiveCoordinates::try_for(catalog, expected)?;
        let rows = self
            .session
            .execute_unpaged(
                &self.read_row,
                (
                    coordinates.network,
                    coordinates.chain_epoch,
                    coordinates.catalog_digest.as_slice(),
                    coordinates.key_domain,
                    coordinates.row_slot.as_slice(),
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .rows::<(
                Option<i32>,
                Option<i64>,
                Option<i32>,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cql)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut fragments = Vec::with_capacity(rows.len());
        for (index, revision, count, row_bytes, payload, digest, row_digest) in rows {
            fragments.push(decode_fragment(
                index,
                revision,
                count,
                row_bytes,
                payload,
                digest,
                row_digest,
            )?);
        }
        let bytes = reconstruct_fragments(fragments, expected.digest())?;
        let decoded = CoordinatorCommitPhysicalBeforeImage::decode_for_catalog(
            &bytes,
            catalog,
        )?;
        if decoded.slot() != expected.slot() || decoded.digest() != expected.digest() {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::Conflict);
        }
        Ok(Some(decoded))
    }

    async fn read_archive_fragment(
        &self,
        coordinates: &ArchiveCoordinates,
        index: i32,
    ) -> Result<Option<ArchiveFragment>, CoordinatorCommitPhysicalArchiveStoreError> {
        let row = self
            .session
            .execute_unpaged(
                &self.read_fragment,
                (
                    coordinates.network,
                    coordinates.chain_epoch,
                    coordinates.catalog_digest.as_slice(),
                    coordinates.key_domain,
                    coordinates.row_slot.as_slice(),
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
        row.map(|(revision, count, row_bytes, payload, digest, row_digest)| {
            decode_fragment(
                Some(index),
                revision,
                count,
                row_bytes,
                payload,
                digest,
                row_digest,
            )
        })
        .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorCommitPhysicalReadBinding {
    BigInt(i64, ScyllaSchemaFamily),
    Blob(Vec<u8>),
    Uuid(Uuid),
    ObjectSingle(i64, i64),
    HashToMany(Vec<u8>, i64),
    MerkleZero(i8, i64, i64),
    MerkleSingle(i64, i8, i64, i64),
    MerkleDouble(i64, i64, i8, i64, i64),
}

impl CoordinatorCommitPhysicalReadBinding {
    fn try_for_key(
        key: &ResolvedScyllaKey,
    ) -> Result<Self, CoordinatorCommitPhysicalArchiveStoreError> {
        let binding = match key.typed_key() {
            TypedTableKey::CheckpointLeaf(checkpoint)
            | TypedTableKey::L2BlockState(checkpoint)
            | TypedTableKey::UnusedCheckpointRealmRoot(checkpoint)
            | TypedTableKey::CheckpointStateRoots(checkpoint)
            | TypedTableKey::CheckpointZkProof(checkpoint) => {
                Self::BigInt(
                    u64_to_i64_exact(checkpoint.get()),
                    ScyllaSchemaFamily::Kiv,
                )
            }
            TypedTableKey::LatestInfo(slot) => {
                Self::BigInt(
                    u64_to_i64_exact(*slot as u8 as u64),
                    ScyllaSchemaFamily::Kiv,
                )
            }
            TypedTableKey::U64Singleton(slot) => {
                Self::BigInt(
                    u64_to_i64_exact(*slot as u8 as u64),
                    ScyllaSchemaFamily::U64,
                )
            }
            TypedTableKey::CheckpointToPending(checkpoint) => Self::BigInt(
                u64_to_i64_exact(checkpoint.get()),
                ScyllaSchemaFamily::U64,
            ),
            TypedTableKey::PendingToCheckpoint(pending) => Self::BigInt(
                u64_to_i64_exact(pending.get()),
                ScyllaSchemaFamily::U64,
            ),
            TypedTableKey::PendingToProc(pending) => Self::BigInt(
                u64_to_i64_exact(pending.get()),
                ScyllaSchemaFamily::U64ToU128,
            ),
            TypedTableKey::ProcToPending(proc_id) => {
                Self::Uuid(Uuid::from_u128(proc_id.as_u128()))
            }
            TypedTableKey::CheckpointRootByHash(root) => {
                Self::Blob(root.as_bytes().to_vec())
            }
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => {
                Self::Blob(checkpoint.get().to_le_bytes().to_vec())
            }
            TypedTableKey::CheckpointedObject(object) => match object {
                CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint) => {
                    Self::object(1, checkpoint.get())
                }
                CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint) => {
                    Self::object(2, checkpoint.get())
                }
                CheckpointedObjectKey::RewardsProofAtPending(pending) => {
                    Self::object(2, pending.get())
                }
                CheckpointedObjectKey::ContractStateProofAtCheckpoint(checkpoint) => {
                    Self::object(3, checkpoint.get())
                }
            },
            TypedTableKey::UserLeaf { user, checkpoint }
            | TypedTableKey::UserPublicKey { user, checkpoint } => {
                Self::object(user.get(), checkpoint.get())
            }
            TypedTableKey::ContractStateTreeHeight {
                contract,
                checkpoint,
            }
            | TypedTableKey::ContractLeaf {
                contract,
                checkpoint,
            }
            | TypedTableKey::ContractCodeDefinition {
                contract,
                checkpoint,
            } => Self::object(contract.get(), checkpoint.get()),
            TypedTableKey::RealmRewardNode { realm, pending } => {
                Self::object(realm.get(), pending.get())
            }
            TypedTableKey::PublicKeyToUser {
                public_key_hash,
                user,
            } => Self::HashToMany(
                public_key_hash.as_bytes().to_vec(),
                u64_to_i64_exact(user.get()),
            ),
            TypedTableKey::GlobalUserMerkle { node, checkpoint }
            | TypedTableKey::GlobalCheckpointMerkle { node, checkpoint }
            | TypedTableKey::UserRegistrationMerkle { node, checkpoint }
            | TypedTableKey::GlobalContractMerkle { node, checkpoint } => {
                Self::MerkleZero(
                    u8_to_i8_exact(node.level()),
                    u64_to_i64_exact(node.index().get()),
                    u64_to_i64_exact(checkpoint.get()),
                )
            }
            TypedTableKey::UserContractMerkle {
                user,
                node,
                checkpoint,
            } => Self::MerkleSingle(
                u64_to_i64_exact(user.get()),
                u8_to_i8_exact(node.level()),
                u64_to_i64_exact(node.index().get()),
                u64_to_i64_exact(checkpoint.get()),
            ),
            TypedTableKey::ContractFunctionMerkle {
                contract,
                node,
                checkpoint,
            } => Self::MerkleSingle(
                u64_to_i64_exact(contract.get()),
                u8_to_i8_exact(node.level()),
                u64_to_i64_exact(node.index().get()),
                u64_to_i64_exact(checkpoint.get()),
            ),
            TypedTableKey::ContractStateMerkle {
                user,
                contract,
                node,
                checkpoint,
            } => Self::MerkleDouble(
                u64_to_i64_exact(user.get()),
                u64_to_i64_exact(contract.get()),
                u8_to_i8_exact(node.level()),
                u64_to_i64_exact(node.index().get()),
                u64_to_i64_exact(checkpoint.get()),
            ),
            TypedTableKey::CheckpointLeafByHash(_)
            | TypedTableKey::CheckpointLeafByCheckpoint(_)
            | TypedTableKey::U64Counter(_)
            | TypedTableKey::RewardTagMerkle { .. }
            | TypedTableKey::ImtLeaf { .. }
            | TypedTableKey::ImtKeyIndex { .. }
            | TypedTableKey::ImtCursor { .. } => {
                return Err(
                    CoordinatorCommitPhysicalArchiveStoreError::UnsupportedTypedKey,
                );
            }
        };
        if binding.family() != key.schema_family() {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::BindingShapeMismatch);
        }
        Ok(binding)
    }

    fn object(object: u64, checkpoint: u64) -> Self {
        Self::ObjectSingle(
            u64_to_i64_exact(object),
            u64_to_i64_exact(checkpoint),
        )
    }

    const fn family(&self) -> ScyllaSchemaFamily {
        match self {
            Self::BigInt(_, family) => *family,
            Self::Blob(_) => ScyllaSchemaFamily::Blob,
            Self::Uuid(_) => ScyllaSchemaFamily::U128ToU64,
            Self::ObjectSingle(_, _) => ScyllaSchemaFamily::ObjectSingle,
            Self::HashToMany(_, _) => ScyllaSchemaFamily::HashToMany,
            Self::MerkleZero(_, _, _) => ScyllaSchemaFamily::MerkleZero,
            Self::MerkleSingle(_, _, _, _) => ScyllaSchemaFamily::MerkleSingle,
            Self::MerkleDouble(_, _, _, _, _) => ScyllaSchemaFamily::MerkleDouble,
        }
    }

    const fn shape(&self) -> &'static [&'static str] {
        match self {
            Self::BigInt(_, _) => &["obj_id:BIGINT"],
            Self::Blob(_) => &["obj_id:BLOB"],
            Self::Uuid(_) => &["obj_id:UUID"],
            Self::ObjectSingle(_, _) => {
                &["obj_id:BIGINT", "checkpoint_id:BIGINT"]
            }
            Self::HashToMany(_, _) => &["hash_id:BLOB", "value_u64:BIGINT"],
            Self::MerkleZero(_, _, _) => &[
                "level:TINYINT",
                "node_index:BIGINT",
                "checkpoint_id:BIGINT",
            ],
            Self::MerkleSingle(_, _, _, _) => &[
                "tree_id:BIGINT",
                "level:TINYINT",
                "node_index:BIGINT",
                "checkpoint_id:BIGINT",
            ],
            Self::MerkleDouble(_, _, _, _, _) => &[
                "tree_id:BIGINT",
                "tree_sub_id:BIGINT",
                "level:TINYINT",
                "node_index:BIGINT",
                "checkpoint_id:BIGINT",
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveFragment {
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: Vec<u8>,
    digest: [u8; 32],
    row_digest: [u8; 32],
}

struct ArchiveCoordinates {
    network: i64,
    chain_epoch: i64,
    catalog_digest: [u8; 32],
    key_domain: i16,
    row_slot: [u8; 32],
}

impl ArchiveCoordinates {
    fn try_for<Hash: Q256BitHash>(
        catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
        before: &CoordinatorCommitPhysicalBeforeImage<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalArchiveStoreError> {
        before.validate_catalog(catalog)?;
        Ok(Self {
            network: i64::from(catalog.target().network_id().chain_id()),
            chain_epoch: i64::try_from(catalog.target().chain_epoch().get()).map_err(
                |_| CoordinatorCommitPhysicalArchiveStoreError::IntegerOutOfCqlRange,
            )?,
            catalog_digest: *catalog.digest(),
            key_domain: i16::try_from(before.key().key_domain().stable_id()).map_err(
                |_| CoordinatorCommitPhysicalArchiveStoreError::IntegerOutOfCqlRange,
            )?,
            row_slot: *before.slot(),
        })
    }
}

fn archive_fragments(
    bytes: &[u8],
    row_digest: &[u8; 32],
) -> Result<Vec<ArchiveFragment>, CoordinatorCommitPhysicalArchiveStoreError> {
    let count = bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
    if count == 0 || count > MAX_FRAGMENTS {
        return Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    let count_i32 = i32::try_from(count)
        .map_err(|_| CoordinatorCommitPhysicalArchiveStoreError::LengthOverflow)?;
    let row_bytes = i64::try_from(bytes.len())
        .map_err(|_| CoordinatorCommitPhysicalArchiveStoreError::LengthOverflow)?;
    Ok(bytes
        .chunks(MAX_FRAGMENT_BYTES)
        .enumerate()
        .map(|(index, payload)| {
            let index = i32::try_from(index).expect("at most sixteen fragments");
            ArchiveFragment {
                index,
                count: count_i32,
                row_bytes,
                payload: payload.to_vec(),
                digest: fragment_digest(
                    row_digest,
                    index,
                    count_i32,
                    row_bytes,
                    payload,
                ),
                row_digest: *row_digest,
            }
        })
        .collect())
}

fn decode_fragment(
    index: Option<i32>,
    revision: Option<i64>,
    count: Option<i32>,
    row_bytes: Option<i64>,
    payload: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    row_digest: Option<Vec<u8>>,
) -> Result<ArchiveFragment, CoordinatorCommitPhysicalArchiveStoreError> {
    if revision != Some(ARCHIVE_REVISION) {
        return Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidArchiveRevision);
    }
    let index = index.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?;
    let count = count.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?;
    let row_bytes = row_bytes.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?;
    let payload = payload.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?;
    let digest = array_32(digest.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?)?;
    let row_digest = array_32(row_digest.ok_or(
        CoordinatorCommitPhysicalArchiveStoreError::MissingArchiveColumn,
    )?)?;
    if fragment_digest(
        &row_digest,
        index,
        count,
        row_bytes,
        &payload,
    ) != digest
    {
        return Err(CoordinatorCommitPhysicalArchiveStoreError::FragmentDigestMismatch);
    }
    Ok(ArchiveFragment {
        index,
        count,
        row_bytes,
        payload,
        digest,
        row_digest,
    })
}

fn reconstruct_fragments(
    mut fragments: Vec<ArchiveFragment>,
    expected_digest: &[u8; 32],
) -> Result<Vec<u8>, CoordinatorCommitPhysicalArchiveStoreError> {
    fragments.sort_by_key(|fragment| fragment.index);
    let first = fragments
        .first()
        .ok_or(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet)?;
    let count = usize::try_from(first.count)
        .map_err(|_| CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet)?;
    let row_bytes = usize::try_from(first.row_bytes)
        .map_err(|_| CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet)?;
    if count == 0
        || count > MAX_FRAGMENTS
        || fragments.len() != count
        || &first.row_digest != expected_digest
    {
        return Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    let mut bytes = Vec::with_capacity(row_bytes);
    for (expected_index, fragment) in fragments.iter().enumerate() {
        if fragment.index != expected_index as i32
            || fragment.count != first.count
            || fragment.row_bytes != first.row_bytes
            || fragment.row_digest != first.row_digest
            || fragment.payload.len() > MAX_FRAGMENT_BYTES
            || fragment_digest(
                &fragment.row_digest,
                fragment.index,
                fragment.count,
                fragment.row_bytes,
                &fragment.payload,
            ) != fragment.digest
        {
            return Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet);
        }
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() != row_bytes {
        return Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    Ok(bytes)
}

fn fragment_digest(
    row_digest: &[u8; 32],
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(row_digest);
    hasher.update(index.to_be_bytes());
    hasher.update(count.to_be_bytes());
    hasher.update(row_bytes.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn participant_dataset_hasher<Hash: Q256BitHash>(
    scope: &CoordinatorCommitPhysicalArchiveScope<Hash>,
    catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
    entry_count: u64,
    store_fingerprint: &[u8; 32],
) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(PARTICIPANT_DATASET_DIGEST_DOMAIN);
    hasher.update(
        scope
            .archiving_head
            .revision()
            .as_i64()
            .to_be_bytes(),
    );
    hasher.update(scope.archiving_head.canonical_ref_bytes());
    hasher.update(scope.archiving_head.rollback_control_bytes());
    hasher.update(catalog.digest());
    hasher.update(store_fingerprint);
    hasher.update(entry_count.to_be_bytes());
    hasher
}

fn update_participant_dataset(
    hasher: &mut Sha256,
    index: usize,
    row: CoordinatorCommitPhysicalArchivedRow,
) -> Result<(), CoordinatorCommitPhysicalArchiveOwnerError> {
    let index = u64::try_from(index)
        .map_err(|_| CoordinatorCommitPhysicalArchiveOwnerError::LengthOverflow)?;
    hasher.update(index.to_be_bytes());
    hasher.update(row.slot);
    hasher.update(row.digest);
    Ok(())
}

fn store_fingerprint(
    archive_keyspace: &CqlKeyspaceName,
    source_keyspace: &CqlKeyspaceName,
    catalog_digest: &[u8; 32],
    queries: &CoordinatorCommitPhysicalArchiveQueries,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update(archive_keyspace.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(source_keyspace.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(catalog_digest);
    hasher.update(queries.insert.as_bytes());
    hasher.update(queries.read_row.as_bytes());
    hasher.update(queries.read_fragment.as_bytes());
    for (table, spec) in &queries.source_reads {
        hasher.update(table.stable_id().to_be_bytes());
        hasher.update(spec.cql().as_bytes());
    }
    hasher.finalize().into()
}

async fn prepare_read(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorCommitPhysicalArchiveStoreError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorCommitPhysicalArchiveStoreError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, CoordinatorCommitPhysicalArchiveStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorCommitPhysicalArchiveStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidAppliedColumn),
    }
}

fn array_32(
    bytes: Vec<u8>,
) -> Result<[u8; 32], CoordinatorCommitPhysicalArchiveStoreError> {
    bytes.try_into().map_err(|_| {
        CoordinatorCommitPhysicalArchiveStoreError::InvalidDigestLength
    })
}

fn cql(error: impl fmt::Display) -> CoordinatorCommitPhysicalArchiveStoreError {
    CoordinatorCommitPhysicalArchiveStoreError::Cql(error.to_string())
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitPhysicalArchiveOwnerError {
    CanonicalHead(String),
    CommitSource(String),
    Archive(CoordinatorCommitPhysicalArchiveStoreError),
    HeadMissing,
    NotExactArchivingHead,
    EpochUnderflow,
    CatalogChanged,
    HeadChanged,
    EntryReceiptMismatch,
    ReceiptBindingMismatch,
    ArchiveRowChanged,
    DatasetChanged,
    LengthOverflow,
}

impl From<CanonicalHeadPrototypeError>
    for CoordinatorCommitPhysicalArchiveOwnerError
{
    fn from(error: CanonicalHeadPrototypeError) -> Self {
        Self::CanonicalHead(error.to_string())
    }
}

impl From<CoordinatorCommitPhysicalArchiveStoreError>
    for CoordinatorCommitPhysicalArchiveOwnerError
{
    fn from(error: CoordinatorCommitPhysicalArchiveStoreError) -> Self {
        Self::Archive(error)
    }
}

impl From<CoordinatorCommitPhysicalBeforeImageError>
    for CoordinatorCommitPhysicalArchiveOwnerError
{
    fn from(error: CoordinatorCommitPhysicalBeforeImageError) -> Self {
        Self::Archive(CoordinatorCommitPhysicalArchiveStoreError::BeforeImage(
            error,
        ))
    }
}

impl fmt::Display for CoordinatorCommitPhysicalArchiveOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Coordinator physical archive owner failed: {self:?}",
        )
    }
}

impl Error for CoordinatorCommitPhysicalArchiveOwnerError {}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitPhysicalArchiveStoreError {
    BeforeImage(CoordinatorCommitPhysicalBeforeImageError),
    Cql(String),
    CatalogEntryMissing,
    CatalogMismatch,
    QueryShapeConflict,
    BindingShapeMismatch,
    UnsupportedTypedKey,
    UnsupportedSchemaFamily,
    MissingPreparedSource,
    MissingSource,
    MissingSourceColumn,
    SelectedSourceMismatch,
    SourceChanged,
    MissingAfterPersist,
    Conflict,
    Indeterminate(String),
    ReceiptBindingMismatch,
    ReceiptStale,
    IntegerOutOfCqlRange,
    LengthOverflow,
    InvalidFragmentSet,
    InvalidArchiveRevision,
    MissingArchiveColumn,
    FragmentDigestMismatch,
    InvalidDigestLength,
    MissingAppliedColumn,
    InvalidAppliedColumn,
}

impl From<CoordinatorCommitPhysicalBeforeImageError>
    for CoordinatorCommitPhysicalArchiveStoreError
{
    fn from(error: CoordinatorCommitPhysicalBeforeImageError) -> Self {
        Self::BeforeImage(error)
    }
}

impl fmt::Display for CoordinatorCommitPhysicalArchiveStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Coordinator physical archive store failed: {self:?}",
        )
    }
}

impl Error for CoordinatorCommitPhysicalArchiveStoreError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CheckpointHash, CheckpointId as ChainCheckpointId, CheckpointRef,
    };
    use psy_node_core::store::typed::{
        CheckpointId, ContractId, MerkleNode, NodeIndex, PublicKeyHash,
        ProcCheckpointUniqueId, TypedTableKey, U64SingletonSlot,
        UniquePendingId, UserId,
    };
    use psy_node_core::store::{
        rollback_control::{RollbackPlanDigest, RollbackRequest},
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;
    use crate::rollback::describe_existing_key;

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            ChainCheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
            )),
        )
    }

    fn rollback_request(mode: RollbackExecutionMode) -> RollbackRequest<PHash> {
        RollbackRequest::try_new(
            checkpoint(100, 10),
            checkpoint(90, 20),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            mode,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap()
    }

    fn head(
        epoch: u64,
        checkpoint: CheckpointRef<PHash>,
        control: RollbackControlState<PHash>,
    ) -> StoredCanonicalHead<PHash> {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        StoredCanonicalHead::decode_persisted(
            network,
            7,
            &CanonicalChainRef::new(network, ChainEpoch::new(epoch), checkpoint)
                .to_canonical_bytes(),
            &control.to_canonical_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn participant_scope_is_selected_only_from_exact_in_place_archiving_head() {
        let request = rollback_request(RollbackExecutionMode::InPlace);
        let scope = CoordinatorCommitPhysicalArchiveScope::try_from_head(head(
            7,
            *request.requested_head(),
            RollbackControlState::Archiving(request),
        ))
        .unwrap();
        assert_eq!(scope.target.chain_epoch(), ChainEpoch::new(6));
        assert_eq!(scope.target.checkpoint(), request.target());
        assert_eq!(scope.old_head.chain_epoch(), ChainEpoch::new(6));
        assert_eq!(scope.old_head.checkpoint(), request.requested_head());

        for control in [
            RollbackControlState::Idle,
            RollbackControlState::Requested(request),
            RollbackControlState::ArchiveBarrierReady(request),
            RollbackControlState::Deleting(request),
        ] {
            assert_eq!(
                CoordinatorCommitPhysicalArchiveScope::try_from_head(head(
                    7,
                    *request.requested_head(),
                    control,
                )),
                Err(CoordinatorCommitPhysicalArchiveOwnerError::NotExactArchivingHead),
            );
        }

        let snapshot_request =
            rollback_request(RollbackExecutionMode::SnapshotReplay);
        assert_eq!(
            CoordinatorCommitPhysicalArchiveScope::try_from_head(head(
                7,
                *snapshot_request.requested_head(),
                RollbackControlState::Archiving(snapshot_request),
            )),
            Err(CoordinatorCommitPhysicalArchiveOwnerError::NotExactArchivingHead),
        );
        // StoredCanonicalHead itself rejects an active rollback whose current
        // checkpoint differs from requested_head, or whose epoch is zero.
        // The owner therefore receives only canonical-head-valid inputs and
        // additionally narrows them to exact ARCHIVING + InPlace above.
    }

    #[test]
    fn typed_bindings_cover_every_supported_physical_shape() {
        let checkpoint = CheckpointId::try_new(7).unwrap();
        let node = MerkleNode::new(3, NodeIndex::new(9));
        let samples = [
            TypedTableKey::CheckpointLeaf(checkpoint),
            TypedTableKey::CheckpointRootByHash(
                psy_node_core::store::typed::CheckpointRootKey::new(vec![1; 32]),
            ),
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
            TypedTableKey::PendingToProc(UniquePendingId::try_new(8).unwrap()),
            TypedTableKey::ProcToPending(ProcCheckpointUniqueId::from_u128(9)),
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            TypedTableKey::ContractLeaf {
                contract: ContractId::new(10),
                checkpoint,
            },
            TypedTableKey::PublicKeyToUser {
                public_key_hash: PublicKeyHash::new(vec![2; 32]),
                user: UserId::new(11),
            },
            TypedTableKey::GlobalUserMerkle { node, checkpoint },
            TypedTableKey::ContractFunctionMerkle {
                contract: ContractId::new(12),
                node,
                checkpoint,
            },
            TypedTableKey::ContractStateMerkle {
                user: UserId::new(13),
                contract: ContractId::new(14),
                node,
                checkpoint,
            },
        ];
        let keyspace = CqlKeyspaceName::try_new("state_data").unwrap();
        for sample in samples {
            let key = describe_existing_key(&sample);
            let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(&key)
                .unwrap();
            let spec = CoordinatorCommitPhysicalReadSpec::try_for_key(
                &keyspace,
                &key,
            )
            .unwrap();
            assert_eq!(binding.shape(), spec.bind_shape(), "{sample:?}");
            assert_eq!(binding.family(), key.schema_family(), "{sample:?}");
        }
    }

    #[test]
    fn participant_owner_streams_fixed_size_row_commitments_into_dataset_hash() {
        assert_eq!(
            std::mem::size_of::<CoordinatorCommitPhysicalArchivedRow>(),
            64,
        );
        let source = include_str!("coordinator_commit_physical_archive_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("participant_dataset_hasher"));
        assert!(production.contains("update_participant_dataset"));
        assert!(production.contains("revalidate_catalog_entry"));
        assert!(!production.contains("Vec<CoordinatorCommitPhysicalArchivedRow"));
        assert!(!production.contains("Vec<PersistedCoordinatorCommitPhysicalBeforeImage"));
    }

    #[test]
    fn fragment_codec_rejects_missing_extra_corrupt_and_mixed_rows() {
        let bytes = vec![0x5a; MAX_FRAGMENT_BYTES + 17];
        let row_digest = Sha256::digest(&bytes).into();
        let fragments = archive_fragments(&bytes, &row_digest).unwrap();
        assert_eq!(fragments.len(), 2);
        assert_eq!(
            reconstruct_fragments(fragments.clone(), &row_digest).unwrap(),
            bytes,
        );

        assert_eq!(
            reconstruct_fragments(vec![fragments[0].clone()], &row_digest),
            Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet),
        );
        let mut extra = fragments.clone();
        extra.push(fragments[1].clone());
        assert_eq!(
            reconstruct_fragments(extra, &row_digest),
            Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet),
        );
        let mut corrupt = fragments.clone();
        corrupt[1].payload[0] ^= 1;
        assert_eq!(
            reconstruct_fragments(corrupt, &row_digest),
            Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet),
        );
        let mut mixed = fragments;
        mixed[1].row_digest = [9; 32];
        assert_eq!(
            reconstruct_fragments(mixed, &row_digest),
            Err(CoordinatorCommitPhysicalArchiveStoreError::InvalidFragmentSet),
        );
    }

    #[test]
    fn raw_store_api_exposes_no_barrier_delete_restore_or_head_mutation() {
        let source = include_str!("coordinator_commit_physical_archive_store.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix");
        for forbidden in [
            "global_archive_barrier(",
            "delete_hot_suffix(",
            "restore_target_head(",
            "publish_target_head(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden API {forbidden}",
            );
        }
        assert!(production.contains("IF NOT EXISTS"));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("USING TIMESTAMP"));
        assert!(production.contains("archive_current_request"));
        assert!(production.contains("scan_floor_bound_physical_catalog"));
        assert!(production.contains("persist_catalog_entry_and_readback"));
        assert!(production.contains("revalidate_participant_receipt"));
        assert!(production.contains("RollbackControlState::Archiving"));
        assert!(production.contains("RollbackExecutionMode::InPlace"));
    }
}
