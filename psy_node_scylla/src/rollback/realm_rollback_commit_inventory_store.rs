//! Append-only storage for complete Realm commit inventories.
//!
//! Inventory fragments are written before the normal commit mutates any
//! non-h22 hot row. A separate COMMITTED marker is inserted only after the
//! full manifest, authority-local head, Published pipeline, and Active writer
//! agree on the same Realm candidate. Neither table grants archive, delete,
//! restore, barrier, or canonical-head rewind authority.

use std::{error::Error, fmt, sync::Arc};

use futures::TryStreamExt;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, ChainEpoch, NetworkId},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_local_head::StoredAuthorityLocalHead,
    authority_commit::AuthorityTimestampKey,
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::{PendingProcessingState, StoredPendingPipeline},
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactDeploymentNoTabletKeyspace, BranchExactWriterState,
    PendingQueueArtifactDataKeyspace,
    StoredBranchExactWriterLifecycle,
    realm_rollback_commit_inventory::{
        RealmRollbackCommitInventory, RealmRollbackCommitInventoryError,
        RealmRollbackCommitInventorySlot,
    },
    realm_full_commit_manifest_store::PersistedRealmFullCommitManifestReceipt,
};

pub(super) const REALM_ROLLBACK_COMMIT_INVENTORY_FRAGMENT_TABLE: &str =
    "branch_exact_realm_rollback_commit_inventory_fragment_v1";
pub(super) const REALM_ROLLBACK_COMMIT_MARKER_TABLE: &str =
    "branch_exact_realm_rollback_commit_marker_v1";

const ROW_REVISION: i64 = 1;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const MARKER_MAGIC: &[u8; 8] = b"PSYRRCMT";
const MARKER_VERSION: u16 = 1;
const MARKER_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-commit-marker.v1\0";
const FRAGMENT_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-commit-inventory-fragment.v1\0";
const STORE_FINGERPRINT_DOMAIN: &[u8] = b"psy.rollback.realm-commit-inventory-store.v1\0";
const SUFFIX_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-committed-suffix.v1\0";
const MAX_SUFFIX_ROWS: u64 = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackCommitInventoryQueries {
    create_fragment: String,
    create_marker: String,
    read_fragments: String,
    insert_fragment: String,
    read_marker: String,
    insert_marker: String,
    scan_markers: String,
}

impl RealmRollbackCommitInventoryQueries {
    pub(super) fn new(
        control: &BranchExactDeploymentNoTabletKeyspace,
        data: &PendingQueueArtifactDataKeyspace,
    ) -> Self {
        let fragment = format!(
            "{}.{}",
            data.as_str(),
            REALM_ROLLBACK_COMMIT_INVENTORY_FRAGMENT_TABLE,
        );
        let marker = format!(
            "{}.{}",
            control.as_str(),
            REALM_ROLLBACK_COMMIT_MARKER_TABLE,
        );
        Self {
            create_fragment: format!(
                "CREATE TABLE IF NOT EXISTS {fragment} (inventory_slot blob, fragment_index int, revision bigint, fragment_count int, inventory_bytes bigint, inventory_digest blob, payload blob, payload_digest blob, PRIMARY KEY ((inventory_slot), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)"
            ),
            create_marker: format!(
                "CREATE TABLE IF NOT EXISTS {marker} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, chain_epoch bigint, checkpoint_id bigint, revision bigint, inventory_slot blob, marker blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, chain_epoch), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id ASC)"
            ),
            read_fragments: format!(
                "SELECT fragment_index, revision, fragment_count, inventory_bytes, inventory_digest, payload, payload_digest FROM {fragment} WHERE inventory_slot = ?"
            ),
            insert_fragment: format!(
                "INSERT INTO {fragment} (inventory_slot, fragment_index, revision, fragment_count, inventory_bytes, inventory_digest, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_marker: format!(
                "SELECT revision, inventory_slot, marker FROM {marker} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND chain_epoch = ? AND checkpoint_id = ?"
            ),
            insert_marker: format!(
                "INSERT INTO {marker} (network_chain_id, authority_kind, realm_id, realm_sub_id, chain_epoch, checkpoint_id, revision, inventory_slot, marker) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            scan_markers: format!(
                "SELECT checkpoint_id, revision, inventory_slot, marker FROM {marker} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND chain_epoch = ? AND checkpoint_id > ? AND checkpoint_id <= ?"
            ),
        }
    }

    pub(super) fn golden(&self) -> String {
        format!(
            "create_fragment\n{}\n\ncreate_marker\n{}\n\nread_fragments\n{}\nBLOB\n\ninsert_fragment\n{}\nBLOB,INT,BIGINT,INT,BIGINT,BLOB,BLOB,BLOB\n\nread_marker\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BIGINT\n\ninsert_marker\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BIGINT,BIGINT,BLOB,BLOB\n\nscan_markers\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BIGINT,BIGINT\n",
            self.create_fragment,
            self.create_marker,
            self.read_fragments,
            self.insert_fragment,
            self.read_marker,
            self.insert_marker,
            self.scan_markers,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RealmRollbackCommitInventoryStoreFingerprint([u8; 32]);

/// Exact exhaustive prewrite. Deliberately non-Clone and not a COMMITTED
/// marker or rollback capability.
#[derive(Debug)]
pub(super) struct PersistedRealmRollbackCommitInventoryReceipt<Hash> {
    store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    inventory: RealmRollbackCommitInventory<Hash>,
}

impl<Hash> PersistedRealmRollbackCommitInventoryReceipt<Hash> {
    pub(super) const fn inventory(&self) -> &RealmRollbackCommitInventory<Hash> {
        &self.inventory
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackCommittedMarker<Hash> {
    inventory_slot: RealmRollbackCommitInventorySlot,
    inventory_digest: [u8; 32],
    manifest_slot: [u8; 32],
    manifest_digest: [u8; 32],
    candidate: psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
    timestamp: i64,
    coverage_digest: [u8; 32],
    total_mutation_count: u64,
    head_revision: u64,
    head_payload: Vec<u8>,
    pipeline_revision: u64,
    pipeline_payload: Vec<u8>,
    writer_revision: u64,
    marker_payload: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmRollbackCommittedMarker<Hash> {
    fn try_new(
        store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
        inventory: &RealmRollbackCommitInventory<Hash>,
        manifest: &PersistedRealmFullCommitManifestReceipt<Hash>,
        head: &StoredAuthorityLocalHead<Hash>,
        pipeline: &StoredPendingPipeline<Hash>,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<Self, RealmRollbackCommitInventoryStoreError> {
        let manifest = manifest.manifest();
        let BranchExactWriterState::Active(active) = writer.state() else {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        };
        if inventory.authority() != manifest.authority()
            || inventory.candidate() != manifest.candidate()
            || inventory.timestamp() != manifest.write_timestamp()
            || inventory.coverage_digest() != manifest.coverage_digest()
            || inventory.total_mutation_count() != manifest.total_mutation_count()
            || head.head().key().authority() != inventory.authority()
            || head.head().chain() != inventory.candidate().canonical_chain()
            || head.commit_write_timestamp() != inventory.timestamp()
            || head.manifest_digest().as_bytes() != manifest.digest()
            || pipeline.key().authority() != inventory.authority()
            || pipeline.frontier().chain() != inventory.candidate().canonical_chain()
            || pipeline.processing().pending_id() != inventory.candidate().pending_id()
            || !matches!(pipeline.processing_state(), PendingProcessingState::Published { .. })
            || active.watermark() != inventory.candidate()
            || writer.revision().get() != manifest.writer_revision().saturating_add(1)
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        let mut marker = Self {
            inventory_slot: inventory.slot(),
            inventory_digest: *inventory.digest(),
            manifest_slot: *manifest.slot().as_bytes(),
            manifest_digest: *manifest.digest(),
            candidate: *inventory.candidate(),
            timestamp: inventory.timestamp().as_i64(),
            coverage_digest: *inventory.coverage_digest(),
            total_mutation_count: inventory.total_mutation_count(),
            head_revision: head.revision().get(),
            head_payload: head.encode_canonical().to_vec(),
            pipeline_revision: pipeline.revision().get(),
            pipeline_payload: pipeline.canonical_payload().to_vec(),
            writer_revision: writer.revision().get(),
            marker_payload: Vec::new(),
            digest: [0; 32],
        };
        marker.marker_payload = encode_marker(store_fingerprint, &marker)?;
        marker.digest = marker.marker_payload[marker.marker_payload.len() - 32..]
            .try_into()
            .expect("marker codec appends digest");
        Ok(marker)
    }

    fn decode_persisted(
        store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
        inventory: &RealmRollbackCommitInventory<Hash>,
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, RealmRollbackCommitInventoryStoreError> {
        if revision != ROW_REVISION || payload.len() < 8 + 2 + 32 * 5 + 8 * 6 + 4 * 2 + 32 {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedMarker);
        }
        let body_len = payload.len().checked_sub(32)
            .ok_or(RealmRollbackCommitInventoryStoreError::MalformedMarker)?;
        let (body, encoded_digest) = payload.split_at(body_len);
        let digest = marker_digest(body);
        if encoded_digest != digest {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedMarker);
        }
        let mut cursor = Cursor::new(body);
        if cursor.take(8)? != MARKER_MAGIC || cursor.u16()? != MARKER_VERSION {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedMarker);
        }
        if cursor.array32()? != store_fingerprint.0 {
            return Err(RealmRollbackCommitInventoryStoreError::StoreBindingMismatch);
        }
        let inventory_slot = RealmRollbackCommitInventorySlot::from_persisted(cursor.array32()?);
        let inventory_digest = cursor.array32()?;
        let manifest_slot = cursor.array32()?;
        let manifest_digest = cursor.array32()?;
        let timestamp = cursor.i64()?;
        let coverage_digest = cursor.array32()?;
        let total_mutation_count = cursor.u64()?;
        let head_revision = cursor.u64()?;
        let head_payload = cursor.bytes()?.to_vec();
        let pipeline_revision = cursor.u64()?;
        let pipeline_payload = cursor.bytes()?.to_vec();
        let writer_revision = cursor.u64()?;
        if !cursor.is_empty()
            || inventory_slot != inventory.slot()
            || inventory_digest != *inventory.digest()
            || timestamp != inventory.timestamp().as_i64()
            || coverage_digest != *inventory.coverage_digest()
            || total_mutation_count != inventory.total_mutation_count()
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        let decoded = Self {
            inventory_slot,
            inventory_digest,
            manifest_slot,
            manifest_digest,
            candidate: *inventory.candidate(),
            timestamp,
            coverage_digest,
            total_mutation_count,
            head_revision,
            head_payload,
            pipeline_revision,
            pipeline_payload,
            writer_revision,
            marker_payload: payload.to_vec(),
            digest,
        };
        let selected_head_key = AuthorityTimestampKey::new(
            inventory.candidate().canonical_chain().network_id(),
            inventory.authority(),
        );
        let typed_head = StoredAuthorityLocalHead::<Hash>::decode_persisted(
            selected_head_key,
            i64::try_from(decoded.head_revision)
                .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
            &decoded.head_payload,
        )
        .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)?;
        if typed_head.head().chain() != inventory.candidate().canonical_chain()
            || typed_head.commit_write_timestamp() != inventory.timestamp()
            || typed_head.manifest_digest().as_bytes() != &decoded.manifest_digest
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        let selected_pipeline_key = PendingGenerationLedgerKey::new(
            inventory.candidate().canonical_chain().network_id(),
            inventory.authority(),
        );
        let typed_pipeline = StoredPendingPipeline::<Hash>::decode_persisted(
            selected_pipeline_key,
            i64::try_from(decoded.pipeline_revision)
                .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
            &decoded.pipeline_payload,
        )
        .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)?;
        if typed_pipeline.frontier().chain() != inventory.candidate().canonical_chain()
            || typed_pipeline.processing().pending_id() != inventory.candidate().pending_id()
            || !matches!(
                typed_pipeline.processing_state(),
                PendingProcessingState::Published { .. }
            )
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        if encode_marker(store_fingerprint, &decoded)? != payload {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedMarker);
        }
        Ok(decoded)
    }

    pub(super) const fn inventory_slot(&self) -> RealmRollbackCommitInventorySlot {
        self.inventory_slot
    }
    pub(super) const fn candidate(&self) -> &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash> {
        &self.candidate
    }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

#[derive(Debug)]
pub(super) struct PersistedRealmRollbackCommittedReceipt<Hash> {
    store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    marker: RealmRollbackCommittedMarker<Hash>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedRealmRollbackCommittedSuffixEntry<Hash> {
    inventory: RealmRollbackCommitInventory<Hash>,
    marker: RealmRollbackCommittedMarker<Hash>,
}

impl<Hash> VerifiedRealmRollbackCommittedSuffixEntry<Hash> {
    pub(super) const fn inventory(&self) -> &RealmRollbackCommitInventory<Hash> {
        &self.inventory
    }

    pub(super) const fn marker(&self) -> &RealmRollbackCommittedMarker<Hash> {
        &self.marker
    }
}

impl<Hash: Q256BitHash> VerifiedRealmRollbackCommittedSuffixEntry<Hash> {
    /// Decode the exact authority-local head captured by this immutable
    /// committed marker. The restore path uses the typed row rather than
    /// copying marker bytes into the live table.
    pub(super) fn stored_head(
        &self,
    ) -> Result<StoredAuthorityLocalHead<Hash>, RealmRollbackCommitInventoryStoreError> {
        StoredAuthorityLocalHead::decode_persisted(
            AuthorityTimestampKey::new(
                self.inventory.candidate().canonical_chain().network_id(),
                self.inventory.authority(),
            ),
            i64::try_from(self.marker.head_revision)
                .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
            &self.marker.head_payload,
        )
        .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)
    }

    /// Decode the historical published pipeline only as target evidence. The
    /// live pipeline is reset at a higher revision with fresh pending/proc
    /// generations; this historical row is never copied over the live row.
    pub(super) fn stored_pipeline(
        &self,
    ) -> Result<StoredPendingPipeline<Hash>, RealmRollbackCommitInventoryStoreError> {
        StoredPendingPipeline::decode_persisted(
            PendingGenerationLedgerKey::new(
                self.inventory.candidate().canonical_chain().network_id(),
                self.inventory.authority(),
            ),
            i64::try_from(self.marker.pipeline_revision)
                .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
            &self.marker.pipeline_payload,
        )
        .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)
    }

    pub(super) const fn writer_revision(&self) -> u64 {
        self.marker.writer_revision
    }
}

/// Exact, storage-selected committed Realm suffix in `(target, source_head]`.
///
/// This is deliberately inert evidence. It cannot archive, cross the global
/// barrier, delete, restore, or publish a head.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct VerifiedRealmRollbackCommittedSuffix<Hash> {
    store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    source_head: CanonicalChainRef<Hash>,
    entries: Vec<VerifiedRealmRollbackCommittedSuffixEntry<Hash>>,
    digest: [u8; 32],
}

impl<Hash> VerifiedRealmRollbackCommittedSuffix<Hash> {
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn source_head(&self) -> &CanonicalChainRef<Hash> { &self.source_head }
    pub(super) fn entries(&self) -> &[VerifiedRealmRollbackCommittedSuffixEntry<Hash>] {
        &self.entries
    }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

pub(super) struct ScyllaRealmRollbackCommitInventoryStore {
    session: Arc<Session>,
    queries: RealmRollbackCommitInventoryQueries,
    fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    read_fragments: PreparedStatement,
    insert_fragment: PreparedStatement,
    read_marker: PreparedStatement,
    insert_marker: PreparedStatement,
    scan_markers: PreparedStatement,
}

impl ScyllaRealmRollbackCommitInventoryStore {
    pub(super) async fn create_schema(
        session: &Session,
        control: &BranchExactDeploymentNoTabletKeyspace,
        data: &PendingQueueArtifactDataKeyspace,
    ) -> Result<(), RealmRollbackCommitInventoryStoreError> {
        let queries = RealmRollbackCommitInventoryQueries::new(control, data);
        session.query_unpaged(queries.create_fragment.as_str(), &[]).await.map_err(cql)?;
        session.query_unpaged(queries.create_marker.as_str(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        control: BranchExactDeploymentNoTabletKeyspace,
        data: PendingQueueArtifactDataKeyspace,
    ) -> Result<Self, RealmRollbackCommitInventoryStoreError> {
        let queries = RealmRollbackCommitInventoryQueries::new(&control, &data);
        Ok(Self {
            fingerprint: store_fingerprint(&control, &data, &queries),
            read_fragments: prepare_regular(&session, &queries.read_fragments).await?,
            insert_fragment: prepare_lwt(&session, &queries.insert_fragment).await?,
            read_marker: prepare_regular(&session, &queries.read_marker).await?,
            insert_marker: prepare_lwt(&session, &queries.insert_marker).await?,
            scan_markers: prepare_regular(&session, &queries.scan_markers).await?,
            session,
            queries,
        })
    }

    pub(super) const fn queries(&self) -> &RealmRollbackCommitInventoryQueries {
        &self.queries
    }

    pub(super) async fn persist_prewrite<Hash: Q256BitHash>(
        &self,
        inventory: RealmRollbackCommitInventory<Hash>,
    ) -> Result<PersistedRealmRollbackCommitInventoryReceipt<Hash>, RealmRollbackCommitInventoryStoreError> {
        let fragments = split_inventory(&inventory)?;
        for fragment in &fragments {
            let execution = self.session.execute_unpaged(
                &self.insert_fragment,
                (
                    inventory.slot().as_bytes().as_slice(),
                    fragment.index,
                    ROW_REVISION,
                    fragment.count,
                    fragment.inventory_bytes,
                    inventory.digest().as_slice(),
                    fragment.payload.as_slice(),
                    fragment.digest.as_slice(),
                ),
            ).await;
            match execution {
                Ok(result) => {
                    let _ = decode_applied(result)?;
                }
                Err(error) => {
                    let current = self.read_inventory(inventory.slot()).await;
                    match current {
                        Ok(Some(current)) if current == inventory => break,
                        Ok(_) => return Err(RealmRollbackCommitInventoryStoreError::Indeterminate(error.to_string())),
                        Err(read) => return Err(RealmRollbackCommitInventoryStoreError::Indeterminate(format!("execute={error}; read={read}"))),
                    }
                }
            }
        }
        let current = self.read_inventory(inventory.slot()).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if current != inventory {
            return Err(RealmRollbackCommitInventoryStoreError::Conflict);
        }
        Ok(PersistedRealmRollbackCommitInventoryReceipt {
            store_fingerprint: self.fingerprint,
            inventory: current,
        })
    }

    pub(super) async fn read_inventory<Hash: Q256BitHash>(
        &self,
        slot: RealmRollbackCommitInventorySlot,
    ) -> Result<Option<RealmRollbackCommitInventory<Hash>>, RealmRollbackCommitInventoryStoreError> {
        let rows = self.session.execute_unpaged(&self.read_fragments, (slot.as_bytes().as_slice(),)).await
            .map_err(cql)?.into_rows_result().map_err(cql)?;
        let mut fragments = rows.rows::<(i32, i64, i32, i64, Vec<u8>, Vec<u8>, Vec<u8>)>()
            .map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if fragments.is_empty() { return Ok(None); }
        fragments.sort_by_key(|row| row.0);
        let count = usize::try_from(fragments[0].2).map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedFragment)?;
        let inventory_bytes = usize::try_from(fragments[0].3).map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedFragment)?;
        let digest: [u8; 32] = fragments[0].4.as_slice().try_into().map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedFragment)?;
        if count == 0 || count > MAX_FRAGMENTS || fragments.len() != count {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedFragment);
        }
        let mut bytes = Vec::with_capacity(inventory_bytes);
        for (expected, (index, revision, observed_count, observed_bytes, observed_digest, payload, payload_digest)) in fragments.into_iter().enumerate() {
            let payload_digest: [u8; 32] = payload_digest.as_slice().try_into().map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedFragment)?;
            if index != expected as i32
                || revision != ROW_REVISION
                || observed_count != count as i32
                || observed_bytes != inventory_bytes as i64
                || observed_digest.as_slice() != digest
                || payload.is_empty()
                || payload.len() > MAX_FRAGMENT_BYTES
                || fragment_digest(expected as i32, &payload) != payload_digest
            {
                return Err(RealmRollbackCommitInventoryStoreError::MalformedFragment);
            }
            bytes.extend_from_slice(&payload);
        }
        if bytes.len() != inventory_bytes {
            return Err(RealmRollbackCommitInventoryStoreError::MalformedFragment);
        }
        let inventory = RealmRollbackCommitInventory::decode_canonical(&bytes)?;
        if inventory.slot() != slot || inventory.digest() != &digest {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        Ok(Some(inventory))
    }

    pub(super) async fn revalidate_prewrite<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmRollbackCommitInventoryReceipt<Hash>,
    ) -> Result<(), RealmRollbackCommitInventoryStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmRollbackCommitInventoryStoreError::StoreBindingMismatch);
        }
        let current = self.read_inventory(receipt.inventory.slot()).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if current != receipt.inventory {
            return Err(RealmRollbackCommitInventoryStoreError::Conflict);
        }
        Ok(())
    }

    /// Restart selector derives the stable slot from the durable Realm
    /// candidate; callers cannot supply an arbitrary inventory slot.
    pub(super) async fn read_prewrite_for_candidate<Hash: Q256BitHash>(
        &self,
        authority: AuthorityScope,
        candidate: &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
    ) -> Result<PersistedRealmRollbackCommitInventoryReceipt<Hash>, RealmRollbackCommitInventoryStoreError> {
        let slot = RealmRollbackCommitInventorySlot::for_candidate(authority, candidate);
        let inventory = self.read_inventory(slot).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if inventory.authority() != authority || inventory.candidate() != candidate {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        Ok(PersistedRealmRollbackCommitInventoryReceipt {
            store_fingerprint: self.fingerprint,
            inventory,
        })
    }

    pub(super) async fn mark_committed<Hash: Q256BitHash>(
        &self,
        inventory: &PersistedRealmRollbackCommitInventoryReceipt<Hash>,
        manifest: &PersistedRealmFullCommitManifestReceipt<Hash>,
        head: &StoredAuthorityLocalHead<Hash>,
        pipeline: &StoredPendingPipeline<Hash>,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<PersistedRealmRollbackCommittedReceipt<Hash>, RealmRollbackCommitInventoryStoreError> {
        self.revalidate_prewrite(inventory).await?;
        let marker = RealmRollbackCommittedMarker::try_new(
            self.fingerprint,
            inventory.inventory(),
            manifest,
            head,
            pipeline,
            writer,
        )?;
        let key = marker_key(inventory.inventory().authority(), marker.candidate())?;
        let execution = self.session.execute_unpaged(
            &self.insert_marker,
            (
                key.network_chain_id, key.authority_kind, key.realm_id,
                key.realm_sub_id, key.chain_epoch, key.checkpoint_id,
                ROW_REVISION, marker.inventory_slot.as_bytes().as_slice(),
                marker.marker_payload.as_slice(),
            ),
        ).await;
        if let Err(error) = execution {
            return match self.read_marker(inventory.inventory()).await {
                Ok(Some(current)) if current == marker => Ok(PersistedRealmRollbackCommittedReceipt { store_fingerprint: self.fingerprint, marker: current }),
                Ok(_) => Err(RealmRollbackCommitInventoryStoreError::Indeterminate(error.to_string())),
                Err(read) => Err(RealmRollbackCommitInventoryStoreError::Indeterminate(format!("execute={error}; read={read}"))),
            };
        }
        let _ = decode_applied(execution.expect("checked success"))?;
        let current = self.read_marker(inventory.inventory()).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if current != marker { return Err(RealmRollbackCommitInventoryStoreError::Conflict); }
        self.revalidate_prewrite(inventory).await?;
        Ok(PersistedRealmRollbackCommittedReceipt { store_fingerprint: self.fingerprint, marker: current })
    }

    async fn read_marker<Hash: Q256BitHash>(
        &self,
        inventory: &RealmRollbackCommitInventory<Hash>,
    ) -> Result<Option<RealmRollbackCommittedMarker<Hash>>, RealmRollbackCommitInventoryStoreError> {
        let key = marker_key(inventory.authority(), inventory.candidate())?;
        let row = self.session.execute_unpaged(
            &self.read_marker,
            (key.network_chain_id, key.authority_kind, key.realm_id, key.realm_sub_id, key.chain_epoch, key.checkpoint_id),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(i64, Vec<u8>, Vec<u8>)>().map_err(cql)?;
        let Some((revision, selected_slot, payload)) = row else { return Ok(None); };
        if selected_slot.as_slice() != inventory.slot().as_bytes() {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        Ok(Some(RealmRollbackCommittedMarker::decode_persisted(
            self.fingerprint, inventory, revision, &payload,
        )?))
    }

    pub(super) async fn revalidate_committed<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmRollbackCommittedReceipt<Hash>,
    ) -> Result<(), RealmRollbackCommitInventoryStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmRollbackCommitInventoryStoreError::StoreBindingMismatch);
        }
        let inventory = self.read_inventory(receipt.marker.inventory_slot).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        let current = self.read_marker(&inventory).await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if current != receipt.marker { return Err(RealmRollbackCommitInventoryStoreError::Conflict); }
        Ok(())
    }

    /// Reconstruct the complete committed Realm suffix from the immutable
    /// checkpoint marker partition. The caller supplies the product request's
    /// exact target and source head, never a list of inventory slots.
    pub(super) async fn scan_committed_suffix<Hash: Q256BitHash>(
        &self,
        authority: AuthorityScope,
        target: CanonicalChainRef<Hash>,
        source_head: CanonicalChainRef<Hash>,
    ) -> Result<VerifiedRealmRollbackCommittedSuffix<Hash>, RealmRollbackCommitInventoryStoreError> {
        let partition = marker_partition_key(authority, &source_head)?;
        if target.network_id() != source_head.network_id()
            || target.chain_epoch() != source_head.chain_epoch()
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        let target_height = target.checkpoint().checkpoint_id().get();
        let source_height = source_head.checkpoint().checkpoint_id().get();
        let expected_rows = source_height
            .checked_sub(target_height)
            .ok_or(RealmRollbackCommitInventoryStoreError::InvalidSuffixRange)?;
        if expected_rows == 0 || expected_rows > MAX_SUFFIX_ROWS {
            return Err(RealmRollbackCommitInventoryStoreError::InvalidSuffixRange);
        }
        let target_i64 = i64::try_from(target_height)
            .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?;
        let source_i64 = i64::try_from(source_height)
            .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?;
        let mut stream = self
            .session
            .execute_iter(
                self.scan_markers.clone(),
                (
                    partition.network_chain_id,
                    partition.authority_kind,
                    partition.realm_id,
                    partition.realm_sub_id,
                    partition.chain_epoch,
                    target_i64,
                    source_i64,
                ),
            )
            .await
            .map_err(cql)?
            .rows_stream::<(i64, i64, Vec<u8>, Vec<u8>)>()
            .map_err(cql)?;
        let capacity = usize::try_from(expected_rows)
            .map_err(|_| RealmRollbackCommitInventoryStoreError::InvalidSuffixRange)?;
        let mut entries = Vec::with_capacity(capacity);
        let mut expected_checkpoint = target_height
            .checked_add(1)
            .ok_or(RealmRollbackCommitInventoryStoreError::InvalidSuffixRange)?;
        let mut previous_pending = None;
        while let Some((checkpoint, revision, selected_slot, payload)) =
            stream.try_next().await.map_err(cql)?
        {
            let checkpoint = u64::try_from(checkpoint)
                .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?;
            if checkpoint != expected_checkpoint || entries.len() >= capacity {
                return Err(RealmRollbackCommitInventoryStoreError::IncompleteSuffix);
            }
            let slot = RealmRollbackCommitInventorySlot::from_persisted(
                selected_slot
                    .as_slice()
                    .try_into()
                    .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)?,
            );
            let inventory = self
                .read_inventory(slot)
                .await?
                .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
            let candidate = inventory.candidate();
            if inventory.authority() != authority
                || candidate.canonical_chain().network_id() != source_head.network_id()
                || candidate.canonical_chain().chain_epoch() != source_head.chain_epoch()
                || candidate.canonical_chain().checkpoint().checkpoint_id().get() != checkpoint
            {
                return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
            }
            if previous_pending
                .is_some_and(|previous| candidate.pending_id().get() <= previous)
            {
                return Err(RealmRollbackCommitInventoryStoreError::NonMonotonicPending);
            }
            previous_pending = Some(candidate.pending_id().get());
            let marker = RealmRollbackCommittedMarker::decode_persisted(
                self.fingerprint,
                &inventory,
                revision,
                &payload,
            )?;
            if marker.inventory_slot != slot {
                return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
            }
            let point_marker = self
                .read_marker(&inventory)
                .await?
                .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
            if point_marker != marker {
                return Err(RealmRollbackCommitInventoryStoreError::Conflict);
            }
            entries.push(VerifiedRealmRollbackCommittedSuffixEntry {
                inventory,
                marker,
            });
            expected_checkpoint = expected_checkpoint
                .checked_add(1)
                .ok_or(RealmRollbackCommitInventoryStoreError::InvalidSuffixRange)?;
        }
        if entries.len() != capacity
            || entries
                .last()
                .map(|entry| entry.inventory.candidate().canonical_chain())
                != Some(&source_head)
        {
            return Err(RealmRollbackCommitInventoryStoreError::IncompleteSuffix);
        }
        let digest = suffix_digest(
            self.fingerprint,
            authority,
            &target,
            &source_head,
            &entries,
        );
        Ok(VerifiedRealmRollbackCommittedSuffix {
            store_fingerprint: self.fingerprint,
            authority,
            target,
            source_head,
            entries,
            digest,
        })
    }

    /// Select one exact committed checkpoint without trusting a pending id or
    /// inventory slot supplied by the caller. This is used to recover mutable
    /// target values before any suffix row can be deleted.
    pub(super) async fn read_committed_checkpoint<Hash: Q256BitHash>(
        &self,
        authority: AuthorityScope,
        candidate: CanonicalChainRef<Hash>,
    ) -> Result<VerifiedRealmRollbackCommittedSuffixEntry<Hash>, RealmRollbackCommitInventoryStoreError> {
        let selected = self
            .read_committed_height(
                authority,
                candidate.network_id(),
                candidate.chain_epoch(),
                candidate.checkpoint().checkpoint_id().get(),
            )
            .await?;
        if selected.inventory.candidate().canonical_chain() != &candidate {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        Ok(selected)
    }

    /// Select a Realm-local committed chain reference by the product's global
    /// rollback height. Realm hashes are authority-local and must never be
    /// copied from the Coordinator participant plan.
    pub(super) async fn read_committed_height<Hash: Q256BitHash>(
        &self,
        authority: AuthorityScope,
        network: NetworkId,
        chain_epoch: ChainEpoch,
        checkpoint_height: u64,
    ) -> Result<VerifiedRealmRollbackCommittedSuffixEntry<Hash>, RealmRollbackCommitInventoryStoreError> {
        let partition = marker_partition_coordinates(authority, network, chain_epoch)?;
        let checkpoint = i64::try_from(checkpoint_height)
            .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?;
        let row = self
            .session
            .execute_unpaged(
                &self.read_marker,
                (
                    partition.network_chain_id,
                    partition.authority_kind,
                    partition.realm_id,
                    partition.realm_sub_id,
                    partition.chain_epoch,
                    checkpoint,
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(i64, Vec<u8>, Vec<u8>)>()
            .map_err(cql)?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingCommittedCheckpoint)?;
        let (revision, selected_slot, payload) = row;
        let slot = RealmRollbackCommitInventorySlot::from_persisted(
            selected_slot
                .as_slice()
                .try_into()
                .map_err(|_| RealmRollbackCommitInventoryStoreError::MalformedMarker)?,
        );
        let inventory = self
            .read_inventory(slot)
            .await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if inventory.authority() != authority
            || inventory.candidate().canonical_chain().network_id() != network
            || inventory.candidate().canonical_chain().chain_epoch() != chain_epoch
            || inventory.candidate().canonical_chain().checkpoint().checkpoint_id().get()
                != checkpoint_height
        {
            return Err(RealmRollbackCommitInventoryStoreError::SourceMismatch);
        }
        let marker = RealmRollbackCommittedMarker::decode_persisted(
            self.fingerprint,
            &inventory,
            revision,
            &payload,
        )?;
        let point_marker = self
            .read_marker(&inventory)
            .await?
            .ok_or(RealmRollbackCommitInventoryStoreError::MissingAfterWrite)?;
        if marker != point_marker {
            return Err(RealmRollbackCommitInventoryStoreError::Conflict);
        }
        Ok(VerifiedRealmRollbackCommittedSuffixEntry { inventory, marker })
    }

    pub(super) async fn revalidate_committed_suffix<Hash: Q256BitHash>(
        &self,
        suffix: &VerifiedRealmRollbackCommittedSuffix<Hash>,
    ) -> Result<(), RealmRollbackCommitInventoryStoreError> {
        if suffix.store_fingerprint != self.fingerprint {
            return Err(RealmRollbackCommitInventoryStoreError::StoreBindingMismatch);
        }
        let current = self
            .scan_committed_suffix(
                suffix.authority,
                suffix.target,
                suffix.source_head,
            )
            .await?;
        if current != *suffix {
            return Err(RealmRollbackCommitInventoryStoreError::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Fragment {
    index: i32,
    count: i32,
    inventory_bytes: i64,
    payload: Vec<u8>,
    digest: [u8; 32],
}

fn split_inventory<Hash: Q256BitHash>(inventory: &RealmRollbackCommitInventory<Hash>) -> Result<Vec<Fragment>, RealmRollbackCommitInventoryStoreError> {
    let bytes = inventory.canonical_bytes();
    let chunks = bytes.chunks(MAX_FRAGMENT_BYTES).collect::<Vec<_>>();
    if chunks.is_empty() || chunks.len() > MAX_FRAGMENTS {
        return Err(RealmRollbackCommitInventoryStoreError::PayloadTooLarge);
    }
    let count = i32::try_from(chunks.len()).map_err(|_| RealmRollbackCommitInventoryStoreError::PayloadTooLarge)?;
    let inventory_bytes = i64::try_from(bytes.len()).map_err(|_| RealmRollbackCommitInventoryStoreError::PayloadTooLarge)?;
    Ok(chunks.into_iter().enumerate().map(|(index, payload)| Fragment {
        index: index as i32,
        count,
        inventory_bytes,
        payload: payload.to_vec(),
        digest: fragment_digest(index as i32, payload),
    }).collect())
}

fn encode_marker<Hash: Q256BitHash>(
    store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    marker: &RealmRollbackCommittedMarker<Hash>,
) -> Result<Vec<u8>, RealmRollbackCommitInventoryStoreError> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(MARKER_MAGIC);
    out.extend_from_slice(&MARKER_VERSION.to_be_bytes());
    out.extend_from_slice(&store_fingerprint.0);
    out.extend_from_slice(marker.inventory_slot.as_bytes());
    out.extend_from_slice(&marker.inventory_digest);
    out.extend_from_slice(&marker.manifest_slot);
    out.extend_from_slice(&marker.manifest_digest);
    out.extend_from_slice(&marker.timestamp.to_be_bytes());
    out.extend_from_slice(&marker.coverage_digest);
    out.extend_from_slice(&marker.total_mutation_count.to_be_bytes());
    out.extend_from_slice(&marker.head_revision.to_be_bytes());
    encode_bytes(&marker.head_payload, &mut out)?;
    out.extend_from_slice(&marker.pipeline_revision.to_be_bytes());
    encode_bytes(&marker.pipeline_payload, &mut out)?;
    out.extend_from_slice(&marker.writer_revision.to_be_bytes());
    let digest = marker_digest(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), RealmRollbackCommitInventoryStoreError> {
    out.extend_from_slice(&u32::try_from(bytes.len()).map_err(|_| RealmRollbackCommitInventoryStoreError::PayloadTooLarge)?.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn fragment_digest(index: i32, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(index.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn marker_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MARKER_DIGEST_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn store_fingerprint(
    control: &BranchExactDeploymentNoTabletKeyspace,
    data: &PendingQueueArtifactDataKeyspace,
    queries: &RealmRollbackCommitInventoryQueries,
) -> RealmRollbackCommitInventoryStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    for value in [control.as_str(), data.as_str(), queries.golden().as_str()] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    RealmRollbackCommitInventoryStoreFingerprint(hasher.finalize().into())
}

#[derive(Clone, Copy)]
struct MarkerKey {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i32,
    chain_epoch: i64,
    checkpoint_id: i64,
}

fn marker_key<Hash: Q256BitHash>(
    authority: AuthorityScope,
    candidate: &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
) -> Result<MarkerKey, RealmRollbackCommitInventoryStoreError> {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
        return Err(RealmRollbackCommitInventoryStoreError::RealmRequired);
    };
    Ok(MarkerKey {
        network_chain_id: i64::from(candidate.canonical_chain().network_id().chain_id()),
        authority_kind: 2,
        realm_id: i64::from(realm_id),
        realm_sub_id: i32::from(realm_sub_id),
        chain_epoch: i64::try_from(candidate.canonical_chain().chain_epoch().get()).map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
        checkpoint_id: i64::try_from(candidate.canonical_chain().checkpoint().checkpoint_id().get()).map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
    })
}

fn marker_partition_key<Hash: Q256BitHash>(
    authority: AuthorityScope,
    source_head: &CanonicalChainRef<Hash>,
) -> Result<MarkerKey, RealmRollbackCommitInventoryStoreError> {
    marker_partition_coordinates(
        authority,
        source_head.network_id(),
        source_head.chain_epoch(),
    )
}

fn marker_partition_coordinates(
    authority: AuthorityScope,
    network: NetworkId,
    chain_epoch: ChainEpoch,
) -> Result<MarkerKey, RealmRollbackCommitInventoryStoreError> {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = authority
    else {
        return Err(RealmRollbackCommitInventoryStoreError::RealmRequired);
    };
    Ok(MarkerKey {
        network_chain_id: i64::from(network.chain_id()),
        authority_kind: 2,
        realm_id: i64::from(realm_id),
        realm_sub_id: i32::from(realm_sub_id),
        chain_epoch: i64::try_from(chain_epoch.get())
            .map_err(|_| RealmRollbackCommitInventoryStoreError::CoordinateOutOfRange)?,
        checkpoint_id: 0,
    })
}

fn suffix_digest<Hash: Q256BitHash>(
    store_fingerprint: RealmRollbackCommitInventoryStoreFingerprint,
    authority: AuthorityScope,
    target: &CanonicalChainRef<Hash>,
    source_head: &CanonicalChainRef<Hash>,
    entries: &[VerifiedRealmRollbackCommittedSuffixEntry<Hash>],
) -> [u8; 32] {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = authority
    else {
        unreachable!("suffix scanner validates Realm authority")
    };
    let mut hasher = Sha256::new();
    hasher.update(SUFFIX_DIGEST_DOMAIN);
    hasher.update(store_fingerprint.0);
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(target.to_canonical_bytes());
    hasher.update(source_head.to_canonical_bytes());
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(entry.inventory.slot().as_bytes());
        hasher.update(entry.inventory.digest());
        hasher.update(entry.marker.digest());
    }
    hasher.finalize().into()
}

async fn prepare_regular(session: &Session, cql_text: &str) -> Result<PreparedStatement, RealmRollbackCommitInventoryStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: &str) -> Result<PreparedStatement, RealmRollbackCommitInventoryStoreError> {
    let mut statement = prepare_regular(session, cql_text).await?;
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RealmRollbackCommitInventoryStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    if rows.rows_num() != 1 { return Err(RealmRollbackCommitInventoryStoreError::MalformedLwt); }
    let row = rows.rows::<Row>().map_err(cql)?.next().ok_or(RealmRollbackCommitInventoryStoreError::MalformedLwt)?.map_err(cql)?;
    match row.columns.first() {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RealmRollbackCommitInventoryStoreError::MalformedLwt),
    }
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackCommitInventoryStoreError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackCommitInventoryStoreError::MalformedMarker)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackCommitInventoryStoreError::MalformedMarker)?;
        self.offset = end; Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackCommitInventoryStoreError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmRollbackCommitInventoryStoreError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackCommitInventoryStoreError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackCommitInventoryStoreError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], RealmRollbackCommitInventoryStoreError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn bytes(&mut self) -> Result<&'a [u8], RealmRollbackCommitInventoryStoreError> { let len = self.u32()? as usize; self.take(len) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackCommitInventoryStoreError {
    RealmRequired,
    CoordinateOutOfRange,
    InvalidSuffixRange,
    IncompleteSuffix,
    NonMonotonicPending,
    MissingCommittedCheckpoint,
    PayloadTooLarge,
    MalformedFragment,
    MalformedMarker,
    MalformedLwt,
    SourceMismatch,
    StoreBindingMismatch,
    MissingAfterWrite,
    Conflict,
    Indeterminate(String),
    Inventory(RealmRollbackCommitInventoryError),
    Cql(String),
}

impl From<RealmRollbackCommitInventoryError> for RealmRollbackCommitInventoryStoreError {
    fn from(value: RealmRollbackCommitInventoryError) -> Self { Self::Inventory(value) }
}
impl fmt::Display for RealmRollbackCommitInventoryStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmRollbackCommitInventoryStoreError {}
fn cql(error: impl fmt::Display) -> RealmRollbackCommitInventoryStoreError { RealmRollbackCommitInventoryStoreError::Cql(error.to_string()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_append_only_and_split_across_control_and_data() {
        let control =
            BranchExactDeploymentNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let data = PendingQueueArtifactDataKeyspace::try_new("realm_inventory_data".to_owned()).unwrap();
        let queries = RealmRollbackCommitInventoryQueries::new(&control, &data);
        let golden = queries.golden();
        assert!(golden.contains("realm_inventory_data.branch_exact_realm_rollback_commit_inventory_fragment_v1"));
        assert!(golden.contains("control_nt.branch_exact_realm_rollback_commit_marker_v1"));
        assert_eq!(golden.matches("IF NOT EXISTS").count(), 4);
        for forbidden in ["UPDATE ", "DELETE ", " TTL", "TIMESTAMP", "ALLOW FILTERING"] {
            assert!(!golden.contains(forbidden));
        }
    }

    #[test]
    fn store_exposes_no_archive_delete_or_restore_route() {
        let source = include_str!("realm_rollback_commit_inventory_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["archive_suffix", "delete_suffix", "restore_target", "cross_barrier", "compare_and_set"] {
            assert!(!production.contains(forbidden));
        }
        assert!(!production.contains("impl Clone for PersistedRealmRollback"));
    }
}
