//! Immutable fragmented persistence for exact Realm rollback before-images.
//!
//! This adapter deliberately reuses the rollback archive table already
//! materialized by the Coordinator setup.  A stable participant-plan/Realm
//! row identity means a delayed different value conflicts at the same LWT
//! partition.  The adapter can only persist and revalidate before-images; it
//! cannot cross the global archive barrier or mutate hot state.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    realm_rollback_physical_before_image::{
        RealmRollbackPhysicalBeforeImage, RealmRollbackPhysicalBeforeImageError,
    },
    realm_rollback_physical_catalog::{
        RealmRollbackPhysicalCatalog, RealmRollbackPhysicalCatalogEntry,
    },
    realm_rollback_participant_completion::{
        REALM_PARTICIPANT_COMPLETION_KEY_DOMAIN,
        RealmRollbackParticipantCompletion,
        RealmRollbackParticipantCompletionError,
    },
};

const ARCHIVE_REVISION: i64 = 1;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const FRAGMENT_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-physical-before-image-fragment.v1\0";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.realm-physical-archive-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_ROW_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ? AND fragment_index = ?";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmRollbackPhysicalArchiveQueries {
    insert: String,
    read_row: String,
    read_fragment: String,
}

impl RealmRollbackPhysicalArchiveQueries {
    fn new(keyspace: &CqlKeyspaceName) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        Self {
            insert: INSERT_TEMPLATE.replace("{table}", &table),
            read_row: READ_ROW_TEMPLATE.replace("{table}", &table),
            read_fragment: READ_FRAGMENT_TEMPLATE.replace("{table}", &table),
        }
    }
}

/// Private, affine-adjacent evidence of exact immutable readback.  It is not
/// Clone and cannot authorize a delete, restore, barrier, or head transition.
#[derive(Debug)]
pub(super) struct PersistedRealmRollbackPhysicalBeforeImage<Hash> {
    store_fingerprint: [u8; 32],
    before_image: RealmRollbackPhysicalBeforeImage<Hash>,
}

impl<Hash> PersistedRealmRollbackPhysicalBeforeImage<Hash> {
    pub(super) const fn before_image(&self) -> &RealmRollbackPhysicalBeforeImage<Hash> {
        &self.before_image
    }
}

/// Storage-private, non-Clone proof that one exact Realm participant
/// completion was persisted and reconstructed from all immutable fragments.
/// It remains pre-barrier and is not accepted by any destructive operation.
#[derive(Debug)]
pub(super) struct PersistedRealmRollbackParticipantCompletion<Hash> {
    store_fingerprint: [u8; 32],
    completion: RealmRollbackParticipantCompletion<Hash>,
}

impl<Hash> PersistedRealmRollbackParticipantCompletion<Hash> {
    pub(super) fn from_recovered(
        store_fingerprint: [u8; 32],
        completion: RealmRollbackParticipantCompletion<Hash>,
    ) -> Self {
        Self { store_fingerprint, completion }
    }

    pub(super) const fn completion(&self) -> &RealmRollbackParticipantCompletion<Hash> {
        &self.completion
    }
}

pub(super) struct ScyllaRealmRollbackPhysicalArchiveStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read_row: PreparedStatement,
    read_fragment: PreparedStatement,
}

impl ScyllaRealmRollbackPhysicalArchiveStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: CqlKeyspaceName,
    ) -> Result<Self, RealmRollbackPhysicalArchiveStoreError> {
        let queries = RealmRollbackPhysicalArchiveQueries::new(&keyspace);
        let mut hasher = Sha256::new();
        hasher.update(STORE_FINGERPRINT_DOMAIN);
        hasher.update(keyspace.as_str().as_bytes());
        hasher.update(queries.insert.as_bytes());
        hasher.update(queries.read_row.as_bytes());
        hasher.update(queries.read_fragment.as_bytes());
        Ok(Self {
            insert: prepare_lwt(&session, &queries.insert).await?,
            read_row: prepare_read(&session, &queries.read_row).await?,
            read_fragment: prepare_read(&session, &queries.read_fragment).await?,
            fingerprint: hasher.finalize().into(),
            session,
        })
    }

    pub(super) const fn fingerprint(&self) -> &[u8; 32] { &self.fingerprint }

    /// Persist every fragment using IF NOT EXISTS, then reconstruct and
    /// compare the full canonical object.  An execute error is reconciled by
    /// full-PK point read; any non-exact result is indeterminate/conflicting.
    pub(super) async fn persist_and_readback<Hash: Q256BitHash>(
        &self,
        image: RealmRollbackPhysicalBeforeImage<Hash>,
    ) -> Result<PersistedRealmRollbackPhysicalBeforeImage<Hash>, RealmRollbackPhysicalArchiveStoreError> {
        let coordinates = ArchiveCoordinates::try_from_image(&image)?;
        self.persist_bytes(&coordinates, image.canonical_bytes(), image.digest()).await?;
        let current = self.read_selected::<Hash>(&coordinates).await?
            .ok_or(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist)?;
        if current != image {
            return Err(RealmRollbackPhysicalArchiveStoreError::Conflict);
        }
        Ok(PersistedRealmRollbackPhysicalBeforeImage {
            store_fingerprint: self.fingerprint,
            before_image: current,
        })
    }

    pub(super) async fn persist_participant_completion<Hash: Q256BitHash>(
        &self,
        completion: RealmRollbackParticipantCompletion<Hash>,
    ) -> Result<PersistedRealmRollbackParticipantCompletion<Hash>, RealmRollbackPhysicalArchiveStoreError> {
        let coordinates = ArchiveCoordinates::try_from_completion(&completion)?;
        self.persist_bytes(
            &coordinates,
            completion.canonical_bytes(),
            completion.digest(),
        ).await?;
        let current = self.read_participant_completion::<Hash>(&coordinates).await?
            .ok_or(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist)?;
        if current != completion {
            return Err(RealmRollbackPhysicalArchiveStoreError::Conflict);
        }
        Ok(PersistedRealmRollbackParticipantCompletion {
            store_fingerprint: self.fingerprint,
            completion: current,
        })
    }

    pub(super) async fn read_participant_completion_exact<Hash: Q256BitHash>(
        &self,
        completion: &RealmRollbackParticipantCompletion<Hash>,
    ) -> Result<Option<RealmRollbackParticipantCompletion<Hash>>, RealmRollbackPhysicalArchiveStoreError> {
        let coordinates = ArchiveCoordinates::try_from_completion(completion)?;
        self.read_participant_completion(&coordinates).await
    }

    pub(super) async fn revalidate_participant_completion<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmRollbackParticipantCompletion<Hash>,
    ) -> Result<(), RealmRollbackPhysicalArchiveStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmRollbackPhysicalArchiveStoreError::ReceiptBindingMismatch);
        }
        match self.read_participant_completion_exact(&receipt.completion).await? {
            Some(current) if current == receipt.completion => Ok(()),
            Some(_) => Err(RealmRollbackPhysicalArchiveStoreError::Conflict),
            None => Err(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist),
        }
    }

    async fn persist_bytes(
        &self,
        coordinates: &ArchiveCoordinates,
        bytes: &[u8],
        row_digest: &[u8; 32],
    ) -> Result<(), RealmRollbackPhysicalArchiveStoreError> {
        for fragment in archive_fragments(bytes, row_digest)? {
            let execution = self.session.execute_unpaged(
                &self.insert,
                (
                    coordinates.network,
                    coordinates.chain_epoch,
                    coordinates.participant_plan_digest.as_slice(),
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
            ).await;
            match execution {
                Ok(result) => {
                    if !decode_applied(result)?
                        && self.read_fragment(&coordinates, fragment.index).await?.as_ref()
                            != Some(&fragment)
                    {
                        return Err(RealmRollbackPhysicalArchiveStoreError::Conflict);
                    }
                }
                Err(error) => match self.read_fragment(&coordinates, fragment.index).await {
                    Ok(Some(current)) if current == fragment => {}
                    Ok(_) => return Err(RealmRollbackPhysicalArchiveStoreError::Indeterminate(error.to_string())),
                    Err(read) => return Err(RealmRollbackPhysicalArchiveStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    )),
                },
            }
        }
        Ok(())
    }

    pub(super) async fn revalidate_exact<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmRollbackPhysicalBeforeImage<Hash>,
    ) -> Result<(), RealmRollbackPhysicalArchiveStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmRollbackPhysicalArchiveStoreError::ReceiptBindingMismatch);
        }
        let coordinates = ArchiveCoordinates::try_from_image(&receipt.before_image)?;
        match self.read_selected::<Hash>(&coordinates).await? {
            Some(current) if current == receipt.before_image => Ok(()),
            Some(_) => Err(RealmRollbackPhysicalArchiveStoreError::Conflict),
            None => Err(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist),
        }
    }

    pub(super) async fn revalidate_image_exact<Hash: Q256BitHash>(
        &self,
        image: &RealmRollbackPhysicalBeforeImage<Hash>,
    ) -> Result<(), RealmRollbackPhysicalArchiveStoreError> {
        let coordinates = ArchiveCoordinates::try_from_image(image)?;
        match self.read_selected::<Hash>(&coordinates).await? {
            Some(current) if current == *image => Ok(()),
            Some(_) => Err(RealmRollbackPhysicalArchiveStoreError::Conflict),
            None => Err(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist),
        }
    }

    /// Point-select and strictly bind one immutable before-image using only
    /// the post-barrier catalog.  It never consults the hot row, so deletion
    /// retries can recover after a process crash without weakening identity.
    pub(super) async fn read_catalog_image<Hash: Q256BitHash>(
        &self,
        participant_plan_digest: [u8; 32],
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
    ) -> Result<RealmRollbackPhysicalBeforeImage<Hash>, RealmRollbackPhysicalArchiveStoreError> {
        let (key_domain, row_slot) =
            RealmRollbackPhysicalBeforeImage::selector_for_catalog_entry(
                participant_plan_digest,
                catalog,
                entry,
            )?;
        let coordinates = ArchiveCoordinates {
            network: i64::from(catalog.suffix().target().network_id().chain_id()),
            chain_epoch: i64::try_from(
                catalog.suffix().target().chain_epoch().get(),
            )
            .map_err(|_| RealmRollbackPhysicalArchiveStoreError::IntegerOutOfCqlRange)?,
            participant_plan_digest,
            key_domain,
            row_slot,
        };
        let image = self
            .read_selected::<Hash>(&coordinates)
            .await?
            .ok_or(RealmRollbackPhysicalArchiveStoreError::MissingAfterPersist)?;
        image.require_catalog_entry(participant_plan_digest, catalog, entry)?;
        Ok(image)
    }

    async fn read_selected<Hash: Q256BitHash>(
        &self,
        coordinates: &ArchiveCoordinates,
    ) -> Result<Option<RealmRollbackPhysicalBeforeImage<Hash>>, RealmRollbackPhysicalArchiveStoreError> {
        let Some((bytes, row_digest)) = self.read_selected_bytes(coordinates).await? else {
            return Ok(None);
        };
        let image = RealmRollbackPhysicalBeforeImage::decode_canonical(&bytes)?;
        if image.participant_plan_digest() != &coordinates.participant_plan_digest
            || image.key_domain() != coordinates.key_domain
            || image.slot() != &coordinates.row_slot
            || image.digest() != &row_digest
        {
            return Err(RealmRollbackPhysicalArchiveStoreError::Conflict);
        }
        Ok(Some(image))
    }

    async fn read_participant_completion<Hash: Q256BitHash>(
        &self,
        coordinates: &ArchiveCoordinates,
    ) -> Result<Option<RealmRollbackParticipantCompletion<Hash>>, RealmRollbackPhysicalArchiveStoreError> {
        let Some((bytes, row_digest)) = self.read_selected_bytes(coordinates).await? else {
            return Ok(None);
        };
        let completion = RealmRollbackParticipantCompletion::decode_canonical(&bytes)?;
        if completion.participant_plan_digest() != &coordinates.participant_plan_digest
            || coordinates.key_domain != REALM_PARTICIPANT_COMPLETION_KEY_DOMAIN
            || completion.slot() != &coordinates.row_slot
            || completion.digest() != &row_digest
        {
            return Err(RealmRollbackPhysicalArchiveStoreError::Conflict);
        }
        Ok(Some(completion))
    }

    async fn read_selected_bytes(
        &self,
        coordinates: &ArchiveCoordinates,
    ) -> Result<Option<(Vec<u8>, [u8; 32])>, RealmRollbackPhysicalArchiveStoreError> {
        let rows = self.session.execute_unpaged(
            &self.read_row,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                coordinates.key_domain,
                coordinates.row_slot.as_slice(),
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .rows::<(
                Option<i32>, Option<i64>, Option<i32>, Option<i64>,
                Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if rows.is_empty() { return Ok(None); }
        let mut fragments = Vec::with_capacity(rows.len());
        for (index, revision, count, row_bytes, payload, digest, row_digest) in rows {
            fragments.push(decode_fragment(index, revision, count, row_bytes, payload, digest, row_digest)?);
        }
        let row_digest = fragments[0].row_digest;
        let bytes = reconstruct_fragments(fragments, &row_digest)?;
        Ok(Some((bytes, row_digest)))
    }

    async fn read_fragment(
        &self,
        coordinates: &ArchiveCoordinates,
        index: i32,
    ) -> Result<Option<ArchiveFragment>, RealmRollbackPhysicalArchiveStoreError> {
        let row = self.session.execute_unpaged(
            &self.read_fragment,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                coordinates.key_domain,
                coordinates.row_slot.as_slice(),
                index,
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(
                Option<i64>, Option<i32>, Option<i64>, Option<Vec<u8>>,
                Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?;
        row.map(|(revision, count, row_bytes, payload, digest, row_digest)| {
            decode_fragment(Some(index), revision, count, row_bytes, payload, digest, row_digest)
        }).transpose()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArchiveCoordinates {
    network: i64,
    chain_epoch: i64,
    participant_plan_digest: [u8; 32],
    key_domain: i16,
    row_slot: [u8; 32],
}

impl ArchiveCoordinates {
    fn try_from_image<Hash: Q256BitHash>(
        image: &RealmRollbackPhysicalBeforeImage<Hash>,
    ) -> Result<Self, RealmRollbackPhysicalArchiveStoreError> {
        Ok(Self {
            network: i64::from(image.target().network_id().chain_id()),
            chain_epoch: i64::try_from(image.target().chain_epoch().get())
                .map_err(|_| RealmRollbackPhysicalArchiveStoreError::IntegerOutOfCqlRange)?,
            participant_plan_digest: *image.participant_plan_digest(),
            key_domain: image.key_domain(),
            row_slot: *image.slot(),
        })
    }

    fn try_from_completion<Hash: Q256BitHash>(
        completion: &RealmRollbackParticipantCompletion<Hash>,
    ) -> Result<Self, RealmRollbackPhysicalArchiveStoreError> {
        Ok(Self {
            network: i64::from(completion.network().chain_id()),
            chain_epoch: i64::try_from(completion.old_chain_epoch())
                .map_err(|_| RealmRollbackPhysicalArchiveStoreError::IntegerOutOfCqlRange)?,
            participant_plan_digest: *completion.participant_plan_digest(),
            key_domain: REALM_PARTICIPANT_COMPLETION_KEY_DOMAIN,
            row_slot: *completion.slot(),
        })
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

fn archive_fragments(
    bytes: &[u8],
    row_digest: &[u8; 32],
) -> Result<Vec<ArchiveFragment>, RealmRollbackPhysicalArchiveStoreError> {
    let count = bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
    if count == 0 || count > MAX_FRAGMENTS {
        return Err(RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    let count = i32::try_from(count).map_err(|_| RealmRollbackPhysicalArchiveStoreError::LengthOverflow)?;
    let row_bytes = i64::try_from(bytes.len()).map_err(|_| RealmRollbackPhysicalArchiveStoreError::LengthOverflow)?;
    Ok(bytes.chunks(MAX_FRAGMENT_BYTES).enumerate().map(|(index, payload)| {
        let index = i32::try_from(index).expect("at most sixteen fragments");
        ArchiveFragment {
            index,
            count,
            row_bytes,
            payload: payload.to_vec(),
            digest: fragment_digest(row_digest, index, count, row_bytes, payload),
            row_digest: *row_digest,
        }
    }).collect())
}

fn decode_fragment(
    index: Option<i32>, revision: Option<i64>, count: Option<i32>,
    row_bytes: Option<i64>, payload: Option<Vec<u8>>, digest: Option<Vec<u8>>,
    row_digest: Option<Vec<u8>>,
) -> Result<ArchiveFragment, RealmRollbackPhysicalArchiveStoreError> {
    if revision != Some(ARCHIVE_REVISION) {
        return Err(RealmRollbackPhysicalArchiveStoreError::InvalidArchiveRevision);
    }
    let index = index.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?;
    let count = count.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?;
    let row_bytes = row_bytes.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?;
    let payload = payload.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?;
    let digest = array_32(digest.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?)?;
    let row_digest = array_32(row_digest.ok_or(RealmRollbackPhysicalArchiveStoreError::MissingArchiveColumn)?)?;
    if fragment_digest(&row_digest, index, count, row_bytes, &payload) != digest {
        return Err(RealmRollbackPhysicalArchiveStoreError::FragmentDigestMismatch);
    }
    Ok(ArchiveFragment { index, count, row_bytes, payload, digest, row_digest })
}

fn reconstruct_fragments(
    mut fragments: Vec<ArchiveFragment>,
    expected_digest: &[u8; 32],
) -> Result<Vec<u8>, RealmRollbackPhysicalArchiveStoreError> {
    fragments.sort_by_key(|fragment| fragment.index);
    let Some(first) = fragments.first() else {
        return Err(RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet);
    };
    let expected_count = usize::try_from(first.count)
        .map_err(|_| RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet)?;
    let expected_bytes = usize::try_from(first.row_bytes)
        .map_err(|_| RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet)?;
    if expected_count == 0 || expected_count > MAX_FRAGMENTS || fragments.len() != expected_count {
        return Err(RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    let mut bytes = Vec::with_capacity(expected_bytes);
    for (expected_index, fragment) in fragments.iter().enumerate() {
        if fragment.index != expected_index as i32
            || fragment.count != first.count
            || fragment.row_bytes != first.row_bytes
            || &fragment.row_digest != expected_digest
        {
            return Err(RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet);
        }
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() != expected_bytes || bytes.len() > MAX_FRAGMENT_BYTES * MAX_FRAGMENTS {
        return Err(RealmRollbackPhysicalArchiveStoreError::InvalidFragmentSet);
    }
    Ok(bytes)
}

fn fragment_digest(
    row_digest: &[u8; 32], index: i32, count: i32, row_bytes: i64, payload: &[u8],
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

async fn prepare_read(
    session: &Session, query: &str,
) -> Result<PreparedStatement, RealmRollbackPhysicalArchiveStoreError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session, query: &str,
) -> Result<PreparedStatement, RealmRollbackPhysicalArchiveStoreError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RealmRollbackPhysicalArchiveStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(RealmRollbackPhysicalArchiveStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmRollbackPhysicalArchiveStoreError::InvalidAppliedColumn),
    }
}

fn array_32(bytes: Vec<u8>) -> Result<[u8; 32], RealmRollbackPhysicalArchiveStoreError> {
    bytes.try_into().map_err(|_| RealmRollbackPhysicalArchiveStoreError::InvalidDigestLength)
}

fn cql(error: impl fmt::Display) -> RealmRollbackPhysicalArchiveStoreError {
    RealmRollbackPhysicalArchiveStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackPhysicalArchiveStoreError {
    BeforeImage(RealmRollbackPhysicalBeforeImageError),
    ParticipantCompletion(RealmRollbackParticipantCompletionError),
    Cql(String),
    Conflict,
    Indeterminate(String),
    MissingAfterPersist,
    ReceiptBindingMismatch,
    InvalidFragmentSet,
    InvalidArchiveRevision,
    MissingArchiveColumn,
    FragmentDigestMismatch,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    InvalidDigestLength,
    IntegerOutOfCqlRange,
    LengthOverflow,
}

impl From<RealmRollbackPhysicalBeforeImageError> for RealmRollbackPhysicalArchiveStoreError {
    fn from(value: RealmRollbackPhysicalBeforeImageError) -> Self { Self::BeforeImage(value) }
}
impl From<RealmRollbackParticipantCompletionError> for RealmRollbackPhysicalArchiveStoreError {
    fn from(value: RealmRollbackParticipantCompletionError) -> Self { Self::ParticipantCompletion(value) }
}

impl fmt::Display for RealmRollbackPhysicalArchiveStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm rollback physical archive error: {self:?}")
    }
}
impl Error for RealmRollbackPhysicalArchiveStoreError {}

#[cfg(test)]
mod tests {
    use super::{archive_fragments, reconstruct_fragments};

    #[test]
    fn fragments_are_bounded_ordered_and_exact() {
        let bytes = vec![7; 4 * 1024 * 1024 + 17];
        let digest = [3; 32];
        let mut fragments = archive_fragments(&bytes, &digest).unwrap();
        assert_eq!(fragments.len(), 2);
        fragments.reverse();
        assert_eq!(reconstruct_fragments(fragments, &digest).unwrap(), bytes);
    }

    #[test]
    fn store_has_no_barrier_delete_restore_or_head_api() {
        let source = include_str!("realm_rollback_physical_archive_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["execute_delete", "execute_restore", "cross_archive_barrier", "publish_head"] {
            assert!(!production.contains(forbidden));
        }
    }
}
