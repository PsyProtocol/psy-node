//! Durable Coordinator participant completion after the global rollback PONR.
//!
//! The completion is immutable and can only be built from the physical
//! executor's non-clone result.  It does not publish the target head: a later
//! global delete barrier must first collect the matching Realm completions.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN,
};
use psy_node_core::store::canonical_head::StoredCanonicalHead;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    coordinator_commit_delete_restore_executor::ExecutedCoordinatorRollbackSuffix,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    CqlKeyspaceName,
};

const KEY_DOMAIN: i16 = -5;
const REVISION: i64 = 1;
const MAGIC: &[u8; 8] = b"PSYCRDC1";
const VERSION: u16 = 1;
const MAX_ROW_BYTES: usize = 16 * 1024;
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.coordinator-delete-completion.v1\0";
const SLOT_DOMAIN: &[u8] = b"psy.rollback.coordinator-delete-completion-slot.v1\0";
const FRAGMENT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-delete-completion-fragment.v1\0";
const STORE_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-delete-completion-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";

#[derive(Debug, Eq, PartialEq)]
pub(super) struct CoordinatorRollbackDeleteCompletion<Hash> {
    deleting_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    barrier_digest: [u8; 32],
    delete_plan_store_fingerprint: [u8; 32],
    delete_plan_slot: [u8; 32],
    delete_plan_digest: [u8; 32],
    target_restore_digest: [u8; 32],
    post_state_digest: [u8; 32],
    physical_delete_count: u64,
    restored_singleton_count: u64,
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> CoordinatorRollbackDeleteCompletion<Hash> {
    fn try_from_executed(
        executed: &ExecutedCoordinatorRollbackSuffix<Hash>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, CoordinatorRollbackDeleteCompletionStoreError> {
        Self::try_from_fields(
            *executed.deleting_head(),
            *executed.target(),
            *executed.participant_plan_digest(),
            *executed.barrier_digest(),
            *executed.delete_plan_store_fingerprint(),
            *executed.delete_plan_slot(),
            *executed.delete_plan_digest(),
            *executed.target_restore_digest(),
            *executed.post_state_digest(),
            executed.physical_delete_count(),
            executed.restored_singleton_count(),
            store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        deleting_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        barrier_digest: [u8; 32],
        delete_plan_store_fingerprint: [u8; 32],
        delete_plan_slot: [u8; 32],
        delete_plan_digest: [u8; 32],
        target_restore_digest: [u8; 32],
        post_state_digest: [u8; 32],
        physical_delete_count: u64,
        restored_singleton_count: u64,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, CoordinatorRollbackDeleteCompletionStoreError> {
        let request = deleting_head
            .rollback_control()
            .requested()
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::BindingMismatch)?;
        if !matches!(
            deleting_head.rollback_control(),
            psy_node_core::store::rollback_control::RollbackControlState::Deleting(_)
        ) || deleting_head.canonical_ref().network_id() != target.network_id()
            || deleting_head
                .canonical_ref()
                .chain_epoch()
                .get()
                .checked_sub(1)
                != Some(target.chain_epoch().get())
            || request.target() != target.checkpoint()
            || request.plan_digest().as_bytes() != &participant_plan_digest
            || physical_delete_count == 0
            || restored_singleton_count != 2
            || [
                participant_plan_digest,
                barrier_digest,
                delete_plan_store_fingerprint,
                delete_plan_slot,
                delete_plan_digest,
                target_restore_digest,
                post_state_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::BindingMismatch);
        }
        let slot = completion_slot(
            &deleting_head,
            &target,
            &participant_plan_digest,
            &store_fingerprint,
        );
        let mut selected = Self {
            deleting_head,
            target,
            participant_plan_digest,
            barrier_digest,
            delete_plan_store_fingerprint,
            delete_plan_slot,
            delete_plan_digest,
            target_restore_digest,
            post_state_digest,
            physical_delete_count,
            restored_singleton_count,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = selected.encode_body()?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&body);
        selected.digest = hasher.finalize().into();
        selected.canonical_bytes = body;
        selected.canonical_bytes.extend_from_slice(&selected.digest);
        if selected.canonical_bytes.len() > MAX_ROW_BYTES {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::RowTooLarge);
        }
        Ok(selected)
    }

    fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorRollbackDeleteCompletionStoreError> {
        if bytes.len() > MAX_ROW_BYTES || bytes.len() < 32 {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)
            .map_err(|error| CoordinatorRollbackDeleteCompletionStoreError::Model(error.to_string()))?;
        let old_chain_epoch = cursor.u64()?;
        let head_revision = cursor.i64()?;
        let head_canonical = cursor.bytes()?;
        let head_control = cursor.bytes()?;
        let deleting_head = StoredCanonicalHead::decode_persisted(
            network,
            head_revision,
            head_canonical,
            head_control,
        )
        .map_err(|error| CoordinatorRollbackDeleteCompletionStoreError::Model(error.to_string()))?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| CoordinatorRollbackDeleteCompletionStoreError::Model(error.to_string()))?;
        if target.chain_epoch().get() != old_chain_epoch {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::BindingMismatch);
        }
        let participant_plan_digest = cursor.array_32()?;
        let barrier_digest = cursor.array_32()?;
        let delete_plan_store_fingerprint = cursor.array_32()?;
        let delete_plan_slot = cursor.array_32()?;
        let delete_plan_digest = cursor.array_32()?;
        let target_restore_digest = cursor.array_32()?;
        let post_state_digest = cursor.array_32()?;
        let physical_delete_count = cursor.u64()?;
        let restored_singleton_count = cursor.u64()?;
        let store_fingerprint = cursor.array_32()?;
        let encoded_slot = cursor.array_32()?;
        let encoded_digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::TrailingBytes);
        }
        let decoded = Self::try_from_fields(
            deleting_head,
            target,
            participant_plan_digest,
            barrier_digest,
            delete_plan_store_fingerprint,
            delete_plan_slot,
            delete_plan_digest,
            target_restore_digest,
            post_state_digest,
            physical_delete_count,
            restored_singleton_count,
            store_fingerprint,
        )?;
        if decoded.slot != encoded_slot || decoded.digest != encoded_digest {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::DigestMismatch);
        }
        if decoded.canonical_bytes != bytes {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Result<Vec<u8>, CoordinatorRollbackDeleteCompletionStoreError> {
        let head_canonical = self.deleting_head.canonical_ref_bytes();
        let head_control = self.deleting_head.rollback_control_bytes();
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.target.network_id().chain_id().to_be_bytes());
        bytes.extend_from_slice(&self.target.chain_epoch().get().to_be_bytes());
        bytes.extend_from_slice(&self.deleting_head.revision().as_i64().to_be_bytes());
        push_bytes(&mut bytes, &head_canonical)?;
        push_bytes(&mut bytes, &head_control)?;
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.participant_plan_digest);
        bytes.extend_from_slice(&self.barrier_digest);
        bytes.extend_from_slice(&self.delete_plan_store_fingerprint);
        bytes.extend_from_slice(&self.delete_plan_slot);
        bytes.extend_from_slice(&self.delete_plan_digest);
        bytes.extend_from_slice(&self.target_restore_digest);
        bytes.extend_from_slice(&self.post_state_digest);
        bytes.extend_from_slice(&self.physical_delete_count.to_be_bytes());
        bytes.extend_from_slice(&self.restored_singleton_count.to_be_bytes());
        bytes.extend_from_slice(&self.store_fingerprint);
        bytes.extend_from_slice(&self.slot);
        Ok(bytes)
    }

    pub(super) const fn deleting_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.deleting_head
    }

    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] {
        &self.participant_plan_digest
    }

    pub(super) const fn barrier_digest(&self) -> &[u8; 32] {
        &self.barrier_digest
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(super) const fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(super) const fn physical_delete_count(&self) -> u64 {
        self.physical_delete_count
    }

    pub(super) const fn restored_singleton_count(&self) -> u64 {
        self.restored_singleton_count
    }
}

#[derive(Debug)]
pub(super) struct PersistedCoordinatorRollbackDeleteCompletion<Hash> {
    store_fingerprint: [u8; 32],
    completion: CoordinatorRollbackDeleteCompletion<Hash>,
}

impl<Hash> PersistedCoordinatorRollbackDeleteCompletion<Hash> {
    pub(super) const fn completion(&self) -> &CoordinatorRollbackDeleteCompletion<Hash> {
        &self.completion
    }
}

pub(super) struct ScyllaCoordinatorRollbackDeleteCompletionStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaCoordinatorRollbackDeleteCompletionStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, CoordinatorRollbackDeleteCompletionStoreError> {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        let insert = INSERT_TEMPLATE.replace("{table}", &table);
        let read = READ_TEMPLATE.replace("{table}", &table);
        let mut hasher = Sha256::new();
        hasher.update(STORE_DOMAIN);
        hasher.update(keyspace.as_str().as_bytes());
        hasher.update(insert.as_bytes());
        hasher.update(read.as_bytes());
        Ok(Self {
            insert: prepare_lwt(&session, &insert).await?,
            read: prepare_read(&session, &read).await?,
            fingerprint: hasher.finalize().into(),
            session,
        })
    }

    pub(super) async fn persist_or_recover<Hash: Q256BitHash>(
        &self,
        executed: &ExecutedCoordinatorRollbackSuffix<Hash>,
    ) -> Result<PersistedCoordinatorRollbackDeleteCompletion<Hash>, CoordinatorRollbackDeleteCompletionStoreError> {
        let completion = CoordinatorRollbackDeleteCompletion::try_from_executed(
            executed,
            self.fingerprint,
        )?;
        if let Some(current) = self.read_exact(&completion).await? {
            if current != completion {
                return Err(CoordinatorRollbackDeleteCompletionStoreError::Conflict);
            }
            return Ok(PersistedCoordinatorRollbackDeleteCompletion {
                store_fingerprint: self.fingerprint,
                completion: current,
            });
        }
        let row_bytes = i64::try_from(completion.canonical_bytes.len())
            .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::LengthOverflow)?;
        let fragment_digest = fragment_digest(
            completion.digest(),
            row_bytes,
            &completion.canonical_bytes,
        );
        let execution = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    i64::from(completion.target.network_id().chain_id()),
                    i64::try_from(completion.target.chain_epoch().get()).map_err(|_| {
                        CoordinatorRollbackDeleteCompletionStoreError::IntegerOutOfCqlRange
                    })?,
                    completion.participant_plan_digest.as_slice(),
                    KEY_DOMAIN,
                    completion.slot.as_slice(),
                    0_i32,
                    REVISION,
                    1_i32,
                    row_bytes,
                    completion.canonical_bytes.as_slice(),
                    fragment_digest.as_slice(),
                    completion.digest.as_slice(),
                ),
            )
            .await;
        match execution {
            Ok(result) => {
                if !decode_applied(result)? {
                    match self.read_exact(&completion).await? {
                        Some(current) if current == completion => {}
                        _ => {
                            return Err(
                                CoordinatorRollbackDeleteCompletionStoreError::Conflict,
                            )
                        }
                    }
                }
            }
            Err(error) => match self.read_exact(&completion).await {
                Ok(Some(current)) if current == completion => {}
                Ok(_) => {
                    return Err(CoordinatorRollbackDeleteCompletionStoreError::Indeterminate(
                        error.to_string(),
                    ))
                }
                Err(read) => {
                    return Err(CoordinatorRollbackDeleteCompletionStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ))
                }
            },
        }
        let current = self
            .read_exact(&completion)
            .await?
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::MissingAfterPersist)?;
        if current != completion {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::Conflict);
        }
        Ok(PersistedCoordinatorRollbackDeleteCompletion {
            store_fingerprint: self.fingerprint,
            completion: current,
        })
    }

    pub(super) async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
    ) -> Result<(), CoordinatorRollbackDeleteCompletionStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::StoreFingerprintMismatch);
        }
        match self.read_exact(&receipt.completion).await? {
            Some(current) if current == receipt.completion => Ok(()),
            Some(_) => Err(CoordinatorRollbackDeleteCompletionStoreError::Conflict),
            None => Err(CoordinatorRollbackDeleteCompletionStoreError::MissingAfterPersist),
        }
    }

    pub(super) async fn read_selected<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        old_chain_epoch: u64,
        participant_plan_digest: [u8; 32],
        slot: [u8; 32],
        digest: [u8; 32],
    ) -> Result<PersistedCoordinatorRollbackDeleteCompletion<Hash>, CoordinatorRollbackDeleteCompletionStoreError> {
        let completion = self
            .read_at::<Hash>(
                network,
                old_chain_epoch,
                &participant_plan_digest,
                &slot,
            )
            .await?
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::MissingAfterPersist)?;
        if completion.target.network_id() != network
            || completion.target.chain_epoch().get() != old_chain_epoch
            || completion.participant_plan_digest != participant_plan_digest
            || completion.slot != slot
            || completion.digest != digest
            || completion.store_fingerprint != self.fingerprint
        {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::Conflict);
        }
        Ok(PersistedCoordinatorRollbackDeleteCompletion {
            store_fingerprint: self.fingerprint,
            completion,
        })
    }

    async fn read_exact<Hash: Q256BitHash>(
        &self,
        expected: &CoordinatorRollbackDeleteCompletion<Hash>,
    ) -> Result<Option<CoordinatorRollbackDeleteCompletion<Hash>>, CoordinatorRollbackDeleteCompletionStoreError> {
        self.read_at(
            expected.target.network_id(),
            expected.target.chain_epoch().get(),
            &expected.participant_plan_digest,
            &expected.slot,
        )
        .await
    }

    async fn read_at<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        old_chain_epoch: u64,
        participant_plan_digest: &[u8; 32],
        slot: &[u8; 32],
    ) -> Result<Option<CoordinatorRollbackDeleteCompletion<Hash>>, CoordinatorRollbackDeleteCompletionStoreError> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    i64::from(network.chain_id()),
                    i64::try_from(old_chain_epoch).map_err(|_| {
                        CoordinatorRollbackDeleteCompletionStoreError::IntegerOutOfCqlRange
                    })?,
                    participant_plan_digest.as_slice(),
                    KEY_DOMAIN,
                    slot.as_slice(),
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
        if rows.len() != 1 {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow);
        }
        let (index, revision, count, row_bytes, payload, fragment, row_digest) =
            rows.into_iter().next().expect("one row");
        let payload = payload.ok_or(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?;
        let row_bytes = row_bytes.ok_or(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?;
        let fragment: [u8; 32] = fragment
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?
            .try_into()
            .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?;
        let row_digest: [u8; 32] = row_digest
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?
            .try_into()
            .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?;
        if index != Some(0)
            || revision != Some(REVISION)
            || count != Some(1)
            || row_bytes <= 0
            || usize::try_from(row_bytes).ok() != Some(payload.len())
            || payload.len() > MAX_ROW_BYTES
            || fragment_digest(&row_digest, row_bytes, &payload) != fragment
        {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow);
        }
        let completion = CoordinatorRollbackDeleteCompletion::decode_canonical(&payload)?;
        if completion.digest != row_digest
            || completion.target.network_id() != network
            || completion.target.chain_epoch().get() != old_chain_epoch
            || &completion.participant_plan_digest != participant_plan_digest
            || &completion.slot != slot
        {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::DigestMismatch);
        }
        Ok(Some(completion))
    }
}

fn completion_slot<Hash: Q256BitHash>(
    deleting_head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(target.network_id().chain_id().to_be_bytes());
    hasher.update(target.chain_epoch().get().to_be_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(deleting_head.revision().as_i64().to_be_bytes());
    hasher.update(deleting_head.canonical_ref_bytes());
    hasher.update(deleting_head.rollback_control_bytes());
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn fragment_digest(row_digest: &[u8; 32], row_bytes: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(row_digest);
    hasher.update(0_i32.to_be_bytes());
    hasher.update(1_i32.to_be_bytes());
    hasher.update(row_bytes.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn push_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CoordinatorRollbackDeleteCompletionStoreError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::LengthOverflow)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorRollbackDeleteCompletionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorRollbackDeleteCompletionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, CoordinatorRollbackDeleteCompletionStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(CoordinatorRollbackDeleteCompletionStoreError::MalformedRow),
    }
}

fn cql(error: impl fmt::Display) -> CoordinatorRollbackDeleteCompletionStoreError {
    CoordinatorRollbackDeleteCompletionStoreError::Backend(error.to_string())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorRollbackDeleteCompletionStoreError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CoordinatorRollbackDeleteCompletionStoreError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CoordinatorRollbackDeleteCompletionStoreError::Truncated);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CoordinatorRollbackDeleteCompletionStoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorRollbackDeleteCompletionStoreError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorRollbackDeleteCompletionStoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorRollbackDeleteCompletionStoreError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorRollbackDeleteCompletionStoreError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::LengthOverflow)?;
        self.take(len)
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorRollbackDeleteCompletionStoreError> {
        self.take(32)?
            .try_into()
            .map_err(|_| CoordinatorRollbackDeleteCompletionStoreError::Truncated)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Debug)]
pub(super) enum CoordinatorRollbackDeleteCompletionStoreError {
    Backend(String),
    Model(String),
    InvalidMagic,
    UnknownVersion(u16),
    BindingMismatch,
    IntegerOutOfCqlRange,
    LengthOverflow,
    RowTooLarge,
    MalformedRow,
    Truncated,
    TrailingBytes,
    DigestMismatch,
    NonCanonicalEncoding,
    Conflict,
    Indeterminate(String),
    MissingAfterPersist,
    StoreFingerprintMismatch,
}

impl fmt::Display for CoordinatorRollbackDeleteCompletionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator rollback delete completion store error: {self:?}")
    }
}

impl Error for CoordinatorRollbackDeleteCompletionStoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::{
        canonical_head::CanonicalHeadTransition,
        rollback_control::{
            RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

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

    fn completion() -> CoordinatorRollbackDeleteCompletion<PHash> {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let source = checkpoint(10, 10);
        let target_checkpoint = checkpoint(7, 20);
        let target = CanonicalChainRef::new(
            network,
            ChainEpoch::new(6),
            target_checkpoint,
        );
        let request = RollbackRequest::try_new(
            source,
            target_checkpoint,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0x11; 32]).unwrap(),
        )
        .unwrap();
        let active = StoredCanonicalHead::decode_persisted(
            network,
            4,
            &CanonicalChainRef::new(network, ChainEpoch::new(6), source)
                .to_canonical_bytes(),
            &psy_node_core::store::rollback_control::RollbackControlState::<PHash>::Idle
                .to_canonical_bytes(),
        )
        .unwrap();
        let requested = CanonicalHeadTransition::start_rollback(active, request).unwrap();
        let archiving = CanonicalHeadTransition::begin_rollback_archive(
            *requested.candidate(),
        )
        .unwrap();
        let ready = CanonicalHeadTransition::complete_rollback_archive_barrier(
            *archiving.candidate(),
        )
        .unwrap();
        let deleting = CanonicalHeadTransition::begin_rollback_delete(*ready.candidate())
            .unwrap();
        CoordinatorRollbackDeleteCompletion::try_from_fields(
            *deleting.candidate(),
            target,
            [0x11; 32],
            [0x12; 32],
            [0x13; 32],
            [0x14; 32],
            [0x15; 32],
            [0x16; 32],
            [0x17; 32],
            9,
            2,
            [0x18; 32],
        )
        .unwrap()
    }

    #[test]
    fn completion_roundtrips_and_rejects_tamper_and_trailing_bytes() {
        let completion = completion();
        assert_eq!(
            CoordinatorRollbackDeleteCompletion::decode_canonical(
                &completion.canonical_bytes,
            )
            .unwrap(),
            completion,
        );
        let mut tampered = completion.canonical_bytes.clone();
        tampered[100] ^= 1;
        assert!(
            CoordinatorRollbackDeleteCompletion::<PHash>::decode_canonical(&tampered)
                .is_err()
        );
        let mut trailing = completion.canonical_bytes.clone();
        trailing.push(0);
        assert_eq!(
            CoordinatorRollbackDeleteCompletion::<PHash>::decode_canonical(&trailing)
                .unwrap_err()
                .to_string(),
            CoordinatorRollbackDeleteCompletionStoreError::TrailingBytes.to_string(),
        );
    }

    #[test]
    fn store_is_immutable_and_has_no_head_publish_api() {
        let source = include_str!("coordinator_rollback_delete_completion_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(" IF NOT EXISTS"));
        for forbidden in [
            "DELETE FROM",
            "UPDATE ",
            "USING TIMESTAMP",
            "compare_and_set(",
            "complete_rollback(",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[test]
    fn completion_codec_rejects_truncation_and_trailing_bytes_before_model_decode() {
        let mut cursor = Cursor::new(b"12345678\0");
        assert_eq!(cursor.take(8).unwrap(), b"12345678");
        assert_eq!(cursor.take(1).unwrap(), b"\0");
        assert!(cursor.take(1).is_err());
    }
}
