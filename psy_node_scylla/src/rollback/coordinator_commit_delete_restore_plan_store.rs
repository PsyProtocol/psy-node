//! Immutable persistence for the exact Coordinator destructive-work plan.
//!
//! This row is written while the canonical control is still ARCHIVING and is
//! selected by a content-independent request slot.  The global archive
//! barrier commits its slot and digest.  Consequently the post-barrier delete
//! owner can recover the exact key/action stream without consulting hot rows
//! that it may already have deleted.  This adapter grants no delete, restore,
//! or canonical-head mutation authority.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName, CoordinatorCommitDeleteRestorePlan,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
};

const KEY_DOMAIN: i16 = -4;
const REVISION: i64 = 1;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 32;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.coordinator-delete-restore-plan-slot.v1\0";
const FRAGMENT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-delete-restore-plan-fragment.v1\0";
const STORE_DOMAIN: &[u8] = b"psy.rollback.coordinator-delete-restore-plan-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_ROW_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ? AND fragment_index = ?";

#[derive(Debug)]
pub(super) struct PersistedCoordinatorCommitDeleteRestorePlan<Hash> {
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    plan: CoordinatorCommitDeleteRestorePlan<Hash>,
}

impl<Hash> PersistedCoordinatorCommitDeleteRestorePlan<Hash> {
    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] {
        &self.store_fingerprint
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(super) const fn plan(&self) -> &CoordinatorCommitDeleteRestorePlan<Hash> {
        &self.plan
    }

    pub(super) fn into_plan(self) -> CoordinatorCommitDeleteRestorePlan<Hash> {
        self.plan
    }
}

pub(super) struct ScyllaCoordinatorCommitDeleteRestorePlanStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read_row: PreparedStatement,
    read_fragment: PreparedStatement,
}

impl ScyllaCoordinatorCommitDeleteRestorePlanStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanStoreError> {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        let insert = INSERT_TEMPLATE.replace("{table}", &table);
        let read_row = READ_ROW_TEMPLATE.replace("{table}", &table);
        let read_fragment = READ_FRAGMENT_TEMPLATE.replace("{table}", &table);
        let mut fingerprint = Sha256::new();
        fingerprint.update(STORE_DOMAIN);
        fingerprint.update(keyspace.as_str().as_bytes());
        fingerprint.update(insert.as_bytes());
        fingerprint.update(read_row.as_bytes());
        fingerprint.update(read_fragment.as_bytes());
        Ok(Self {
            insert: prepare_lwt(&session, &insert).await?,
            read_row: prepare_read(&session, &read_row).await?,
            read_fragment: prepare_read(&session, &read_fragment).await?,
            fingerprint: fingerprint.finalize().into(),
            session,
        })
    }

    pub(super) const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub(super) async fn persist_or_recover<Hash: Q256BitHash>(
        &self,
        plan: CoordinatorCommitDeleteRestorePlan<Hash>,
    ) -> Result<PersistedCoordinatorCommitDeleteRestorePlan<Hash>, CoordinatorCommitDeleteRestorePlanStoreError> {
        let coordinates = Coordinates::try_from_plan(&plan, &self.fingerprint)?;
        if let Some(current) = self.read_at::<Hash>(&coordinates).await? {
            if current != plan {
                return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
            }
            return Ok(PersistedCoordinatorCommitDeleteRestorePlan {
                store_fingerprint: self.fingerprint,
                slot: coordinates.slot,
                plan: current,
            });
        }
        for fragment in fragments(plan.canonical_bytes(), plan.digest())? {
            let execution = self.session.execute_unpaged(
                &self.insert,
                (
                    coordinates.network,
                    coordinates.chain_epoch,
                    coordinates.participant_plan_digest.as_slice(),
                    KEY_DOMAIN,
                    coordinates.slot.as_slice(),
                    fragment.index,
                    REVISION,
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
                        return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
                    }
                }
                Err(error) => match self.read_fragment(&coordinates, fragment.index).await {
                    Ok(Some(current)) if current == fragment => {}
                    Ok(_) => return Err(CoordinatorCommitDeleteRestorePlanStoreError::Indeterminate(
                        error.to_string(),
                    )),
                    Err(read) => return Err(CoordinatorCommitDeleteRestorePlanStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    )),
                },
            }
        }
        let current = self.read_at::<Hash>(&coordinates).await?
            .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MissingAfterPersist)?;
        if current != plan {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
        }
        Ok(PersistedCoordinatorCommitDeleteRestorePlan {
            store_fingerprint: self.fingerprint,
            slot: coordinates.slot,
            plan: current,
        })
    }

    pub(super) async fn read_selected<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        old_chain_epoch: u64,
        participant_plan_digest: [u8; 32],
        slot: [u8; 32],
        digest: [u8; 32],
    ) -> Result<PersistedCoordinatorCommitDeleteRestorePlan<Hash>, CoordinatorCommitDeleteRestorePlanStoreError> {
        let coordinates = Coordinates {
            network: i64::from(network.chain_id()),
            chain_epoch: i64::try_from(old_chain_epoch)
                .map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::IntegerOutOfCqlRange)?,
            participant_plan_digest,
            slot,
        };
        let plan = self.read_at::<Hash>(&coordinates).await?
            .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MissingAfterPersist)?;
        let expected = Coordinates::try_from_plan(&plan, &self.fingerprint)?;
        if expected != coordinates || plan.digest() != &digest {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
        }
        Ok(PersistedCoordinatorCommitDeleteRestorePlan {
            store_fingerprint: self.fingerprint,
            slot,
            plan,
        })
    }

    pub(super) async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedCoordinatorCommitDeleteRestorePlan<Hash>,
    ) -> Result<(), CoordinatorCommitDeleteRestorePlanStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::StoreFingerprintMismatch);
        }
        let coordinates = Coordinates::try_from_plan(&receipt.plan, &self.fingerprint)?;
        if coordinates.slot != receipt.slot {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
        }
        match self.read_at(&coordinates).await? {
            Some(current) if current == receipt.plan => Ok(()),
            Some(_) => Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict),
            None => Err(CoordinatorCommitDeleteRestorePlanStoreError::MissingAfterPersist),
        }
    }

    async fn read_at<Hash: Q256BitHash>(
        &self,
        coordinates: &Coordinates,
    ) -> Result<Option<CoordinatorCommitDeleteRestorePlan<Hash>>, CoordinatorCommitDeleteRestorePlanStoreError> {
        let rows = self.session.execute_unpaged(
            &self.read_row,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                KEY_DOMAIN,
                coordinates.slot.as_slice(),
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .rows::<(
                Option<i32>, Option<i64>, Option<i32>, Option<i64>,
                Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut decoded = Vec::with_capacity(rows.len());
        for (index, revision, count, row_bytes, payload, digest, row_digest) in rows {
            decoded.push(decode_fragment(
                index, revision, count, row_bytes, payload, digest, row_digest,
            )?);
        }
        let row_digest = decoded[0].row_digest;
        let bytes = reconstruct(decoded, &row_digest)?;
        let plan = CoordinatorCommitDeleteRestorePlan::decode_canonical(&bytes)?;
        if plan.digest() != &row_digest {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::Conflict);
        }
        Ok(Some(plan))
    }

    async fn read_fragment(
        &self,
        coordinates: &Coordinates,
        index: i32,
    ) -> Result<Option<Fragment>, CoordinatorCommitDeleteRestorePlanStoreError> {
        self.session.execute_unpaged(
            &self.read_fragment,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                KEY_DOMAIN,
                coordinates.slot.as_slice(),
                index,
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(
                Option<i64>, Option<i32>, Option<i64>, Option<Vec<u8>>,
                Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?
            .map(|(revision, count, row_bytes, payload, digest, row_digest)| {
                decode_fragment(Some(index), revision, count, row_bytes, payload, digest, row_digest)
            }).transpose()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Coordinates {
    network: i64,
    chain_epoch: i64,
    participant_plan_digest: [u8; 32],
    slot: [u8; 32],
}

impl Coordinates {
    fn try_from_plan<Hash: Q256BitHash>(
        plan: &CoordinatorCommitDeleteRestorePlan<Hash>,
        store_fingerprint: &[u8; 32],
    ) -> Result<Self, CoordinatorCommitDeleteRestorePlanStoreError> {
        let request = plan.archiving_head().rollback_control().requested()
            .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::BindingMismatch)?;
        if !plan.archiving_head().rollback_control().is_archiving()
            || plan.target().network_id() != plan.old_head().network_id()
            || plan.target().chain_epoch() != plan.old_head().chain_epoch()
            || plan.target().network_id() != plan.archiving_head().canonical_ref().network_id()
        {
            return Err(CoordinatorCommitDeleteRestorePlanStoreError::BindingMismatch);
        }
        let network = plan.target().network_id();
        let old_chain_epoch = plan.target().chain_epoch().get();
        let participant_plan_digest = *request.plan_digest().as_bytes();
        Ok(Self {
            network: i64::from(network.chain_id()),
            chain_epoch: i64::try_from(old_chain_epoch)
                .map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::IntegerOutOfCqlRange)?,
            participant_plan_digest,
            slot: plan_slot(plan, store_fingerprint),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Fragment {
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: Vec<u8>,
    digest: [u8; 32],
    row_digest: [u8; 32],
}

fn fragments(
    bytes: &[u8],
    row_digest: &[u8; 32],
) -> Result<Vec<Fragment>, CoordinatorCommitDeleteRestorePlanStoreError> {
    let count = bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
    if count == 0 || count > MAX_FRAGMENTS {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::InvalidFragmentSet);
    }
    let count = i32::try_from(count)
        .map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::LengthOverflow)?;
    let row_bytes = i64::try_from(bytes.len())
        .map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::LengthOverflow)?;
    Ok(bytes.chunks(MAX_FRAGMENT_BYTES).enumerate().map(|(index, payload)| {
        let index = i32::try_from(index).expect("at most thirty-two fragments");
        Fragment {
            index,
            count,
            row_bytes,
            payload: payload.to_vec(),
            digest: fragment_digest(row_digest, index, count, row_bytes, payload),
            row_digest: *row_digest,
        }
    }).collect())
}

#[allow(clippy::too_many_arguments)]
fn decode_fragment(
    index: Option<i32>,
    revision: Option<i64>,
    count: Option<i32>,
    row_bytes: Option<i64>,
    payload: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    row_digest: Option<Vec<u8>>,
) -> Result<Fragment, CoordinatorCommitDeleteRestorePlanStoreError> {
    if revision != Some(REVISION) {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow);
    }
    let index = index.ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let count = count.ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let row_bytes = row_bytes.ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let payload = payload.ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let digest: [u8; 32] = digest
        .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?
        .try_into().map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let row_digest: [u8; 32] = row_digest
        .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?
        .try_into().map_err(|_| CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    if index < 0 || count <= 0 || count as usize > MAX_FRAGMENTS
        || index >= count || row_bytes <= 0
        || payload.len() > MAX_FRAGMENT_BYTES
        || fragment_digest(&row_digest, index, count, row_bytes, &payload) != digest
    {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow);
    }
    Ok(Fragment { index, count, row_bytes, payload, digest, row_digest })
}

fn reconstruct(
    mut rows: Vec<Fragment>,
    row_digest: &[u8; 32],
) -> Result<Vec<u8>, CoordinatorCommitDeleteRestorePlanStoreError> {
    if rows.is_empty() {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::InvalidFragmentSet);
    }
    rows.sort_by_key(|row| row.index);
    let count = rows[0].count;
    let row_bytes = rows[0].row_bytes;
    if rows.len() != count as usize || rows.iter().enumerate().any(|(index, row)| {
        row.index != index as i32
            || row.count != count
            || row.row_bytes != row_bytes
            || &row.row_digest != row_digest
            || fragment_digest(
                &row.row_digest,
                row.index,
                row.count,
                row.row_bytes,
                &row.payload,
            ) != row.digest
    }) {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::InvalidFragmentSet);
    }
    let mut bytes = Vec::with_capacity(row_bytes as usize);
    for row in rows {
        bytes.extend_from_slice(&row.payload);
    }
    if bytes.len() != row_bytes as usize {
        return Err(CoordinatorCommitDeleteRestorePlanStoreError::InvalidFragmentSet);
    }
    Ok(bytes)
}

fn plan_slot<Hash: Q256BitHash>(
    plan: &CoordinatorCommitDeleteRestorePlan<Hash>,
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let request = plan.archiving_head().rollback_control().requested()
        .expect("validated delete/restore plan always binds rollback request");
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(plan.target().network_id().chain_id().to_be_bytes());
    hasher.update(plan.target().chain_epoch().get().to_be_bytes());
    hasher.update(request.plan_digest().as_bytes());
    hasher.update(plan.archiving_head().revision().as_i64().to_be_bytes());
    hasher.update(plan.archiving_head().canonical_ref_bytes());
    hasher.update(plan.archiving_head().rollback_control_bytes());
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn fragment_digest(
    row_digest: &[u8; 32],
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(row_digest);
    hasher.update(index.to_be_bytes());
    hasher.update(count.to_be_bytes());
    hasher.update(row_bytes.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorCommitDeleteRestorePlanStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorCommitDeleteRestorePlanStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, CoordinatorCommitDeleteRestorePlanStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(CoordinatorCommitDeleteRestorePlanStoreError::MalformedRow),
    }
}

fn cql(error: impl fmt::Display) -> CoordinatorCommitDeleteRestorePlanStoreError {
    CoordinatorCommitDeleteRestorePlanStoreError::Backend(error.to_string())
}

#[derive(Debug)]
pub(super) enum CoordinatorCommitDeleteRestorePlanStoreError {
    Backend(String),
    Plan(String),
    BindingMismatch,
    IntegerOutOfCqlRange,
    LengthOverflow,
    InvalidFragmentSet,
    MalformedRow,
    Conflict,
    Indeterminate(String),
    MissingAfterPersist,
    StoreFingerprintMismatch,
}

impl From<super::CoordinatorCommitDeleteRestorePlanError>
    for CoordinatorCommitDeleteRestorePlanStoreError
{
    fn from(value: super::CoordinatorCommitDeleteRestorePlanError) -> Self {
        Self::Plan(value.to_string())
    }
}

impl fmt::Display for CoordinatorCommitDeleteRestorePlanStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator delete/restore plan store error: {self:?}")
    }
}

impl Error for CoordinatorCommitDeleteRestorePlanStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_reconstruction_is_exact_and_fail_closed() {
        let bytes = vec![7; MAX_FRAGMENT_BYTES + 31];
        let digest = [9; 32];
        let rows = fragments(&bytes, &digest).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(reconstruct(rows.clone(), &digest).unwrap(), bytes);
        assert!(reconstruct(Vec::new(), &digest).is_err());
        let mut extra = rows.clone();
        extra.push(rows[0].clone());
        assert!(reconstruct(extra, &digest).is_err());
        let mut corrupt = rows;
        corrupt[0].payload[0] ^= 1;
        assert!(reconstruct(corrupt, &digest).is_err());
    }

    #[test]
    fn store_has_no_destructive_or_head_api() {
        let source = include_str!("coordinator_commit_delete_restore_plan_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "DELETE FROM",
            "USING TIMESTAMP",
            "begin_rollback_delete(",
            "compare_and_set(",
            "restore_target(",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
