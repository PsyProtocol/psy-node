//! Immutable successor-keyed locator for Realm deferred application work.
//!
//! Deferred bytes remain in the predecessor application archive. This table
//! stores only the exact locator and commitments required to find and verify
//! them after a future pipeline rotation. Missing rows never mean empty.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::queue::realm_processor_generation_terminal::{
    RealmGenerationTerminalError, RealmProcessorDeferredCarryover,
    RealmProcessorDeferredCarryoverSlot,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(super) const REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE: &str =
    "branch_exact_realm_processor_deferred_carryover_v1";
const REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-deferred-carryover-store/v1";

const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (successor_slot blob PRIMARY KEY, revision bigint, carryover_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, carryover_payload FROM {table} WHERE successor_slot = ?";
const BOOTSTRAP_TEMPLATE: &str = "INSERT INTO {table} (successor_slot, revision, carryover_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmProcessorDeferredCarryoverQueries {
    create: String,
    read: String,
    bootstrap: String,
}

impl RealmProcessorDeferredCarryoverQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
        );
        Self {
            create: CREATE_TEMPLATE.replace("{table}", &table),
            read: READ_TEMPLATE.replace("{table}", &table),
            bootstrap: BOOTSTRAP_TEMPLATE.replace("{table}", &table),
        }
    }

    fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RealmProcessorDeferredCarryoverStoreFingerprint([u8; 32]);

pub(super) struct ScyllaRealmProcessorDeferredCarryoverStore {
    session: Arc<Session>,
    fingerprint: RealmProcessorDeferredCarryoverStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
}

#[derive(Debug)]
struct PersistedRealmProcessorDeferredCarryoverReceipt {
    store_fingerprint: RealmProcessorDeferredCarryoverStoreFingerprint,
    carryover: RealmProcessorDeferredCarryover,
}

impl PersistedRealmProcessorDeferredCarryoverReceipt {
    const fn carryover(&self) -> &RealmProcessorDeferredCarryover {
        &self.carryover
    }
}

impl ScyllaRealmProcessorDeferredCarryoverStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), RealmProcessorDeferredCarryoverStoreError> {
        let queries = RealmProcessorDeferredCarryoverQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, RealmProcessorDeferredCarryoverStoreError> {
        let queries = RealmProcessorDeferredCarryoverQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            session,
        })
    }

    async fn read(
        &self,
        slot: RealmProcessorDeferredCarryoverSlot,
    ) -> Result<Option<RealmProcessorDeferredCarryover>, RealmProcessorDeferredCarryoverStoreError> {
        let row = self
            .session
            .execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>()
            .map_err(cql)?;
        let Some((revision, payload)) = row else {
            return Ok(None);
        };
        Ok(Some(RealmProcessorDeferredCarryover::decode_selected(
            slot,
            revision.ok_or(RealmProcessorDeferredCarryoverStoreError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(RealmProcessorDeferredCarryoverStoreError::MissingColumn)?,
        )?))
    }

    async fn persist(
        &self,
        carryover: RealmProcessorDeferredCarryover,
    ) -> Result<PersistedRealmProcessorDeferredCarryoverReceipt, RealmProcessorDeferredCarryoverStoreError> {
        let payload = carryover.to_canonical_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    carryover.slot().as_bytes().as_slice(),
                    REVISION,
                    payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(carryover.slot()).await {
                Ok(Some(current)) if current == carryover => false,
                Ok(_) => {
                    return Err(RealmProcessorDeferredCarryoverStoreError::Indeterminate(
                        error.to_string(),
                    ))
                }
                Err(read) => {
                    return Err(RealmProcessorDeferredCarryoverStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ))
                }
            },
        };
        let current = self
            .read(carryover.slot())
            .await?
            .ok_or(RealmProcessorDeferredCarryoverStoreError::MissingAfterLwt)?;
        if current != carryover {
            return Err(if applied {
                RealmProcessorDeferredCarryoverStoreError::AppliedStateMismatch
            } else {
                RealmProcessorDeferredCarryoverStoreError::Conflict
            });
        }
        Ok(PersistedRealmProcessorDeferredCarryoverReceipt {
            store_fingerprint: self.fingerprint,
            carryover: current,
        })
    }

    async fn revalidate(
        &self,
        receipt: &PersistedRealmProcessorDeferredCarryoverReceipt,
    ) -> Result<(), RealmProcessorDeferredCarryoverStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmProcessorDeferredCarryoverStoreError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.carryover.slot())
            .await?
            .ok_or(RealmProcessorDeferredCarryoverStoreError::ReceiptStale)?;
        if current != receipt.carryover {
            return Err(RealmProcessorDeferredCarryoverStoreError::ReceiptStale);
        }
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &RealmProcessorDeferredCarryoverQueries,
) -> RealmProcessorDeferredCarryoverStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    RealmProcessorDeferredCarryoverStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmProcessorDeferredCarryoverStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmProcessorDeferredCarryoverStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, RealmProcessorDeferredCarryoverStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RealmProcessorDeferredCarryoverStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmProcessorDeferredCarryoverStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> RealmProcessorDeferredCarryoverStoreError {
    RealmProcessorDeferredCarryoverStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmProcessorDeferredCarryoverStoreError {
    Cql(String),
    Core(RealmGenerationTerminalError),
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    Conflict,
    ReceiptBindingMismatch,
    ReceiptStale,
    Indeterminate(String),
}

impl From<RealmGenerationTerminalError> for RealmProcessorDeferredCarryoverStoreError {
    fn from(value: RealmGenerationTerminalError) -> Self { Self::Core(value) }
}
impl fmt::Display for RealmProcessorDeferredCarryoverStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmProcessorDeferredCarryoverStoreError {}

#[cfg(test)]
impl ScyllaRealmProcessorDeferredCarryoverStore {
    pub(super) async fn qualification_persist(
        &self,
        carryover: RealmProcessorDeferredCarryover,
    ) -> Result<(), RealmProcessorDeferredCarryoverStoreError> {
        let receipt = self.persist(carryover).await?;
        self.revalidate(&receipt).await
    }

    pub(super) async fn qualification_commit_then_discard_response(
        &self,
        carryover: RealmProcessorDeferredCarryover,
    ) -> Result<(), RealmProcessorDeferredCarryoverStoreError> {
        let payload = carryover.to_canonical_bytes();
        let result = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    carryover.slot().as_bytes().as_slice(),
                    REVISION,
                    payload.as_slice(),
                ),
            )
            .await
            .map_err(cql)?;
        if !decode_applied(result)? {
            return Err(RealmProcessorDeferredCarryoverStoreError::Conflict);
        }
        self.qualification_persist(carryover).await
    }

    pub(super) async fn qualification_read(
        &self,
        slot: RealmProcessorDeferredCarryoverSlot,
    ) -> Result<Option<RealmProcessorDeferredCarryover>, RealmProcessorDeferredCarryoverStoreError> {
        self.read(slot).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cql_is_successor_keyed_append_only_lwt_with_stable_bind_order() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let queries = RealmProcessorDeferredCarryoverQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.branch_exact_realm_processor_deferred_carryover_v1 (successor_slot blob PRIMARY KEY, revision bigint, carryover_payload blob)");
        assert_eq!(queries.read, "SELECT revision, carryover_payload FROM control_nt.branch_exact_realm_processor_deferred_carryover_v1 WHERE successor_slot = ?");
        assert_eq!(queries.bootstrap, "INSERT INTO control_nt.branch_exact_realm_processor_deferred_carryover_v1 (successor_slot, revision, carryover_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        let production = include_str!("realm_processor_deferred_carryover.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("USING TTL"));
        assert!(!production.contains("USING TIMESTAMP"));
    }

    #[test]
    fn store_receipt_is_private_and_has_no_rotation_or_pipeline_apply_api() {
        let source = include_str!("realm_processor_deferred_carryover.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("struct PersistedRealmProcessorDeferredCarryoverReceipt"));
        assert!(!production.contains("pub(super) async fn persist"));
        assert!(!production.contains("seal_pipeline_rotation"));
        assert!(!production.contains("ScyllaPendingPipelineStore"));
        assert!(!production.contains("pipeline.apply"));
    }
}
