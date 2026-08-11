//! Immutable predecessor-keyed Realm terminal/rotation-intent substrate.
//!
//! The private receipt proves only exact persistence. It cannot execute a
//! pending-pipeline transition and is not a substitute for the future c4f
//! writer/head terminal authorization.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::realm_processor_generation_terminal::{
    RealmGenerationTerminalError, RealmProcessorGenerationTerminal,
    RealmProcessorGenerationTerminalSlot,
    RealmProcessorGenerationTerminalStoreFingerprint,
};
use psy_node_core::store::pending_generation_identity::{
    PendingGenerationActivationDigest, PendingGenerationContext,
    PendingGenerationLedgerKey,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(super) const REALM_PROCESSOR_GENERATION_TERMINAL_TABLE: &str =
    "branch_exact_realm_processor_generation_terminal_v1";
const REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-generation-terminal-store/v1";

const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (terminal_slot blob PRIMARY KEY, revision bigint, terminal_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, terminal_payload FROM {table} WHERE terminal_slot = ?";
const BOOTSTRAP_TEMPLATE: &str = "INSERT INTO {table} (terminal_slot, revision, terminal_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmProcessorGenerationTerminalQueries {
    create: String,
    read: String,
    bootstrap: String,
}

impl RealmProcessorGenerationTerminalQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
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

pub(super) struct ScyllaRealmProcessorGenerationTerminalStore {
    session: Arc<Session>,
    fingerprint: RealmProcessorGenerationTerminalStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
}

#[derive(Debug)]
struct PersistedRealmProcessorGenerationTerminalReceipt<Hash> {
    store_fingerprint: RealmProcessorGenerationTerminalStoreFingerprint,
    terminal: RealmProcessorGenerationTerminal<Hash>,
}

impl<Hash> PersistedRealmProcessorGenerationTerminalReceipt<Hash> {
    const fn terminal(&self) -> &RealmProcessorGenerationTerminal<Hash> {
        &self.terminal
    }

    const fn store_fingerprint(&self) -> RealmProcessorGenerationTerminalStoreFingerprint {
        self.store_fingerprint
    }
}

impl ScyllaRealmProcessorGenerationTerminalStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), RealmProcessorGenerationTerminalStoreError> {
        let queries = RealmProcessorGenerationTerminalQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, RealmProcessorGenerationTerminalStoreError> {
        let queries = RealmProcessorGenerationTerminalQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries)?,
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            session,
        })
    }

    /// Narrow, read-only selector used by the continuation restart owner.
    /// It does not expose the private persistence receipt or mutation path.
    pub(super) async fn observe_for_restart<Hash: Q256BitHash>(
        &self,
        key: PendingGenerationLedgerKey,
        activation: PendingGenerationActivationDigest,
        source: PendingGenerationContext,
    ) -> Result<Option<RealmProcessorGenerationTerminal<Hash>>, RealmProcessorGenerationTerminalStoreError>
    {
        self.read(RealmProcessorGenerationTerminalSlot::for_generation(
            key, activation, source,
        )?)
        .await
    }

    pub(super) const fn restart_fingerprint(
        &self,
    ) -> RealmProcessorGenerationTerminalStoreFingerprint {
        self.fingerprint
    }

    async fn read<Hash: Q256BitHash>(
        &self,
        slot: RealmProcessorGenerationTerminalSlot,
    ) -> Result<Option<RealmProcessorGenerationTerminal<Hash>>, RealmProcessorGenerationTerminalStoreError> {
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
        Ok(Some(
            RealmProcessorGenerationTerminal::<Hash>::decode_selected(
                slot,
                revision.ok_or(RealmProcessorGenerationTerminalStoreError::MissingColumn)?,
                payload
                    .as_deref()
                    .ok_or(RealmProcessorGenerationTerminalStoreError::MissingColumn)?,
            )?,
        ))
    }

    async fn persist<Hash: Q256BitHash>(
        &self,
        terminal: RealmProcessorGenerationTerminal<Hash>,
    ) -> Result<PersistedRealmProcessorGenerationTerminalReceipt<Hash>, RealmProcessorGenerationTerminalStoreError> {
        let payload = terminal.to_canonical_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    terminal.slot().as_bytes().as_slice(),
                    REVISION,
                    payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(terminal.slot()).await {
                Ok(Some(current)) if current == terminal => false,
                Ok(_) => {
                    return Err(RealmProcessorGenerationTerminalStoreError::Indeterminate(
                        error.to_string(),
                    ))
                }
                Err(read) => {
                    return Err(RealmProcessorGenerationTerminalStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ))
                }
            },
        };
        let current = self
            .read(terminal.slot())
            .await?
            .ok_or(RealmProcessorGenerationTerminalStoreError::MissingAfterLwt)?;
        if current != terminal {
            return Err(if applied {
                RealmProcessorGenerationTerminalStoreError::AppliedStateMismatch
            } else {
                RealmProcessorGenerationTerminalStoreError::Conflict
            });
        }
        Ok(PersistedRealmProcessorGenerationTerminalReceipt {
            store_fingerprint: self.fingerprint,
            terminal: current,
        })
    }

    async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmProcessorGenerationTerminalReceipt<Hash>,
    ) -> Result<(), RealmProcessorGenerationTerminalStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmProcessorGenerationTerminalStoreError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.terminal.slot())
            .await?
            .ok_or(RealmProcessorGenerationTerminalStoreError::ReceiptStale)?;
        if current != receipt.terminal {
            return Err(RealmProcessorGenerationTerminalStoreError::ReceiptStale);
        }
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &RealmProcessorGenerationTerminalQueries,
) -> Result<RealmProcessorGenerationTerminalStoreFingerprint, RealmProcessorGenerationTerminalStoreError> {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    Ok(RealmProcessorGenerationTerminalStoreFingerprint::try_new(
        hasher.finalize().into(),
    )?)
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmProcessorGenerationTerminalStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmProcessorGenerationTerminalStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, RealmProcessorGenerationTerminalStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RealmProcessorGenerationTerminalStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmProcessorGenerationTerminalStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> RealmProcessorGenerationTerminalStoreError {
    RealmProcessorGenerationTerminalStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmProcessorGenerationTerminalStoreError {
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

impl From<RealmGenerationTerminalError> for RealmProcessorGenerationTerminalStoreError {
    fn from(value: RealmGenerationTerminalError) -> Self { Self::Core(value) }
}
impl fmt::Display for RealmProcessorGenerationTerminalStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmProcessorGenerationTerminalStoreError {}

#[cfg(test)]
impl ScyllaRealmProcessorGenerationTerminalStore {
    pub(super) const fn qualification_fingerprint(
        &self,
    ) -> RealmProcessorGenerationTerminalStoreFingerprint {
        self.fingerprint
    }

    pub(super) async fn qualification_persist<Hash: Q256BitHash>(
        &self,
        terminal: RealmProcessorGenerationTerminal<Hash>,
    ) -> Result<(), RealmProcessorGenerationTerminalStoreError> {
        let receipt = self.persist(terminal).await?;
        self.revalidate(&receipt).await
    }

    pub(super) async fn qualification_commit_then_discard_response<Hash: Q256BitHash>(
        &self,
        terminal: RealmProcessorGenerationTerminal<Hash>,
    ) -> Result<(), RealmProcessorGenerationTerminalStoreError> {
        let payload = terminal.to_canonical_bytes();
        let result = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    terminal.slot().as_bytes().as_slice(),
                    REVISION,
                    payload.as_slice(),
                ),
            )
            .await
            .map_err(cql)?;
        if !decode_applied(result)? {
            return Err(RealmProcessorGenerationTerminalStoreError::Conflict);
        }
        self.qualification_persist(terminal).await
    }

    pub(super) async fn qualification_read<Hash: Q256BitHash>(
        &self,
        slot: RealmProcessorGenerationTerminalSlot,
    ) -> Result<Option<RealmProcessorGenerationTerminal<Hash>>, RealmProcessorGenerationTerminalStoreError> {
        self.read(slot).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cql_is_single_row_append_only_lwt_with_stable_bind_order() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let queries = RealmProcessorGenerationTerminalQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.branch_exact_realm_processor_generation_terminal_v1 (terminal_slot blob PRIMARY KEY, revision bigint, terminal_payload blob)");
        assert_eq!(queries.read, "SELECT revision, terminal_payload FROM control_nt.branch_exact_realm_processor_generation_terminal_v1 WHERE terminal_slot = ?");
        assert_eq!(queries.bootstrap, "INSERT INTO control_nt.branch_exact_realm_processor_generation_terminal_v1 (terminal_slot, revision, terminal_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        let production = include_str!("realm_processor_generation_terminal.rs")
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
        let source = include_str!("realm_processor_generation_terminal.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("struct PersistedRealmProcessorGenerationTerminalReceipt"));
        assert!(!production.contains("pub(super) async fn persist"));
        assert!(!production.contains("seal_pipeline_rotation"));
        assert!(!production.contains("ScyllaPendingPipelineStore"));
        assert!(!production.contains("pipeline.apply"));
    }
}
