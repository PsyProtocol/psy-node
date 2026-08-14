//! Immutable Scylla store for Coordinator full-completion records.
//!
//! Persistence requires a private full-manifest receipt, a source-bound local
//! backup observation, and fresh reconstruction of all manifest sources on
//! both sides of the LWT. The resulting private receipt still grants no
//! COMMITTED-marker or canonical-head mutation authority.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    coordinator_commit_source::{
        CoordinatorCheckpointBackupEvidence, CoordinatorCommitSource,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CanonicalHeadNoTabletKeyspace, ScyllaBranchExactWriterRuntime,
    ScyllaCoordinatorCommitSourceStore,
    coordinator_commit_full_completion::{
        CoordinatorCommitFullCompletion, CoordinatorCommitFullCompletionError,
        CoordinatorCommitFullCompletionSlot, coordinator_commit_full_completion_slot,
    },
    coordinator_commit_full_manifest_store::{
        CoordinatorCommitFullManifestStoreError,
        PersistedCoordinatorCommitFullManifestReceipt,
        ScyllaCoordinatorCommitFullManifestStore,
    },
    coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule,
    coordinator_commit_physical_scylla::CoordinatorCommitPhysicalScyllaExecutor,
};

pub(crate) const COORDINATOR_COMMIT_FULL_COMPLETION_TABLE: &str =
    "coordinator_commit_full_completion_v1";
const REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-full-completion-store.v1\0";
const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (completion_slot blob PRIMARY KEY, revision bigint, completion_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, completion_payload FROM {table} WHERE completion_slot = ?";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (completion_slot, revision, completion_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorCommitFullCompletionQueries {
    create: String,
    read: String,
    insert: String,
}

impl CoordinatorCommitFullCompletionQueries {
    fn new(keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_COMMIT_FULL_COMPLETION_TABLE,
        );
        Self {
            create: CREATE_TEMPLATE.replace("{table}", &table),
            read: READ_TEMPLATE.replace("{table}", &table),
            insert: INSERT_TEMPLATE.replace("{table}", &table),
        }
    }

    fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBLOB\n\ninsert\n{}\nBLOB,BIGINT,BLOB\n",
            self.create, self.read, self.insert,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorCommitFullCompletionStoreFingerprint([u8; 32]);

#[derive(Debug)]
pub(crate) struct PersistedCoordinatorCommitFullCompletionReceipt<Hash> {
    store_fingerprint: CoordinatorCommitFullCompletionStoreFingerprint,
    completion: CoordinatorCommitFullCompletion<Hash>,
}

impl<Hash> PersistedCoordinatorCommitFullCompletionReceipt<Hash> {
    pub(crate) const fn completion(&self) -> &CoordinatorCommitFullCompletion<Hash> {
        &self.completion
    }
}

pub(crate) struct ScyllaCoordinatorCommitFullCompletionStore {
    session: Arc<Session>,
    fingerprint: CoordinatorCommitFullCompletionStoreFingerprint,
    read: PreparedStatement,
    insert: PreparedStatement,
}

impl ScyllaCoordinatorCommitFullCompletionStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), CoordinatorCommitFullCompletionStoreError> {
        let queries = CoordinatorCommitFullCompletionQueries::new(keyspace);
        session
            .query_unpaged(queries.create, &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: CanonicalHeadNoTabletKeyspace,
    ) -> Result<Self, CoordinatorCommitFullCompletionStoreError> {
        let queries = CoordinatorCommitFullCompletionQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, queries.read).await?,
            insert: prepare_lwt(&session, queries.insert).await?,
            session,
        })
    }

    /// Persist completion after the local backup receipt has been converted
    /// into source-bound evidence. Once the LWT starts, any error is
    /// commit-indeterminate and must be recovered by retrying the same source.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn persist_after_exact_backup<Hash: Q256BitHash>(
        &self,
        manifests: &ScyllaCoordinatorCommitFullManifestStore,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        manifest_receipt: &PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        backup: &CoordinatorCheckpointBackupEvidence<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullCompletionReceipt<Hash>,
        CoordinatorCommitFullCompletionStoreError,
    > {
        manifests
            .revalidate_from_fresh_sources(
                manifest_receipt,
                sources,
                writer,
                executor,
                source,
                schedule,
            )
            .await
            .map_err(manifest_store)?;
        let expected = CoordinatorCommitFullCompletion::try_from_manifest_and_backup(
            manifest_receipt.manifest(),
            backup,
        )?;
        let receipt = self.persist(expected).await?;
        manifests
            .revalidate_from_fresh_sources(
                manifest_receipt,
                sources,
                writer,
                executor,
                source,
                schedule,
            )
            .await
            .map_err(manifest_store)?;
        self.revalidate(&receipt).await?;
        receipt
            .completion
            .revalidate_manifest_and_backup(manifest_receipt.manifest(), backup)?;
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn read_after_exact_backup<Hash: Q256BitHash>(
        &self,
        manifests: &ScyllaCoordinatorCommitFullManifestStore,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        manifest_receipt: &PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        backup: &CoordinatorCheckpointBackupEvidence<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullCompletionReceipt<Hash>,
        CoordinatorCommitFullCompletionStoreError,
    > {
        manifests
            .revalidate_from_fresh_sources(
                manifest_receipt,
                sources,
                writer,
                executor,
                source,
                schedule,
            )
            .await
            .map_err(manifest_store)?;
        let slot = coordinator_commit_full_completion_slot(
            source.slot().as_bytes(),
            source.candidate(),
        );
        let completion = self
            .read(slot)
            .await?
            .ok_or(CoordinatorCommitFullCompletionStoreError::ReceiptStale)?;
        let receipt = PersistedCoordinatorCommitFullCompletionReceipt {
            store_fingerprint: self.fingerprint,
            completion,
        };
        self.revalidate(&receipt).await?;
        receipt
            .completion
            .revalidate_manifest_and_backup(manifest_receipt.manifest(), backup)?;
        Ok(receipt)
    }

    async fn read<Hash: Q256BitHash>(
        &self,
        slot: CoordinatorCommitFullCompletionSlot,
    ) -> Result<Option<CoordinatorCommitFullCompletion<Hash>>, CoordinatorCommitFullCompletionStoreError>
    {
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
        let revision = revision.ok_or(CoordinatorCommitFullCompletionStoreError::MissingColumn)?;
        let payload = payload.ok_or(CoordinatorCommitFullCompletionStoreError::MissingColumn)?;
        Ok(Some(CoordinatorCommitFullCompletion::decode_persisted(
            slot.as_bytes(),
            revision,
            &payload,
        )?))
    }

    async fn persist<Hash: Q256BitHash>(
        &self,
        completion: CoordinatorCommitFullCompletion<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullCompletionReceipt<Hash>,
        CoordinatorCommitFullCompletionStoreError,
    > {
        let execution = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    completion.slot().as_bytes().as_slice(),
                    REVISION,
                    completion.canonical_payload(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(completion.slot()).await {
                Ok(Some(current)) if current == completion => false,
                Ok(_) => {
                    return Err(CoordinatorCommitFullCompletionStoreError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(CoordinatorCommitFullCompletionStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ));
                }
            },
        };
        let current = self
            .read(completion.slot())
            .await?
            .ok_or(CoordinatorCommitFullCompletionStoreError::MissingAfterLwt)?;
        if current != completion {
            return Err(if applied {
                CoordinatorCommitFullCompletionStoreError::AppliedStateMismatch
            } else {
                CoordinatorCommitFullCompletionStoreError::Conflict
            });
        }
        Ok(PersistedCoordinatorCommitFullCompletionReceipt {
            store_fingerprint: self.fingerprint,
            completion: current,
        })
    }

    async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedCoordinatorCommitFullCompletionReceipt<Hash>,
    ) -> Result<(), CoordinatorCommitFullCompletionStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(CoordinatorCommitFullCompletionStoreError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.completion.slot())
            .await?
            .ok_or(CoordinatorCommitFullCompletionStoreError::ReceiptStale)?;
        if current != receipt.completion {
            return Err(CoordinatorCommitFullCompletionStoreError::ReceiptStale);
        }
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &CanonicalHeadNoTabletKeyspace,
    queries: &CoordinatorCommitFullCompletionQueries,
) -> CoordinatorCommitFullCompletionStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    CoordinatorCommitFullCompletionStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorCommitFullCompletionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorCommitFullCompletionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, CoordinatorCommitFullCompletionStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorCommitFullCompletionStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(CoordinatorCommitFullCompletionStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> CoordinatorCommitFullCompletionStoreError {
    CoordinatorCommitFullCompletionStoreError::Cql(error.to_string())
}

fn manifest_store(error: CoordinatorCommitFullManifestStoreError) -> CoordinatorCommitFullCompletionStoreError {
    CoordinatorCommitFullCompletionStoreError::ManifestStore(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitFullCompletionStoreError {
    Cql(String),
    ManifestStore(String),
    Completion(CoordinatorCommitFullCompletionError),
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

impl From<CoordinatorCommitFullCompletionError> for CoordinatorCommitFullCompletionStoreError {
    fn from(value: CoordinatorCommitFullCompletionError) -> Self {
        Self::Completion(value)
    }
}

impl fmt::Display for CoordinatorCommitFullCompletionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator full completion store: {self:?}")
    }
}

impl Error for CoordinatorCommitFullCompletionStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_cql_is_immutable_quorum_lwt_and_cannot_publish() {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let queries = CoordinatorCommitFullCompletionQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.coordinator_commit_full_completion_v1 (completion_slot blob PRIMARY KEY, revision bigint, completion_payload blob)");
        assert_eq!(queries.read, "SELECT revision, completion_payload FROM control_nt.coordinator_commit_full_completion_v1 WHERE completion_slot = ?");
        assert_eq!(queries.insert, "INSERT INTO control_nt.coordinator_commit_full_completion_v1 (completion_slot, revision, completion_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        assert!(queries.golden().contains("BLOB,BIGINT,BLOB"));

        let production = include_str!("coordinator_commit_full_completion_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("USING TTL"));
        assert!(!production.contains("USING TIMESTAMP"));
        assert!(production.contains("SerialConsistency::LocalSerial"));
        assert!(production.contains("revalidate_from_fresh_sources"));
        assert!(!production.contains("mark_committed_and_readback"));
        assert!(!production.contains("compare_and_set"));
        assert!(!production.contains("publish_head"));
    }
}
