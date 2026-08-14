//! Immutable Scylla store for a fully verified Coordinator commit manifest.
//!
//! The store consumes the non-forgeable in-memory full-write observation,
//! brackets its LWT with fresh source, narrow-writer and typed-row reads, and
//! returns a private non-Clone receipt. It cannot mark a commit source,
//! rebuild checkpoint backups, or publish the canonical head.

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
    BranchExactWriterState, CanonicalHeadNoTabletKeyspace,
    ScyllaBranchExactWriterRuntime, ScyllaCoordinatorCommitSourceStore,
    coordinator_commit_full_manifest::{
        CoordinatorCommitFullManifest, CoordinatorCommitFullManifestError,
        CoordinatorCommitFullManifestSlot, coordinator_commit_full_manifest_slot,
    },
    coordinator_commit_full_write::CoordinatorCommitFullWriteObservation,
    coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule,
    coordinator_commit_physical_scylla::CoordinatorCommitPhysicalScyllaExecutor,
};
use psy_node_core::store::coordinator_commit_source::CoordinatorCommitSource;

pub(crate) const COORDINATOR_COMMIT_FULL_MANIFEST_TABLE: &str =
    "coordinator_commit_full_manifest_v1";
const REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-full-write-manifest-store.v1\0";
const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (manifest_slot blob PRIMARY KEY, revision bigint, manifest_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, manifest_payload FROM {table} WHERE manifest_slot = ?";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (manifest_slot, revision, manifest_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorCommitFullManifestQueries {
    create: String,
    read: String,
    insert: String,
}

impl CoordinatorCommitFullManifestQueries {
    fn new(keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_COMMIT_FULL_MANIFEST_TABLE,
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
struct CoordinatorCommitFullManifestStoreFingerprint([u8; 32]);

/// Exact persistence receipt. Private fields and the missing `Clone`
/// implementation prevent callers from manufacturing a source-commit or
/// head-publication input from raw bytes.
#[derive(Debug)]
pub(crate) struct PersistedCoordinatorCommitFullManifestReceipt<Hash> {
    store_fingerprint: CoordinatorCommitFullManifestStoreFingerprint,
    manifest: CoordinatorCommitFullManifest<Hash>,
}

impl<Hash> PersistedCoordinatorCommitFullManifestReceipt<Hash> {
    pub(crate) const fn manifest(&self) -> &CoordinatorCommitFullManifest<Hash> {
        &self.manifest
    }
}

pub(crate) struct ScyllaCoordinatorCommitFullManifestStore {
    session: Arc<Session>,
    fingerprint: CoordinatorCommitFullManifestStoreFingerprint,
    read: PreparedStatement,
    insert: PreparedStatement,
}

impl ScyllaCoordinatorCommitFullManifestStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), CoordinatorCommitFullManifestStoreError> {
        let queries = CoordinatorCommitFullManifestQueries::new(keyspace);
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
    ) -> Result<Self, CoordinatorCommitFullManifestStoreError> {
        let queries = CoordinatorCommitFullManifestQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, queries.read).await?,
            insert: prepare_lwt(&session, queries.insert).await?,
            session,
        })
    }

    /// Persist a full-write observation only after reconstructing it from
    /// current durable sources, then require two more exact reconstructions.
    /// Once the LWT starts, an error is commit-indeterminate and callers must
    /// retry the same source/schedule rather than change content.
    pub(crate) async fn persist_from_fresh_sources<Hash: Q256BitHash>(
        &self,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        observation: CoordinatorCommitFullWriteObservation<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        CoordinatorCommitFullManifestStoreError,
    > {
        let expected = CoordinatorCommitFullManifest::try_from_exact_observation(&observation)?;
        let before = self
            .observe_sources(sources, writer, executor, source, schedule)
            .await?;
        if before != expected {
            return Err(CoordinatorCommitFullManifestStoreError::SourceChanged);
        }
        let receipt = self.persist(expected).await?;
        let after = self
            .observe_sources(sources, writer, executor, source, schedule)
            .await?;
        if after != receipt.manifest {
            return Err(CoordinatorCommitFullManifestStoreError::SourceChanged);
        }
        self.revalidate_from_fresh_sources(
            &receipt, sources, writer, executor, source, schedule,
        )
        .await?;
        Ok(receipt)
    }

    pub(crate) async fn read_for_fresh_sources<Hash: Q256BitHash>(
        &self,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        CoordinatorCommitFullManifestStoreError,
    > {
        let slot = coordinator_commit_full_manifest_slot(
            source.slot().as_bytes(),
            source.candidate(),
        );
        let manifest = self
            .read(slot)
            .await?
            .ok_or(CoordinatorCommitFullManifestStoreError::ReceiptStale)?;
        let receipt = PersistedCoordinatorCommitFullManifestReceipt {
            store_fingerprint: self.fingerprint,
            manifest,
        };
        self.revalidate_from_fresh_sources(
            &receipt, sources, writer, executor, source, schedule,
        )
        .await?;
        Ok(receipt)
    }

    pub(crate) async fn revalidate_from_fresh_sources<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    ) -> Result<(), CoordinatorCommitFullManifestStoreError> {
        self.revalidate(receipt).await?;
        let observed = self
            .observe_sources(sources, writer, executor, source, schedule)
            .await?;
        if observed != receipt.manifest {
            return Err(CoordinatorCommitFullManifestStoreError::SourceChanged);
        }
        self.revalidate(receipt).await
    }

    async fn observe_sources<Hash: Q256BitHash>(
        &self,
        sources: &ScyllaCoordinatorCommitSourceStore,
        writer: &ScyllaBranchExactWriterRuntime<Hash>,
        executor: &CoordinatorCommitPhysicalScyllaExecutor,
        expected_source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    ) -> Result<CoordinatorCommitFullManifest<Hash>, CoordinatorCommitFullManifestStoreError> {
        let source = sources
            .read_source(expected_source.candidate())
            .await
            .map_err(source_store)?
            .ok_or(CoordinatorCommitFullManifestStoreError::SourceMissing)?;
        if source != *expected_source
            || source.slot().as_bytes() != *schedule.source_slot()
            || source.digest().as_bytes() != *schedule.source_digest()
        {
            return Err(CoordinatorCommitFullManifestStoreError::SourceChanged);
        }
        let current_writer = writer.read_writer().await.map_err(writer_store)?;
        let BranchExactWriterState::WritesVerified(verified) = current_writer.state() else {
            return Err(CoordinatorCommitFullManifestStoreError::WriterNotWritesVerified);
        };
        let observed_rows = executor
            .read_all(&self.session, schedule)
            .await
            .map_err(typed_store)?;
        let typed = schedule
            .verify_manifest_revalidation(&observed_rows)
            .map_err(execution)?;
        let observation = CoordinatorCommitFullWriteObservation::try_from_storage(
            &source, schedule, verified, typed,
        )
        .map_err(execution)?;
        CoordinatorCommitFullManifest::try_from_exact_observation(&observation)
            .map_err(Into::into)
    }

    async fn read<Hash: Q256BitHash>(
        &self,
        slot: CoordinatorCommitFullManifestSlot,
    ) -> Result<Option<CoordinatorCommitFullManifest<Hash>>, CoordinatorCommitFullManifestStoreError>
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
        let revision = revision.ok_or(CoordinatorCommitFullManifestStoreError::MissingColumn)?;
        let payload = payload.ok_or(CoordinatorCommitFullManifestStoreError::MissingColumn)?;
        Ok(Some(CoordinatorCommitFullManifest::decode_persisted(
            slot.as_bytes(),
            revision,
            &payload,
        )?))
    }

    async fn persist<Hash: Q256BitHash>(
        &self,
        manifest: CoordinatorCommitFullManifest<Hash>,
    ) -> Result<
        PersistedCoordinatorCommitFullManifestReceipt<Hash>,
        CoordinatorCommitFullManifestStoreError,
    > {
        let execution = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    manifest.slot().as_bytes().as_slice(),
                    REVISION,
                    manifest.canonical_payload(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(manifest.slot()).await {
                Ok(Some(current)) if current == manifest => false,
                Ok(_) => {
                    return Err(CoordinatorCommitFullManifestStoreError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(CoordinatorCommitFullManifestStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ));
                }
            },
        };
        let current = self
            .read(manifest.slot())
            .await?
            .ok_or(CoordinatorCommitFullManifestStoreError::MissingAfterLwt)?;
        if current != manifest {
            return Err(if applied {
                CoordinatorCommitFullManifestStoreError::AppliedStateMismatch
            } else {
                CoordinatorCommitFullManifestStoreError::Conflict
            });
        }
        Ok(PersistedCoordinatorCommitFullManifestReceipt {
            store_fingerprint: self.fingerprint,
            manifest: current,
        })
    }

    async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedCoordinatorCommitFullManifestReceipt<Hash>,
    ) -> Result<(), CoordinatorCommitFullManifestStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(CoordinatorCommitFullManifestStoreError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.manifest.slot())
            .await?
            .ok_or(CoordinatorCommitFullManifestStoreError::ReceiptStale)?;
        if current != receipt.manifest {
            return Err(CoordinatorCommitFullManifestStoreError::ReceiptStale);
        }
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &CanonicalHeadNoTabletKeyspace,
    queries: &CoordinatorCommitFullManifestQueries,
) -> CoordinatorCommitFullManifestStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    CoordinatorCommitFullManifestStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorCommitFullManifestStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorCommitFullManifestStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, CoordinatorCommitFullManifestStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorCommitFullManifestStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(CoordinatorCommitFullManifestStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> CoordinatorCommitFullManifestStoreError {
    CoordinatorCommitFullManifestStoreError::Cql(error.to_string())
}

fn source_store(error: impl fmt::Display) -> CoordinatorCommitFullManifestStoreError {
    CoordinatorCommitFullManifestStoreError::SourceStore(error.to_string())
}

fn writer_store(error: impl fmt::Display) -> CoordinatorCommitFullManifestStoreError {
    CoordinatorCommitFullManifestStoreError::WriterStore(error.to_string())
}

fn typed_store(error: impl fmt::Display) -> CoordinatorCommitFullManifestStoreError {
    CoordinatorCommitFullManifestStoreError::TypedStore(error.to_string())
}

fn execution(error: impl fmt::Display) -> CoordinatorCommitFullManifestStoreError {
    CoordinatorCommitFullManifestStoreError::Execution(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitFullManifestStoreError {
    Cql(String),
    SourceStore(String),
    WriterStore(String),
    TypedStore(String),
    Execution(String),
    Manifest(CoordinatorCommitFullManifestError),
    SourceMissing,
    SourceChanged,
    WriterNotWritesVerified,
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

impl From<CoordinatorCommitFullManifestError> for CoordinatorCommitFullManifestStoreError {
    fn from(value: CoordinatorCommitFullManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl fmt::Display for CoordinatorCommitFullManifestStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator full-write manifest store: {self:?}")
    }
}

impl Error for CoordinatorCommitFullManifestStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cql_is_immutable_quorum_lwt_with_stable_bind_order() {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let queries = CoordinatorCommitFullManifestQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.coordinator_commit_full_manifest_v1 (manifest_slot blob PRIMARY KEY, revision bigint, manifest_payload blob)");
        assert_eq!(queries.read, "SELECT revision, manifest_payload FROM control_nt.coordinator_commit_full_manifest_v1 WHERE manifest_slot = ?");
        assert_eq!(queries.insert, "INSERT INTO control_nt.coordinator_commit_full_manifest_v1 (manifest_slot, revision, manifest_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        assert!(queries.golden().contains("BLOB,BIGINT,BLOB"));

        let production = include_str!("coordinator_commit_full_manifest_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("USING TTL"));
        assert!(!production.contains("USING TIMESTAMP"));
        assert!(production.contains("SerialConsistency::LocalSerial"));
        assert!(production.contains("verify_manifest_revalidation"));
        assert!(production.contains("revalidate_from_fresh_sources"));
        assert!(!production.contains("mark_committed_and_readback"));
        assert!(!production.contains("compare_and_set"));
        assert!(!production.contains("publish_head"));
    }
}
