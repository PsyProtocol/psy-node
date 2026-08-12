//! Immutable no-tablet store for one Realm full-commit composite manifest.
//!
//! Raw persistence stays inside this module.  The only sibling-visible write
//! route re-reads the complete h22 writer row and every non-h22 typed row
//! before and after the LWT.  The returned non-Clone receipt proves exact
//! persistence only; it is not a publish, head, terminal, or rotation permit.

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
    BranchExactDeploymentNoTabletKeyspace, BranchExactWriterAuthorityKey,
    BranchExactWriterReadState, BranchExactWriterState,
    ScyllaBranchExactWriterLifecycleStore,
    realm_full_commit_execution::RealmFullCommitExecutionSchedule,
    realm_full_commit_manifest::{
        RealmFullCommitCompositeManifest, RealmFullCommitManifestError,
        RealmFullCommitManifestSlot, RealmNarrowWritesVerifiedEvidence,
    },
    realm_full_commit_plan::RealmFullCommitPhysicalPlan,
    realm_full_commit_scylla::RealmFullCommitScyllaExecutor,
};

pub(super) const REALM_FULL_COMMIT_MANIFEST_TABLE: &str =
    "branch_exact_realm_full_commit_manifest_v1";
const REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-manifest-store.v1\0";
const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (manifest_slot blob PRIMARY KEY, revision bigint, manifest_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, manifest_payload FROM {table} WHERE manifest_slot = ?";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (manifest_slot, revision, manifest_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmFullCommitManifestQueries {
    create: String,
    read: String,
    insert: String,
}

impl RealmFullCommitManifestQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            REALM_FULL_COMMIT_MANIFEST_TABLE,
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
struct RealmFullCommitManifestStoreFingerprint([u8; 32]);

/// Exact durable receipt.  It is deliberately non-Clone and its fields are
/// private so sibling modules cannot manufacture or rewrite it.
#[derive(Debug)]
pub(super) struct PersistedRealmFullCommitManifestReceipt<Hash> {
    store_fingerprint: RealmFullCommitManifestStoreFingerprint,
    manifest: RealmFullCommitCompositeManifest<Hash>,
}

impl<Hash> PersistedRealmFullCommitManifestReceipt<Hash> {
    pub(super) const fn manifest(
        &self,
    ) -> &RealmFullCommitCompositeManifest<Hash> {
        &self.manifest
    }
}

pub(super) struct ScyllaRealmFullCommitManifestStore {
    session: Arc<Session>,
    fingerprint: RealmFullCommitManifestStoreFingerprint,
    read: PreparedStatement,
    insert: PreparedStatement,
}

impl ScyllaRealmFullCommitManifestStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), RealmFullCommitManifestStoreError> {
        let queries = RealmFullCommitManifestQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, RealmFullCommitManifestStoreError> {
        let queries = RealmFullCommitManifestQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, queries.read).await?,
            insert: prepare_lwt(&session, queries.insert).await?,
            session,
        })
    }

    /// Persist only after observing one exact source snapshot, then require
    /// two more equal source snapshots around receipt revalidation.  If an
    /// error is returned after the LWT began, the immutable row may already
    /// exist and callers must retry the same plan rather than change content.
    pub(super) async fn persist_from_fresh_sources<Hash: Q256BitHash>(
        &self,
        writer: &ScyllaBranchExactWriterLifecycleStore,
        writer_key: BranchExactWriterAuthorityKey,
        executor: &RealmFullCommitScyllaExecutor,
        plan: &RealmFullCommitPhysicalPlan,
    ) -> Result<PersistedRealmFullCommitManifestReceipt<Hash>, RealmFullCommitManifestStoreError>
    {
        let before = self
            .observe_sources(writer, writer_key, executor, plan)
            .await?;
        let receipt = self.persist(before.clone()).await?;
        let after = self
            .observe_sources(writer, writer_key, executor, plan)
            .await?;
        if after != before {
            return Err(RealmFullCommitManifestStoreError::SourceChanged);
        }
        self.revalidate_from_fresh_sources(
            &receipt,
            writer,
            writer_key,
            executor,
            plan,
        )
        .await?;
        Ok(receipt)
    }

    /// Fresh consumption fence for a previously returned receipt.  The
    /// manifest row is checked both before and after reconstructing the source
    /// evidence, so a later writer/head owner never relies on a stale receipt
    /// or a source observation read outside this bracket.
    pub(super) async fn revalidate_from_fresh_sources<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmFullCommitManifestReceipt<Hash>,
        writer: &ScyllaBranchExactWriterLifecycleStore,
        writer_key: BranchExactWriterAuthorityKey,
        executor: &RealmFullCommitScyllaExecutor,
        plan: &RealmFullCommitPhysicalPlan,
    ) -> Result<(), RealmFullCommitManifestStoreError> {
        self.revalidate(receipt).await?;
        let observed = self
            .observe_sources(writer, writer_key, executor, plan)
            .await?;
        if observed != receipt.manifest {
            return Err(RealmFullCommitManifestStoreError::SourceChanged);
        }
        self.revalidate(receipt).await
    }

    async fn observe_sources<Hash: Q256BitHash>(
        &self,
        writer: &ScyllaBranchExactWriterLifecycleStore,
        writer_key: BranchExactWriterAuthorityKey,
        executor: &RealmFullCommitScyllaExecutor,
        plan: &RealmFullCommitPhysicalPlan,
    ) -> Result<RealmFullCommitCompositeManifest<Hash>, RealmFullCommitManifestStoreError>
    {
        let BranchExactWriterReadState::Current(current) =
            writer.read(writer_key).await.map_err(writer_error)?
        else {
            return Err(RealmFullCommitManifestStoreError::WriterUninitialized);
        };
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(RealmFullCommitManifestStoreError::WriterNotWritesVerified);
        };
        let narrow = RealmNarrowWritesVerifiedEvidence::try_from_stored(&current)?;
        let schedule = RealmFullCommitExecutionSchedule::try_from_plan(
            plan,
            verified.prepared(),
        )
        .map_err(execution_error)?;
        let observed = executor
            .read_all(&self.session, &schedule)
            .await
            .map_err(source_read_error)?;
        let typed = schedule
            .verify_after_write(&observed)
            .map_err(execution_error)?;
        RealmFullCommitCompositeManifest::try_new(plan, &narrow, &typed)
            .map_err(Into::into)
    }

    async fn read<Hash: Q256BitHash>(
        &self,
        slot: RealmFullCommitManifestSlot,
    ) -> Result<Option<RealmFullCommitCompositeManifest<Hash>>, RealmFullCommitManifestStoreError>
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
        let revision = revision.ok_or(RealmFullCommitManifestStoreError::MissingColumn)?;
        let payload = payload.ok_or(RealmFullCommitManifestStoreError::MissingColumn)?;
        Ok(Some(RealmFullCommitCompositeManifest::decode_persisted(
            slot.as_bytes(),
            revision,
            &payload,
        )?))
    }

    async fn persist<Hash: Q256BitHash>(
        &self,
        manifest: RealmFullCommitCompositeManifest<Hash>,
    ) -> Result<PersistedRealmFullCommitManifestReceipt<Hash>, RealmFullCommitManifestStoreError>
    {
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
                    return Err(RealmFullCommitManifestStoreError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(RealmFullCommitManifestStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ));
                }
            },
        };
        let current = self
            .read(manifest.slot())
            .await?
            .ok_or(RealmFullCommitManifestStoreError::MissingAfterLwt)?;
        if current != manifest {
            return Err(if applied {
                RealmFullCommitManifestStoreError::AppliedStateMismatch
            } else {
                RealmFullCommitManifestStoreError::Conflict
            });
        }
        Ok(PersistedRealmFullCommitManifestReceipt {
            store_fingerprint: self.fingerprint,
            manifest: current,
        })
    }

    async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRealmFullCommitManifestReceipt<Hash>,
    ) -> Result<(), RealmFullCommitManifestStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RealmFullCommitManifestStoreError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.manifest.slot())
            .await?
            .ok_or(RealmFullCommitManifestStoreError::ReceiptStale)?;
        if current != receipt.manifest {
            return Err(RealmFullCommitManifestStoreError::ReceiptStale);
        }
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &RealmFullCommitManifestQueries,
) -> RealmFullCommitManifestStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    RealmFullCommitManifestStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmFullCommitManifestStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, RealmFullCommitManifestStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, RealmFullCommitManifestStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RealmFullCommitManifestStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmFullCommitManifestStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> RealmFullCommitManifestStoreError {
    RealmFullCommitManifestStoreError::Cql(error.to_string())
}

fn writer_error(error: impl fmt::Display) -> RealmFullCommitManifestStoreError {
    RealmFullCommitManifestStoreError::Writer(error.to_string())
}

fn source_read_error(error: impl fmt::Display) -> RealmFullCommitManifestStoreError {
    RealmFullCommitManifestStoreError::SourceRead(error.to_string())
}

fn execution_error(error: impl fmt::Display) -> RealmFullCommitManifestStoreError {
    RealmFullCommitManifestStoreError::Execution(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmFullCommitManifestStoreError {
    Cql(String),
    Writer(String),
    SourceRead(String),
    Execution(String),
    Manifest(RealmFullCommitManifestError),
    WriterUninitialized,
    WriterNotWritesVerified,
    SourceChanged,
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

impl From<RealmFullCommitManifestError> for RealmFullCommitManifestStoreError {
    fn from(value: RealmFullCommitManifestError) -> Self { Self::Manifest(value) }
}

impl fmt::Display for RealmFullCommitManifestStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full-commit manifest store: {self:?}")
    }
}

impl Error for RealmFullCommitManifestStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cql_is_immutable_quorum_lwt_with_stable_bind_order() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "control_nt".to_owned(),
        )
        .unwrap();
        let queries = RealmFullCommitManifestQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.branch_exact_realm_full_commit_manifest_v1 (manifest_slot blob PRIMARY KEY, revision bigint, manifest_payload blob)");
        assert_eq!(queries.read, "SELECT revision, manifest_payload FROM control_nt.branch_exact_realm_full_commit_manifest_v1 WHERE manifest_slot = ?");
        assert_eq!(queries.insert, "INSERT INTO control_nt.branch_exact_realm_full_commit_manifest_v1 (manifest_slot, revision, manifest_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        assert!(queries.golden().contains("BLOB,BIGINT,BLOB"));

        let production = include_str!("realm_full_commit_manifest_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("USING TTL"));
        assert!(!production.contains("USING TIMESTAMP"));
        assert!(production.contains("SerialConsistency::LocalSerial"));
        assert!(production.contains("observe_sources(writer, writer_key, executor, plan)"));
        assert!(production.contains("revalidate_from_fresh_sources"));
        assert_eq!(production.matches("self.revalidate(receipt)").count(), 2);
    }
}
