//! Immutable durable Coordinator GUTA submission adapter.
//!
//! The record is selected before queue publication.  The same full content is
//! idempotent; different content for the same pending/proc/Realm coordinate is
//! a permanent conflict.  There is deliberately no update/delete/TTL path.

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::coordinator_guta_durable_submission::{
    CoordinatorGutaDurableSubmission, CoordinatorGutaDurableSubmissionError,
    CoordinatorGutaDurableSubmissionSlot, CoordinatorGutaDurableSubmissionStore,
};
use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(crate) const COORDINATOR_GUTA_DURABLE_SUBMISSION_TABLE: &str =
    "branch_exact_coordinator_guta_submission_v1";
const REVISION: i64 = 1;
const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (submission_slot blob PRIMARY KEY, revision bigint, submission_payload blob)";
const READ_TEMPLATE: &str =
    "SELECT revision, submission_payload FROM {table} WHERE submission_slot = ?";
const INSERT_TEMPLATE: &str = "INSERT INTO {table} (submission_slot, revision, submission_payload) VALUES (?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorGutaDurableSubmissionQueries {
    create: String,
    read: String,
    insert: String,
}

impl CoordinatorGutaDurableSubmissionQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_GUTA_DURABLE_SUBMISSION_TABLE,
        );
        Self {
            create: CREATE_TEMPLATE.replace("{table}", &table),
            read: READ_TEMPLATE.replace("{table}", &table),
            insert: INSERT_TEMPLATE.replace("{table}", &table),
        }
    }
}

pub(crate) struct ScyllaCoordinatorGutaDurableSubmissionStore {
    session: Arc<Session>,
    network: NetworkId,
    readiness_digest: [u8; 32],
    read: PreparedStatement,
    insert: PreparedStatement,
}

impl ScyllaCoordinatorGutaDurableSubmissionStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), CoordinatorGutaDurableSubmissionStoreError> {
        let queries = CoordinatorGutaDurableSubmissionQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
        network: NetworkId,
        readiness_digest: [u8; 32],
    ) -> Result<Self, CoordinatorGutaDurableSubmissionStoreError> {
        let queries = CoordinatorGutaDurableSubmissionQueries::new(&keyspace);
        Ok(Self {
            network,
            readiness_digest,
            read: prepare_read(&session, queries.read).await?,
            insert: prepare_lwt(&session, queries.insert).await?,
            session,
        })
    }

    async fn read<Hash: Q256BitHash>(
        &self,
        slot: CoordinatorGutaDurableSubmissionSlot,
    ) -> Result<Option<CoordinatorGutaDurableSubmission<Hash>>, CoordinatorGutaDurableSubmissionStoreError> {
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
        if revision.ok_or(CoordinatorGutaDurableSubmissionStoreError::MissingColumn)? != REVISION {
            return Err(CoordinatorGutaDurableSubmissionStoreError::UnknownRevision);
        }
        let payload = payload.ok_or(CoordinatorGutaDurableSubmissionStoreError::MissingColumn)?;
        let submission = CoordinatorGutaDurableSubmission::decode_selected(
            slot,
            &payload,
        )?;
        self.validate_identity(&submission)?;
        Ok(Some(submission))
    }

    async fn persist<Hash: Q256BitHash>(
        &self,
        submission: CoordinatorGutaDurableSubmission<Hash>,
    ) -> Result<CoordinatorGutaDurableSubmission<Hash>, CoordinatorGutaDurableSubmissionStoreError> {
        self.validate_identity(&submission)?;
        let payload = submission.to_canonical_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    submission.slot().as_bytes().as_slice(),
                    REVISION,
                    payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(submission.slot()).await {
                Ok(Some(current)) if current == submission => false,
                Ok(_) => {
                    return Err(CoordinatorGutaDurableSubmissionStoreError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(CoordinatorGutaDurableSubmissionStoreError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    ));
                }
            },
        };
        let current = self
            .read(submission.slot())
            .await?
            .ok_or(CoordinatorGutaDurableSubmissionStoreError::MissingAfterLwt)?;
        if current != submission {
            return Err(if applied {
                CoordinatorGutaDurableSubmissionStoreError::AppliedStateMismatch
            } else {
                CoordinatorGutaDurableSubmissionStoreError::Conflict
            });
        }
        Ok(current)
    }

    fn validate_identity<Hash: Q256BitHash>(
        &self,
        submission: &CoordinatorGutaDurableSubmission<Hash>,
    ) -> Result<(), CoordinatorGutaDurableSubmissionStoreError> {
        if submission.pending().chain().network_id() != self.network
            || submission.pending().authority() != AuthorityScope::Coordinator
        {
            return Err(CoordinatorGutaDurableSubmissionStoreError::IdentityMismatch);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash> CoordinatorGutaDurableSubmissionStore<Hash>
    for ScyllaCoordinatorGutaDurableSubmissionStore
where
    Hash: Q256BitHash + Send + Sync,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn authority(&self) -> AuthorityScope {
        AuthorityScope::Coordinator
    }

    fn readiness_digest(&self) -> [u8; 32] {
        self.readiness_digest
    }

    async fn persist_and_readback(
        &self,
        submission: CoordinatorGutaDurableSubmission<Hash>,
    ) -> anyhow::Result<CoordinatorGutaDurableSubmission<Hash>> {
        Ok(self.persist(submission).await?)
    }

    async fn read_selected(
        &self,
        slot: CoordinatorGutaDurableSubmissionSlot,
    ) -> anyhow::Result<Option<CoordinatorGutaDurableSubmission<Hash>>> {
        Ok(self.read(slot).await?)
    }
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorGutaDurableSubmissionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, CoordinatorGutaDurableSubmissionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, CoordinatorGutaDurableSubmissionStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CoordinatorGutaDurableSubmissionStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(CoordinatorGutaDurableSubmissionStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> CoordinatorGutaDurableSubmissionStoreError {
    CoordinatorGutaDurableSubmissionStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorGutaDurableSubmissionStoreError {
    Cql(String),
    Core(CoordinatorGutaDurableSubmissionError),
    MissingColumn,
    UnknownRevision,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    IdentityMismatch,
    Conflict,
    Indeterminate(String),
}

impl From<CoordinatorGutaDurableSubmissionError>
    for CoordinatorGutaDurableSubmissionStoreError
{
    fn from(value: CoordinatorGutaDurableSubmissionError) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for CoordinatorGutaDurableSubmissionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorGutaDurableSubmissionStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cql_is_append_only_lwt_with_stable_bind_order() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("control_nt".to_owned()).unwrap();
        let queries = CoordinatorGutaDurableSubmissionQueries::new(&keyspace);
        assert_eq!(queries.create, "CREATE TABLE IF NOT EXISTS control_nt.branch_exact_coordinator_guta_submission_v1 (submission_slot blob PRIMARY KEY, revision bigint, submission_payload blob)");
        assert_eq!(queries.read, "SELECT revision, submission_payload FROM control_nt.branch_exact_coordinator_guta_submission_v1 WHERE submission_slot = ?");
        assert_eq!(queries.insert, "INSERT INTO control_nt.branch_exact_coordinator_guta_submission_v1 (submission_slot, revision, submission_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        let production = include_str!("coordinator_guta_durable_submission_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("UPDATE "));
        assert!(!production.contains("DELETE FROM"));
        assert!(!production.contains("USING TTL"));
        assert!(!production.contains("USING TIMESTAMP"));
    }
}
