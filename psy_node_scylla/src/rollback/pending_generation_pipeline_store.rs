//! Isolated no-tablet LWT adapter for the complete pending pipeline row.
//!
//! The h22d3a0 identity-only ledger is superseded by this single durable row;
//! production must never maintain both rows as authorities.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::{
        PendingPipelineBootstrap, PendingPipelineError,
        PendingPipelineReadState, PendingPipelineRevision,
        PendingPipelineWriteOutcome, SealedPendingPipelineTransition,
        StoredPendingPipeline,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};

use super::BranchExactDeploymentNoTabletKeyspace;

const PIPELINE_TABLE: &str = "branch_exact_pending_pipeline_v2";
const RETIRED_V1_PIPELINE_TABLE: &str = "branch_exact_pending_pipeline_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPipelineQueries {
    create: String,
    read: String,
    bootstrap: String,
    cas: String,
}

impl PendingPipelineQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{PIPELINE_TABLE}", keyspace.as_str());
        let authority = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, revision bigint, pipeline blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline FROM {table} WHERE {authority}"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            cas: format!(
                "UPDATE {table} SET revision = ?, pipeline = ? WHERE {authority} IF revision = ? AND pipeline = ?"
            ),
        }
    }

    pub fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBIGINT,TINYINT,BIGINT,INT\n\nbootstrap\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n\ncas\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.cas,
        )
    }
}

pub struct ScyllaPendingPipelineStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaPendingPipelineStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingPipelineStoreError> {
        let queries = PendingPipelineQueries::new(keyspace);
        session
            .query_unpaged(queries.create.as_str(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingPipelineStoreError> {
        let queries = PendingPipelineQueries::new(&keyspace);
        Ok(Self {
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            cas: prepare_lwt(&session, queries.cas).await?,
            session,
        })
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        key: PendingGenerationLedgerKey,
    ) -> Result<PendingPipelineReadState<Hash>, PendingPipelineStoreError> {
        let (network, kind, realm, sub) = bind_key(key);
        let selected = self
            .session
            .execute_unpaged(&self.read, (network, kind, realm, sub))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(
                i64,
                i8,
                i64,
                i32,
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let Some((network, kind, realm, sub, revision, payload)) = selected else {
            return Ok(PendingPipelineReadState::Uninitialized);
        };
        if decode_key(network, kind, realm, sub)? != key {
            return Err(PendingPipelineStoreError::SelectedKeyMismatch);
        }
        let current = StoredPendingPipeline::<Hash>::decode_persisted(
            key,
            revision.ok_or(PendingPipelineStoreError::MissingRevision)?,
            payload
                .as_deref()
                .ok_or(PendingPipelineStoreError::MissingPayload)?,
        )
        .map_err(model)?;
        Ok(PendingPipelineReadState::Current(current))
    }

    pub(crate) async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &PendingPipelineBootstrap<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let candidate = bootstrap.candidate();
        let key = candidate.key();
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    network,
                    kind,
                    realm,
                    sub,
                    candidate.revision().as_i64(),
                    bootstrap.candidate_payload().as_slice(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    pub(crate) async fn apply<Hash: Q256BitHash>(
        &self,
        transition: &SealedPendingPipelineTransition<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let expected = transition.expected();
        let candidate = transition.candidate();
        let key = expected.key();
        if candidate.key() != key {
            return Err(PendingPipelineStoreError::TransitionKeyMismatch);
        }
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.cas,
                (
                    candidate.revision().as_i64(),
                    transition.candidate_payload().as_slice(),
                    network,
                    kind,
                    realm,
                    sub,
                    expected.revision().as_i64(),
                    transition.expected_payload().as_slice(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    async fn finish<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: PendingGenerationLedgerKey,
        candidate: &StoredPendingPipeline<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self.read::<Hash>(key).await {
                    Ok(PendingPipelineReadState::Current(current))
                        if &current == candidate =>
                    {
                        Ok(PendingPipelineWriteOutcome::Idempotent(current))
                    }
                    Ok(PendingPipelineReadState::Current(current)) => {
                        Err(PendingPipelineStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(PendingPipelineReadState::Uninitialized) => {
                        Err(PendingPipelineStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: None,
                        })
                    }
                    Err(read) => Err(PendingPipelineStoreError::IndeterminateReadFailed {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let PendingPipelineReadState::Current(current) = self.read::<Hash>(key).await? else {
            return Err(PendingPipelineStoreError::MissingAfterLwt);
        };
        if applied && &current != candidate {
            return Err(PendingPipelineStoreError::AppliedStateMismatch);
        }
        Ok(if applied {
            PendingPipelineWriteOutcome::Applied(current)
        } else if &current == candidate {
            PendingPipelineWriteOutcome::Idempotent(current)
        } else {
            PendingPipelineWriteOutcome::Conflict(current)
        })
    }
}

fn bind_key(key: PendingGenerationLedgerKey) -> (i64, i8, i64, i32) {
    let (kind, realm, sub) = authority_parts(key.authority());
    (i64::from(key.network().chain_id()), kind, realm, sub)
}

fn authority_parts(authority: AuthorityScope) -> (i8, i64, i32) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (2, i64::from(realm_id), i32::from(realm_sub_id)),
    }
}

fn decode_key(
    network: i64,
    kind: i8,
    realm: i64,
    sub: i32,
) -> Result<PendingGenerationLedgerKey, PendingPipelineStoreError> {
    let network = NetworkId::try_from_chain_id(
        u32::try_from(network).map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
    )
    .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?;
    let authority = match (kind, realm, sub) {
        (1, 0, 0) => AuthorityScope::Coordinator,
        (2, realm, sub) => AuthorityScope::Realm {
            realm_id: u32::try_from(realm)
                .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
            realm_sub_id: u16::try_from(sub)
                .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
        },
        _ => return Err(PendingPipelineStoreError::InvalidAuthority),
    };
    Ok(PendingGenerationLedgerKey::new(network, authority))
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingPipelineStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingPipelineStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingPipelineStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingPipelineStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingPipelineStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingPipelineStoreError {
    PendingPipelineStoreError::Cql(error.to_string())
}

fn model(error: PendingPipelineError) -> PendingPipelineStoreError {
    PendingPipelineStoreError::Model(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingPipelineStoreError {
    Cql(String),
    Model(String),
    SelectedKeyOutOfRange,
    InvalidAuthority,
    SelectedKeyMismatch,
    MissingRevision,
    MissingPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    TransitionKeyMismatch,
    MissingAfterLwt,
    AppliedStateMismatch,
    Indeterminate {
        execute: String,
        observed_revision: Option<PendingPipelineRevision>,
    },
    IndeterminateReadFailed { execute: String, read: String },
}

impl fmt::Display for PendingPipelineStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingPipelineStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_use_one_no_tablet_revision_and_payload_cas_row() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22d3_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = PendingPipelineQueries::new(&keyspace).golden();
        assert!(golden.contains(PIPELINE_TABLE));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND pipeline = ?"));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id))"));
        assert!(!golden.contains("proc_namespace_prefix_claim"));
        assert!(!golden.contains(RETIRED_V1_PIPELINE_TABLE));
    }

    #[test]
    fn v1_table_is_never_read_or_mutated_by_the_v2_adapter() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22d3_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = PendingPipelineQueries::new(&keyspace).golden();
        assert_eq!(golden.matches(PIPELINE_TABLE).count(), 4);
        assert_eq!(golden.matches(RETIRED_V1_PIPELINE_TABLE).count(), 0);
    }

    #[test]
    fn production_setup_does_not_create_or_prepare_the_pipeline() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PIPELINE_TABLE));
        assert!(!setup.contains("ScyllaPendingPipelineStore"));
    }
}
