//! Isolated no-tablet LWT store for the reversible h22e3 cutover lifecycle.
//!
//! Missing means disabled. A row is selected by exact network and authority,
//! while its generation remains inside the canonical payload. Every update
//! compares revision and the complete previous payload. This module is not
//! registered in production setup.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};

use super::{
    BranchExactCutoverBootstrap, BranchExactCutoverError,
    BranchExactCutoverRevision, BranchExactDeploymentNoTabletKeyspace,
    SealedBranchExactCutoverCas, StoredBranchExactCutover,
};

const TABLE: &str = "branch_exact_cutover_lifecycle_v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactCutoverAuthorityKey {
    network: NetworkId,
    authority: AuthorityScope,
}

impl BranchExactCutoverAuthorityKey {
    pub fn try_new(
        network: NetworkId,
        authority: AuthorityScope,
    ) -> Result<Self, BranchExactCutoverStoreError> {
        if matches!(authority, AuthorityScope::Coordinator) {
            return Err(BranchExactCutoverStoreError::CoordinatorNotQualified);
        }
        Ok(Self { network, authority })
    }

    pub fn from_state<Hash: Q256BitHash>(
        state: &StoredBranchExactCutover<Hash>,
    ) -> Result<Self, BranchExactCutoverStoreError> {
        Self::try_new(state.binding().network(), state.binding().authority())
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn authority(self) -> AuthorityScope {
        self.authority
    }

    fn bind(self) -> (i64, i8, i64, i32) {
        match self.authority {
            AuthorityScope::Coordinator => unreachable!("constructor rejects Coordinator"),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => (
                i64::from(self.network.chain_id()),
                2,
                i64::from(realm_id),
                i32::from(realm_sub_id),
            ),
        }
    }

    fn decode(
        network_chain_id: i64,
        authority_kind: i8,
        realm_id: i64,
        realm_sub_id: i32,
    ) -> Result<Self, BranchExactCutoverStoreError> {
        let network_chain_id = u32::try_from(network_chain_id)
            .map_err(|_| BranchExactCutoverStoreError::SelectedKeyOutOfRange)?;
        let network = NetworkId::try_from_chain_id(network_chain_id)
            .map_err(|error| BranchExactCutoverStoreError::SelectedKey(error.to_string()))?;
        if authority_kind != 2 {
            return Err(BranchExactCutoverStoreError::InvalidSelectedAuthority);
        }
        Self::try_new(
            network,
            AuthorityScope::Realm {
                realm_id: u32::try_from(realm_id)
                    .map_err(|_| BranchExactCutoverStoreError::SelectedKeyOutOfRange)?,
                realm_sub_id: u16::try_from(realm_sub_id)
                    .map_err(|_| BranchExactCutoverStoreError::SelectedKeyOutOfRange)?,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl BranchExactCutoverQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{TABLE}", keyspace.as_str());
        let key = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, revision bigint, cutover blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, cutover FROM {table} WHERE {key}"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, cutover) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, cutover = ? WHERE {key} IF revision = ? AND cutover = ?"
            ),
        }
    }

    pub fn create(&self) -> &str {
        &self.create
    }

    pub fn read(&self) -> &str {
        &self.read
    }

    pub fn bootstrap(&self) -> &str {
        &self.bootstrap
    }

    pub fn compare_and_set(&self) -> &str {
        &self.compare_and_set
    }

    pub fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBIGINT,TINYINT,BIGINT,INT\n\nbootstrap\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.compare_and_set,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverReadState<Hash> {
    Uninitialized,
    Current(StoredBranchExactCutover<Hash>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverWriteOutcome<Hash> {
    Applied(StoredBranchExactCutover<Hash>),
    Idempotent(StoredBranchExactCutover<Hash>),
    Conflict(StoredBranchExactCutover<Hash>),
}

pub struct ScyllaBranchExactCutoverStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaBranchExactCutoverStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), BranchExactCutoverStoreError> {
        let queries = BranchExactCutoverQueries::new(keyspace);
        session.query_unpaged(queries.create(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, BranchExactCutoverStoreError> {
        let queries = BranchExactCutoverQueries::new(&keyspace);
        Ok(Self {
            read: prepare_read(&session, queries.read().to_owned()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap().to_owned()).await?,
            cas: prepare_lwt(&session, queries.compare_and_set().to_owned()).await?,
            session,
        })
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        key: BranchExactCutoverAuthorityKey,
    ) -> Result<BranchExactCutoverReadState<Hash>, BranchExactCutoverStoreError> {
        let (network, kind, realm, sub) = key.bind();
        let row = self
            .session
            .execute_unpaged(&self.read, (network, kind, realm, sub))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(i64, i8, i64, i32, Option<i64>, Option<Vec<u8>>)>()
            .map_err(cql)?;
        let Some((selected_network, selected_kind, selected_realm, selected_sub, revision, payload)) = row else {
            return Ok(BranchExactCutoverReadState::Uninitialized);
        };
        let selected = BranchExactCutoverAuthorityKey::decode(
            selected_network,
            selected_kind,
            selected_realm,
            selected_sub,
        )?;
        if selected != key {
            return Err(BranchExactCutoverStoreError::SelectedKeyMismatch);
        }
        let current = StoredBranchExactCutover::decode_selected(
            key.network,
            key.authority,
            revision.ok_or(BranchExactCutoverStoreError::MissingRevision)?,
            payload
                .as_deref()
                .ok_or(BranchExactCutoverStoreError::MissingPayload)?,
        )
        .map_err(model)?;
        Ok(BranchExactCutoverReadState::Current(current))
    }

    pub async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &BranchExactCutoverBootstrap<Hash>,
    ) -> Result<BranchExactCutoverWriteOutcome<Hash>, BranchExactCutoverStoreError> {
        let candidate = bootstrap.candidate();
        let key = BranchExactCutoverAuthorityKey::from_state(candidate)?;
        let (network, kind, realm, sub) = key.bind();
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
                    candidate.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    pub async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        sealed: &SealedBranchExactCutoverCas<Hash>,
    ) -> Result<BranchExactCutoverWriteOutcome<Hash>, BranchExactCutoverStoreError> {
        let expected = sealed.expected();
        let candidate = sealed.candidate();
        let key = BranchExactCutoverAuthorityKey::from_state(candidate)?;
        if BranchExactCutoverAuthorityKey::from_state(expected)? != key {
            return Err(BranchExactCutoverStoreError::PayloadAuthorityMismatch);
        }
        let (network, kind, realm, sub) = key.bind();
        let execution = self
            .session
            .execute_unpaged(
                &self.cas,
                (
                    candidate.revision().as_i64(),
                    candidate.to_canonical_bytes(),
                    network,
                    kind,
                    realm,
                    sub,
                    expected.revision().as_i64(),
                    expected.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    async fn finish<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: BranchExactCutoverAuthorityKey,
        candidate: &StoredBranchExactCutover<Hash>,
    ) -> Result<BranchExactCutoverWriteOutcome<Hash>, BranchExactCutoverStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute_error) => {
                return match self.read(key).await {
                    Ok(BranchExactCutoverReadState::Current(current))
                        if &current == candidate =>
                    {
                        Ok(BranchExactCutoverWriteOutcome::Idempotent(current))
                    }
                    Ok(BranchExactCutoverReadState::Current(current)) => {
                        Err(BranchExactCutoverStoreError::IndeterminateWrite {
                            execute: execute_error.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(BranchExactCutoverReadState::Uninitialized) => {
                        Err(BranchExactCutoverStoreError::IndeterminateWrite {
                            execute: execute_error.to_string(),
                            observed_revision: None,
                        })
                    }
                    Err(read_error) => Err(
                        BranchExactCutoverStoreError::IndeterminateReadFailed {
                            execute: execute_error.to_string(),
                            read: read_error.to_string(),
                        },
                    ),
                };
            }
        };
        let BranchExactCutoverReadState::Current(current) = self.read(key).await? else {
            return Err(BranchExactCutoverStoreError::CurrentMissingAfterLwt);
        };
        if applied {
            if &current != candidate {
                return Err(BranchExactCutoverStoreError::AppliedStateMismatch);
            }
            Ok(BranchExactCutoverWriteOutcome::Applied(current))
        } else if &current == candidate {
            Ok(BranchExactCutoverWriteOutcome::Idempotent(current))
        } else {
            Ok(BranchExactCutoverWriteOutcome::Conflict(current))
        }
    }
}

async fn prepare_read(
    session: &Session,
    cql: String,
) -> Result<PreparedStatement, BranchExactCutoverStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql: String,
) -> Result<PreparedStatement, BranchExactCutoverStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, BranchExactCutoverStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(BranchExactCutoverStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(BranchExactCutoverStoreError::InvalidAppliedColumn),
    }
}

fn model(error: BranchExactCutoverError) -> BranchExactCutoverStoreError {
    BranchExactCutoverStoreError::Lifecycle(error.to_string())
}

fn cql(error: impl fmt::Display) -> BranchExactCutoverStoreError {
    BranchExactCutoverStoreError::Cql(error.to_string())
}

fn cql_error(error: impl fmt::Display) -> BranchExactCutoverStoreError {
    cql(error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverStoreError {
    Lifecycle(String),
    Cql(String),
    SelectedKey(String),
    SelectedKeyOutOfRange,
    InvalidSelectedAuthority,
    SelectedKeyMismatch,
    CoordinatorNotQualified,
    PayloadAuthorityMismatch,
    MissingRevision,
    MissingPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    CurrentMissingAfterLwt,
    AppliedStateMismatch,
    IndeterminateWrite {
        execute: String,
        observed_revision: Option<BranchExactCutoverRevision>,
    },
    IndeterminateReadFailed { execute: String, read: String },
}

impl fmt::Display for BranchExactCutoverStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactCutoverStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_golden_is_no_tablet_full_payload_lwt() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22e3_no_tablet".to_owned(),
        )
        .unwrap();
        let queries = BranchExactCutoverQueries::new(&keyspace);
        let golden = queries.golden();
        assert!(golden.contains("branch_exact_cutover_lifecycle_v1"));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id))"));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND cutover = ?"));
        assert!(golden.contains("BIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB"));
    }

    #[test]
    fn key_is_realm_only_and_round_trips() {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let key = BranchExactCutoverAuthorityKey::try_new(
            network,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 9,
            },
        )
        .unwrap();
        let (network_id, kind, realm, sub) = key.bind();
        assert_eq!(
            BranchExactCutoverAuthorityKey::decode(network_id, kind, realm, sub),
            Ok(key)
        );
        assert_eq!(
            BranchExactCutoverAuthorityKey::try_new(network, AuthorityScope::Coordinator),
            Err(BranchExactCutoverStoreError::CoordinatorNotQualified)
        );
        assert_eq!(
            BranchExactCutoverAuthorityKey::decode(network_id, 1, 0, 0),
            Err(BranchExactCutoverStoreError::InvalidSelectedAuthority)
        );
    }

    #[test]
    fn cutover_table_is_not_registered_in_generic_setup() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(TABLE));
    }
}
