//! Isolated Scylla adapter for one indivisible authority-local serving head.
//!
//! It is intentionally absent from production setup. The adapter provides the
//! real QUORUM/LOCAL_SERIAL interface required by D-04b crash testing.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::{AuthorityScope, AuthorityTimestampKey},
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadModelError,
        AuthorityLocalHeadReadState, AuthorityLocalHeadWriteOutcome,
        SealedAuthorityLocalHeadCas, StoredAuthorityLocalHead,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const D04B_AUTHORITY_LOCAL_HEAD_TABLE: &str =
    "d04b_authority_local_head";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidAuthorityLocalHeadNoTabletKeyspace(pub String);

impl fmt::Display for InvalidAuthorityLocalHeadNoTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authority-local-head keyspace {:?} must end in _no_tablet or _nt",
            self.0
        )
    }
}

impl Error for InvalidAuthorityLocalHeadNoTabletKeyspace {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityLocalHeadNoTabletKeyspace(CqlKeyspaceName);

impl AuthorityLocalHeadNoTabletKeyspace {
    pub fn try_new(
        name: impl Into<String>,
    ) -> Result<Self, AuthorityLocalHeadPrototypeError> {
        let name = name.into();
        let keyspace = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(
                AuthorityLocalHeadPrototypeError::InvalidNoTabletKeyspace(
                    InvalidAuthorityLocalHeadNoTabletKeyspace(name),
                ),
            );
        }
        Ok(Self(keyspace))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityLocalHeadQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityLocalHeadQuery {
    id: AuthorityLocalHeadQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl AuthorityLocalHeadQuery {
    pub const fn id(&self) -> AuthorityLocalHeadQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityLocalHeadQueries {
    create_table: AuthorityLocalHeadQuery,
    read: AuthorityLocalHeadQuery,
    bootstrap: AuthorityLocalHeadQuery,
    compare_and_set: AuthorityLocalHeadQuery,
}

impl AuthorityLocalHeadQueries {
    pub fn new(keyspace: &AuthorityLocalHeadNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{D04B_AUTHORITY_LOCAL_HEAD_TABLE}",
            keyspace.as_str()
        );
        let partition =
            "network_chain_id, authority_kind, realm_id, realm_sub_id";
        Self {
            create_table: AuthorityLocalHeadQuery {
                id: AuthorityLocalHeadQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id bigint, revision bigint, head blob, PRIMARY KEY (({partition})))"
                ),
                bind_shape: &[],
            },
            read: AuthorityLocalHeadQuery {
                id: AuthorityLocalHeadQueryId::Read,
                cql: format!(
                    "SELECT {partition}, revision, head FROM {table} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                ],
            },
            bootstrap: AuthorityLocalHeadQuery {
                id: AuthorityLocalHeadQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {table} ({partition}, revision, head) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                    "candidate_revision:BIGINT",
                    "candidate_head:BLOB",
                ],
            },
            compare_and_set: AuthorityLocalHeadQuery {
                id: AuthorityLocalHeadQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {table} SET revision = ?, head = ? WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? IF revision = ? AND head = ?"
                ),
                bind_shape: &[
                    "candidate_revision:BIGINT",
                    "candidate_head:BLOB",
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                    "expected_revision:BIGINT",
                    "expected_head:BLOB",
                ],
            },
        }
    }

    pub const fn create_table(&self) -> &AuthorityLocalHeadQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &AuthorityLocalHeadQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &AuthorityLocalHeadQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &AuthorityLocalHeadQuery {
        &self.compare_and_set
    }

    pub fn render_golden(&self) -> String {
        let mut out = String::new();
        for query in [
            &self.create_table,
            &self.read,
            &self.bootstrap,
            &self.compare_and_set,
        ] {
            out.push_str(&format!(
                "{:?}|{}\n{}\n",
                query.id,
                query.bind_shape.join(","),
                query.cql
            ));
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityLocalHeadBindValue {
    BigInt(i64),
    TinyInt(i8),
    Blob(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityPartition {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
}

impl AuthorityPartition {
    fn from_key(key: AuthorityTimestampKey) -> Self {
        let (authority_kind, realm_id, realm_sub_id) = match key.authority() {
            AuthorityScope::Coordinator => (1, 0, 0),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => (2, i64::from(realm_id), i64::from(realm_sub_id)),
        };
        Self {
            network_chain_id: i64::from(key.network().chain_id()),
            authority_kind,
            realm_id,
            realm_sub_id,
        }
    }

    fn values(self) -> [AuthorityLocalHeadBindValue; 4] {
        [
            AuthorityLocalHeadBindValue::BigInt(self.network_chain_id),
            AuthorityLocalHeadBindValue::TinyInt(self.authority_kind),
            AuthorityLocalHeadBindValue::BigInt(self.realm_id),
            AuthorityLocalHeadBindValue::BigInt(self.realm_sub_id),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityLocalHeadReadBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
}

impl AuthorityLocalHeadReadBinding {
    pub fn from_key(key: AuthorityTimestampKey) -> Self {
        let partition = AuthorityPartition::from_key(key);
        Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
        }
    }

    pub fn values(&self) -> Vec<AuthorityLocalHeadBindValue> {
        AuthorityPartition {
            network_chain_id: self.network_chain_id,
            authority_kind: self.authority_kind,
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
        }
        .values()
        .into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityLocalHeadBootstrapBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    candidate_revision: i64,
    candidate_head: Vec<u8>,
}

impl AuthorityLocalHeadBootstrapBinding {
    pub fn from_bootstrap<Hash: Q256BitHash>(
        bootstrap: &AuthorityLocalHeadBootstrap<Hash>,
    ) -> Self {
        let partition = AuthorityPartition::from_key(bootstrap.key());
        Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            candidate_revision: bootstrap.candidate().revision().as_i64(),
            candidate_head: bootstrap.candidate_payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<AuthorityLocalHeadBindValue> {
        let mut values = AuthorityPartition {
            network_chain_id: self.network_chain_id,
            authority_kind: self.authority_kind,
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
        }
        .values()
        .to_vec();
        values.push(AuthorityLocalHeadBindValue::BigInt(
            self.candidate_revision,
        ));
        values.push(AuthorityLocalHeadBindValue::Blob(
            self.candidate_head.clone(),
        ));
        values
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityLocalHeadCasBinding {
    candidate_revision: i64,
    candidate_head: Vec<u8>,
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    expected_revision: i64,
    expected_head: Vec<u8>,
}

impl AuthorityLocalHeadCasBinding {
    pub fn from_sealed<Hash: Q256BitHash>(
        sealed: &SealedAuthorityLocalHeadCas<Hash>,
    ) -> Self {
        let partition = AuthorityPartition::from_key(sealed.key());
        Self {
            candidate_revision: sealed.candidate().revision().as_i64(),
            candidate_head: sealed.candidate_payload().to_vec(),
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            expected_revision: sealed.expected().revision().as_i64(),
            expected_head: sealed.expected_payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<AuthorityLocalHeadBindValue> {
        vec![
            AuthorityLocalHeadBindValue::BigInt(self.candidate_revision),
            AuthorityLocalHeadBindValue::Blob(self.candidate_head.clone()),
            AuthorityLocalHeadBindValue::BigInt(self.network_chain_id),
            AuthorityLocalHeadBindValue::TinyInt(self.authority_kind),
            AuthorityLocalHeadBindValue::BigInt(self.realm_id),
            AuthorityLocalHeadBindValue::BigInt(self.realm_sub_id),
            AuthorityLocalHeadBindValue::BigInt(self.expected_revision),
            AuthorityLocalHeadBindValue::Blob(self.expected_head.clone()),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityLocalHeadLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
}

impl AuthorityLocalHeadLwtContract {
    pub const fn rf3_default() -> Self {
        Self {
            regular: Consistency::Quorum,
            serial: SerialConsistency::LocalSerial,
        }
    }

    pub const fn regular(self) -> Consistency {
        self.regular
    }

    pub const fn serial(self) -> SerialConsistency {
        self.serial
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct AuthorityLocalHeadDbRow {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    revision: Option<i64>,
    head: Option<Vec<u8>>,
}

pub struct ScyllaAuthorityLocalHeadStore {
    session: Arc<Session>,
    queries: AuthorityLocalHeadQueries,
    contract: AuthorityLocalHeadLwtContract,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaAuthorityLocalHeadStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &AuthorityLocalHeadNoTabletKeyspace,
    ) -> Result<(), AuthorityLocalHeadPrototypeError> {
        let queries = AuthorityLocalHeadQueries::new(keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: AuthorityLocalHeadNoTabletKeyspace,
    ) -> Result<Self, AuthorityLocalHeadPrototypeError> {
        let queries = AuthorityLocalHeadQueries::new(&keyspace);
        let contract = AuthorityLocalHeadLwtContract::rf3_default();
        let read = prepare_read(&session, queries.read().cql(), contract.regular()).await?;
        let bootstrap = prepare_lwt(&session, queries.bootstrap().cql(), contract).await?;
        let compare_and_set =
            prepare_lwt(&session, queries.compare_and_set().cql(), contract).await?;
        Ok(Self {
            session,
            queries,
            contract,
            read,
            bootstrap,
            compare_and_set,
        })
    }

    pub const fn queries(&self) -> &AuthorityLocalHeadQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> AuthorityLocalHeadLwtContract {
        self.contract
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        key: AuthorityTimestampKey,
    ) -> Result<AuthorityLocalHeadReadState<Hash>, AuthorityLocalHeadPrototypeError> {
        let result = self
            .session
            .execute_unpaged(&self.read, AuthorityLocalHeadReadBinding::from_key(key))
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<AuthorityLocalHeadDbRow>()
            .map_err(cql_error)?;
        match row {
            None => Ok(AuthorityLocalHeadReadState::Uninitialized),
            Some(row) => Ok(AuthorityLocalHeadReadState::Current(
                decode_db_row(key, row)?,
            )),
        }
    }

    pub async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &AuthorityLocalHeadBootstrap<Hash>,
    ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadPrototypeError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                AuthorityLocalHeadBootstrapBinding::from_bootstrap(bootstrap),
            )
            .await;
        self.finish_write(
            "bootstrap",
            execution,
            bootstrap.key(),
            bootstrap.candidate(),
            |applied, current| bootstrap.classify_lwt_observation(applied, current),
        )
        .await
    }

    pub async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        sealed: &SealedAuthorityLocalHeadCas<Hash>,
    ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadPrototypeError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                AuthorityLocalHeadCasBinding::from_sealed(sealed),
            )
            .await;
        self.finish_write(
            "compare_and_set",
            execution,
            sealed.key(),
            sealed.candidate(),
            |applied, current| sealed.classify_lwt_observation(applied, current),
        )
        .await
    }

    async fn finish_write<Hash: Q256BitHash>(
        &self,
        operation: &'static str,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: AuthorityTimestampKey,
        candidate: &StoredAuthorityLocalHead<Hash>,
        classify: impl FnOnce(
            bool,
            StoredAuthorityLocalHead<Hash>,
        ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadModelError>,
    ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadPrototypeError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = match self.read(key).await? {
                    AuthorityLocalHeadReadState::Current(current) => current,
                    AuthorityLocalHeadReadState::Uninitialized => {
                        return Err(
                            AuthorityLocalHeadPrototypeError::CurrentMissingAfterLwt {
                                operation,
                                applied,
                            },
                        );
                    }
                };
                classify(applied, current).map_err(Into::into)
            }
            Err(error) => match self.read(key).await {
                Ok(AuthorityLocalHeadReadState::Current(current))
                    if current == *candidate =>
                {
                    Ok(AuthorityLocalHeadWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(AuthorityLocalHeadPrototypeError::IndeterminateWrite {
                    operation,
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(
                    AuthorityLocalHeadPrototypeError::IndeterminateReadFailed {
                        operation,
                        execute_error: error.to_string(),
                        read_error: read_error.to_string(),
                    },
                ),
            },
        }
    }
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: AuthorityLocalHeadLwtContract,
) -> Result<PreparedStatement, AuthorityLocalHeadPrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(contract.regular());
    statement.set_serial_consistency(Some(contract.serial()));
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_read(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> Result<PreparedStatement, AuthorityLocalHeadPrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_db_row<Hash: Q256BitHash>(
    requested: AuthorityTimestampKey,
    row: AuthorityLocalHeadDbRow,
) -> Result<StoredAuthorityLocalHead<Hash>, AuthorityLocalHeadPrototypeError> {
    decode_authority_local_head_persisted_cells(
        requested,
        row.network_chain_id,
        row.authority_kind,
        row.realm_id,
        row.realm_sub_id,
        row.revision,
        row.head.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn decode_authority_local_head_persisted_cells<Hash: Q256BitHash>(
    requested: AuthorityTimestampKey,
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    revision: Option<i64>,
    head: Option<&[u8]>,
) -> Result<StoredAuthorityLocalHead<Hash>, AuthorityLocalHeadPrototypeError> {
    let expected = AuthorityPartition::from_key(requested);
    let returned = AuthorityPartition {
        network_chain_id,
        authority_kind,
        realm_id,
        realm_sub_id,
    };
    if returned != expected {
        return Err(AuthorityLocalHeadPrototypeError::SelectedPartitionMismatch);
    }
    let revision = revision.ok_or(AuthorityLocalHeadPrototypeError::MissingRevision)?;
    let head = head.ok_or(AuthorityLocalHeadPrototypeError::MissingHeadPayload)?;
    StoredAuthorityLocalHead::decode_persisted(requested, revision, head)
        .map_err(Into::into)
}

fn decode_lwt_applied(
    result: QueryResult,
) -> Result<bool, AuthorityLocalHeadPrototypeError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(AuthorityLocalHeadPrototypeError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(AuthorityLocalHeadPrototypeError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> AuthorityLocalHeadPrototypeError {
    AuthorityLocalHeadPrototypeError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityLocalHeadPrototypeError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    InvalidNoTabletKeyspace(InvalidAuthorityLocalHeadNoTabletKeyspace),
    Model(AuthorityLocalHeadModelError),
    SelectedPartitionMismatch,
    MissingRevision,
    MissingHeadPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    CurrentMissingAfterLwt {
        operation: &'static str,
        applied: bool,
    },
    IndeterminateWrite {
        operation: &'static str,
        execute_error: String,
    },
    IndeterminateReadFailed {
        operation: &'static str,
        execute_error: String,
        read_error: String,
    },
    Cql(String),
}

impl From<InvalidCqlKeyspaceName> for AuthorityLocalHeadPrototypeError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<AuthorityLocalHeadModelError> for AuthorityLocalHeadPrototypeError {
    fn from(value: AuthorityLocalHeadModelError) -> Self {
        Self::Model(value)
    }
}

impl fmt::Display for AuthorityLocalHeadPrototypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AuthorityLocalHeadPrototypeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_contract_is_single_payload_and_exact_lwt() {
        let keyspace = AuthorityLocalHeadNoTabletKeyspace::try_new("psy_d04b_nt")
            .unwrap();
        let queries = AuthorityLocalHeadQueries::new(&keyspace);
        assert!(queries.bootstrap().cql().ends_with("IF NOT EXISTS"));
        assert!(queries.compare_and_set().cql().contains(
            "IF revision = ? AND head = ?"
        ));
        assert_eq!(
            queries.compare_and_set().bind_shape(),
            [
                "candidate_revision:BIGINT",
                "candidate_head:BLOB",
                "network_chain_id:BIGINT",
                "authority_kind:TINYINT",
                "realm_id:BIGINT",
                "realm_sub_id:BIGINT",
                "expected_revision:BIGINT",
                "expected_head:BLOB",
            ]
        );
        assert_eq!(
            queries.render_golden(),
            include_str!("../../tests/golden/rollback_authority_local_head_v1.txt")
        );
    }

    #[test]
    fn ordinary_keyspace_is_rejected() {
        assert!(matches!(
            AuthorityLocalHeadNoTabletKeyspace::try_new("psy_main"),
            Err(AuthorityLocalHeadPrototypeError::InvalidNoTabletKeyspace(_))
        ));
    }
}
