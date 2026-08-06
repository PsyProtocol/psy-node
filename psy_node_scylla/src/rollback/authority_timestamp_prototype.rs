//! Isolated D-04a durable authority intent/timestamp allocator prototype.
//!
//! The adapter owns one LWT row per network/authority. It is deliberately not
//! registered by production setup and accepts only driver-independent sealed
//! bootstrap/reservation/completion values.

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::store::authority_commit::{
    AuthorityCommitModelError, AuthorityScope, AuthorityTimestampBootstrap,
    AuthorityTimestampKey, AuthorityTimestampReadState,
    AuthorityTimestampWriteOutcome, SealedAuthorityTimestampCompletion,
    SealedAuthorityTimestampReservation, StoredAuthorityTimestampState,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const D04A_AUTHORITY_TIMESTAMP_TABLE: &str =
    "d04a_authority_timestamp_intent";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidAuthorityTimestampNoTabletKeyspace(pub String);

impl fmt::Display for InvalidAuthorityTimestampNoTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authority timestamp LWT keyspace {:?} must end in _no_tablet or _nt",
            self.0
        )
    }
}

impl Error for InvalidAuthorityTimestampNoTabletKeyspace {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityTimestampNoTabletKeyspace(CqlKeyspaceName);

impl AuthorityTimestampNoTabletKeyspace {
    pub fn try_new(
        name: impl Into<String>,
    ) -> Result<Self, AuthorityTimestampPrototypeError> {
        let name = name.into();
        let keyspace = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(AuthorityTimestampPrototypeError::InvalidNoTabletKeyspace(
                InvalidAuthorityTimestampNoTabletKeyspace(name),
            ));
        }
        Ok(Self(keyspace))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityTimestampQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityTimestampQuery {
    id: AuthorityTimestampQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl AuthorityTimestampQuery {
    pub const fn id(&self) -> AuthorityTimestampQueryId {
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
pub struct AuthorityTimestampQueries {
    create_table: AuthorityTimestampQuery,
    read: AuthorityTimestampQuery,
    bootstrap: AuthorityTimestampQuery,
    compare_and_set: AuthorityTimestampQuery,
}

impl AuthorityTimestampQueries {
    pub fn new(keyspace: &AuthorityTimestampNoTabletKeyspace) -> Self {
        let qualified = format!(
            "{}.{D04A_AUTHORITY_TIMESTAMP_TABLE}",
            keyspace.as_str()
        );
        let partition =
            "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create_table: AuthorityTimestampQuery {
                id: AuthorityTimestampQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {qualified} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id bigint, revision bigint, state blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
                ),
                bind_shape: &[],
            },
            read: AuthorityTimestampQuery {
                id: AuthorityTimestampQueryId::Read,
                cql: format!(
                    "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, state FROM {qualified} WHERE {partition}"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                ],
            },
            bootstrap: AuthorityTimestampQuery {
                id: AuthorityTimestampQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {qualified} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, state) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                    "candidate_revision:BIGINT",
                    "candidate_state:BLOB",
                ],
            },
            compare_and_set: AuthorityTimestampQuery {
                id: AuthorityTimestampQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {qualified} SET revision = ?, state = ? WHERE {partition} IF revision = ? AND state = ?"
                ),
                bind_shape: &[
                    "candidate_revision:BIGINT",
                    "candidate_state:BLOB",
                    "network_chain_id:BIGINT",
                    "authority_kind:TINYINT",
                    "realm_id:BIGINT",
                    "realm_sub_id:BIGINT",
                    "expected_revision:BIGINT",
                    "expected_state:BLOB",
                ],
            },
        }
    }

    pub const fn create_table(&self) -> &AuthorityTimestampQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &AuthorityTimestampQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &AuthorityTimestampQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &AuthorityTimestampQuery {
        &self.compare_and_set
    }

    pub fn render_golden(&self) -> String {
        [
            &self.create_table,
            &self.read,
            &self.bootstrap,
            &self.compare_and_set,
        ]
        .into_iter()
        .map(|query| {
            format!(
                "{:?}|{}\n{}\n",
                query.id,
                query.bind_shape.join(","),
                query.cql
            )
        })
        .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityTimestampBindValue {
    TinyInt(i8),
    BigInt(i64),
    Blob(Vec<u8>),
}

impl AuthorityTimestampBindValue {
    fn render(&self) -> String {
        match self {
            Self::TinyInt(value) => format!("TINYINT:{value}"),
            Self::BigInt(value) => format!("BIGINT:{value}"),
            Self::Blob(value) => format!("BLOB:{}", hex::encode(value)),
        }
    }
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

    fn values(self) -> Vec<AuthorityTimestampBindValue> {
        vec![
            AuthorityTimestampBindValue::BigInt(self.network_chain_id),
            AuthorityTimestampBindValue::TinyInt(self.authority_kind),
            AuthorityTimestampBindValue::BigInt(self.realm_id),
            AuthorityTimestampBindValue::BigInt(self.realm_sub_id),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityTimestampReadBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
}

impl AuthorityTimestampReadBinding {
    pub fn from_key(key: AuthorityTimestampKey) -> Self {
        let partition = AuthorityPartition::from_key(key);
        Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
        }
    }

    pub fn values(&self) -> Vec<AuthorityTimestampBindValue> {
        AuthorityPartition {
            network_chain_id: self.network_chain_id,
            authority_kind: self.authority_kind,
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
        }
        .values()
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityTimestampBootstrapBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    candidate_revision: i64,
    candidate_state: Vec<u8>,
}

impl AuthorityTimestampBootstrapBinding {
    pub fn from_bootstrap(bootstrap: AuthorityTimestampBootstrap) -> Self {
        let partition = AuthorityPartition::from_key(bootstrap.key());
        let candidate = bootstrap.candidate();
        Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            candidate_revision: candidate.revision().as_i64(),
            candidate_state: candidate.encode_canonical().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<AuthorityTimestampBindValue> {
        vec![
            AuthorityTimestampBindValue::BigInt(self.network_chain_id),
            AuthorityTimestampBindValue::TinyInt(self.authority_kind),
            AuthorityTimestampBindValue::BigInt(self.realm_id),
            AuthorityTimestampBindValue::BigInt(self.realm_sub_id),
            AuthorityTimestampBindValue::BigInt(self.candidate_revision),
            AuthorityTimestampBindValue::Blob(self.candidate_state.clone()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct AuthorityTimestampCasBinding {
    candidate_revision: i64,
    candidate_state: Vec<u8>,
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    expected_revision: i64,
    expected_state: Vec<u8>,
}

impl AuthorityTimestampCasBinding {
    pub fn from_reservation(sealed: SealedAuthorityTimestampReservation) -> Self {
        Self::from_parts(sealed.key(), sealed.expected(), sealed.candidate())
    }

    pub fn from_completion(sealed: SealedAuthorityTimestampCompletion) -> Self {
        Self::from_parts(sealed.key(), sealed.expected(), sealed.candidate())
    }

    fn from_parts(
        key: AuthorityTimestampKey,
        expected: StoredAuthorityTimestampState,
        candidate: StoredAuthorityTimestampState,
    ) -> Self {
        let partition = AuthorityPartition::from_key(key);
        Self {
            candidate_revision: candidate.revision().as_i64(),
            candidate_state: candidate.encode_canonical().to_vec(),
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            expected_revision: expected.revision().as_i64(),
            expected_state: expected.encode_canonical().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<AuthorityTimestampBindValue> {
        vec![
            AuthorityTimestampBindValue::BigInt(self.candidate_revision),
            AuthorityTimestampBindValue::Blob(self.candidate_state.clone()),
            AuthorityTimestampBindValue::BigInt(self.network_chain_id),
            AuthorityTimestampBindValue::TinyInt(self.authority_kind),
            AuthorityTimestampBindValue::BigInt(self.realm_id),
            AuthorityTimestampBindValue::BigInt(self.realm_sub_id),
            AuthorityTimestampBindValue::BigInt(self.expected_revision),
            AuthorityTimestampBindValue::Blob(self.expected_state.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

fn render_bind_values(values: &[AuthorityTimestampBindValue]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}:{}", value.render()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityTimestampLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
    read: Consistency,
}

impl AuthorityTimestampLwtContract {
    pub const fn rf3_default() -> Self {
        Self {
            regular: Consistency::Quorum,
            serial: SerialConsistency::LocalSerial,
            // LOCAL_SERIAL belongs on the Paxos/LWT statement. A plain
            // SELECT uses a regular consistency level; QUORUM is sufficient
            // after an applied LWT and remains fail-closed for an
            // indeterminate response because the caller retries the exact
            // sealed intent rather than allocating a replacement timestamp.
            read: Consistency::Quorum,
        }
    }

    pub const fn regular(self) -> Consistency {
        self.regular
    }

    pub const fn serial(self) -> SerialConsistency {
        self.serial
    }

    pub const fn read(self) -> Consistency {
        self.read
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct AuthorityTimestampDbRow {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    revision: Option<i64>,
    state: Option<Vec<u8>>,
}

pub struct ScyllaAuthorityTimestampStore {
    session: Arc<Session>,
    queries: AuthorityTimestampQueries,
    contract: AuthorityTimestampLwtContract,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaAuthorityTimestampStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &AuthorityTimestampNoTabletKeyspace,
    ) -> Result<(), AuthorityTimestampPrototypeError> {
        let queries = AuthorityTimestampQueries::new(keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: AuthorityTimestampNoTabletKeyspace,
    ) -> Result<Self, AuthorityTimestampPrototypeError> {
        let queries = AuthorityTimestampQueries::new(&keyspace);
        let contract = AuthorityTimestampLwtContract::rf3_default();
        let read = prepare_read(&session, queries.read().cql(), contract.read()).await?;
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

    pub const fn queries(&self) -> &AuthorityTimestampQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> AuthorityTimestampLwtContract {
        self.contract
    }

    pub async fn read(
        &self,
        key: AuthorityTimestampKey,
    ) -> Result<AuthorityTimestampReadState, AuthorityTimestampPrototypeError> {
        let result = self
            .session
            .execute_unpaged(&self.read, AuthorityTimestampReadBinding::from_key(key))
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<AuthorityTimestampDbRow>()
            .map_err(cql_error)?;
        match row {
            None => Ok(AuthorityTimestampReadState::Uninitialized),
            Some(row) => Ok(AuthorityTimestampReadState::Current(decode_db_row(
                key, row,
            )?)),
        }
    }

    pub async fn bootstrap(
        &self,
        bootstrap: AuthorityTimestampBootstrap,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityTimestampPrototypeError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                AuthorityTimestampBootstrapBinding::from_bootstrap(bootstrap),
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

    pub async fn reserve(
        &self,
        sealed: SealedAuthorityTimestampReservation,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityTimestampPrototypeError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                AuthorityTimestampCasBinding::from_reservation(sealed),
            )
            .await;
        self.finish_write(
            "reserve",
            execution,
            sealed.key(),
            sealed.candidate(),
            |applied, current| sealed.classify_lwt_observation(applied, current),
        )
        .await
    }

    pub async fn complete(
        &self,
        sealed: SealedAuthorityTimestampCompletion,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityTimestampPrototypeError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                AuthorityTimestampCasBinding::from_completion(sealed),
            )
            .await;
        self.finish_write(
            "complete",
            execution,
            sealed.key(),
            sealed.candidate(),
            |applied, current| sealed.classify_lwt_observation(applied, current),
        )
        .await
    }

    async fn finish_write(
        &self,
        operation: &'static str,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: AuthorityTimestampKey,
        candidate: StoredAuthorityTimestampState,
        classify: impl FnOnce(
            bool,
            StoredAuthorityTimestampState,
        ) -> Result<AuthorityTimestampWriteOutcome, AuthorityCommitModelError>,
    ) -> Result<AuthorityTimestampWriteOutcome, AuthorityTimestampPrototypeError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = match self.read(key).await? {
                    AuthorityTimestampReadState::Current(current) => current,
                    AuthorityTimestampReadState::Uninitialized => {
                        return Err(
                            AuthorityTimestampPrototypeError::CurrentMissingAfterLwt {
                                operation,
                                applied,
                            },
                        );
                    }
                };
                classify(applied, current).map_err(Into::into)
            }
            Err(error) => match self.read(key).await {
                Ok(AuthorityTimestampReadState::Current(current)) if current == candidate => {
                    Ok(AuthorityTimestampWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(AuthorityTimestampPrototypeError::IndeterminateWrite {
                    operation,
                    execute_error: error.to_string(),
                }),
                Err(read_error) => {
                    Err(AuthorityTimestampPrototypeError::IndeterminateReadFailed {
                        operation,
                        execute_error: error.to_string(),
                        read_error: read_error.to_string(),
                    })
                }
            },
        }
    }
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: AuthorityTimestampLwtContract,
) -> Result<PreparedStatement, AuthorityTimestampPrototypeError> {
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
) -> Result<PreparedStatement, AuthorityTimestampPrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_db_row(
    requested: AuthorityTimestampKey,
    row: AuthorityTimestampDbRow,
) -> Result<StoredAuthorityTimestampState, AuthorityTimestampPrototypeError> {
    decode_authority_timestamp_persisted_cells(
        requested,
        row.network_chain_id,
        row.authority_kind,
        row.realm_id,
        row.realm_sub_id,
        row.revision,
        row.state.as_deref(),
    )
}

pub fn decode_authority_timestamp_persisted_cells(
    requested: AuthorityTimestampKey,
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    revision: Option<i64>,
    state: Option<&[u8]>,
) -> Result<StoredAuthorityTimestampState, AuthorityTimestampPrototypeError> {
    let expected = AuthorityPartition::from_key(requested);
    let returned = AuthorityPartition {
        network_chain_id,
        authority_kind,
        realm_id,
        realm_sub_id,
    };
    if returned != expected {
        return Err(AuthorityTimestampPrototypeError::SelectedPartitionMismatch {
            expected: (
                expected.network_chain_id,
                expected.authority_kind,
                expected.realm_id,
                expected.realm_sub_id,
            ),
            returned: (
                returned.network_chain_id,
                returned.authority_kind,
                returned.realm_id,
                returned.realm_sub_id,
            ),
        });
    }
    let revision = revision.ok_or(AuthorityTimestampPrototypeError::MissingRevision)?;
    let state = state.ok_or(AuthorityTimestampPrototypeError::MissingStatePayload)?;
    StoredAuthorityTimestampState::decode_persisted(revision, state).map_err(Into::into)
}

fn decode_lwt_applied(
    result: QueryResult,
) -> Result<bool, AuthorityTimestampPrototypeError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(AuthorityTimestampPrototypeError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(AuthorityTimestampPrototypeError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> AuthorityTimestampPrototypeError {
    AuthorityTimestampPrototypeError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityTimestampPrototypeError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    InvalidNoTabletKeyspace(InvalidAuthorityTimestampNoTabletKeyspace),
    Model(AuthorityCommitModelError),
    SelectedPartitionMismatch {
        expected: (i64, i8, i64, i64),
        returned: (i64, i8, i64, i64),
    },
    MissingRevision,
    MissingStatePayload,
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

impl fmt::Display for AuthorityTimestampPrototypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyspace(error) => error.fmt(formatter),
            Self::InvalidNoTabletKeyspace(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
            Self::SelectedPartitionMismatch { expected, returned } => write!(
                formatter,
                "authority timestamp SELECT partition mismatch: expected {expected:?}, returned {returned:?}"
            ),
            Self::MissingRevision => {
                formatter.write_str("authority timestamp row has null revision")
            }
            Self::MissingStatePayload => {
                formatter.write_str("authority timestamp row has null state payload")
            }
            Self::MissingAppliedColumn => {
                formatter.write_str("authority timestamp LWT result has no [applied] column")
            }
            Self::InvalidAppliedColumn => formatter.write_str(
                "authority timestamp LWT [applied] column is null or not boolean",
            ),
            Self::CurrentMissingAfterLwt { operation, applied } => write!(
                formatter,
                "authority timestamp {operation} returned applied={applied}, but the row is missing"
            ),
            Self::IndeterminateWrite {
                operation,
                execute_error,
            } => write!(
                formatter,
                "authority timestamp {operation} is indeterminate; retry the same sealed operation: {execute_error}"
            ),
            Self::IndeterminateReadFailed {
                operation,
                execute_error,
                read_error,
            } => write!(
                formatter,
                "authority timestamp {operation} and reconciliation read failed: execute={execute_error}; read={read_error}"
            ),
            Self::Cql(error) => {
                write!(formatter, "authority timestamp Scylla prototype failed: {error}")
            }
        }
    }
}

impl Error for AuthorityTimestampPrototypeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidKeyspace(error) => Some(error),
            Self::InvalidNoTabletKeyspace(error) => Some(error),
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvalidCqlKeyspaceName> for AuthorityTimestampPrototypeError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<AuthorityCommitModelError> for AuthorityTimestampPrototypeError {
    fn from(value: AuthorityCommitModelError) -> Self {
        Self::Model(value)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use psy_data::protocol::canonical_chain::NetworkId;
    use psy_node_core::store::{
        authority_commit::{
            AuthorityClockSampleUs, AuthorityCommitIntentDigest,
            AuthorityTimestampBootstrapReason,
        },
        timestamp::CommitWriteTimestampUs,
    };

    use super::*;

    fn key() -> AuthorityTimestampKey {
        AuthorityTimestampKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
        )
    }

    fn timestamp(value: i64) -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
    }

    fn digest(value: u8) -> AuthorityCommitIntentDigest {
        AuthorityCommitIntentDigest::from_sealed_commit_digest([value; 32])
    }

    fn bootstrap() -> AuthorityTimestampBootstrap {
        AuthorityTimestampBootstrap::new(
            key(),
            timestamp(100),
            AuthorityTimestampBootstrapReason::GenesisNative,
        )
    }

    fn reservation(value: u8) -> SealedAuthorityTimestampReservation {
        bootstrap()
            .candidate()
            .seal_reservation(
                key(),
                digest(value),
                AuthorityClockSampleUs::try_from_i128(200).unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn query_golden_uses_one_composite_partition_and_full_lwt_compare() {
        let keyspace = AuthorityTimestampNoTabletKeyspace::try_new("psy_local_no_tablet")
            .unwrap();
        let queries = AuthorityTimestampQueries::new(&keyspace);
        assert!(queries.bootstrap().cql().ends_with("IF NOT EXISTS"));
        assert!(queries.compare_and_set().cql().contains(
            "IF revision = ? AND state = ?"
        ));
        assert!(queries.compare_and_set().cql().contains(
            "WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
        ));
        assert_eq!(queries.compare_and_set().bind_shape().len(), 8);
        assert_eq!(
            queries.render_golden(),
            AuthorityTimestampQueries::new(&keyspace).render_golden()
        );
    }

    #[test]
    fn no_tablet_keyspace_is_mandatory() {
        assert!(AuthorityTimestampNoTabletKeyspace::try_new("psy_local_no_tablet").is_ok());
        assert!(AuthorityTimestampNoTabletKeyspace::try_new("psy_recovery_nt").is_ok());
        assert!(matches!(
            AuthorityTimestampNoTabletKeyspace::try_new("psy_local"),
            Err(AuthorityTimestampPrototypeError::InvalidNoTabletKeyspace(_))
        ));
    }

    #[test]
    fn lwt_and_reconciliation_consistency_are_explicit() {
        let contract = AuthorityTimestampLwtContract::rf3_default();
        assert_eq!(contract.regular(), Consistency::Quorum);
        assert_eq!(contract.serial(), SerialConsistency::LocalSerial);
        assert_eq!(contract.read(), Consistency::Quorum);
    }

    #[test]
    fn partition_and_cas_bind_order_are_stable() {
        let read = AuthorityTimestampReadBinding::from_key(key());
        assert_eq!(
            read.render_golden(),
            "0:BIGINT:1337\n1:TINYINT:2\n2:BIGINT:7\n3:BIGINT:2"
        );

        let sealed = reservation(1);
        let binding = AuthorityTimestampCasBinding::from_reservation(sealed);
        let values = binding.values();
        assert_eq!(values.len(), 8);
        assert_eq!(values[0], AuthorityTimestampBindValue::BigInt(1));
        assert_eq!(values[2], AuthorityTimestampBindValue::BigInt(1337));
        assert_eq!(values[3], AuthorityTimestampBindValue::TinyInt(2));
        assert_eq!(values[6], AuthorityTimestampBindValue::BigInt(0));
        assert_eq!(
            binding.render_golden(),
            AuthorityTimestampCasBinding::from_reservation(sealed).render_golden()
        );
    }

    #[test]
    fn coordinator_partition_is_canonical_zero_scope() {
        let coordinator = AuthorityTimestampKey::new(
            NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
            AuthorityScope::Coordinator,
        );
        assert_eq!(
            AuthorityTimestampReadBinding::from_key(coordinator).values(),
            vec![
                AuthorityTimestampBindValue::BigInt(1_769_567_056),
                AuthorityTimestampBindValue::TinyInt(1),
                AuthorityTimestampBindValue::BigInt(0),
                AuthorityTimestampBindValue::BigInt(0),
            ]
        );
    }

    #[test]
    fn persisted_row_checks_partition_and_nullable_cells() {
        let state = bootstrap().candidate();
        let bytes = state.encode_canonical();
        assert_eq!(
            decode_authority_timestamp_persisted_cells(
                key(),
                1337,
                2,
                7,
                2,
                Some(0),
                Some(&bytes),
            )
            .unwrap(),
            state
        );
        assert!(matches!(
            decode_authority_timestamp_persisted_cells(
                key(),
                1337,
                2,
                8,
                2,
                Some(0),
                Some(&bytes),
            ),
            Err(AuthorityTimestampPrototypeError::SelectedPartitionMismatch { .. })
        ));
        assert_eq!(
            decode_authority_timestamp_persisted_cells(
                key(), 1337, 2, 7, 2, None, Some(&bytes)
            ),
            Err(AuthorityTimestampPrototypeError::MissingRevision)
        );
        assert_eq!(
            decode_authority_timestamp_persisted_cells(
                key(),
                1337,
                2,
                7,
                2,
                Some(0),
                None,
            ),
            Err(AuthorityTimestampPrototypeError::MissingStatePayload)
        );
    }

    #[tokio::test]
    async fn concurrent_reservations_have_one_expected_state_winner() {
        let current = Arc::new(Mutex::new(bootstrap().candidate()));
        let mut tasks = Vec::new();
        for value in 1..=64u8 {
            let current = Arc::clone(&current);
            tasks.push(tokio::spawn(async move {
                let sealed = bootstrap()
                    .candidate()
                    .seal_reservation(
                        key(),
                        digest(value),
                        AuthorityClockSampleUs::try_from_i128(200 + i128::from(value))
                            .unwrap(),
                    )
                    .unwrap();
                let mut current = current.lock().unwrap();
                if *current == sealed.expected() {
                    *current = sealed.candidate();
                    sealed
                        .classify_lwt_observation(true, *current)
                        .unwrap()
                } else {
                    sealed
                        .classify_lwt_observation(false, *current)
                        .unwrap()
                }
            }));
        }
        let mut applied = 0;
        let mut conflicts = 0;
        for task in tasks {
            match task.await.unwrap() {
                AuthorityTimestampWriteOutcome::Applied(_) => applied += 1,
                AuthorityTimestampWriteOutcome::Conflict(_) => conflicts += 1,
                AuthorityTimestampWriteOutcome::Idempotent(_) => {
                    panic!("distinct intents cannot be idempotent")
                }
            }
        }
        assert_eq!((applied, conflicts), (1, 63));
    }

    #[test]
    fn exact_retry_and_completion_response_loss_are_idempotent() {
        let sealed = reservation(1);
        assert_eq!(
            sealed
                .classify_lwt_observation(false, sealed.candidate())
                .unwrap(),
            AuthorityTimestampWriteOutcome::Idempotent(sealed.candidate())
        );
        let completion = sealed
            .candidate()
            .seal_completion(key(), sealed.lease())
            .unwrap();
        assert_eq!(
            completion
                .classify_lwt_observation(false, completion.candidate())
                .unwrap(),
            AuthorityTimestampWriteOutcome::Idempotent(completion.candidate())
        );
    }

    #[test]
    fn prototype_is_not_registered_by_production_setup() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(D04A_AUTHORITY_TIMESTAMP_TABLE));
    }
}
