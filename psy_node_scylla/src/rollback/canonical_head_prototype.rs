//! Durable Scylla adapter for the Coordinator canonical-head authority.
//!
//! C-01a built and qualified this adapter in isolation. C-01b promotes the
//! same query/binding implementation into the Coordinator-only production
//! setup while keeping Realm/Edge stores and the 32/35 state-table inventory
//! separate.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadModelError, CanonicalHeadReadState,
    CanonicalHeadWriteOutcome, NetworkId, SealedCanonicalHeadCas,
    StoredCanonicalHead,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const COORDINATOR_CANONICAL_HEAD_TABLE: &str = "coordinator_canonical_head";
/// Historical C-01a name retained for source compatibility with the qualified
/// RF=3 harness. It resolves to the production table identity.
pub const C01A_CANONICAL_HEAD_TABLE: &str = COORDINATOR_CANONICAL_HEAD_TABLE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidCanonicalHeadNoTabletKeyspace(pub String);

impl fmt::Display for InvalidCanonicalHeadNoTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical-head LWT keyspace {:?} must use the established _no_tablet or _nt suffix",
            self.0
        )
    }
}

impl Error for InvalidCanonicalHeadNoTabletKeyspace {}

/// Explicit trust boundary for a keyspace provisioned with tablets disabled.
///
/// Current production keyspaces use `_no_tablet`; recovery prototypes use
/// `_nt`. This wrapper prevents accidentally pointing the prototype at an
/// ordinary keyspace name. Deployment still owns replication configuration.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalHeadNoTabletKeyspace(CqlKeyspaceName);

impl CanonicalHeadNoTabletKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, CanonicalHeadPrototypeError> {
        let name = name.into();
        let keyspace = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(CanonicalHeadPrototypeError::InvalidNoTabletKeyspace(
                InvalidCanonicalHeadNoTabletKeyspace(name),
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
pub enum CanonicalHeadQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHeadQuery {
    id: CanonicalHeadQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl CanonicalHeadQuery {
    pub const fn id(&self) -> CanonicalHeadQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

/// Single source of CQL for prepare, execute, and golden tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHeadQueries {
    create_table: CanonicalHeadQuery,
    read: CanonicalHeadQuery,
    bootstrap: CanonicalHeadQuery,
    compare_and_set: CanonicalHeadQuery,
}

impl CanonicalHeadQueries {
    pub fn new(no_tablet_keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let qualified = format!(
            "{}.{COORDINATOR_CANONICAL_HEAD_TABLE}",
            no_tablet_keyspace.as_str()
        );
        Self {
            create_table: CanonicalHeadQuery {
                id: CanonicalHeadQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {qualified} (network_chain_id bigint PRIMARY KEY, revision bigint, canonical_ref blob)"
                ),
                bind_shape: &[],
            },
            read: CanonicalHeadQuery {
                id: CanonicalHeadQueryId::Read,
                cql: format!(
                    "SELECT network_chain_id, revision, canonical_ref FROM {qualified} WHERE network_chain_id = ?"
                ),
                bind_shape: &["network_chain_id:BIGINT"],
            },
            bootstrap: CanonicalHeadQuery {
                id: CanonicalHeadQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {qualified} (network_chain_id, revision, canonical_ref) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "candidate_revision:BIGINT",
                    "candidate_canonical_ref:BLOB",
                ],
            },
            compare_and_set: CanonicalHeadQuery {
                id: CanonicalHeadQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {qualified} SET revision = ?, canonical_ref = ? WHERE network_chain_id = ? IF revision = ? AND canonical_ref = ?"
                ),
                bind_shape: &[
                    "candidate_revision:BIGINT",
                    "candidate_canonical_ref:BLOB",
                    "network_chain_id:BIGINT",
                    "expected_revision:BIGINT",
                    "expected_canonical_ref:BLOB",
                ],
            },
        }
    }

    pub const fn create_table(&self) -> &CanonicalHeadQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &CanonicalHeadQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &CanonicalHeadQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &CanonicalHeadQuery {
        &self.compare_and_set
    }

    pub fn render_golden(&self) -> String {
        let mut rendered = String::new();
        for query in [
            &self.create_table,
            &self.read,
            &self.bootstrap,
            &self.compare_and_set,
        ] {
            rendered.push_str(&format!(
                "{:?}|{}\n{}\n",
                query.id,
                query.bind_shape.join(","),
                query.cql
            ));
        }
        rendered
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalHeadBindValue {
    BigInt(i64),
    Blob(Vec<u8>),
}

impl CanonicalHeadBindValue {
    fn render(&self) -> String {
        match self {
            Self::BigInt(value) => format!("BIGINT:{value}"),
            Self::Blob(value) => format!("BLOB:{}", hex::encode(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct CanonicalHeadReadBinding {
    network_chain_id: i64,
}

impl CanonicalHeadReadBinding {
    pub fn try_from_network(network: NetworkId) -> Result<Self, CanonicalHeadPrototypeError> {
        Ok(Self {
            network_chain_id: i64::from(network.chain_id()),
        })
    }

    pub fn values(&self) -> Vec<CanonicalHeadBindValue> {
        vec![CanonicalHeadBindValue::BigInt(self.network_chain_id)]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct CanonicalHeadBootstrapBinding {
    network_chain_id: i64,
    candidate_revision: i64,
    candidate_canonical_ref: Vec<u8>,
}

impl CanonicalHeadBootstrapBinding {
    pub fn from_bootstrap<Hash: Q256BitHash>(bootstrap: &CanonicalHeadBootstrap<Hash>) -> Self {
        Self {
            network_chain_id: i64::from(bootstrap.candidate().canonical_ref().network_id().chain_id()),
            candidate_revision: bootstrap.candidate().revision().as_i64(),
            candidate_canonical_ref: bootstrap.candidate_payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<CanonicalHeadBindValue> {
        vec![
            CanonicalHeadBindValue::BigInt(self.network_chain_id),
            CanonicalHeadBindValue::BigInt(self.candidate_revision),
            CanonicalHeadBindValue::Blob(self.candidate_canonical_ref.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct CanonicalHeadCasBinding {
    candidate_revision: i64,
    candidate_canonical_ref: Vec<u8>,
    network_chain_id: i64,
    expected_revision: i64,
    expected_canonical_ref: Vec<u8>,
}

impl CanonicalHeadCasBinding {
    pub fn from_sealed<Hash: Q256BitHash>(sealed: &SealedCanonicalHeadCas<Hash>) -> Self {
        Self {
            candidate_revision: sealed.candidate().revision().as_i64(),
            candidate_canonical_ref: sealed.candidate_payload().to_vec(),
            network_chain_id: i64::from(sealed.expected().canonical_ref().network_id().chain_id()),
            expected_revision: sealed.expected().revision().as_i64(),
            expected_canonical_ref: sealed.expected_payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<CanonicalHeadBindValue> {
        vec![
            CanonicalHeadBindValue::BigInt(self.candidate_revision),
            CanonicalHeadBindValue::Blob(self.candidate_canonical_ref.clone()),
            CanonicalHeadBindValue::BigInt(self.network_chain_id),
            CanonicalHeadBindValue::BigInt(self.expected_revision),
            CanonicalHeadBindValue::Blob(self.expected_canonical_ref.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

fn render_bind_values(values: &[CanonicalHeadBindValue]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}:{}", value.render()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalHeadLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
}

impl CanonicalHeadLwtContract {
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
struct CanonicalHeadDbRow {
    network_chain_id: i64,
    revision: Option<i64>,
    canonical_ref: Option<Vec<u8>>,
}

/// Isolated durable adapter. The raw Session remains behind this composition
/// root; write APIs accept only validated bootstrap or sealed CAS values.
pub struct ScyllaCanonicalHeadStore {
    session: Arc<Session>,
    queries: CanonicalHeadQueries,
    contract: CanonicalHeadLwtContract,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

/// Historical alias retained so the original C-01a tests continue exercising
/// the exact adapter that production now uses.
pub type CanonicalHeadPrototypeAdapter = ScyllaCanonicalHeadStore;

impl ScyllaCanonicalHeadStore {
    /// Create only the table in an already provisioned no-tablet keyspace. The
    /// adapter deliberately does not choose replication factor or deployment
    /// profile.
    pub async fn create_schema(
        session: &Session,
        no_tablet_keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), CanonicalHeadPrototypeError> {
        let queries = CanonicalHeadQueries::new(no_tablet_keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        no_tablet_keyspace: CanonicalHeadNoTabletKeyspace,
    ) -> Result<Self, CanonicalHeadPrototypeError> {
        let queries = CanonicalHeadQueries::new(&no_tablet_keyspace);
        let contract = CanonicalHeadLwtContract::rf3_default();
        let read = prepare_read(&session, queries.read().cql(), contract.regular()).await?;
        let bootstrap = prepare_lwt(&session, queries.bootstrap().cql(), contract).await?;
        let compare_and_set = prepare_lwt(&session, queries.compare_and_set().cql(), contract).await?;
        Ok(Self {
            session,
            queries,
            contract,
            read,
            bootstrap,
            compare_and_set,
        })
    }

    pub const fn queries(&self) -> &CanonicalHeadQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> CanonicalHeadLwtContract {
        self.contract
    }

    pub fn prepared_contracts(
        &self,
    ) -> [
        (Option<Consistency>, Option<SerialConsistency>);
        3
    ] {
        [
            (self.read.get_consistency(), self.read.get_serial_consistency()),
            (
                self.bootstrap.get_consistency(),
                self.bootstrap.get_serial_consistency(),
            ),
            (
                self.compare_and_set.get_consistency(),
                self.compare_and_set.get_serial_consistency(),
            ),
        ]
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
    ) -> Result<CanonicalHeadReadState<Hash>, CanonicalHeadPrototypeError> {
        let binding = CanonicalHeadReadBinding::try_from_network(network)?;
        let result = self
            .session
            .execute_unpaged(&self.read, binding)
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<CanonicalHeadDbRow>()
            .map_err(cql_error)?;
        match row {
            None => Ok(CanonicalHeadReadState::Uninitialized),
            Some(row) => Ok(CanonicalHeadReadState::Current(decode_db_row(network, row)?)),
        }
    }

    pub async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &CanonicalHeadBootstrap<Hash>,
    ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadPrototypeError> {
        let binding = CanonicalHeadBootstrapBinding::from_bootstrap(bootstrap);
        let execution = self.session.execute_unpaged(&self.bootstrap, binding).await;
        self.finish_write(
            "bootstrap",
            execution,
            bootstrap.candidate(),
            |applied, current| bootstrap.classify_lwt_observation(applied, current),
        )
        .await
    }

    pub async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        sealed: &SealedCanonicalHeadCas<Hash>,
    ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadPrototypeError> {
        let binding = CanonicalHeadCasBinding::from_sealed(sealed);
        let execution = self
            .session
            .execute_unpaged(&self.compare_and_set, binding)
            .await;
        self.finish_write(
            "compare_and_set",
            execution,
            sealed.candidate(),
            |applied, current| sealed.classify_lwt_observation(applied, current),
        )
        .await
    }

    async fn finish_write<Hash: Q256BitHash>(
        &self,
        operation: &'static str,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredCanonicalHead<Hash>,
        classify: impl FnOnce(
            bool,
            StoredCanonicalHead<Hash>,
        ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadModelError>,
    ) -> Result<CanonicalHeadWriteOutcome<Hash>, CanonicalHeadPrototypeError> {
        let network = candidate.canonical_ref().network_id();
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = match self.read(network).await? {
                    CanonicalHeadReadState::Current(current) => current,
                    CanonicalHeadReadState::Uninitialized => {
                        return Err(CanonicalHeadPrototypeError::CurrentMissingAfterLwt {
                            operation,
                            applied,
                        });
                    }
                };
                classify(applied, current).map_err(Into::into)
            }
            Err(error) => match self.read(network).await {
                Ok(CanonicalHeadReadState::Current(current)) if &current == candidate => {
                    Ok(CanonicalHeadWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(CanonicalHeadPrototypeError::IndeterminateWrite {
                    operation,
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(CanonicalHeadPrototypeError::IndeterminateReadFailed {
                    operation,
                    execute_error: error.to_string(),
                    read_error: read_error.to_string(),
                }),
            },
        }
    }
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: CanonicalHeadLwtContract,
) -> Result<PreparedStatement, CanonicalHeadPrototypeError> {
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
) -> Result<PreparedStatement, CanonicalHeadPrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_db_row<Hash: Q256BitHash>(
    requested_network: NetworkId,
    row: CanonicalHeadDbRow,
) -> Result<StoredCanonicalHead<Hash>, CanonicalHeadPrototypeError> {
    decode_canonical_head_persisted_cells(
        requested_network,
        row.network_chain_id,
        row.revision,
        row.canonical_ref.as_deref(),
    )
}

/// Decode nullable CQL cells through the same fail-closed path used by the
/// real SELECT adapter. This is a read trust boundary, not a write bypass.
pub fn decode_canonical_head_persisted_cells<Hash: Q256BitHash>(
    requested_network: NetworkId,
    network_chain_id: i64,
    revision: Option<i64>,
    canonical_ref: Option<&[u8]>,
) -> Result<StoredCanonicalHead<Hash>, CanonicalHeadPrototypeError> {
    let chain_id = u32::try_from(network_chain_id)
        .map_err(|_| CanonicalHeadPrototypeError::NetworkChainIdOutOfRange(network_chain_id))?;
    let partition_network = NetworkId::try_from_chain_id(chain_id).map_err(CanonicalHeadModelError::from)?;
    if partition_network != requested_network {
        return Err(CanonicalHeadPrototypeError::SelectedPartitionMismatch {
            requested: requested_network,
            returned: partition_network,
        });
    }
    let revision = revision.ok_or(CanonicalHeadPrototypeError::MissingRevision)?;
    let canonical_ref = canonical_ref.ok_or(CanonicalHeadPrototypeError::MissingCanonicalPayload)?;
    StoredCanonicalHead::decode_persisted(partition_network, revision, canonical_ref).map_err(Into::into)
}

fn decode_lwt_applied(result: QueryResult) -> Result<bool, CanonicalHeadPrototypeError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(CanonicalHeadPrototypeError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(CanonicalHeadPrototypeError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> CanonicalHeadPrototypeError {
    CanonicalHeadPrototypeError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalHeadPrototypeError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    InvalidNoTabletKeyspace(InvalidCanonicalHeadNoTabletKeyspace),
    Model(CanonicalHeadModelError),
    NetworkChainIdOutOfRange(i64),
    SelectedPartitionMismatch { requested: NetworkId, returned: NetworkId },
    MissingRevision,
    MissingCanonicalPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    CurrentMissingAfterLwt { operation: &'static str, applied: bool },
    IndeterminateWrite { operation: &'static str, execute_error: String },
    IndeterminateReadFailed {
        operation: &'static str,
        execute_error: String,
        read_error: String,
    },
    Cql(String),
}

impl fmt::Display for CanonicalHeadPrototypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyspace(error) => error.fmt(formatter),
            Self::InvalidNoTabletKeyspace(error) => error.fmt(formatter),
            Self::Model(error) => error.fmt(formatter),
            Self::NetworkChainIdOutOfRange(value) => write!(
                formatter,
                "canonical-head network_chain_id BIGINT is outside u32 range: {value}"
            ),
            Self::SelectedPartitionMismatch { requested, returned } => write!(
                formatter,
                "canonical-head SELECT requested network {:?} but returned {:?}",
                requested, returned
            ),
            Self::MissingRevision => formatter.write_str("canonical-head row has null revision"),
            Self::MissingCanonicalPayload => {
                formatter.write_str("canonical-head row has null canonical_ref")
            }
            Self::MissingAppliedColumn => {
                formatter.write_str("canonical-head LWT result has no [applied] column")
            }
            Self::InvalidAppliedColumn => {
                formatter.write_str("canonical-head LWT [applied] column is null or not boolean")
            }
            Self::CurrentMissingAfterLwt { operation, applied } => write!(
                formatter,
                "canonical-head {operation} LWT returned applied={applied}, but the durable row is missing"
            ),
            Self::IndeterminateWrite {
                operation,
                execute_error,
            } => write!(
                formatter,
                "canonical-head {operation} result is indeterminate; retry the same sealed intent: {execute_error}"
            ),
            Self::IndeterminateReadFailed {
                operation,
                execute_error,
                read_error,
            } => write!(
                formatter,
                "canonical-head {operation} and reconciliation read both failed: execute={execute_error}; read={read_error}"
            ),
            Self::Cql(error) => write!(formatter, "canonical-head Scylla prototype failed: {error}"),
        }
    }
}

impl Error for CanonicalHeadPrototypeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidKeyspace(error) => Some(error),
            Self::InvalidNoTabletKeyspace(error) => Some(error),
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvalidCqlKeyspaceName> for CanonicalHeadPrototypeError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<CanonicalHeadModelError> for CanonicalHeadPrototypeError {
    fn from(value: CanonicalHeadModelError) -> Self {
        Self::Model(value)
    }
}
