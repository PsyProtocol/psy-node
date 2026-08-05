//! Durable no-tablet single-slot inbox for Processor-bound rollback admission.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::canonical_head::NetworkId;
use psy_node_core::store::rollback_admission::{
    RollbackAdmissionCodecError, RollbackAdmissionSlotBootstrap,
    RollbackAdmissionSlotReadState, RollbackAdmissionSlotWriteOutcome,
    SealedRollbackAdmissionSlotCas, StoredRollbackAdmissionSlot,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::CanonicalHeadNoTabletKeyspace;

pub const COORDINATOR_ROLLBACK_ADMISSION_TABLE: &str =
    "coordinator_rollback_admission_inbox";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RollbackAdmissionQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackAdmissionQuery {
    id: RollbackAdmissionQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl RollbackAdmissionQuery {
    pub const fn id(&self) -> RollbackAdmissionQueryId {
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
pub struct RollbackAdmissionQueries {
    create_table: RollbackAdmissionQuery,
    read: RollbackAdmissionQuery,
    bootstrap: RollbackAdmissionQuery,
    compare_and_set: RollbackAdmissionQuery,
}

impl RollbackAdmissionQueries {
    pub fn new(keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let qualified = format!(
            "{}.{COORDINATOR_ROLLBACK_ADMISSION_TABLE}",
            keyspace.as_str()
        );
        Self {
            create_table: RollbackAdmissionQuery {
                id: RollbackAdmissionQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {qualified} (network_chain_id bigint PRIMARY KEY, revision bigint, slot blob)"
                ),
                bind_shape: &[],
            },
            read: RollbackAdmissionQuery {
                id: RollbackAdmissionQueryId::Read,
                cql: format!(
                    "SELECT network_chain_id, revision, slot FROM {qualified} WHERE network_chain_id = ?"
                ),
                bind_shape: &["network_chain_id:BIGINT"],
            },
            bootstrap: RollbackAdmissionQuery {
                id: RollbackAdmissionQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {qualified} (network_chain_id, revision, slot) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "network_chain_id:BIGINT",
                    "candidate_revision:BIGINT",
                    "candidate_slot:BLOB",
                ],
            },
            compare_and_set: RollbackAdmissionQuery {
                id: RollbackAdmissionQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {qualified} SET revision = ?, slot = ? WHERE network_chain_id = ? IF revision = ? AND slot = ?"
                ),
                bind_shape: &[
                    "candidate_revision:BIGINT",
                    "candidate_slot:BLOB",
                    "network_chain_id:BIGINT",
                    "expected_revision:BIGINT",
                    "expected_slot:BLOB",
                ],
            },
        }
    }

    pub const fn create_table(&self) -> &RollbackAdmissionQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &RollbackAdmissionQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &RollbackAdmissionQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &RollbackAdmissionQuery {
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

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct RollbackAdmissionReadBinding {
    network_chain_id: i64,
}

impl RollbackAdmissionReadBinding {
    pub fn from_network(network: NetworkId) -> Self {
        Self {
            network_chain_id: i64::from(network.chain_id()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct RollbackAdmissionBootstrapBinding {
    network_chain_id: i64,
    candidate_revision: i64,
    candidate_slot: Vec<u8>,
}

impl RollbackAdmissionBootstrapBinding {
    pub fn from_bootstrap<Hash: Q256BitHash>(
        bootstrap: &RollbackAdmissionSlotBootstrap<Hash>,
    ) -> Self {
        Self {
            network_chain_id: i64::from(bootstrap.network().chain_id()),
            candidate_revision: bootstrap.candidate().revision().as_i64(),
            candidate_slot: bootstrap.candidate_payload().to_vec(),
        }
    }

    pub fn golden_values(&self) -> Vec<String> {
        vec![
            format!("BIGINT:{}", self.network_chain_id),
            format!("BIGINT:{}", self.candidate_revision),
            format!("BLOB:{}", hex::encode(&self.candidate_slot)),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct RollbackAdmissionCasBinding {
    candidate_revision: i64,
    candidate_slot: Vec<u8>,
    network_chain_id: i64,
    expected_revision: i64,
    expected_slot: Vec<u8>,
}

impl RollbackAdmissionCasBinding {
    pub fn from_sealed<Hash: Q256BitHash>(
        sealed: &SealedRollbackAdmissionSlotCas<Hash>,
    ) -> Self {
        Self {
            candidate_revision: sealed.candidate().revision().as_i64(),
            candidate_slot: sealed.candidate_payload().to_vec(),
            network_chain_id: i64::from(sealed.network().chain_id()),
            expected_revision: sealed.expected().revision().as_i64(),
            expected_slot: sealed.expected_payload().to_vec(),
        }
    }

    pub fn golden_values(&self) -> Vec<String> {
        vec![
            format!("BIGINT:{}", self.candidate_revision),
            format!("BLOB:{}", hex::encode(&self.candidate_slot)),
            format!("BIGINT:{}", self.network_chain_id),
            format!("BIGINT:{}", self.expected_revision),
            format!("BLOB:{}", hex::encode(&self.expected_slot)),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdmissionLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
}

impl RollbackAdmissionLwtContract {
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
struct RollbackAdmissionDbRow {
    network_chain_id: i64,
    revision: Option<i64>,
    slot: Option<Vec<u8>>,
}

pub struct ScyllaRollbackAdmissionStore {
    session: Arc<Session>,
    queries: RollbackAdmissionQueries,
    contract: RollbackAdmissionLwtContract,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaRollbackAdmissionStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), RollbackAdmissionScyllaError> {
        let queries = RollbackAdmissionQueries::new(keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: CanonicalHeadNoTabletKeyspace,
    ) -> Result<Self, RollbackAdmissionScyllaError> {
        let queries = RollbackAdmissionQueries::new(&keyspace);
        let contract = RollbackAdmissionLwtContract::rf3_default();
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

    pub const fn queries(&self) -> &RollbackAdmissionQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> RollbackAdmissionLwtContract {
        self.contract
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
    ) -> Result<RollbackAdmissionSlotReadState<Hash>, RollbackAdmissionScyllaError> {
        let result = self
            .session
            .execute_unpaged(&self.read, RollbackAdmissionReadBinding::from_network(network))
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<RollbackAdmissionDbRow>()
            .map_err(cql_error)?;
        match row {
            None => Ok(RollbackAdmissionSlotReadState::Uninitialized),
            Some(row) => Ok(RollbackAdmissionSlotReadState::Current(decode_db_row(
                network, row,
            )?)),
        }
    }

    pub async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &RollbackAdmissionSlotBootstrap<Hash>,
    ) -> Result<RollbackAdmissionSlotWriteOutcome<Hash>, RollbackAdmissionScyllaError> {
        let binding = RollbackAdmissionBootstrapBinding::from_bootstrap(bootstrap);
        let execution = self.session.execute_unpaged(&self.bootstrap, binding).await;
        self.finish_write(
            "bootstrap",
            execution,
            bootstrap.network(),
            bootstrap.candidate(),
            |applied, current| bootstrap.classify_lwt_observation(applied, current),
        )
        .await
    }

    pub async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        sealed: &SealedRollbackAdmissionSlotCas<Hash>,
    ) -> Result<RollbackAdmissionSlotWriteOutcome<Hash>, RollbackAdmissionScyllaError> {
        let binding = RollbackAdmissionCasBinding::from_sealed(sealed);
        let execution = self
            .session
            .execute_unpaged(&self.compare_and_set, binding)
            .await;
        self.finish_write(
            "compare_and_set",
            execution,
            sealed.network(),
            sealed.candidate(),
            |applied, current| sealed.classify_lwt_observation(applied, current),
        )
        .await
    }

    async fn finish_write<Hash: Q256BitHash>(
        &self,
        operation: &'static str,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        network: NetworkId,
        candidate: &StoredRollbackAdmissionSlot<Hash>,
        classify: impl FnOnce(
            bool,
            StoredRollbackAdmissionSlot<Hash>,
        ) -> RollbackAdmissionSlotWriteOutcome<Hash>,
    ) -> Result<RollbackAdmissionSlotWriteOutcome<Hash>, RollbackAdmissionScyllaError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = match self.read(network).await? {
                    RollbackAdmissionSlotReadState::Current(current) => current,
                    RollbackAdmissionSlotReadState::Uninitialized => {
                        return Err(RollbackAdmissionScyllaError::CurrentMissingAfterLwt {
                            operation,
                            applied,
                        });
                    }
                };
                Ok(classify(applied, current))
            }
            Err(error) => match self.read(network).await {
                Ok(RollbackAdmissionSlotReadState::Current(current))
                    if &current == candidate =>
                {
                    Ok(RollbackAdmissionSlotWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(RollbackAdmissionScyllaError::IndeterminateWrite {
                    operation,
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(RollbackAdmissionScyllaError::IndeterminateReadFailed {
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
    contract: RollbackAdmissionLwtContract,
) -> Result<PreparedStatement, RollbackAdmissionScyllaError> {
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
) -> Result<PreparedStatement, RollbackAdmissionScyllaError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_db_row<Hash: Q256BitHash>(
    requested_network: NetworkId,
    row: RollbackAdmissionDbRow,
) -> Result<StoredRollbackAdmissionSlot<Hash>, RollbackAdmissionScyllaError> {
    decode_rollback_admission_persisted_cells(
        requested_network,
        row.network_chain_id,
        row.revision,
        row.slot.as_deref(),
    )
}

/// Fail-closed trust boundary shared by the real SELECT path and contract
/// tests. Null/malformed cells are never interpreted as an empty inbox.
pub fn decode_rollback_admission_persisted_cells<Hash: Q256BitHash>(
    requested_network: NetworkId,
    network_chain_id: i64,
    revision: Option<i64>,
    slot: Option<&[u8]>,
) -> Result<StoredRollbackAdmissionSlot<Hash>, RollbackAdmissionScyllaError> {
    let chain_id = u32::try_from(network_chain_id).map_err(|_| {
        RollbackAdmissionScyllaError::NetworkChainIdOutOfRange(network_chain_id)
    })?;
    let partition_network = NetworkId::try_from_chain_id(chain_id)
        .map_err(|error| RollbackAdmissionScyllaError::Codec(error.to_string()))?;
    if partition_network != requested_network {
        return Err(RollbackAdmissionScyllaError::SelectedPartitionMismatch {
            requested: requested_network,
            returned: partition_network,
        });
    }
    let revision = revision.ok_or(RollbackAdmissionScyllaError::MissingRevision)?;
    let slot = slot.ok_or(RollbackAdmissionScyllaError::MissingSlot)?;
    StoredRollbackAdmissionSlot::decode_persisted(partition_network, revision, slot)
        .map_err(Into::into)
}

fn decode_lwt_applied(result: QueryResult) -> Result<bool, RollbackAdmissionScyllaError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RollbackAdmissionScyllaError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackAdmissionScyllaError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> RollbackAdmissionScyllaError {
    RollbackAdmissionScyllaError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackAdmissionScyllaError {
    Codec(String),
    Model(RollbackAdmissionCodecError),
    NetworkChainIdOutOfRange(i64),
    SelectedPartitionMismatch {
        requested: NetworkId,
        returned: NetworkId,
    },
    MissingRevision,
    MissingSlot,
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

impl fmt::Display for RollbackAdmissionScyllaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "rollback admission network codec: {error}"),
            Self::Model(error) => error.fmt(formatter),
            Self::NetworkChainIdOutOfRange(value) => {
                write!(formatter, "rollback admission network BIGINT is outside u32: {value}")
            }
            Self::SelectedPartitionMismatch { requested, returned } => write!(
                formatter,
                "rollback admission SELECT requested {:?}, returned {:?}",
                requested, returned
            ),
            Self::MissingRevision => formatter.write_str("rollback admission row has null revision"),
            Self::MissingSlot => formatter.write_str("rollback admission row has null slot"),
            Self::MissingAppliedColumn => formatter.write_str("rollback admission LWT has no [applied]"),
            Self::InvalidAppliedColumn => formatter.write_str("rollback admission [applied] is invalid"),
            Self::CurrentMissingAfterLwt { operation, applied } => write!(
                formatter,
                "rollback admission {operation} returned applied={applied}, but row is missing"
            ),
            Self::IndeterminateWrite { operation, execute_error } => write!(
                formatter,
                "rollback admission {operation} is indeterminate; retry exact sealed intent: {execute_error}"
            ),
            Self::IndeterminateReadFailed { operation, execute_error, read_error } => write!(
                formatter,
                "rollback admission {operation} and reconcile read failed: execute={execute_error}; read={read_error}"
            ),
            Self::Cql(error) => write!(formatter, "rollback admission Scylla failed: {error}"),
        }
    }
}

impl Error for RollbackAdmissionScyllaError {}

impl From<RollbackAdmissionCodecError> for RollbackAdmissionScyllaError {
    fn from(value: RollbackAdmissionCodecError) -> Self {
        Self::Model(value)
    }
}
