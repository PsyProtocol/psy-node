//! No-tablet, per-authority LWT store for the h22 writer lifecycle.
//!
//! Missing means disabled. Every mutation compares both the monotonic revision
//! and the complete canonical lifecycle payload; transport errors are resolved
//! only by an exact QUORUM readback.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::store::branch_exact_schema::AuthorityScope;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};

use super::{
    BranchExactDeploymentNoTabletKeyspace, BranchExactShadowAuditReadState,
    BranchExactShadowAuditState, BranchExactShadowAuditWriteOutcome,
    BranchExactWriterActivationPlan, BranchExactWriterBootstrap,
    BranchExactWriterLifecycleError, BranchExactWriterRevision, BranchExactWriterSlot,
    BranchExactWriterState, SealedBranchExactShadowAuditCas,
    SealedBranchExactWriterCas, ScyllaBranchExactShadowAuditStore,
    StoredBranchExactWriterLifecycle,
};

const TABLE: &str = "branch_exact_writer_lifecycle_v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriterAuthorityKey {
    network: NetworkId,
    authority: AuthorityScope,
}

impl BranchExactWriterAuthorityKey {
    pub const fn new(network: NetworkId, authority: AuthorityScope) -> Self {
        Self { network, authority }
    }

    pub fn from_plan<Hash: Q256BitHash>(
        plan: &BranchExactWriterActivationPlan<Hash>,
    ) -> Self {
        Self::new(plan.baseline().canonical_chain().network_id(), plan.authority())
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn authority(self) -> AuthorityScope {
        self.authority
    }

    fn bind(self) -> (i64, i8, i64, i32) {
        match self.authority {
            AuthorityScope::Coordinator => {
                (i64::from(self.network.chain_id()), 1, 0, 0)
            }
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

    fn slot(self) -> BranchExactWriterSlot {
        BranchExactWriterSlot::for_authority(self.network, self.authority)
    }

    fn decode(
        network_chain_id: i64,
        authority_kind: i8,
        realm_id: i64,
        realm_sub_id: i32,
    ) -> Result<Self, BranchExactWriterStoreError> {
        let network_chain_id = u32::try_from(network_chain_id)
            .map_err(|_| BranchExactWriterStoreError::SelectedKeyOutOfRange)?;
        let network = NetworkId::try_from_chain_id(network_chain_id)
            .map_err(|error| BranchExactWriterStoreError::SelectedKey(error.to_string()))?;
        let authority = match authority_kind {
            1 if realm_id == 0 && realm_sub_id == 0 => AuthorityScope::Coordinator,
            2 => AuthorityScope::Realm {
                realm_id: u32::try_from(realm_id)
                    .map_err(|_| BranchExactWriterStoreError::SelectedKeyOutOfRange)?,
                realm_sub_id: u16::try_from(realm_sub_id)
                    .map_err(|_| BranchExactWriterStoreError::SelectedKeyOutOfRange)?,
            },
            _ => return Err(BranchExactWriterStoreError::InvalidSelectedAuthority),
        };
        Ok(Self { network, authority })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterLifecycleQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl BranchExactWriterLifecycleQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{TABLE}", keyspace.as_str());
        let key = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, revision bigint, lifecycle blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, lifecycle FROM {table} WHERE {key}"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, lifecycle) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, lifecycle = ? WHERE {key} IF revision = ? AND lifecycle = ?"
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
pub enum BranchExactWriterReadState<Hash> {
    Uninitialized,
    Current(StoredBranchExactWriterLifecycle<Hash>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterWriteOutcome<Hash> {
    Applied(StoredBranchExactWriterLifecycle<Hash>),
    Idempotent(StoredBranchExactWriterLifecycle<Hash>),
    Conflict(StoredBranchExactWriterLifecycle<Hash>),
}

pub struct ScyllaBranchExactWriterLifecycleStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaBranchExactWriterLifecycleStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), BranchExactWriterStoreError> {
        let queries = BranchExactWriterLifecycleQueries::new(keyspace);
        session.query_unpaged(queries.create(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, BranchExactWriterStoreError> {
        let queries = BranchExactWriterLifecycleQueries::new(&keyspace);
        Ok(Self {
            read: prepare_read(&session, queries.read().to_owned()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap().to_owned()).await?,
            cas: prepare_lwt(&session, queries.compare_and_set().to_owned()).await?,
            session,
        })
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        key: BranchExactWriterAuthorityKey,
    ) -> Result<BranchExactWriterReadState<Hash>, BranchExactWriterStoreError> {
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
            return Ok(BranchExactWriterReadState::Uninitialized);
        };
        let selected = BranchExactWriterAuthorityKey::decode(
            selected_network,
            selected_kind,
            selected_realm,
            selected_sub,
        )?;
        if selected != key {
            return Err(BranchExactWriterStoreError::SelectedKeyMismatch);
        }
        let slot = key.slot();
        let current = StoredBranchExactWriterLifecycle::decode_persisted(
            slot.as_bytes(),
            revision.ok_or(BranchExactWriterStoreError::MissingRevision)?,
            payload
                .as_deref()
                .ok_or(BranchExactWriterStoreError::MissingPayload)?,
        )
        .map_err(model)?;
        if BranchExactWriterAuthorityKey::from_plan(current.plan()) != key {
            return Err(BranchExactWriterStoreError::PayloadAuthorityMismatch);
        }
        Ok(BranchExactWriterReadState::Current(current))
    }

    pub async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &BranchExactWriterBootstrap<Hash>,
    ) -> Result<BranchExactWriterWriteOutcome<Hash>, BranchExactWriterStoreError> {
        let candidate = bootstrap.candidate();
        let key = BranchExactWriterAuthorityKey::from_plan(candidate.plan());
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
        sealed: &SealedBranchExactWriterCas<Hash>,
    ) -> Result<BranchExactWriterWriteOutcome<Hash>, BranchExactWriterStoreError> {
        let candidate = sealed.candidate();
        let expected = sealed.expected();
        let key = BranchExactWriterAuthorityKey::from_plan(candidate.plan());
        if BranchExactWriterAuthorityKey::from_plan(expected.plan()) != key {
            return Err(BranchExactWriterStoreError::PayloadAuthorityMismatch);
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
        key: BranchExactWriterAuthorityKey,
        candidate: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<BranchExactWriterWriteOutcome<Hash>, BranchExactWriterStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute_error) => {
                return match self.read(key).await {
                    Ok(BranchExactWriterReadState::Current(current))
                        if &current == candidate =>
                    {
                        Ok(BranchExactWriterWriteOutcome::Idempotent(current))
                    }
                    Ok(BranchExactWriterReadState::Current(current)) => {
                        Err(BranchExactWriterStoreError::IndeterminateWrite {
                            execute: execute_error.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(BranchExactWriterReadState::Uninitialized) => {
                        Err(BranchExactWriterStoreError::IndeterminateWrite {
                            execute: execute_error.to_string(),
                            observed_revision: None,
                        })
                    }
                    Err(read_error) => Err(
                        BranchExactWriterStoreError::IndeterminateReadFailed {
                            execute: execute_error.to_string(),
                            read: read_error.to_string(),
                        },
                    ),
                };
            }
        };
        let BranchExactWriterReadState::Current(current) = self.read(key).await? else {
            return Err(BranchExactWriterStoreError::CurrentMissingAfterLwt);
        };
        if applied {
            if &current != candidate {
                return Err(BranchExactWriterStoreError::AppliedStateMismatch);
            }
            Ok(BranchExactWriterWriteOutcome::Applied(current))
        } else if &current == candidate {
            Ok(BranchExactWriterWriteOutcome::Idempotent(current))
        } else {
            Ok(BranchExactWriterWriteOutcome::Conflict(current))
        }
    }
}

/// Crash-safe activation ordering: persist writer PREPARED, consume the exact
/// h21 VERIFIED receipt, then make the baseline watermark Active.
pub struct ScyllaBranchExactWriterActivationExecutor;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterActivationOutcome<Hash> {
    Activated(StoredBranchExactWriterLifecycle<Hash>),
    Idempotent(StoredBranchExactWriterLifecycle<Hash>),
}

impl ScyllaBranchExactWriterActivationExecutor {
    pub async fn activate<Hash: Q256BitHash>(
        writer: &ScyllaBranchExactWriterLifecycleStore,
        shadow: &ScyllaBranchExactShadowAuditStore,
        plan: BranchExactWriterActivationPlan<Hash>,
    ) -> Result<BranchExactWriterActivationOutcome<Hash>, BranchExactWriterStoreError> {
        let bootstrap = BranchExactWriterBootstrap::new(plan.clone());
        let current = match writer.bootstrap(&bootstrap).await? {
            BranchExactWriterWriteOutcome::Applied(current)
            | BranchExactWriterWriteOutcome::Idempotent(current) => current,
            BranchExactWriterWriteOutcome::Conflict(current) => current,
        };
        if current.plan() != &plan {
            return Err(BranchExactWriterStoreError::ActivationConflict);
        }
        if !matches!(
            current.state(),
            BranchExactWriterState::ActivationPrepared | BranchExactWriterState::Active(_)
        ) {
            return Err(BranchExactWriterStoreError::ActivationConflict);
        }

        let consumed = match shadow
            .read(plan.shadow_audit_slot())
            .await
            .map_err(|error| BranchExactWriterStoreError::Shadow(error.to_string()))?
        {
            BranchExactShadowAuditReadState::Current(stored) => match stored.state() {
                BranchExactShadowAuditState::Verified(receipt)
                    if receipt.digest() == plan.shadow_verified_digest() =>
                {
                    let sealed = SealedBranchExactShadowAuditCas::consume(
                        &stored,
                        plan.digest(),
                    )
                    .map_err(|error| BranchExactWriterStoreError::Shadow(error.to_string()))?;
                    match shadow
                        .compare_and_set(&sealed)
                        .await
                        .map_err(|error| BranchExactWriterStoreError::Shadow(error.to_string()))?
                    {
                        BranchExactShadowAuditWriteOutcome::Applied(next)
                        | BranchExactShadowAuditWriteOutcome::Idempotent(next) => {
                            let BranchExactShadowAuditState::Consumed(receipt) = next.state() else {
                                return Err(BranchExactWriterStoreError::ShadowConsumptionConflict);
                            };
                            receipt.clone()
                        }
                        BranchExactShadowAuditWriteOutcome::Conflict(next) => {
                            let BranchExactShadowAuditState::Consumed(receipt) = next.state() else {
                                return Err(BranchExactWriterStoreError::ShadowConsumptionConflict);
                            };
                            receipt.clone()
                        }
                    }
                }
                BranchExactShadowAuditState::Consumed(receipt)
                    if receipt.verified().digest() == plan.shadow_verified_digest()
                        && receipt.writer_activation_digest() == plan.digest() =>
                {
                    receipt.clone()
                }
                _ => return Err(BranchExactWriterStoreError::ShadowConsumptionConflict),
            },
            BranchExactShadowAuditReadState::Uninitialized => {
                return Err(BranchExactWriterStoreError::ShadowUninitialized)
            }
        };

        let key = BranchExactWriterAuthorityKey::from_plan(&plan);
        let BranchExactWriterReadState::Current(current) = writer.read(key).await? else {
            return Err(BranchExactWriterStoreError::CurrentMissingAfterLwt);
        };
        if current.plan() != &plan {
            return Err(BranchExactWriterStoreError::ActivationConflict);
        }
        if matches!(current.state(), BranchExactWriterState::Active(_)) {
            return Ok(BranchExactWriterActivationOutcome::Idempotent(current));
        }
        let sealed = SealedBranchExactWriterCas::activate(&current, &consumed).map_err(model)?;
        match writer.compare_and_set(&sealed).await? {
            BranchExactWriterWriteOutcome::Applied(current) => {
                Ok(BranchExactWriterActivationOutcome::Activated(current))
            }
            BranchExactWriterWriteOutcome::Idempotent(current) => {
                Ok(BranchExactWriterActivationOutcome::Idempotent(current))
            }
            BranchExactWriterWriteOutcome::Conflict(current)
                if current.plan() == &plan
                    && matches!(current.state(), BranchExactWriterState::Active(_)) =>
            {
                Ok(BranchExactWriterActivationOutcome::Idempotent(current))
            }
            BranchExactWriterWriteOutcome::Conflict(_) => {
                Err(BranchExactWriterStoreError::ActivationConflict)
            }
        }
    }
}

async fn prepare_read(
    session: &Session,
    cql: String,
) -> Result<PreparedStatement, BranchExactWriterStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql: String,
) -> Result<PreparedStatement, BranchExactWriterStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, BranchExactWriterStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(BranchExactWriterStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(BranchExactWriterStoreError::InvalidAppliedColumn),
    }
}

fn model(error: BranchExactWriterLifecycleError) -> BranchExactWriterStoreError {
    BranchExactWriterStoreError::Lifecycle(error.to_string())
}

fn cql(error: impl fmt::Display) -> BranchExactWriterStoreError {
    BranchExactWriterStoreError::Cql(error.to_string())
}

fn cql_error(error: impl fmt::Display) -> BranchExactWriterStoreError {
    cql(error)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterStoreError {
    Lifecycle(String),
    Cql(String),
    SelectedKey(String),
    SelectedKeyOutOfRange,
    InvalidSelectedAuthority,
    SelectedKeyMismatch,
    PayloadAuthorityMismatch,
    MissingRevision,
    MissingPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    CurrentMissingAfterLwt,
    AppliedStateMismatch,
    IndeterminateWrite {
        execute: String,
        observed_revision: Option<BranchExactWriterRevision>,
    },
    IndeterminateReadFailed { execute: String, read: String },
    ActivationConflict,
    Shadow(String),
    ShadowUninitialized,
    ShadowConsumptionConflict,
}

impl fmt::Display for BranchExactWriterStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactWriterStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_golden_uses_one_authority_partition_and_full_payload_cas() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22_no_tablet".to_owned(),
        )
        .unwrap();
        let queries = BranchExactWriterLifecycleQueries::new(&keyspace);
        let golden = queries.golden();
        assert!(golden.contains("branch_exact_writer_lifecycle_v1"));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id))"));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND lifecycle = ?"));
        assert!(golden.contains("BIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB"));
    }

    #[test]
    fn authority_key_round_trip_rejects_invalid_coordinator_padding() {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let coordinator = BranchExactWriterAuthorityKey::new(
            network,
            AuthorityScope::Coordinator,
        );
        let (chain, kind, realm, sub) = coordinator.bind();
        assert_eq!(
            BranchExactWriterAuthorityKey::decode(chain, kind, realm, sub).unwrap(),
            coordinator
        );
        assert_eq!(
            BranchExactWriterAuthorityKey::decode(chain, 1, 1, 0),
            Err(BranchExactWriterStoreError::InvalidSelectedAuthority)
        );
    }
}
