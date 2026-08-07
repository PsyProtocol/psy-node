//! Production-shaped predecessor-state reader for the Realm IMT graph Gate.
//!
//! The adapter reads only the typed requests emitted by
//! `RealmImtMutationGraphPlan`. It deliberately returns `Option<Hash>` so the
//! Scylla layer never guesses a tree height or zero hash.

use std::{error::Error, fmt, marker::PhantomData};

use futures::future::join_all;
use parth_core::protocol::core_types::QDBHashBase;
use psy_node_core::store::realm_imt_mutation_graph::{
    RealmImtBaselineNodeKey, RealmImtPredecessorReadPlan,
    RealmImtPredecessorReadRequest, RealmImtPredecessorReadRow,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};

use crate::utils::{u64_to_i64_exact, u8_to_i8_exact};

use super::{
    physical_descriptor, CqlKeyspaceName, ScyllaPhysicalTableId,
};

pub const REALM_IMT_PREDECESSOR_CONCURRENT_LIMIT: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RealmImtPredecessorQueryId {
    GlobalUser = 1,
    UserContract = 2,
    ContractState = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmImtPredecessorQuery {
    id: RealmImtPredecessorQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl RealmImtPredecessorQuery {
    pub const fn id(&self) -> RealmImtPredecessorQueryId { self.id }
    pub fn cql(&self) -> &str { &self.cql }
    pub const fn bind_shape(&self) -> &'static [&'static str] { self.bind_shape }
}

/// Single source of CQL for prepare, execute and golden tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmImtPredecessorQueries {
    global_user: RealmImtPredecessorQuery,
    user_contract: RealmImtPredecessorQuery,
    contract_state: RealmImtPredecessorQuery,
}

impl RealmImtPredecessorQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let global_user = physical_descriptor(ScyllaPhysicalTableId::GlobalUserTree).physical_name;
        let user_contract = physical_descriptor(ScyllaPhysicalTableId::UserContractTree).physical_name;
        let contract_state = physical_descriptor(ScyllaPhysicalTableId::ContractStateTree).physical_name;
        Self {
            global_user: RealmImtPredecessorQuery {
                id: RealmImtPredecessorQueryId::GlobalUser,
                cql: format!(
                    "SELECT value FROM {}.{global_user} WHERE level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
                    keyspace.as_str(),
                ),
                bind_shape: &["level:TINYINT", "node_index:BIGINT", "predecessor_checkpoint:BIGINT"],
            },
            user_contract: RealmImtPredecessorQuery {
                id: RealmImtPredecessorQueryId::UserContract,
                cql: format!(
                    "SELECT value FROM {}.{user_contract} WHERE tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
                    keyspace.as_str(),
                ),
                bind_shape: &[
                    "tree_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "predecessor_checkpoint:BIGINT",
                ],
            },
            contract_state: RealmImtPredecessorQuery {
                id: RealmImtPredecessorQueryId::ContractState,
                cql: format!(
                    "SELECT value FROM {}.{contract_state} WHERE tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id <= ? LIMIT 1",
                    keyspace.as_str(),
                ),
                bind_shape: &[
                    "tree_id:BIGINT",
                    "tree_sub_id:BIGINT",
                    "level:TINYINT",
                    "node_index:BIGINT",
                    "predecessor_checkpoint:BIGINT",
                ],
            },
        }
    }

    pub const fn global_user(&self) -> &RealmImtPredecessorQuery { &self.global_user }
    pub const fn user_contract(&self) -> &RealmImtPredecessorQuery { &self.user_contract }
    pub const fn contract_state(&self) -> &RealmImtPredecessorQuery { &self.contract_state }

    pub fn all(&self) -> [&RealmImtPredecessorQuery; 3] {
        [&self.global_user, &self.user_contract, &self.contract_state]
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in self.all() {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.id,
                query.cql,
                query.bind_shape.join(","),
            ));
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmImtPredecessorBindValue {
    TinyInt(i8),
    BigInt(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmImtPredecessorBinding {
    GlobalUser { level: i8, node_index: i64, checkpoint: i64 },
    UserContract { tree_id: i64, level: i8, node_index: i64, checkpoint: i64 },
    ContractState {
        tree_id: i64,
        tree_sub_id: i64,
        level: i8,
        node_index: i64,
        checkpoint: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmImtPredecessorCheckpointOutOfRange(pub u64);

impl fmt::Display for RealmImtPredecessorCheckpointOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "predecessor checkpoint {} exceeds non-negative CQL BIGINT range", self.0)
    }
}

impl Error for RealmImtPredecessorCheckpointOutOfRange {}

impl RealmImtPredecessorBinding {
    pub fn try_new(
        checkpoint: u64,
        request: RealmImtPredecessorReadRequest,
    ) -> Result<Self, RealmImtPredecessorCheckpointOutOfRange> {
        let checkpoint = i64::try_from(checkpoint)
            .map_err(|_| RealmImtPredecessorCheckpointOutOfRange(checkpoint))?;
        Ok(match request.key() {
            RealmImtBaselineNodeKey::GlobalUser { level, index } => Self::GlobalUser {
                level: u8_to_i8_exact(level),
                node_index: u64_to_i64_exact(index),
                checkpoint,
            },
            RealmImtBaselineNodeKey::UserContract { user_id, level, index } => Self::UserContract {
                tree_id: u64_to_i64_exact(user_id),
                level: u8_to_i8_exact(level),
                node_index: u64_to_i64_exact(index),
                checkpoint,
            },
            RealmImtBaselineNodeKey::ContractState { user_id, contract_id, level, index } => Self::ContractState {
                tree_id: u64_to_i64_exact(user_id),
                tree_sub_id: u64_to_i64_exact(contract_id),
                level: u8_to_i8_exact(level),
                node_index: u64_to_i64_exact(index),
                checkpoint,
            },
        })
    }

    pub const fn query_id(&self) -> RealmImtPredecessorQueryId {
        match self {
            Self::GlobalUser { .. } => RealmImtPredecessorQueryId::GlobalUser,
            Self::UserContract { .. } => RealmImtPredecessorQueryId::UserContract,
            Self::ContractState { .. } => RealmImtPredecessorQueryId::ContractState,
        }
    }

    pub fn bind_values(&self) -> Vec<RealmImtPredecessorBindValue> {
        use RealmImtPredecessorBindValue::{BigInt, TinyInt};
        match *self {
            Self::GlobalUser { level, node_index, checkpoint } => {
                vec![TinyInt(level), BigInt(node_index), BigInt(checkpoint)]
            }
            Self::UserContract { tree_id, level, node_index, checkpoint } => {
                vec![BigInt(tree_id), TinyInt(level), BigInt(node_index), BigInt(checkpoint)]
            }
            Self::ContractState { tree_id, tree_sub_id, level, node_index, checkpoint } => vec![
                BigInt(tree_id),
                BigInt(tree_sub_id),
                TinyInt(level),
                BigInt(node_index),
                BigInt(checkpoint),
            ],
        }
    }
}

pub struct RealmImtPredecessorAdapter<Hash> {
    queries: RealmImtPredecessorQueries,
    global_user: PreparedStatement,
    user_contract: PreparedStatement,
    contract_state: PreparedStatement,
    _hash: PhantomData<Hash>,
}

impl<Hash: QDBHashBase> RealmImtPredecessorAdapter<Hash> {
    pub async fn prepare(
        session: &Session,
        keyspace: CqlKeyspaceName,
    ) -> anyhow::Result<Self> {
        Self::prepare_with_consistency(session, keyspace, Consistency::LocalQuorum).await
    }

    pub async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = RealmImtPredecessorQueries::new(&keyspace);
        let global_user = prepare_read(session, queries.global_user.cql(), consistency).await?;
        let user_contract = prepare_read(session, queries.user_contract.cql(), consistency).await?;
        let contract_state = prepare_read(session, queries.contract_state.cql(), consistency).await?;
        Ok(Self { queries, global_user, user_contract, contract_state, _hash: PhantomData })
    }

    pub const fn queries(&self) -> &RealmImtPredecessorQueries { &self.queries }

    pub async fn read_plan(
        &self,
        session: &Session,
        plan: &RealmImtPredecessorReadPlan,
    ) -> anyhow::Result<Vec<RealmImtPredecessorReadRow<Hash>>> {
        let checkpoint = plan.checkpoint().get();
        let mut output = Vec::with_capacity(plan.requests().len());
        for chunk in plan.requests().chunks(REALM_IMT_PREDECESSOR_CONCURRENT_LIMIT) {
            let results = join_all(
                chunk
                    .iter()
                    .copied()
                    .map(|request| self.read_one(session, checkpoint, request)),
            )
            .await;
            for result in results {
                output.push(result?);
            }
        }
        Ok(output)
    }

    async fn read_one(
        &self,
        session: &Session,
        checkpoint: u64,
        request: RealmImtPredecessorReadRequest,
    ) -> anyhow::Result<RealmImtPredecessorReadRow<Hash>> {
        let binding = RealmImtPredecessorBinding::try_new(checkpoint, request)?;
        let result = match binding {
            RealmImtPredecessorBinding::GlobalUser { level, node_index, checkpoint } => {
                session.execute_unpaged(&self.global_user, (level, node_index, checkpoint)).await?
            }
            RealmImtPredecessorBinding::UserContract { tree_id, level, node_index, checkpoint } => {
                session.execute_unpaged(&self.user_contract, (tree_id, level, node_index, checkpoint)).await?
            }
            RealmImtPredecessorBinding::ContractState {
                tree_id,
                tree_sub_id,
                level,
                node_index,
                checkpoint,
            } => {
                session
                    .execute_unpaged(
                        &self.contract_state,
                        (tree_id, tree_sub_id, level, node_index, checkpoint),
                    )
                    .await?
            }
        };
        let rows = result.into_rows_result()?;
        let value = rows
            .maybe_first_row::<(Vec<u8>,)>()?
            .map(|row| Hash::from_slice_32bytes(&row.0))
            .transpose()?;
        Ok(RealmImtPredecessorReadRow::new(request, value))
    }
}

async fn prepare_read(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(cql).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}
