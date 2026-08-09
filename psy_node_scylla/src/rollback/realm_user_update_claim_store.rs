//! No-tablet full-payload LWT store for Realm Edge user-update claims.
//!
//! This store is part of the recoverable queue sidecar schema.  It does not
//! make Redis submitted-status or proof/temp writes authoritative; callers
//! must advance the claim only after exact dependency readback.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::realm_user_update_claim::{
    RealmUserUpdateClaimError, RealmUserUpdateClaimPhase,
    RealmUserUpdateClaimBucket, RealmUserUpdateClaimSlot,
    StoredRealmUserUpdateClaim,
};
use psy_node_core::store::typed::UserId;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(super) const REALM_USER_UPDATE_CLAIM_TABLE: &str =
    "branch_exact_realm_user_update_claim_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateClaimQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl RealmUserUpdateClaimQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), REALM_USER_UPDATE_CLAIM_TABLE);
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (generation_slot blob, claim_bucket smallint, user_id bigint, revision bigint, claim_payload blob, PRIMARY KEY ((generation_slot, claim_bucket), user_id))"
            ),
            read: format!(
                "SELECT generation_slot, claim_bucket, user_id, revision, claim_payload FROM {table} WHERE generation_slot = ? AND claim_bucket = ? AND user_id = ?"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (generation_slot, claim_bucket, user_id, revision, claim_payload) VALUES (?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, claim_payload = ? WHERE generation_slot = ? AND claim_bucket = ? AND user_id = ? IF revision = ? AND claim_payload = ?"
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
            "create\n{}\n\nread\n{}\nBLOB,SMALLINT,BIGINT\n\nbootstrap\n{}\nBLOB,SMALLINT,BIGINT,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BLOB,SMALLINT,BIGINT,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.compare_and_set,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateClaimReadState<Hash> {
    Uninitialized,
    Current(StoredRealmUserUpdateClaim<Hash>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateClaimWriteDisposition {
    Applied,
    Resumed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateClaimReceipt<Hash> {
    current: StoredRealmUserUpdateClaim<Hash>,
    disposition: RealmUserUpdateClaimWriteDisposition,
}

impl<Hash> RealmUserUpdateClaimReceipt<Hash> {
    pub const fn current(&self) -> &StoredRealmUserUpdateClaim<Hash> {
        &self.current
    }

    pub const fn disposition(&self) -> RealmUserUpdateClaimWriteDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateClaimWriteOutcome<Hash> {
    Applied(RealmUserUpdateClaimReceipt<Hash>),
    Resumed(RealmUserUpdateClaimReceipt<Hash>),
    Conflict(StoredRealmUserUpdateClaim<Hash>),
}

pub(crate) struct ScyllaRealmUserUpdateClaimStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaRealmUserUpdateClaimStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), RealmUserUpdateClaimStoreError> {
        let queries = RealmUserUpdateClaimQueries::new(keyspace);
        session
            .query_unpaged(queries.create(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, RealmUserUpdateClaimStoreError> {
        let queries = RealmUserUpdateClaimQueries::new(&keyspace);
        Ok(Self {
            read: prepare_read(&session, queries.read()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap()).await?,
            compare_and_set: prepare_lwt(&session, queries.compare_and_set()).await?,
            session,
        })
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        slot: RealmUserUpdateClaimSlot,
        bucket: RealmUserUpdateClaimBucket,
        user_id: UserId,
    ) -> Result<RealmUserUpdateClaimReadState<Hash>, RealmUserUpdateClaimStoreError> {
        let row = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    slot.as_bytes().to_vec(),
                    bucket.as_i16().map_err(model)?,
                    i64::try_from(user_id.get())
                        .map_err(|_| RealmUserUpdateClaimStoreError::UserOutOfRange)?,
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(
                Vec<u8>,
                i16,
                i64,
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let Some((selected_slot, selected_bucket, selected_user_id, revision, payload)) = row else {
            return Ok(RealmUserUpdateClaimReadState::Uninitialized);
        };
        let selected_slot = RealmUserUpdateClaimSlot::try_from_bytes(
            selected_slot
                .try_into()
                .map_err(|_| RealmUserUpdateClaimStoreError::SelectedSlotMismatch)?,
        )
        .map_err(model)?;
        if selected_slot != slot {
            return Err(RealmUserUpdateClaimStoreError::SelectedSlotMismatch);
        }
        let current = StoredRealmUserUpdateClaim::decode_selected(
            slot,
            selected_bucket,
            selected_user_id,
            revision.ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
        )
        .map_err(model)?;
        Ok(RealmUserUpdateClaimReadState::Current(current))
    }

    /// Claim one pending/user coordinate. A retry with the same full request
    /// identity resumes the winner and therefore reuses its timestamp/status;
    /// a different request returns a durable conflict.
    pub async fn claim<Hash: Q256BitHash>(
        &self,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateClaimWriteOutcome<Hash>, RealmUserUpdateClaimStoreError> {
        if candidate.phase() != RealmUserUpdateClaimPhase::Claimed {
            return Err(RealmUserUpdateClaimStoreError::InvalidTransition);
        }
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    candidate.slot().as_bytes().to_vec(),
                    candidate.bucket().as_i16().map_err(model)?,
                    i64::try_from(candidate.user_id().get())
                        .map_err(|_| RealmUserUpdateClaimStoreError::UserOutOfRange)?,
                    candidate.revision().as_i64().map_err(model)?,
                    candidate.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish_claim(execution, candidate).await
    }

    pub async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        expected: &StoredRealmUserUpdateClaim<Hash>,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateClaimWriteOutcome<Hash>, RealmUserUpdateClaimStoreError> {
        if expected.slot() != candidate.slot()
            || candidate.revision().get() != expected.revision().get() + 1
        {
            return Err(RealmUserUpdateClaimStoreError::InvalidTransition);
        }
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    candidate.revision().as_i64().map_err(model)?,
                    candidate.to_canonical_bytes(),
                    candidate.slot().as_bytes().to_vec(),
                    candidate.bucket().as_i16().map_err(model)?,
                    i64::try_from(candidate.user_id().get())
                        .map_err(|_| RealmUserUpdateClaimStoreError::UserOutOfRange)?,
                    expected.revision().as_i64().map_err(model)?,
                    expected.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish_exact(execution, candidate).await
    }

    async fn finish_claim<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateClaimWriteOutcome<Hash>, RealmUserUpdateClaimStoreError> {
        let applied = match execution {
            Ok(result) => Some(decode_applied(result)?),
            Err(execute) => {
                let observed = self
                    .read(candidate.slot(), candidate.bucket(), candidate.user_id())
                    .await;
                return match observed {
                    Ok(RealmUserUpdateClaimReadState::Current(current))
                        if current.same_request_as(candidate) => Ok(resumed(current)),
                    Ok(RealmUserUpdateClaimReadState::Current(current)) => {
                        Err(RealmUserUpdateClaimStoreError::IndeterminateConflict {
                            execute: execute.to_string(),
                            observed_revision: current.revision().get(),
                        })
                    }
                    Ok(RealmUserUpdateClaimReadState::Uninitialized) => {
                        Err(RealmUserUpdateClaimStoreError::IndeterminateWrite {
                            execute: execute.to_string(),
                        })
                    }
                    Err(read) => Err(RealmUserUpdateClaimStoreError::IndeterminateRead {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let RealmUserUpdateClaimReadState::Current(current) =
            self.read(candidate.slot(), candidate.bucket(), candidate.user_id())
                .await?
        else {
            return Err(RealmUserUpdateClaimStoreError::MissingAfterLwt);
        };
        if !current.same_request_as(candidate) {
            return Ok(RealmUserUpdateClaimWriteOutcome::Conflict(current));
        }
        if applied == Some(true) {
            if &current != candidate {
                return Err(RealmUserUpdateClaimStoreError::AppliedStateMismatch);
            }
            Ok(applied_receipt(current))
        } else {
            Ok(resumed(current))
        }
    }

    async fn finish_exact<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<RealmUserUpdateClaimWriteOutcome<Hash>, RealmUserUpdateClaimStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self
                    .read(candidate.slot(), candidate.bucket(), candidate.user_id())
                    .await
                {
                    Ok(RealmUserUpdateClaimReadState::Current(current))
                        if current == *candidate => Ok(resumed(current)),
                    Ok(RealmUserUpdateClaimReadState::Current(current)) => {
                        Err(RealmUserUpdateClaimStoreError::IndeterminateConflict {
                            execute: execute.to_string(),
                            observed_revision: current.revision().get(),
                        })
                    }
                    Ok(RealmUserUpdateClaimReadState::Uninitialized) => {
                        Err(RealmUserUpdateClaimStoreError::IndeterminateWrite {
                            execute: execute.to_string(),
                        })
                    }
                    Err(read) => Err(RealmUserUpdateClaimStoreError::IndeterminateRead {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let RealmUserUpdateClaimReadState::Current(current) =
            self.read(candidate.slot(), candidate.bucket(), candidate.user_id())
                .await?
        else {
            return Err(RealmUserUpdateClaimStoreError::MissingAfterLwt);
        };
        if applied {
            if &current != candidate {
                return Err(RealmUserUpdateClaimStoreError::AppliedStateMismatch);
            }
            Ok(applied_receipt(current))
        } else if &current == candidate {
            Ok(resumed(current))
        } else {
            Ok(RealmUserUpdateClaimWriteOutcome::Conflict(current))
        }
    }
}

fn applied_receipt<Hash>(
    current: StoredRealmUserUpdateClaim<Hash>,
) -> RealmUserUpdateClaimWriteOutcome<Hash> {
    RealmUserUpdateClaimWriteOutcome::Applied(RealmUserUpdateClaimReceipt {
        current,
        disposition: RealmUserUpdateClaimWriteDisposition::Applied,
    })
}

fn resumed<Hash>(
    current: StoredRealmUserUpdateClaim<Hash>,
) -> RealmUserUpdateClaimWriteOutcome<Hash> {
    RealmUserUpdateClaimWriteOutcome::Resumed(RealmUserUpdateClaimReceipt {
        current,
        disposition: RealmUserUpdateClaimWriteDisposition::Resumed,
    })
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmUserUpdateClaimStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmUserUpdateClaimStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RealmUserUpdateClaimStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RealmUserUpdateClaimStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmUserUpdateClaimStoreError::InvalidAppliedColumn),
    }
}

fn model(error: RealmUserUpdateClaimError) -> RealmUserUpdateClaimStoreError {
    RealmUserUpdateClaimStoreError::Claim(error.to_string())
}

fn cql(error: impl fmt::Display) -> RealmUserUpdateClaimStoreError {
    RealmUserUpdateClaimStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateClaimStoreError {
    Claim(String),
    Cql(String),
    InvalidTransition,
    SelectedSlotMismatch,
    UserOutOfRange,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    IndeterminateWrite {
        execute: String,
    },
    IndeterminateConflict {
        execute: String,
        observed_revision: u64,
    },
    IndeterminateRead {
        execute: String,
        read: String,
    },
}

impl fmt::Display for RealmUserUpdateClaimStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateClaimStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_golden_is_full_payload_no_tablet_lwt() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_claim_no_tablet".to_owned(),
        )
        .unwrap();
        let queries = RealmUserUpdateClaimQueries::new(&keyspace);
        let golden = queries.golden();
        assert!(golden.contains(REALM_USER_UPDATE_CLAIM_TABLE));
        assert!(golden.contains("PRIMARY KEY ((generation_slot, claim_bucket), user_id)"));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND claim_payload = ?"));
        assert!(golden.contains("BIGINT,BLOB,BLOB,SMALLINT,BIGINT,BIGINT,BLOB"));
    }

    #[test]
    fn store_is_only_materialized_by_explicit_sidecar_deployment() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(REALM_USER_UPDATE_CLAIM_TABLE));
        assert!(!setup.contains("ScyllaRealmUserUpdateClaimStore"));
        let sidecar = include_str!("pending_queue_sidecar_schema.rs");
        assert!(sidecar.contains("ScyllaRealmUserUpdateClaimStore::create_schema"));
    }
}
