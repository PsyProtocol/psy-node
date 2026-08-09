//! No-tablet full-payload LWT store for Realm Edge user-update claims.
//!
//! This store is part of the recoverable queue sidecar schema.  It does not
//! make Redis submitted-status or proof/temp writes authoritative; callers
//! must advance the claim only after exact dependency readback.

use std::{error::Error, fmt, sync::Arc};

use futures::TryStreamExt;
use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::realm_user_update_claim::{
    RealmUserUpdateClaimError, RealmUserUpdateClaimPartition,
    RealmUserUpdateClaimPhase,
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
    "branch_exact_realm_user_update_claim_v2";
#[cfg(test)]
pub(super) const RETIRED_REALM_USER_UPDATE_CLAIM_V1_TABLE: &str =
    "branch_exact_realm_user_update_claim_v1";
#[allow(dead_code)]
const MAX_CLAIMS_PER_BUCKET_SCAN: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateClaimQueries {
    create: String,
    read: String,
    scan_bucket: String,
    bootstrap: String,
    compare_and_set: String,
}

impl RealmUserUpdateClaimQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), REALM_USER_UPDATE_CLAIM_TABLE);
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, activation_digest blob, unique_pending_id bigint, proc_checkpoint_id blob, claim_bucket smallint, user_id bigint, revision bigint, claim_payload blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, claim_bucket), user_id))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, claim_bucket, user_id, revision, claim_payload FROM {table} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ?"
            ),
            scan_bucket: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, claim_bucket, user_id, revision, claim_payload FROM {table} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ?"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, claim_bucket, user_id, revision, claim_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, claim_payload = ? WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ? IF revision = ? AND claim_payload = ?"
            ),
        }
    }

    pub fn create(&self) -> &str {
        &self.create
    }

    pub fn read(&self) -> &str {
        &self.read
    }

    pub fn scan_bucket(&self) -> &str {
        &self.scan_bucket
    }

    pub fn bootstrap(&self) -> &str {
        &self.bootstrap
    }

    pub fn compare_and_set(&self) -> &str {
        &self.compare_and_set
    }

    pub fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT,BIGINT\n\nscan_bucket\n{}\nBIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT\n\nbootstrap\n{}\nBIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT,BIGINT,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT,BIGINT,BIGINT,BLOB\n",
            self.create, self.read, self.scan_bucket, self.bootstrap, self.compare_and_set,
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

type ClaimPartitionBind = (i64, i8, i64, i32, Vec<u8>, i64, Vec<u8>, i16);

fn bind_partition(
    partition: RealmUserUpdateClaimPartition,
) -> Result<ClaimPartitionBind, RealmUserUpdateClaimStoreError> {
    let capture = partition.capture();
    let psy_data::protocol::chain_context::AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        return Err(RealmUserUpdateClaimStoreError::InvalidAuthority);
    };
    Ok((
        i64::from(capture.key().network().chain_id()),
        1,
        i64::from(realm_id),
        i32::from(realm_sub_id),
        capture.activation().as_bytes().to_vec(),
        i64::try_from(capture.processing().pending_id().get())
            .map_err(|_| RealmUserUpdateClaimStoreError::PendingOutOfRange)?,
        capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
        partition.bucket().as_i16().map_err(model)?,
    ))
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn selected_partition_matches(
    partition: RealmUserUpdateClaimPartition,
    network: i64,
    kind: i8,
    realm: i64,
    sub: i32,
    activation: &[u8],
    pending: i64,
    proc_id: &[u8],
    bucket: i16,
) -> bool {
    bind_partition(partition).is_ok_and(
        |(
            expected_network,
            expected_kind,
            expected_realm,
            expected_sub,
            expected_activation,
            expected_pending,
            expected_proc,
            expected_bucket,
        )| {
            network == expected_network
                && kind == expected_kind
                && realm == expected_realm
                && sub == expected_sub
                && activation == expected_activation
                && pending == expected_pending
                && proc_id == expected_proc
                && bucket == expected_bucket
        },
    )
}

pub(crate) struct ScyllaRealmUserUpdateClaimStore {
    session: Arc<Session>,
    read: PreparedStatement,
    #[allow(dead_code)]
    scan_bucket: PreparedStatement,
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
            scan_bucket: prepare_read(&session, queries.scan_bucket()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap()).await?,
            compare_and_set: prepare_lwt(&session, queries.compare_and_set()).await?,
            session,
        })
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        partition: RealmUserUpdateClaimPartition,
        user_id: UserId,
    ) -> Result<RealmUserUpdateClaimReadState<Hash>, RealmUserUpdateClaimStoreError> {
        let (network, kind, realm, sub, activation, pending, proc_id, bucket) =
            bind_partition(partition)?;
        let row = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    network,
                    kind,
                    realm,
                    sub,
                    activation,
                    pending,
                    proc_id,
                    bucket,
                    i64::try_from(user_id.get())
                        .map_err(|_| RealmUserUpdateClaimStoreError::UserOutOfRange)?,
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(
                i64,
                i8,
                i64,
                i32,
                Vec<u8>,
                i64,
                Vec<u8>,
                i16,
                i64,
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let Some((
            selected_network,
            selected_kind,
            selected_realm,
            selected_sub,
            selected_activation,
            selected_pending,
            selected_proc,
            selected_bucket,
            selected_user_id,
            revision,
            payload,
        )) = row else {
            return Ok(RealmUserUpdateClaimReadState::Uninitialized);
        };
        if (
            selected_network,
            selected_kind,
            selected_realm,
            selected_sub,
            selected_activation.as_slice(),
            selected_pending,
            selected_proc.as_slice(),
            selected_bucket,
        ) != (
            network,
            kind,
            realm,
            sub,
            partition.capture().activation().as_bytes().as_slice(),
            pending,
            partition.capture().processing().proc_checkpoint_id().as_bytes().as_slice(),
            bucket,
        ) {
            return Err(RealmUserUpdateClaimStoreError::SelectedPartitionMismatch);
        }
        let current = StoredRealmUserUpdateClaim::decode_selected(
            partition,
            selected_user_id,
            revision.ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
        )
        .map_err(model)?;
        Ok(RealmUserUpdateClaimReadState::Current(current))
    }

    /// Page through one exact, addressable generation bucket. This is a
    /// discovery primitive only: a later generation-close fence must make all
    /// 256 scans stable before their result can authorize rotation.
    #[allow(dead_code)]
    pub(crate) async fn scan_bucket<Hash: Q256BitHash>(
        &self,
        partition: RealmUserUpdateClaimPartition,
    ) -> Result<Vec<StoredRealmUserUpdateClaim<Hash>>, RealmUserUpdateClaimStoreError> {
        let (network, kind, realm, sub, activation, pending, proc_id, bucket) =
            bind_partition(partition)?;
        let mut rows = self
            .session
            .execute_iter(
                self.scan_bucket.clone(),
                (
                    network,
                    kind,
                    realm,
                    sub,
                    activation,
                    pending,
                    proc_id,
                    bucket,
                ),
            )
            .await
            .map_err(cql)?
            .rows_stream::<(
                i64,
                i8,
                i64,
                i32,
                Vec<u8>,
                i64,
                Vec<u8>,
                i16,
                i64,
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let mut output = Vec::new();
        let mut prior_user = None;
        while let Some((
            selected_network,
            selected_kind,
            selected_realm,
            selected_sub,
            selected_activation,
            selected_pending,
            selected_proc,
            selected_bucket,
            selected_user,
            revision,
            payload,
        )) = rows.try_next().await.map_err(cql)?
        {
            if output.len() >= MAX_CLAIMS_PER_BUCKET_SCAN {
                return Err(RealmUserUpdateClaimStoreError::ScanLimitExceeded);
            }
            if !selected_partition_matches(
                partition,
                selected_network,
                selected_kind,
                selected_realm,
                selected_sub,
                &selected_activation,
                selected_pending,
                &selected_proc,
                selected_bucket,
            ) || prior_user.is_some_and(|value| value >= selected_user)
            {
                return Err(RealmUserUpdateClaimStoreError::SelectedPartitionMismatch);
            }
            let claim = StoredRealmUserUpdateClaim::decode_selected(
                partition,
                selected_user,
                revision.ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
                payload
                    .as_deref()
                    .ok_or(RealmUserUpdateClaimStoreError::MissingColumn)?,
            )
            .map_err(model)?;
            prior_user = Some(selected_user);
            output.push(claim);
        }
        Ok(output)
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
        let partition = candidate.partition().map_err(model)?;
        let (network, kind, realm, sub, activation, pending, proc_id, bucket) =
            bind_partition(partition)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    network,
                    kind,
                    realm,
                    sub,
                    activation,
                    pending,
                    proc_id,
                    bucket,
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
            || expected.partition().map_err(model)?
                != candidate.partition().map_err(model)?
            || candidate.revision().get() != expected.revision().get() + 1
        {
            return Err(RealmUserUpdateClaimStoreError::InvalidTransition);
        }
        let partition = candidate.partition().map_err(model)?;
        let (network, kind, realm, sub, activation, pending, proc_id, bucket) =
            bind_partition(partition)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    candidate.revision().as_i64().map_err(model)?,
                    candidate.to_canonical_bytes(),
                    network,
                    kind,
                    realm,
                    sub,
                    activation,
                    pending,
                    proc_id,
                    bucket,
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
                    .read(candidate.partition().map_err(model)?, candidate.user_id())
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
            self.read(candidate.partition().map_err(model)?, candidate.user_id())
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
                    .read(candidate.partition().map_err(model)?, candidate.user_id())
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
            self.read(candidate.partition().map_err(model)?, candidate.user_id())
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
    SelectedPartitionMismatch,
    InvalidAuthority,
    PendingOutOfRange,
    ScanLimitExceeded,
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
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, claim_bucket), user_id)"));
        assert!(golden.contains("scan_bucket"));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND claim_payload = ?"));
        assert!(golden.contains("BIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT"));
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
