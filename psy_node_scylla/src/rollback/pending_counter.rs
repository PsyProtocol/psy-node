//! D-02T9 LWT allocation for the monotonic pending counter.
//!
//! Counter CAS alone cannot prove which concurrent request owns the candidate
//! pending ID. Ownership is therefore claimed in the existing pending-to-proc
//! forward mapping with `IF NOT EXISTS`; only an exact proc UUID match produces
//! a verified token for the remaining mappings.
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::PendingCounterAdapter;
//! ```
//!
//! ```compile_fail
//! use psy_node_core::store::{timestamp::CommitWriteTimestampUs, typed::{ProcCheckpointUniqueId, UniquePendingId}};
//! use psy_node_scylla::rollback::{PendingCounterPlanDigest, TimestampedWriteKind, VerifiedPendingOwnership};
//! let _forged = VerifiedPendingOwnership {
//!     pending: UniquePendingId::try_new(1).unwrap(),
//!     proc_id: ProcCheckpointUniqueId::from_u128(1),
//!     write_timestamp_us: CommitWriteTimestampUs::try_from_i128(1).unwrap(),
//!     write_kind: TimestampedWriteKind::AuthorityCommit,
//!     plan_digest: unsafe { std::mem::zeroed::<PendingCounterPlanDigest>() },
//! };
//! ```

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, NewBranchWriteTimestampUs},
    typed::{ProcCheckpointUniqueId, U64CounterSlot, UniquePendingId},
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::utils::{i64_to_u64_exact, u64_to_i64_exact};

use super::{
    physical_descriptor, CqlKeyspaceName, PendingContextQueries,
    PrototypeBindValue, ScyllaPhysicalTableId, TimestampedWriteKind,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCounterExpected {
    Absent,
    Present(UniquePendingId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCounterReadState {
    Uninitialized,
    Current(UniquePendingId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingOwnershipReadState {
    Unclaimed,
    OwnedBy(ProcCheckpointUniqueId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingCounterPlanDigest([u8; 32]);

impl PendingCounterPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedPendingOwnership {
    pending: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
    write_timestamp_us: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    plan_digest: PendingCounterPlanDigest,
}

impl VerifiedPendingOwnership {
    pub const fn pending(self) -> UniquePendingId {
        self.pending
    }

    pub const fn proc_id(self) -> ProcCheckpointUniqueId {
        self.proc_id
    }

    pub const fn write_timestamp_us(self) -> CommitWriteTimestampUs {
        self.write_timestamp_us
    }

    pub const fn write_kind(self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub const fn plan_digest(self) -> PendingCounterPlanDigest {
        self.plan_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingCounterQueryKind {
    ReadCounter = 1,
    InsertCounterIfAbsent = 2,
    CompareAndSetCounter = 3,
    ReadOwnership = 4,
    ClaimOwnershipIfAbsent = 5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCounterQuery {
    kind: PendingCounterQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingCounterQuery {
    pub const fn kind(&self) -> PendingCounterQueryKind {
        self.kind
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCounterQueries {
    read_counter: PendingCounterQuery,
    insert_counter_if_absent: PendingCounterQuery,
    compare_and_set_counter: PendingCounterQuery,
    read_ownership: PendingCounterQuery,
    claim_ownership_if_absent: PendingCounterQuery,
}

impl PendingCounterQueries {
    pub fn new(
        no_tablet_keyspace: &CqlKeyspaceName,
        standard_keyspace: &CqlKeyspaceName,
    ) -> Self {
        let counter = physical_descriptor(
            ScyllaPhysicalTableId::U64CounterSingleton,
        )
        .physical_name;
        let owner = physical_descriptor(
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
        )
        .physical_name;
        let counter_qualified =
            format!("{}.{counter}", no_tablet_keyspace.as_str());
        let owner_qualified =
            format!("{}.{owner}", standard_keyspace.as_str());
        let owner_catalog = PendingContextQueries::new(standard_keyspace);
        let owner_claim = owner_catalog.pending_to_proc_claim_if_absent();
        Self {
            read_counter: PendingCounterQuery {
                kind: PendingCounterQueryKind::ReadCounter,
                cql: format!(
                    "SELECT value FROM {counter_qualified} WHERE obj_id = ?"
                ),
                bind_shape: &["counter_slot:BIGINT"],
            },
            insert_counter_if_absent: PendingCounterQuery {
                kind: PendingCounterQueryKind::InsertCounterIfAbsent,
                cql: format!(
                    "INSERT INTO {counter_qualified} (obj_id, value) VALUES (?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "counter_slot:BIGINT",
                    "candidate_pending:BIGINT",
                ],
            },
            compare_and_set_counter: PendingCounterQuery {
                kind: PendingCounterQueryKind::CompareAndSetCounter,
                cql: format!(
                    "UPDATE {counter_qualified} SET value = ? WHERE obj_id = ? IF value = ?"
                ),
                bind_shape: &[
                    "candidate_pending:BIGINT",
                    "counter_slot:BIGINT",
                    "expected_pending:BIGINT",
                ],
            },
            read_ownership: PendingCounterQuery {
                kind: PendingCounterQueryKind::ReadOwnership,
                cql: format!(
                    "SELECT value FROM {owner_qualified} WHERE obj_id = ? LIMIT 1"
                ),
                bind_shape: &["candidate_pending:BIGINT"],
            },
            claim_ownership_if_absent: PendingCounterQuery {
                kind: PendingCounterQueryKind::ClaimOwnershipIfAbsent,
                cql: owner_claim.cql().to_owned(),
                bind_shape: owner_claim.bind_shape(),
            },
        }
    }

    pub const fn read_counter(&self) -> &PendingCounterQuery {
        &self.read_counter
    }

    pub const fn insert_counter_if_absent(&self) -> &PendingCounterQuery {
        &self.insert_counter_if_absent
    }

    pub const fn compare_and_set_counter(&self) -> &PendingCounterQuery {
        &self.compare_and_set_counter
    }

    pub const fn read_ownership(&self) -> &PendingCounterQuery {
        &self.read_ownership
    }

    pub const fn claim_ownership_if_absent(&self) -> &PendingCounterQuery {
        &self.claim_ownership_if_absent
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [
            self.read_counter(),
            self.insert_counter_if_absent(),
            self.compare_and_set_counter(),
            self.read_ownership(),
            self.claim_ownership_if_absent(),
        ] {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.kind(),
                query.cql(),
                query.bind_shape().join(",")
            ));
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedPendingCounterAllocation {
    expected: PendingCounterExpected,
    candidate: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
    write_timestamp_us: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    digest: PendingCounterPlanDigest,
}

impl SealedPendingCounterAllocation {
    pub fn try_for_commit(
        expected: PendingCounterExpected,
        proc_id: ProcCheckpointUniqueId,
        write_timestamp_us: CommitWriteTimestampUs,
    ) -> Result<Self, PendingCounterPlanError> {
        Self::try_build(
            expected,
            proc_id,
            write_timestamp_us,
            TimestampedWriteKind::AuthorityCommit,
        )
    }

    pub fn try_for_rollback(
        expected: PendingCounterExpected,
        proc_id: ProcCheckpointUniqueId,
        write_timestamp_us: NewBranchWriteTimestampUs,
    ) -> Result<Self, PendingCounterPlanError> {
        Self::try_build(
            expected,
            proc_id,
            write_timestamp_us.as_commit_timestamp(),
            TimestampedWriteKind::NewBranchAfterFence,
        )
    }

    fn try_build(
        expected: PendingCounterExpected,
        proc_id: ProcCheckpointUniqueId,
        write_timestamp_us: CommitWriteTimestampUs,
        write_kind: TimestampedWriteKind,
    ) -> Result<Self, PendingCounterPlanError> {
        if proc_id.as_u128() == 0 {
            return Err(PendingCounterPlanError::ZeroProcId);
        }
        let candidate_raw = match expected {
            PendingCounterExpected::Absent => 1,
            PendingCounterExpected::Present(current) => current
                .get()
                .checked_add(1)
                .ok_or(PendingCounterPlanError::CounterExhausted)?,
        };
        let candidate = UniquePendingId::try_new(candidate_raw)
            .map_err(|_| PendingCounterPlanError::CounterExhausted)?;
        let digest = allocation_digest(
            expected,
            candidate,
            proc_id,
            write_timestamp_us,
            write_kind,
        );
        Ok(Self {
            expected,
            candidate,
            proc_id,
            write_timestamp_us,
            write_kind,
            digest,
        })
    }

    pub const fn expected(&self) -> PendingCounterExpected {
        self.expected
    }

    pub const fn candidate(&self) -> UniquePendingId {
        self.candidate
    }

    pub const fn proc_id(&self) -> ProcCheckpointUniqueId {
        self.proc_id
    }

    pub const fn write_timestamp_us(&self) -> CommitWriteTimestampUs {
        self.write_timestamp_us
    }

    pub const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub const fn digest(&self) -> PendingCounterPlanDigest {
        self.digest
    }

    pub fn counter_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(counter_slot_i64())]
    }

    pub fn counter_lwt_bind_values(&self) -> Vec<PrototypeBindValue> {
        match self.expected {
            PendingCounterExpected::Absent => vec![
                PrototypeBindValue::BigInt(counter_slot_i64()),
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.candidate.get(),
                )),
            ],
            PendingCounterExpected::Present(expected) => vec![
                PrototypeBindValue::BigInt(u64_to_i64_exact(
                    self.candidate.get(),
                )),
                PrototypeBindValue::BigInt(counter_slot_i64()),
                PrototypeBindValue::BigInt(u64_to_i64_exact(expected.get())),
            ],
        }
    }

    pub fn ownership_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(u64_to_i64_exact(
            self.candidate.get(),
        ))]
    }

    pub fn ownership_claim_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(
                self.candidate.get(),
            )),
            PrototypeBindValue::Uuid(*self.proc_id.as_bytes()),
        ]
    }

    pub fn reconcile(
        &self,
        counter: PendingCounterReadState,
        ownership: PendingOwnershipReadState,
    ) -> PendingCounterReconcileAction {
        if counter == expected_read_state(self.expected) {
            return match ownership {
                PendingOwnershipReadState::Unclaimed => {
                    PendingCounterReconcileAction::ClaimOwnership
                }
                PendingOwnershipReadState::OwnedBy(owner)
                    if owner == self.proc_id =>
                {
                    PendingCounterReconcileAction::ApplyCounterLwt
                }
                PendingOwnershipReadState::OwnedBy(owner) => {
                    PendingCounterReconcileAction::Conflict(
                        PendingCounterConflict::OwnedByOther {
                            candidate: self.candidate,
                            owner,
                        },
                    )
                }
            };
        }
        match counter {
            PendingCounterReadState::Current(current)
                if current == self.candidate =>
            {
                match ownership {
                    PendingOwnershipReadState::Unclaimed => {
                        PendingCounterReconcileAction::Conflict(
                            PendingCounterConflict::CounterAdvancedWithoutOwner {
                                candidate: self.candidate,
                            },
                        )
                    }
                    PendingOwnershipReadState::OwnedBy(owner)
                        if owner == self.proc_id =>
                    {
                        PendingCounterReconcileAction::Owned(
                            self.verified_ownership(),
                        )
                    }
                    PendingOwnershipReadState::OwnedBy(owner) => {
                        PendingCounterReconcileAction::Conflict(
                            PendingCounterConflict::OwnedByOther {
                                candidate: self.candidate,
                                owner,
                            },
                        )
                    }
                }
            }
            PendingCounterReadState::Current(current)
                if current > self.candidate =>
            {
                match ownership {
                    PendingOwnershipReadState::OwnedBy(owner)
                        if owner == self.proc_id =>
                    {
                        PendingCounterReconcileAction::Owned(
                            self.verified_ownership(),
                        )
                    }
                    PendingOwnershipReadState::Unclaimed => {
                        PendingCounterReconcileAction::Conflict(
                            PendingCounterConflict::CandidateSuperseded {
                                candidate: self.candidate,
                                current,
                                owner: None,
                            },
                        )
                    }
                    PendingOwnershipReadState::OwnedBy(owner) => {
                        PendingCounterReconcileAction::Conflict(
                            PendingCounterConflict::CandidateSuperseded {
                                candidate: self.candidate,
                                current,
                                owner: Some(owner),
                            },
                        )
                    }
                }
            }
            actual => PendingCounterReconcileAction::Conflict(
                PendingCounterConflict::UnexpectedCounter {
                    expected: self.expected,
                    candidate: self.candidate,
                    actual,
                },
            ),
        }
    }

    fn verified_ownership(&self) -> VerifiedPendingOwnership {
        VerifiedPendingOwnership {
            pending: self.candidate,
            proc_id: self.proc_id,
            write_timestamp_us: self.write_timestamp_us,
            write_kind: self.write_kind,
            plan_digest: self.digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCounterConflict {
    UnexpectedCounter {
        expected: PendingCounterExpected,
        candidate: UniquePendingId,
        actual: PendingCounterReadState,
    },
    OwnedByOther {
        candidate: UniquePendingId,
        owner: ProcCheckpointUniqueId,
    },
    CandidateSuperseded {
        candidate: UniquePendingId,
        current: UniquePendingId,
        owner: Option<ProcCheckpointUniqueId>,
    },
    CounterAdvancedWithoutOwner {
        candidate: UniquePendingId,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCounterReconcileAction {
    ApplyCounterLwt,
    ClaimOwnership,
    Owned(VerifiedPendingOwnership),
    Conflict(PendingCounterConflict),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCounterAllocationOutcome {
    Owned(VerifiedPendingOwnership),
    Conflict(PendingCounterConflict),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCounterLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
    read: Consistency,
}

impl PendingCounterLwtContract {
    pub const fn rf3_default() -> Self {
        Self {
            regular: Consistency::Quorum,
            serial: SerialConsistency::LocalSerial,
            read: Consistency::LocalSerial,
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

struct PreparedPendingCounter {
    read_counter: PreparedStatement,
    insert_counter_if_absent: PreparedStatement,
    compare_and_set_counter: PreparedStatement,
    read_ownership: PreparedStatement,
    claim_ownership_if_absent: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct PendingCounterAdapter {
    session: Arc<Session>,
    queries: PendingCounterQueries,
    contract: PendingCounterLwtContract,
    prepared: PreparedPendingCounter,
}

#[allow(dead_code)]
impl PendingCounterAdapter {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        no_tablet_keyspace: CqlKeyspaceName,
        standard_keyspace: CqlKeyspaceName,
    ) -> Result<Self, PendingCounterAdapterError> {
        let queries = PendingCounterQueries::new(
            &no_tablet_keyspace,
            &standard_keyspace,
        );
        let contract = PendingCounterLwtContract::rf3_default();
        let prepared = PreparedPendingCounter {
            read_counter: prepare_read(
                &session,
                queries.read_counter().cql(),
                contract.read(),
            )
            .await?,
            insert_counter_if_absent: prepare_lwt(
                &session,
                queries.insert_counter_if_absent().cql(),
                contract,
            )
            .await?,
            compare_and_set_counter: prepare_lwt(
                &session,
                queries.compare_and_set_counter().cql(),
                contract,
            )
            .await?,
            read_ownership: prepare_read(
                &session,
                queries.read_ownership().cql(),
                contract.read(),
            )
            .await?,
            claim_ownership_if_absent: prepare_lwt(
                &session,
                queries.claim_ownership_if_absent().cql(),
                contract,
            )
            .await?,
        };
        Ok(Self {
            session,
            queries,
            contract,
            prepared,
        })
    }

    pub(crate) const fn queries(&self) -> &PendingCounterQueries {
        &self.queries
    }

    pub(crate) const fn lwt_contract(&self) -> PendingCounterLwtContract {
        self.contract
    }

    pub(crate) async fn allocate(
        &self,
        plan: &SealedPendingCounterAllocation,
    ) -> Result<PendingCounterAllocationOutcome, PendingCounterAdapterError> {
        let counter = self.read_counter().await?;
        let ownership = self.read_ownership(plan.candidate).await?;
        match plan.reconcile(counter, ownership) {
            PendingCounterReconcileAction::ClaimOwnership => {
                self.claim_ownership(plan).await
            }
            PendingCounterReconcileAction::ApplyCounterLwt => {
                self.advance_counter(plan).await
            }
            PendingCounterReconcileAction::Owned(ownership) => {
                Ok(PendingCounterAllocationOutcome::Owned(ownership))
            }
            PendingCounterReconcileAction::Conflict(conflict) => {
                Ok(PendingCounterAllocationOutcome::Conflict(conflict))
            }
        }
    }

    async fn advance_counter(
        &self,
        plan: &SealedPendingCounterAllocation,
    ) -> Result<PendingCounterAllocationOutcome, PendingCounterAdapterError> {
        let counter_result = match plan.expected {
            PendingCounterExpected::Absent => self
                .session
                .execute_unpaged(
                    &self.prepared.insert_counter_if_absent,
                    (
                        counter_slot_i64(),
                        u64_to_i64_exact(plan.candidate.get()),
                    ),
                )
                .await,
            PendingCounterExpected::Present(expected) => self
                .session
                .execute_unpaged(
                    &self.prepared.compare_and_set_counter,
                    (
                        u64_to_i64_exact(plan.candidate.get()),
                        counter_slot_i64(),
                        u64_to_i64_exact(expected.get()),
                    ),
                )
                .await,
        };
        let counter_execute_error = match counter_result {
            Ok(result) => {
                decode_lwt_applied(result)?;
                None
            }
            Err(error) => Some(error.to_string()),
        };

        let counter = self.read_counter().await?;
        let ownership = self.read_ownership(plan.candidate).await?;
        match plan.reconcile(counter, ownership) {
            PendingCounterReconcileAction::ApplyCounterLwt => {
                if let Some(execute_error) = counter_execute_error {
                    return Err(PendingCounterAdapterError::IndeterminateCounter {
                        execute_error,
                    });
                }
                Err(PendingCounterAdapterError::CounterNotAdvanced)
            }
            PendingCounterReconcileAction::ClaimOwnership => {
                Err(PendingCounterAdapterError::OwnershipLostBeforeCounter)
            }
            PendingCounterReconcileAction::Owned(ownership) => {
                Ok(PendingCounterAllocationOutcome::Owned(ownership))
            }
            PendingCounterReconcileAction::Conflict(conflict) => {
                Ok(PendingCounterAllocationOutcome::Conflict(conflict))
            }
        }
    }

    async fn claim_ownership(
        &self,
        plan: &SealedPendingCounterAllocation,
    ) -> Result<PendingCounterAllocationOutcome, PendingCounterAdapterError> {
        let result = self
            .session
            .execute_unpaged(
                &self.prepared.claim_ownership_if_absent,
                (
                    u64_to_i64_exact(plan.candidate.get()),
                    Uuid::from_u128(plan.proc_id.as_u128()),
                ),
            )
            .await;
        let claim_error = match result {
            Ok(result) => {
                decode_lwt_applied(result)?;
                None
            }
            Err(error) => Some(error.to_string()),
        };
        let counter = self.read_counter().await?;
        let ownership = self.read_ownership(plan.candidate).await?;
        match plan.reconcile(counter, ownership) {
            PendingCounterReconcileAction::ApplyCounterLwt => {
                self.advance_counter(plan).await
            }
            PendingCounterReconcileAction::Owned(verified) => {
                Ok(PendingCounterAllocationOutcome::Owned(verified))
            }
            PendingCounterReconcileAction::Conflict(conflict) => {
                Ok(PendingCounterAllocationOutcome::Conflict(conflict))
            }
            _ if claim_error.is_some() => {
                Err(PendingCounterAdapterError::IndeterminateOwnership {
                    execute_error: claim_error.expect("checked"),
                })
            }
            _ => Err(PendingCounterAdapterError::OwnershipNotClaimed),
        }
    }

    async fn read_counter(
        &self,
    ) -> Result<PendingCounterReadState, PendingCounterAdapterError> {
        let result = self
            .session
            .execute_unpaged(
                &self.prepared.read_counter,
                (counter_slot_i64(),),
            )
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<(Option<i64>,)>()
            .map_err(cql_error)?;
        match row.and_then(|(value,)| value) {
            None => Ok(PendingCounterReadState::Uninitialized),
            Some(value) if value >= 0 => {
                let pending = UniquePendingId::try_new(i64_to_u64_exact(value))
                    .map_err(|_| PendingCounterAdapterError::InvalidCounter(value))?;
                Ok(PendingCounterReadState::Current(pending))
            }
            Some(value) => Err(PendingCounterAdapterError::InvalidCounter(value)),
        }
    }

    async fn read_ownership(
        &self,
        pending: UniquePendingId,
    ) -> Result<PendingOwnershipReadState, PendingCounterAdapterError> {
        let result = self
            .session
            .execute_unpaged(
                &self.prepared.read_ownership,
                (u64_to_i64_exact(pending.get()),),
            )
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<(Option<Uuid>,)>()
            .map_err(cql_error)?;
        Ok(match row.and_then(|(value,)| value) {
            None => PendingOwnershipReadState::Unclaimed,
            Some(value) => PendingOwnershipReadState::OwnedBy(
                ProcCheckpointUniqueId::from_u128(value.as_u128()),
            ),
        })
    }
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: PendingCounterLwtContract,
) -> Result<PreparedStatement, PendingCounterAdapterError> {
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
) -> Result<PreparedStatement, PendingCounterAdapterError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_lwt_applied(
    result: QueryResult,
) -> Result<bool, PendingCounterAdapterError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingCounterAdapterError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(PendingCounterAdapterError::InvalidAppliedColumn),
    }
}

fn expected_read_state(
    expected: PendingCounterExpected,
) -> PendingCounterReadState {
    match expected {
        PendingCounterExpected::Absent => PendingCounterReadState::Uninitialized,
        PendingCounterExpected::Present(value) => {
            PendingCounterReadState::Current(value)
        }
    }
}

fn counter_slot_i64() -> i64 {
    u64_to_i64_exact(U64CounterSlot::UniquePending as u8 as u64)
}

fn allocation_digest(
    expected: PendingCounterExpected,
    candidate: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
) -> PendingCounterPlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/pending-counter-allocation/v1");
    match expected {
        PendingCounterExpected::Absent => hasher.update([0]),
        PendingCounterExpected::Present(value) => {
            hasher.update([1]);
            hasher.update(value.get().to_be_bytes());
        }
    }
    hasher.update(candidate.get().to_be_bytes());
    hasher.update(proc_id.as_bytes());
    hasher.update(timestamp.as_i64().to_be_bytes());
    hasher.update([write_kind as u8]);
    PendingCounterPlanDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingCounterPlanError {
    ZeroProcId,
    CounterExhausted,
}

impl fmt::Display for PendingCounterPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pending counter allocation rejected: {self:?}")
    }
}

impl Error for PendingCounterPlanError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingCounterAdapterError {
    MissingAppliedColumn,
    InvalidAppliedColumn,
    InvalidCounter(i64),
    CounterNotAdvanced,
    OwnershipNotClaimed,
    OwnershipLostBeforeCounter,
    IndeterminateCounter { execute_error: String },
    IndeterminateOwnership { execute_error: String },
    Cql(String),
}

impl fmt::Display for PendingCounterAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pending counter adapter failed: {self:?}")
    }
}

impl Error for PendingCounterAdapterError {}

fn cql_error(error: impl fmt::Display) -> PendingCounterAdapterError {
    PendingCounterAdapterError::Cql(error.to_string())
}
