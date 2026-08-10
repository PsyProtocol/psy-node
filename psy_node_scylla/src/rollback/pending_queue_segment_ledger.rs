//! Default-off no-tablet LWT adapter for one authority's recoverable NATS
//! generation-to-segment assignments and bounded active-segment rotation.
//!
//! A reservation is charged once per generation. The Coordinator's three
//! source artifacts (or a Realm's one source artifact) consume the same
//! opaque assignment receipt. Rotation uses a durable staging CAS followed by
//! a Provisioned-bound activation CAS. Segment release remains a separate
//! terminal/lifecycle operation.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::{
    queue::recoverable_ephemeral::PendingQueueCaptureContext,
};
use psy_node_nats::recoverable_assignment::{
    PendingQueueGenerationSegmentAssignment,
    PendingQueueSegmentLedgerBootstrap, PendingQueueSegmentLedgerError,
    PendingQueueSegmentLedgerKey, PendingQueueSegmentLedgerRevision,
    PendingQueueSegmentLedgerSlot, PendingQueueSegmentReservationPlan,
    PendingQueueSegmentRotationActivationPlan,
    PendingQueueSegmentRotationStagePlan, StoredPendingQueueSegmentLedger,
};
use psy_node_nats::recoverable_segment::{
    RecoverableNatsSegmentContractDigest, RecoverableNatsSegmentId,
    RecoverableNatsStreamSegment, RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    pending_queue_stream_provision::PersistedPendingQueueStreamProvisionedReceipt,
    BranchExactDeploymentNoTabletKeyspace,
};

pub(super) const SEGMENT_LEDGER_TABLE: &str =
    "branch_exact_pending_queue_segment_ledger_v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-segment-ledger-store/v1";
const CLOSURE_SNAPSHOT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-segment-ledger-closure/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingQueueSegmentLedgerQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSegmentLedgerQuery {
    id: PendingQueueSegmentLedgerQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingQueueSegmentLedgerQuery {
    pub const fn id(&self) -> PendingQueueSegmentLedgerQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

const READ_BIND: &[&str] = &["ledger_slot:BLOB"];
const BOOTSTRAP_BIND: &[&str] = &[
    "ledger_slot:BLOB",
    "revision:BIGINT",
    "ledger_payload:BLOB",
];
const CAS_BIND: &[&str] = &[
    "candidate_revision:BIGINT",
    "candidate_payload:BLOB",
    "ledger_slot:BLOB",
    "expected_revision:BIGINT",
    "expected_payload:BLOB",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSegmentLedgerQueries {
    create_table: PendingQueueSegmentLedgerQuery,
    read: PendingQueueSegmentLedgerQuery,
    bootstrap: PendingQueueSegmentLedgerQuery,
    compare_and_set: PendingQueueSegmentLedgerQuery,
}

impl PendingQueueSegmentLedgerQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{SEGMENT_LEDGER_TABLE}", keyspace.as_str());
        Self {
            create_table: PendingQueueSegmentLedgerQuery {
                id: PendingQueueSegmentLedgerQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {table} (ledger_slot blob PRIMARY KEY, revision bigint, ledger_payload blob)"
                ),
                bind_shape: &[],
            },
            read: PendingQueueSegmentLedgerQuery {
                id: PendingQueueSegmentLedgerQueryId::Read,
                cql: format!(
                    "SELECT revision, ledger_payload FROM {table} WHERE ledger_slot = ?"
                ),
                bind_shape: READ_BIND,
            },
            bootstrap: PendingQueueSegmentLedgerQuery {
                id: PendingQueueSegmentLedgerQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {table} (ledger_slot, revision, ledger_payload) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: BOOTSTRAP_BIND,
            },
            compare_and_set: PendingQueueSegmentLedgerQuery {
                id: PendingQueueSegmentLedgerQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {table} SET revision = ?, ledger_payload = ? WHERE ledger_slot = ? IF revision = ? AND ledger_payload = ?"
                ),
                bind_shape: CAS_BIND,
            },
        }
    }

    pub const fn create_table(&self) -> &PendingQueueSegmentLedgerQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &PendingQueueSegmentLedgerQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &PendingQueueSegmentLedgerQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &PendingQueueSegmentLedgerQuery {
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

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct LedgerReadBinding {
    ledger_slot: Vec<u8>,
}

impl LedgerReadBinding {
    fn new(slot: PendingQueueSegmentLedgerSlot) -> Self {
        Self {
            ledger_slot: slot.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct LedgerBootstrapBinding {
    ledger_slot: Vec<u8>,
    revision: i64,
    ledger_payload: Vec<u8>,
}

impl LedgerBootstrapBinding {
    fn new(bootstrap: &PendingQueueSegmentLedgerBootstrap) -> Self {
        let candidate = bootstrap.candidate();
        Self {
            ledger_slot: candidate.key().slot().as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            ledger_payload: candidate.to_persisted_bytes(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct LedgerCasBinding {
    candidate_revision: i64,
    candidate_payload: Vec<u8>,
    ledger_slot: Vec<u8>,
    expected_revision: i64,
    expected_payload: Vec<u8>,
}

impl LedgerCasBinding {
    fn try_new(
        expected: &StoredPendingQueueSegmentLedger,
        candidate: &StoredPendingQueueSegmentLedger,
    ) -> Result<Self, PendingQueueSegmentLedgerStoreError> {
        if expected.key() != candidate.key()
            || candidate.revision().get()
                != expected
                    .revision()
                    .get()
                    .checked_add(1)
                    .ok_or(PendingQueueSegmentLedgerStoreError::RevisionOverflow)?
        {
            return Err(PendingQueueSegmentLedgerStoreError::InvalidTransition);
        }
        Ok(Self {
            candidate_revision: candidate.revision().as_i64(),
            candidate_payload: candidate.to_persisted_bytes(),
            ledger_slot: expected.key().slot().as_bytes().to_vec(),
            expected_revision: expected.revision().as_i64(),
            expected_payload: expected.to_persisted_bytes(),
        })
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct LedgerDbRow {
    revision: i64,
    ledger_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSegmentLedgerStoreFingerprint([u8; 32]);

impl PendingQueueSegmentLedgerStoreFingerprint {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLedgerStoreError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLedgerStoreError::ClosureBindingMismatch)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueSegmentLedgerQueries,
) -> PendingQueueSegmentLedgerStoreFingerprint {
    let mut hasher = Sha256::new();
    for part in [
        STORE_FINGERPRINT_DOMAIN,
        keyspace.as_str().as_bytes(),
        queries.render_golden().as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    PendingQueueSegmentLedgerStoreFingerprint(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSegmentLedgerReadState {
    Uninitialized,
    Current(StoredPendingQueueSegmentLedger),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSegmentLedgerWriteOutcome {
    Applied(StoredPendingQueueSegmentLedger),
    Idempotent(StoredPendingQueueSegmentLedger),
    Conflict(StoredPendingQueueSegmentLedger),
}

impl PendingQueueSegmentLedgerWriteOutcome {
    pub const fn current(&self) -> &StoredPendingQueueSegmentLedger {
        match self {
            Self::Applied(current) | Self::Idempotent(current) | Self::Conflict(current) => current,
        }
    }
}

/// Opaque exact-readback proof of one once-per-generation reservation.
/// It is deliberately not `Clone` and has no public constructor.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::PendingQueueSegmentAssignmentReceipt;
/// let _ = PendingQueueSegmentAssignmentReceipt {};
/// ```
#[derive(Debug)]
pub struct PendingQueueSegmentAssignmentReceipt {
    store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_slot: PendingQueueSegmentLedgerSlot,
    ledger_revision: PendingQueueSegmentLedgerRevision,
    assignment: PendingQueueGenerationSegmentAssignment,
}

/// Opaque exact-readback proof that one deterministic successor is durably
/// staged. It grants no NATS create authority by itself; the provision store
/// consumes it through its operator-only path.
#[derive(Debug)]
pub(super) struct PendingQueueSegmentRotationStagedReceipt {
    store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_key: PendingQueueSegmentLedgerKey,
    ledger_revision: PendingQueueSegmentLedgerRevision,
    segment: RecoverableNatsStreamSegment,
}

impl PendingQueueSegmentRotationStagedReceipt {
    pub(super) const fn ledger_key(&self) -> &PendingQueueSegmentLedgerKey {
        &self.ledger_key
    }

    pub(super) const fn ledger_revision(&self) -> PendingQueueSegmentLedgerRevision {
        self.ledger_revision
    }

    pub(super) const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.segment
    }
}

#[derive(Debug)]
pub(super) struct PendingQueueSegmentRotationActivatedReceipt {
    store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_key: PendingQueueSegmentLedgerKey,
    ledger_revision: PendingQueueSegmentLedgerRevision,
    segment: RecoverableNatsStreamSegment,
}

impl PendingQueueSegmentRotationActivatedReceipt {
    pub(super) const fn ledger_revision(&self) -> PendingQueueSegmentLedgerRevision {
        self.ledger_revision
    }

    pub(super) const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.segment
    }
}

/// Fresh assignment-to-segment resolution. The assignment revision is
/// immutable while the ledger revision may continue advancing on another
/// segment.
#[derive(Debug)]
pub(super) struct PendingQueueSegmentAssignmentRouteReceipt {
    store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_key: PendingQueueSegmentLedgerKey,
    assignment: PendingQueueSegmentAssignmentReceipt,
    segment: RecoverableNatsStreamSegment,
}

impl PendingQueueSegmentAssignmentRouteReceipt {
    pub(super) const fn ledger_key(&self) -> &PendingQueueSegmentLedgerKey {
        &self.ledger_key
    }

    pub(super) const fn assignment(&self) -> &PendingQueueSegmentAssignmentReceipt {
        &self.assignment
    }

    pub(super) const fn segment(&self) -> &RecoverableNatsStreamSegment {
        &self.segment
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSegmentClosureDigest([u8; 32]);

impl PendingQueueSegmentClosureDigest {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLedgerStoreError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLedgerStoreError::ClosureBindingMismatch)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact, revalidatable observation for one physical segment. The closure
/// commitment is segment-local: unrelated assignments on a newer active
/// segment may advance the ledger without invalidating this frozen member set.
#[derive(Debug)]
pub(super) struct PendingQueueSegmentClosureSnapshot {
    store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_key: PendingQueueSegmentLedgerKey,
    ledger_revision: PendingQueueSegmentLedgerRevision,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    ledger_payload_digest: PendingQueueSegmentClosureDigest,
    assignments: Vec<PendingQueueSegmentAssignmentReceipt>,
}

impl PendingQueueSegmentClosureSnapshot {
    pub(super) const fn store_fingerprint(
        &self,
    ) -> PendingQueueSegmentLedgerStoreFingerprint {
        self.store_fingerprint
    }

    pub(super) const fn ledger_revision(&self) -> PendingQueueSegmentLedgerRevision {
        self.ledger_revision
    }

    pub(super) const fn ledger_slot(&self) -> PendingQueueSegmentLedgerSlot {
        self.ledger_key.slot()
    }

    pub(super) const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub(super) const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub(super) const fn ledger_payload_digest(&self) -> PendingQueueSegmentClosureDigest {
        self.ledger_payload_digest
    }

    pub(super) fn assignments(&self) -> &[PendingQueueSegmentAssignmentReceipt] {
        &self.assignments
    }
}

impl PendingQueueSegmentAssignmentReceipt {
    pub const fn store_fingerprint(&self) -> PendingQueueSegmentLedgerStoreFingerprint {
        self.store_fingerprint
    }

    pub const fn ledger_slot(&self) -> PendingQueueSegmentLedgerSlot {
        self.ledger_slot
    }

    pub const fn ledger_revision(&self) -> PendingQueueSegmentLedgerRevision {
        self.ledger_revision
    }

    pub const fn assignment(&self) -> &PendingQueueGenerationSegmentAssignment {
        &self.assignment
    }
}

pub struct ScyllaPendingQueueSegmentLedgerStore {
    session: Arc<Session>,
    queries: PendingQueueSegmentLedgerQueries,
    fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaPendingQueueSegmentLedgerStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueSegmentLedgerStoreError> {
        let queries = PendingQueueSegmentLedgerQueries::new(keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueSegmentLedgerStoreError> {
        let queries = PendingQueueSegmentLedgerQueries::new(&keyspace);
        let fingerprint = store_fingerprint(&keyspace, &queries);
        Ok(Self {
            read: prepare_regular(&session, queries.read().cql()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap().cql()).await?,
            compare_and_set: prepare_lwt(&session, queries.compare_and_set().cql()).await?,
            session,
            queries,
            fingerprint,
        })
    }

    pub const fn queries(&self) -> &PendingQueueSegmentLedgerQueries {
        &self.queries
    }

    pub const fn fingerprint(&self) -> PendingQueueSegmentLedgerStoreFingerprint {
        self.fingerprint
    }

    pub(super) fn is_bound_to_keyspace(
        &self,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> bool {
        self.fingerprint == store_fingerprint(keyspace, &PendingQueueSegmentLedgerQueries::new(keyspace))
    }

    pub async fn read(
        &self,
        key: &PendingQueueSegmentLedgerKey,
    ) -> Result<PendingQueueSegmentLedgerReadState, PendingQueueSegmentLedgerStoreError> {
        self.read_slot(key.slot(), Some(key)).await
    }

    pub async fn bootstrap(
        &self,
        bootstrap: &PendingQueueSegmentLedgerBootstrap,
    ) -> Result<PendingQueueSegmentLedgerWriteOutcome, PendingQueueSegmentLedgerStoreError> {
        let candidate = bootstrap.candidate();
        let execution = self
            .session
            .execute_unpaged(&self.bootstrap, LedgerBootstrapBinding::new(bootstrap))
            .await;
        self.finish_write(execution, candidate).await
    }

    pub async fn reserve_generation(
        &self,
        key: &PendingQueueSegmentLedgerKey,
        context: PendingQueueCaptureContext,
    ) -> Result<PendingQueueSegmentAssignmentReceipt, PendingQueueSegmentLedgerStoreError> {
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await? else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        match current.reserve_generation(context).map_err(model)? {
            PendingQueueSegmentReservationPlan::Idempotent(assignment) => {
                self.receipt_from_exact(&current, assignment)
            }
            PendingQueueSegmentReservationPlan::Advance {
                expected,
                candidate,
                assignment,
            } => {
                let binding = LedgerCasBinding::try_new(&expected, &candidate)?;
                let execution = self
                    .session
                    .execute_unpaged(&self.compare_and_set, binding)
                    .await;
                let outcome = self.finish_write(execution, &candidate).await?;
                match outcome {
                    PendingQueueSegmentLedgerWriteOutcome::Applied(current)
                    | PendingQueueSegmentLedgerWriteOutcome::Idempotent(current) => {
                        self.receipt_from_exact(&current, assignment)
                    }
                    PendingQueueSegmentLedgerWriteOutcome::Conflict(current) => {
                        Err(PendingQueueSegmentLedgerStoreError::Conflict {
                            current_revision: current.revision(),
                        })
                    }
                }
            }
        }
    }

    /// Stage the deterministic `highest_segment_id + 1` successor. No caller
    /// supplied segment ID, stream name, subject or retention contract crosses
    /// this boundary.
    pub(super) async fn stage_next_rotation(
        &self,
        key: &PendingQueueSegmentLedgerKey,
    ) -> Result<PendingQueueSegmentRotationStagedReceipt, PendingQueueSegmentLedgerStoreError> {
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await? else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let plan = current.stage_next_rotation().map_err(model)?;
        let staged_segment = plan.current().stream_segment(plan.staged().segment_id()).map_err(model)?;
        let stored = match plan {
            PendingQueueSegmentRotationStagePlan::Idempotent { current, .. } => current,
            PendingQueueSegmentRotationStagePlan::Advance {
                expected,
                candidate,
                ..
            } => {
                let binding = LedgerCasBinding::try_new(&expected, &candidate)?;
                let execution = self
                    .session
                    .execute_unpaged(&self.compare_and_set, binding)
                    .await;
                match self.finish_write(execution, &candidate).await? {
                    PendingQueueSegmentLedgerWriteOutcome::Applied(current)
                    | PendingQueueSegmentLedgerWriteOutcome::Idempotent(current) => current,
                    PendingQueueSegmentLedgerWriteOutcome::Conflict(current) => {
                        return Err(PendingQueueSegmentLedgerStoreError::Conflict {
                            current_revision: current.revision(),
                        })
                    }
                }
            }
        };
        let exact = stored
            .stream_segment(staged_segment.segment_id())
            .map_err(model)?;
        if stored.staged_segment_id() != Some(exact.segment_id()) || exact != staged_segment {
            return Err(PendingQueueSegmentLedgerStoreError::RotationBindingMismatch);
        }
        Ok(PendingQueueSegmentRotationStagedReceipt {
            store_fingerprint: self.fingerprint,
            ledger_key: key.clone(),
            ledger_revision: stored.revision(),
            segment: exact,
        })
    }

    pub(super) async fn revalidate_staged_rotation(
        &self,
        staged: &PendingQueueSegmentRotationStagedReceipt,
    ) -> Result<(), PendingQueueSegmentLedgerStoreError> {
        if staged.store_fingerprint != self.fingerprint {
            return Err(PendingQueueSegmentLedgerStoreError::RotationBindingMismatch);
        }
        let PendingQueueSegmentLedgerReadState::Current(current) =
            self.read(&staged.ledger_key).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let exact = current
            .stream_segment(staged.segment.segment_id())
            .map_err(model)?;
        if current.revision() != staged.ledger_revision
            || current.staged_segment_id() != Some(staged.segment.segment_id())
            || exact != staged.segment
        {
            return Err(PendingQueueSegmentLedgerStoreError::RotationBindingMismatch);
        }
        Ok(())
    }

    /// Consume a freshly revalidated durable Provisioned receipt and switch
    /// the ledger's admitting segment with one full-payload LWT.
    pub(super) async fn activate_staged_rotation(
        &self,
        staged: &PendingQueueSegmentRotationStagedReceipt,
        provisioned: &PersistedPendingQueueStreamProvisionedReceipt,
    ) -> Result<PendingQueueSegmentRotationActivatedReceipt, PendingQueueSegmentLedgerStoreError> {
        if staged.store_fingerprint != self.fingerprint
            || provisioned.segment() != &staged.segment
        {
            return Err(PendingQueueSegmentLedgerStoreError::RotationBindingMismatch);
        }
        let PendingQueueSegmentLedgerReadState::Current(current) =
            self.read(&staged.ledger_key).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let plan = current
            .activate_staged_segment(&staged.segment)
            .map_err(model)?;
        let stored = match plan {
            PendingQueueSegmentRotationActivationPlan::Idempotent { current, .. } => current,
            PendingQueueSegmentRotationActivationPlan::Advance {
                expected,
                candidate,
                ..
            } => {
                let binding = LedgerCasBinding::try_new(&expected, &candidate)?;
                let execution = self
                    .session
                    .execute_unpaged(&self.compare_and_set, binding)
                    .await;
                match self.finish_write(execution, &candidate).await? {
                    PendingQueueSegmentLedgerWriteOutcome::Applied(current)
                    | PendingQueueSegmentLedgerWriteOutcome::Idempotent(current) => current,
                    PendingQueueSegmentLedgerWriteOutcome::Conflict(current) => {
                        return Err(PendingQueueSegmentLedgerStoreError::Conflict {
                            current_revision: current.revision(),
                        })
                    }
                }
            }
        };
        let exact = stored
            .stream_segment(staged.segment.segment_id())
            .map_err(model)?;
        if stored.staged_segment_id().is_some()
            || stored.active_segment_id() != exact.segment_id()
            || exact != staged.segment
        {
            return Err(PendingQueueSegmentLedgerStoreError::RotationBindingMismatch);
        }
        Ok(PendingQueueSegmentRotationActivatedReceipt {
            store_fingerprint: self.fingerprint,
            ledger_key: staged.ledger_key.clone(),
            ledger_revision: stored.revision(),
            segment: exact,
        })
    }

    /// Read an assignment already reserved by the generation owner. Edge
    /// publishers are readers of this authority: they may not create a new
    /// reservation merely because a user request arrived.
    pub async fn read_assignment_exact(
        &self,
        key: &PendingQueueSegmentLedgerKey,
        context: PendingQueueCaptureContext,
    ) -> Result<PendingQueueSegmentAssignmentReceipt, PendingQueueSegmentLedgerStoreError> {
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await? else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let assignment = current
            .assignment_for(context)
            .ok_or(PendingQueueSegmentLedgerStoreError::AssignmentMissing)?
            .clone();
        if assignment.context() != context {
            return Err(PendingQueueSegmentLedgerStoreError::AssignmentContextMismatch);
        }
        // Assignments are append-only. A later generation may advance the
        // ledger revision, but it cannot mutate this receipt's assignment or
        // assigned-at revision. Requiring the whole row to remain unchanged
        // here would create a false outage under concurrent reservations.
        self.receipt_from_exact(&current, assignment)
    }

    pub(super) async fn read_assignment_route_exact(
        &self,
        key: &PendingQueueSegmentLedgerKey,
        context: PendingQueueCaptureContext,
    ) -> Result<PendingQueueSegmentAssignmentRouteReceipt, PendingQueueSegmentLedgerStoreError> {
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await? else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let assignment = current
            .assignment_for(context)
            .ok_or(PendingQueueSegmentLedgerStoreError::AssignmentMissing)?
            .clone();
        if assignment.context() != context {
            return Err(PendingQueueSegmentLedgerStoreError::AssignmentContextMismatch);
        }
        let segment = current
            .stream_segment(assignment.segment_id())
            .map_err(model)?;
        if segment.digest() != assignment.contract_digest() {
            return Err(PendingQueueSegmentLedgerStoreError::LiveSegmentMismatch);
        }
        let assignment = self.receipt_from_exact(&current, assignment)?;
        Ok(PendingQueueSegmentAssignmentRouteReceipt {
            store_fingerprint: self.fingerprint,
            ledger_key: key.clone(),
            assignment,
            segment,
        })
    }

    pub(super) async fn revalidate_assignment_route(
        &self,
        receipt: &PendingQueueSegmentAssignmentRouteReceipt,
    ) -> Result<(), PendingQueueSegmentLedgerStoreError> {
        if receipt.store_fingerprint != self.fingerprint
            || receipt.assignment.store_fingerprint != self.fingerprint
            || receipt.assignment.ledger_slot != receipt.ledger_key.slot()
        {
            return Err(PendingQueueSegmentLedgerStoreError::RouteBindingMismatch);
        }
        let PendingQueueSegmentLedgerReadState::Current(current) =
            self.read(&receipt.ledger_key).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let assignment = current
            .assignment_for(receipt.assignment.assignment.context())
            .ok_or(PendingQueueSegmentLedgerStoreError::AssignmentMissing)?;
        let segment = current
            .stream_segment(assignment.segment_id())
            .map_err(model)?;
        if assignment != &receipt.assignment.assignment
            || segment != receipt.segment
            || segment.digest() != assignment.contract_digest()
        {
            return Err(PendingQueueSegmentLedgerStoreError::RouteBindingMismatch);
        }
        Ok(())
    }

    /// Freshly prove that one exact physical segment remains a live member of
    /// the durable ledger. This deliberately ignores unrelated ledger
    /// revision advances caused by append-only assignments, while rejecting a
    /// removed segment or any contract/key drift.
    pub(super) async fn require_live_segment_exact(
        &self,
        key: &PendingQueueSegmentLedgerKey,
        segment: &RecoverableNatsStreamSegment,
    ) -> Result<(), PendingQueueSegmentLedgerStoreError> {
        if segment.generation_key() != key.generation_key()
            || segment.base_namespace() != key.base_namespace()
        {
            return Err(PendingQueueSegmentLedgerStoreError::LiveSegmentMismatch);
        }
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let live = current
            .live_segments()
            .iter()
            .find(|live| live.segment_id() == segment.segment_id())
            .ok_or(PendingQueueSegmentLedgerStoreError::SegmentMissing)?;
        if live.contract_digest() != segment.digest()
            || live.retention() != segment.retention()
        {
            return Err(PendingQueueSegmentLedgerStoreError::LiveSegmentMismatch);
        }
        Ok(())
    }

    /// Freeze the exact assignment set currently owned by one non-admitting
    /// segment. The second read rejects changes to that segment but permits
    /// unrelated progress on another active segment.
    pub(super) async fn observe_segment_closure(
        &self,
        key: &PendingQueueSegmentLedgerKey,
        segment_id: RecoverableNatsSegmentId,
    ) -> Result<PendingQueueSegmentClosureSnapshot, PendingQueueSegmentLedgerStoreError> {
        let PendingQueueSegmentLedgerReadState::Current(current) = self.read(key).await? else {
            return Err(PendingQueueSegmentLedgerStoreError::Uninitialized);
        };
        let snapshot = self.build_segment_closure(&current, segment_id)?;
        self.revalidate_segment_closure(&snapshot).await?;
        Ok(snapshot)
    }

    pub(super) async fn revalidate_segment_closure(
        &self,
        snapshot: &PendingQueueSegmentClosureSnapshot,
    ) -> Result<(), PendingQueueSegmentLedgerStoreError> {
        if snapshot.store_fingerprint != self.fingerprint {
            return Err(PendingQueueSegmentLedgerStoreError::ClosureBindingMismatch);
        }
        let PendingQueueSegmentLedgerReadState::Current(current) =
            self.read(&snapshot.ledger_key).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::ClosureStale);
        };
        let observed = self.build_segment_closure(&current, snapshot.segment_id)?;
        if observed.store_fingerprint != snapshot.store_fingerprint
            || observed.contract_digest != snapshot.contract_digest
            || observed.ledger_payload_digest != snapshot.ledger_payload_digest
            || observed.assignments.len() != snapshot.assignments.len()
            || observed
                .assignments
                .iter()
                .zip(&snapshot.assignments)
                .any(|(left, right)| {
                    left.ledger_revision != right.ledger_revision
                        || left.assignment != right.assignment
                })
        {
            return Err(PendingQueueSegmentLedgerStoreError::ClosureStale);
        }
        Ok(())
    }

    fn build_segment_closure(
        &self,
        current: &StoredPendingQueueSegmentLedger,
        segment_id: RecoverableNatsSegmentId,
    ) -> Result<PendingQueueSegmentClosureSnapshot, PendingQueueSegmentLedgerStoreError> {
        build_segment_closure(self.fingerprint, current, segment_id)
    }

    fn receipt_from_exact(
        &self,
        current: &StoredPendingQueueSegmentLedger,
        assignment: PendingQueueGenerationSegmentAssignment,
    ) -> Result<PendingQueueSegmentAssignmentReceipt, PendingQueueSegmentLedgerStoreError> {
        assignment_receipt(self.fingerprint, current, assignment)
    }

    async fn finish_write(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredPendingQueueSegmentLedger,
    ) -> Result<PendingQueueSegmentLedgerWriteOutcome, PendingQueueSegmentLedgerStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self.read(candidate.key()).await {
                    Ok(PendingQueueSegmentLedgerReadState::Current(current))
                        if current == *candidate =>
                    {
                        Ok(PendingQueueSegmentLedgerWriteOutcome::Idempotent(current))
                    }
                    Ok(PendingQueueSegmentLedgerReadState::Current(current)) => {
                        Err(PendingQueueSegmentLedgerStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(PendingQueueSegmentLedgerReadState::Uninitialized) => {
                        Err(PendingQueueSegmentLedgerStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: None,
                        })
                    }
                    Err(read) => Err(PendingQueueSegmentLedgerStoreError::IndeterminateReadFailed {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let PendingQueueSegmentLedgerReadState::Current(current) =
            self.read(candidate.key()).await?
        else {
            return Err(PendingQueueSegmentLedgerStoreError::MissingAfterLwt);
        };
        classify_observation(applied, candidate, current)
    }

    async fn read_slot(
        &self,
        slot: PendingQueueSegmentLedgerSlot,
        expected_key: Option<&PendingQueueSegmentLedgerKey>,
    ) -> Result<PendingQueueSegmentLedgerReadState, PendingQueueSegmentLedgerStoreError> {
        let row = self
            .session
            .execute_unpaged(&self.read, LedgerReadBinding::new(slot))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<LedgerDbRow>()
            .map_err(cql)?;
        let Some(row) = row else {
            return Ok(PendingQueueSegmentLedgerReadState::Uninitialized);
        };
        let current = StoredPendingQueueSegmentLedger::decode_persisted(
            slot,
            row.revision,
            &row.ledger_payload,
        )
        .map_err(model)?;
        if expected_key.is_some_and(|expected| current.key() != expected) {
            return Err(PendingQueueSegmentLedgerStoreError::SelectedKeyMismatch);
        }
        Ok(PendingQueueSegmentLedgerReadState::Current(current))
    }
}

fn assignment_receipt(
    fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    current: &StoredPendingQueueSegmentLedger,
    assignment: PendingQueueGenerationSegmentAssignment,
) -> Result<PendingQueueSegmentAssignmentReceipt, PendingQueueSegmentLedgerStoreError> {
    let exact = current
        .assignment_for(assignment.context())
        .ok_or(PendingQueueSegmentLedgerStoreError::AssignmentMissing)?;
    if exact != &assignment {
        return Err(PendingQueueSegmentLedgerStoreError::AssignmentMismatch);
    }
    Ok(PendingQueueSegmentAssignmentReceipt {
        store_fingerprint: fingerprint,
        ledger_slot: current.key().slot(),
        // This is the immutable assignment revision, not the mutable ledger
        // head revision. Later reservations cannot invalidate the receipt.
        ledger_revision: exact.assigned_at_ledger_revision(),
        assignment,
    })
}

fn build_segment_closure(
    fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    current: &StoredPendingQueueSegmentLedger,
    segment_id: RecoverableNatsSegmentId,
) -> Result<PendingQueueSegmentClosureSnapshot, PendingQueueSegmentLedgerStoreError> {
    let segment = current
        .live_segments()
        .iter()
        .find(|segment| segment.segment_id() == segment_id)
        .ok_or(PendingQueueSegmentLedgerStoreError::SegmentMissing)?;
    if current.staged_segment_id() == Some(segment_id) {
        return Err(PendingQueueSegmentLedgerStoreError::SegmentNotClosable);
    }
    if current.active_segment_id() == segment_id {
        let next_reserved = segment
            .reserved_bytes()
            .checked_add(current.generation_admission_budget_bytes())
            .ok_or(PendingQueueSegmentLedgerStoreError::ClosureBindingMismatch)?;
        let next_required = next_reserved
            .checked_add(RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES)
            .ok_or(PendingQueueSegmentLedgerStoreError::ClosureBindingMismatch)?;
        if segment.generation_count() < current.max_generations_per_segment()
            && next_required <= segment.max_stream_bytes()
        {
            return Err(PendingQueueSegmentLedgerStoreError::SegmentStillAdmitting);
        }
    }
    let assignments = current
        .assignments()
        .iter()
        .filter(|assignment| assignment.segment_id() == segment_id)
        .cloned()
        .map(|assignment| assignment_receipt(fingerprint, current, assignment))
        .collect::<Result<Vec<_>, _>>()?;
    if usize::try_from(segment.generation_count()).ok() != Some(assignments.len()) {
        return Err(PendingQueueSegmentLedgerStoreError::ClosureAssignmentMismatch);
    }
    // The global ledger revision continues advancing when another segment is
    // staged, activated or assigned. A closure must therefore carry the last
    // immutable assignment revision owned by this segment, so it can be
    // reconstructed after restart and still match an existing lifecycle row.
    let segment_assignment_revision = assignments
        .iter()
        .map(|assignment| assignment.ledger_revision().get())
        .max()
        .ok_or(PendingQueueSegmentLedgerStoreError::ClosureAssignmentMismatch)?;
    let segment_assignment_revision =
        PendingQueueSegmentLedgerRevision::try_new(segment_assignment_revision)
            .map_err(model)?;
    let mut hasher = Sha256::new();
    hasher.update(CLOSURE_SNAPSHOT_DOMAIN);
    hasher.update(fingerprint.as_bytes());
    hasher.update(current.key().slot().as_bytes());
    hasher.update(segment_id.get().to_be_bytes());
    hasher.update(segment.contract_digest().as_bytes());
    let retention = segment.retention();
    hasher.update((retention.stream_replicas() as u64).to_be_bytes());
    hasher.update(retention.max_stream_bytes().to_be_bytes());
    hasher.update(retention.generation_admission_budget_bytes().to_be_bytes());
    hasher.update(retention.max_live_segments().to_be_bytes());
    hasher.update(retention.max_consumers_per_segment().to_be_bytes());
    hasher.update(segment.reserved_bytes().to_be_bytes());
    hasher.update(segment.generation_count().to_be_bytes());
    hasher.update((assignments.len() as u64).to_be_bytes());
    for assignment in &assignments {
        let payload = assignment.assignment().to_canonical_bytes();
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
    }
    Ok(PendingQueueSegmentClosureSnapshot {
        store_fingerprint: fingerprint,
        ledger_key: current.key().clone(),
        ledger_revision: segment_assignment_revision,
        segment_id,
        contract_digest: segment.contract_digest(),
        ledger_payload_digest: PendingQueueSegmentClosureDigest(hasher.finalize().into()),
        assignments,
    })
}

pub fn classify_observation(
    applied: bool,
    candidate: &StoredPendingQueueSegmentLedger,
    current: StoredPendingQueueSegmentLedger,
) -> Result<PendingQueueSegmentLedgerWriteOutcome, PendingQueueSegmentLedgerStoreError> {
    if current == *candidate {
        Ok(if applied {
            PendingQueueSegmentLedgerWriteOutcome::Applied(current)
        } else {
            PendingQueueSegmentLedgerWriteOutcome::Idempotent(current)
        })
    } else if applied {
        Err(PendingQueueSegmentLedgerStoreError::AppliedStateMismatch)
    } else {
        Ok(PendingQueueSegmentLedgerWriteOutcome::Conflict(current))
    }
}

async fn prepare_regular(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueSegmentLedgerStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueSegmentLedgerStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueSegmentLedgerStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingQueueSegmentLedgerStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueSegmentLedgerStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueSegmentLedgerStoreError {
    PendingQueueSegmentLedgerStoreError::Cql(error.to_string())
}

fn model(error: PendingQueueSegmentLedgerError) -> PendingQueueSegmentLedgerStoreError {
    PendingQueueSegmentLedgerStoreError::Model(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSegmentLedgerStoreError {
    Cql(String),
    Model(String),
    InvalidTransition,
    RevisionOverflow,
    SelectedKeyMismatch,
    Uninitialized,
    AssignmentMissing,
    AssignmentContextMismatch,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    AssignmentMismatch,
    SegmentMissing,
    LiveSegmentMismatch,
    RotationBindingMismatch,
    RouteBindingMismatch,
    SegmentStillAdmitting,
    SegmentNotClosable,
    ClosureAssignmentMismatch,
    ClosureBindingMismatch,
    ClosureStale,
    Conflict {
        current_revision: PendingQueueSegmentLedgerRevision,
    },
    Indeterminate {
        execute: String,
        observed_revision: Option<PendingQueueSegmentLedgerRevision>,
    },
    IndeterminateReadFailed {
        execute: String,
        read: String,
    },
}

impl fmt::Display for PendingQueueSegmentLedgerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueSegmentLedgerStoreError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};
    use psy_node_core::{
        queue::recoverable_ephemeral::PendingQueueCaptureContext,
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };
    use psy_node_nats::{
        recoverable_assignment::PendingQueueSegmentLedgerBootstrap,
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueuePublisherKind,
            PendingQueueSourceQuota,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    use super::*;

    fn bootstrap() -> PendingQueueSegmentLedgerBootstrap {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Coordinator,
        );
        let retention = RecoverableNatsRetentionContract::try_new(
            3,
            1024 * 1024 * 1024,
            128 * 1024 * 1024,
            3,
            16,
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention,
        )
        .unwrap();
        let attested = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let mib = 1024 * 1024_u64;
        let budget = PendingQueueGenerationBudgetContract::try_new(
            AuthorityScope::Coordinator,
            vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorRegistration,
                    10_000,
                    15 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorDeploy,
                    10_000,
                    47 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorGuta,
                    10_000,
                    63 * mib,
                    mib,
                )
                .unwrap(),
            ],
            128 * mib,
        )
        .unwrap();
        PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &attested,
            budget,
            8,
        )
        .unwrap()
    }

    fn context(pending: u64) -> PendingQueueCaptureContext {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Coordinator,
        );
        PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(pending, u128::from(pending) + 1000)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn queries_are_no_tablet_full_payload_lwt_and_stable() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("psy_control_nt").unwrap();
        let queries = PendingQueueSegmentLedgerQueries::new(&keyspace);
        assert!(queries.create_table().cql().contains("psy_control_nt."));
        assert!(queries.bootstrap().cql().contains("IF NOT EXISTS"));
        assert!(queries
            .compare_and_set()
            .cql()
            .contains("IF revision = ? AND ledger_payload = ?"));
        assert_eq!(queries.read().bind_shape(), READ_BIND);
        assert_eq!(queries.bootstrap().bind_shape(), BOOTSTRAP_BIND);
        assert_eq!(queries.compare_and_set().bind_shape(), CAS_BIND);
        assert!(!queries.render_golden().contains(" TTL "));
        assert!(!queries.render_golden().contains("ALLOW FILTERING"));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(SEGMENT_LEDGER_TABLE));
        assert!(!crate::rollback::PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
        assert!(!crate::rollback::PRODUCTION_CQL_CAPABILITIES.delete_adapter);
    }

    #[test]
    fn binding_and_response_loss_classification_are_exact() {
        let initial = bootstrap().candidate().clone();
        let PendingQueueSegmentReservationPlan::Advance {
            expected,
            candidate,
            ..
        } = initial.reserve_generation(context(1)).unwrap()
        else {
            unreachable!()
        };
        let binding = LedgerCasBinding::try_new(&expected, &candidate).unwrap();
        assert_eq!(binding.expected_revision, 1);
        assert_eq!(binding.candidate_revision, 2);
        assert_eq!(binding.ledger_slot, expected.key().slot().as_bytes());
        assert_eq!(binding.expected_payload, expected.to_persisted_bytes());
        assert_eq!(binding.candidate_payload, candidate.to_persisted_bytes());
        assert!(matches!(
            classify_observation(false, &candidate, candidate.clone()).unwrap(),
            PendingQueueSegmentLedgerWriteOutcome::Idempotent(_)
        ));
        assert!(matches!(
            classify_observation(false, &candidate, expected.clone()).unwrap(),
            PendingQueueSegmentLedgerWriteOutcome::Conflict(_)
        ));
        let fingerprint = PendingQueueSegmentLedgerStoreFingerprint([7; 32]);
        assert!(matches!(
            build_segment_closure(fingerprint, &expected, expected.active_segment_id()),
            Err(PendingQueueSegmentLedgerStoreError::SegmentStillAdmitting)
        ));
        assert!(matches!(
            build_segment_closure(fingerprint, &candidate, candidate.active_segment_id()),
            Err(PendingQueueSegmentLedgerStoreError::SegmentStillAdmitting)
        ));
        let mut closed = candidate.clone();
        for pending in 2..=7 {
            let PendingQueueSegmentReservationPlan::Advance { candidate, .. } =
                closed.reserve_generation(context(pending)).unwrap()
            else {
                unreachable!()
            };
            closed = candidate;
        }
        assert!(matches!(
            closed.reserve_generation(context(8)),
            Err(PendingQueueSegmentLedgerError::SegmentCapacityExceeded)
        ));
        let after =
            build_segment_closure(fingerprint, &closed, closed.active_segment_id()).unwrap();
        assert_eq!(after.assignments().len(), 7);
        assert_eq!(after.ledger_revision(), closed.revision());
        assert_eq!(
            after.assignments()[0].ledger_revision(),
            closed.assignments()[0].assigned_at_ledger_revision(),
        );
        assert_eq!(after.store_fingerprint(), fingerprint);
        assert_eq!(
            classify_observation(true, &candidate, expected),
            Err(PendingQueueSegmentLedgerStoreError::AppliedStateMismatch)
        );
    }

    #[test]
    fn segment_local_closure_survives_unrelated_new_segment_progress() {
        let fingerprint = PendingQueueSegmentLedgerStoreFingerprint([7; 32]);
        let mut full = bootstrap().candidate().clone();
        for pending in 1..=7 {
            let PendingQueueSegmentReservationPlan::Advance { candidate, .. } =
                full.reserve_generation(context(pending)).unwrap()
            else {
                unreachable!()
            };
            full = candidate;
        }
        let old_segment = full.active_segment_id();
        let PendingQueueSegmentRotationStagePlan::Advance {
            candidate: staged,
            ..
        } = full.stage_next_rotation().unwrap()
        else {
            unreachable!()
        };
        let frozen = build_segment_closure(fingerprint, &staged, old_segment).unwrap();
        assert_eq!(frozen.assignments().len(), 7);
        assert!(matches!(
            build_segment_closure(
                fingerprint,
                &staged,
                staged.staged_segment_id().unwrap(),
            ),
            Err(PendingQueueSegmentLedgerStoreError::SegmentNotClosable)
        ));
        let next = staged
            .stream_segment(staged.staged_segment_id().unwrap())
            .unwrap();
        let PendingQueueSegmentRotationActivationPlan::Advance {
            candidate: active,
            ..
        } = staged.activate_staged_segment(&next).unwrap()
        else {
            unreachable!()
        };
        let PendingQueueSegmentReservationPlan::Advance {
            candidate: advanced,
            assignment,
            ..
        } = active.reserve_generation(context(8)).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(assignment.segment_id(), next.segment_id());
        let observed = build_segment_closure(fingerprint, &advanced, old_segment).unwrap();
        assert!(advanced.revision().get() > frozen.ledger_revision().get());
        assert_eq!(observed.ledger_revision(), frozen.ledger_revision());
        assert_eq!(observed.contract_digest(), frozen.contract_digest());
        assert_eq!(observed.ledger_payload_digest(), frozen.ledger_payload_digest());
        assert_eq!(observed.assignments().len(), frozen.assignments().len());
        assert!(observed
            .assignments()
            .iter()
            .zip(frozen.assignments())
            .all(|(left, right)| left.assignment() == right.assignment()));
    }

}
