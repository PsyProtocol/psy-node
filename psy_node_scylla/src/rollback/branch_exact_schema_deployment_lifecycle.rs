//! Isolated durable lifecycle for branch-exact schema deployment.
//!
//! The lifecycle persists one canonical payload behind an exact LWT revision.
//! It authorizes a typed, resumable backfill after `SchemaVerified`, but no
//! value in this module grants reader/writer cutover or production activation.

use std::{error::Error, fmt, sync::Arc};

use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};
use psy_node_core::store::branch_exact_schema::AuthorityScope;

use super::{
    BranchExactBackfillError, BranchExactBackfillPlan,
    BranchExactBackfillProgress, BranchExactBackfillVerifiedReceipt,
    BranchExactDeploymentError, BranchExactDeploymentIntent,
    BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
    InvalidCqlKeyspaceName, SealedBranchExactBackfillChunkCas,
    SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas,
    BACKFILL_PLANNED_PAYLOAD_KIND, BACKFILL_PROGRESS_PAYLOAD_KIND,
    BACKFILL_VERIFIED_PAYLOAD_KIND,
};

pub const BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE: &str =
    "branch_exact_schema_deployment_lifecycle";

const DEPLOYMENT_SLOT_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-deployment-slot/v1";
const INTENT_PAYLOAD_KIND: u8 = 1;
const VERIFIED_PAYLOAD_KIND: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactDeploymentRevision(u64);

impl BranchExactDeploymentRevision {
    pub const ZERO: Self = Self(0);

    pub const fn try_new(value: u64) -> Result<Self, BranchExactDeploymentLifecycleError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(BranchExactDeploymentLifecycleError::RevisionOutOfRange)
        }
    }

    pub const fn from_i64(value: i64) -> Result<Self, BranchExactDeploymentLifecycleError> {
        if value < 0 {
            Err(BranchExactDeploymentLifecycleError::NegativeRevision(value))
        } else {
            Ok(Self(value as u64))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub(crate) fn next(self) -> Result<Self, BranchExactDeploymentLifecycleError> {
        Self::try_new(self.0 + 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactDeploymentSlotId([u8; 32]);

impl BranchExactDeploymentSlotId {
    pub fn from_intent(intent: &BranchExactDeploymentIntent) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DEPLOYMENT_SLOT_DOMAIN);
        hasher.update(intent.schema_version().to_be_bytes());
        match intent.authority() {
            AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => {
                hasher.update([2]);
                hasher.update(realm_id.to_be_bytes());
                hasher.update(realm_sub_id.to_be_bytes());
            }
        }
        hasher.update((intent.keyspace().as_str().len() as u32).to_be_bytes());
        hasher.update(intent.keyspace().as_str().as_bytes());
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn try_from_slice(bytes: &[u8]) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let bytes = <[u8; 32]>::try_from(bytes).map_err(|_| {
            BranchExactDeploymentLifecycleError::MalformedDeploymentSlot
        })?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentLifecyclePhase {
    Intent,
    SchemaVerified,
    BackfillPlanned,
    BackfillProgress,
    BackfillVerified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentLifecycleState {
    Intent(BranchExactDeploymentIntent),
    SchemaVerified(BranchExactVerifiedDeploymentReceipt),
    BackfillPlanned(BranchExactBackfillPlan),
    BackfillProgress(BranchExactBackfillProgress),
    BackfillVerified(BranchExactBackfillVerifiedReceipt),
}

impl BranchExactDeploymentLifecycleState {
    pub const fn phase(&self) -> BranchExactDeploymentLifecyclePhase {
        match self {
            Self::Intent(_) => BranchExactDeploymentLifecyclePhase::Intent,
            Self::SchemaVerified(_) => {
                BranchExactDeploymentLifecyclePhase::SchemaVerified
            }
            Self::BackfillPlanned(_) => {
                BranchExactDeploymentLifecyclePhase::BackfillPlanned
            }
            Self::BackfillProgress(_) => {
                BranchExactDeploymentLifecyclePhase::BackfillProgress
            }
            Self::BackfillVerified(_) => {
                BranchExactDeploymentLifecyclePhase::BackfillVerified
            }
        }
    }

    pub const fn intent(&self) -> &BranchExactDeploymentIntent {
        match self {
            Self::Intent(intent) => intent,
            Self::SchemaVerified(receipt) => receipt.intent(),
            Self::BackfillPlanned(plan) => plan.deployment().intent(),
            Self::BackfillProgress(progress) => {
                progress.plan().deployment().intent()
            }
            Self::BackfillVerified(receipt) => {
                receipt.plan().deployment().intent()
            }
        }
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Intent(intent) => intent.to_canonical_bytes(),
            Self::SchemaVerified(receipt) => receipt.to_canonical_bytes(),
            Self::BackfillPlanned(plan) => plan.to_canonical_bytes(),
            Self::BackfillProgress(progress) => progress.to_canonical_bytes(),
            Self::BackfillVerified(receipt) => receipt.to_canonical_bytes(),
        }
    }

    pub fn decode_persisted(
        bytes: &[u8],
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let kind = *bytes
            .get(2)
            .ok_or(BranchExactDeploymentLifecycleError::TruncatedLifecyclePayload)?;
        match kind {
            INTENT_PAYLOAD_KIND => Ok(Self::Intent(
                BranchExactDeploymentIntent::decode_persisted(bytes)?,
            )),
            VERIFIED_PAYLOAD_KIND => Ok(Self::SchemaVerified(
                BranchExactVerifiedDeploymentReceipt::decode_persisted(bytes)?,
            )),
            BACKFILL_PLANNED_PAYLOAD_KIND => Ok(Self::BackfillPlanned(
                BranchExactBackfillPlan::decode_persisted(bytes)?,
            )),
            BACKFILL_PROGRESS_PAYLOAD_KIND => Ok(Self::BackfillProgress(
                BranchExactBackfillProgress::decode_persisted(bytes)?,
            )),
            BACKFILL_VERIFIED_PAYLOAD_KIND => Ok(Self::BackfillVerified(
                BranchExactBackfillVerifiedReceipt::decode_persisted(bytes)?,
            )),
            value => Err(BranchExactDeploymentLifecycleError::UnknownLifecycleKind(
                value,
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBranchExactDeploymentLifecycle {
    slot: BranchExactDeploymentSlotId,
    revision: BranchExactDeploymentRevision,
    state: BranchExactDeploymentLifecycleState,
    payload: Vec<u8>,
}

impl StoredBranchExactDeploymentLifecycle {
    pub(crate) fn try_new(
        revision: BranchExactDeploymentRevision,
        state: BranchExactDeploymentLifecycleState,
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let expected_revision = match state.phase() {
            BranchExactDeploymentLifecyclePhase::Intent => 0,
            BranchExactDeploymentLifecyclePhase::SchemaVerified => 1,
            BranchExactDeploymentLifecyclePhase::BackfillPlanned => 2,
            BranchExactDeploymentLifecyclePhase::BackfillProgress => {
                let BranchExactDeploymentLifecycleState::BackfillProgress(
                    progress,
                ) = &state
                else {
                    unreachable!()
                };
                2_u64 + u64::from(progress.next_chunk_index())
            }
            BranchExactDeploymentLifecyclePhase::BackfillVerified => {
                let BranchExactDeploymentLifecycleState::BackfillVerified(
                    receipt,
                ) = &state
                else {
                    unreachable!()
                };
                3_u64 + u64::from(receipt.plan().total_chunks())
            }
        };
        if revision.get() != expected_revision {
            return Err(BranchExactDeploymentLifecycleError::PhaseRevisionMismatch {
                phase: state.phase(),
                revision: revision.get(),
            });
        }
        let slot = BranchExactDeploymentSlotId::from_intent(state.intent());
        let payload = state.to_canonical_bytes();
        Ok(Self {
            slot,
            revision,
            state,
            payload,
        })
    }

    pub fn decode_persisted(
        selected_slot: &[u8],
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let selected_slot = BranchExactDeploymentSlotId::try_from_slice(selected_slot)?;
        let revision = BranchExactDeploymentRevision::from_i64(revision)?;
        let state = BranchExactDeploymentLifecycleState::decode_persisted(payload)?;
        let stored = Self::try_new(revision, state)?;
        if stored.slot != selected_slot {
            return Err(BranchExactDeploymentLifecycleError::SelectedSlotMismatch);
        }
        Ok(stored)
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.slot
    }

    pub const fn revision(&self) -> BranchExactDeploymentRevision {
        self.revision
    }

    pub const fn state(&self) -> &BranchExactDeploymentLifecycleState {
        &self.state
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDeploymentLifecycleBootstrap {
    candidate: StoredBranchExactDeploymentLifecycle,
}

impl BranchExactDeploymentLifecycleBootstrap {
    pub fn new(intent: BranchExactDeploymentIntent) -> Self {
        let candidate = StoredBranchExactDeploymentLifecycle::try_new(
            BranchExactDeploymentRevision::ZERO,
            BranchExactDeploymentLifecycleState::Intent(intent),
        )
        .expect("revision zero is the only INTENT revision");
        Self { candidate }
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.candidate.slot()
    }

    pub const fn candidate(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.candidate
    }

    fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredBranchExactDeploymentLifecycle,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError>
    {
        classify_write(applied, &self.candidate, current)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactSchemaVerifiedCas {
    expected: StoredBranchExactDeploymentLifecycle,
    candidate: StoredBranchExactDeploymentLifecycle,
}

impl SealedBranchExactSchemaVerifiedCas {
    pub fn try_new(
        expected: &StoredBranchExactDeploymentLifecycle,
        verified: BranchExactVerifiedDeploymentReceipt,
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let BranchExactDeploymentLifecycleState::Intent(expected_intent) =
            expected.state()
        else {
            return Err(BranchExactDeploymentLifecycleError::ExpectedIntentPhase);
        };
        if expected_intent != verified.intent() {
            return Err(BranchExactDeploymentLifecycleError::VerifiedIntentMismatch);
        }
        let candidate = StoredBranchExactDeploymentLifecycle::try_new(
            expected.revision().next()?,
            BranchExactDeploymentLifecycleState::SchemaVerified(verified),
        )?;
        if candidate.slot() != expected.slot() {
            return Err(BranchExactDeploymentLifecycleError::SelectedSlotMismatch);
        }
        Ok(Self {
            expected: expected.clone(),
            candidate,
        })
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.expected.slot()
    }

    pub const fn expected(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.candidate
    }

    #[cfg(test)]
    fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredBranchExactDeploymentLifecycle,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError>
    {
        classify_write(applied, &self.candidate, current)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentLifecycleReadState {
    Uninitialized,
    Current(StoredBranchExactDeploymentLifecycle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentLifecycleWriteOutcome {
    Applied(StoredBranchExactDeploymentLifecycle),
    Idempotent(StoredBranchExactDeploymentLifecycle),
    Conflict(StoredBranchExactDeploymentLifecycle),
}

fn classify_write(
    applied: bool,
    candidate: &StoredBranchExactDeploymentLifecycle,
    current: StoredBranchExactDeploymentLifecycle,
) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
    if applied {
        if &current != candidate {
            return Err(BranchExactDeploymentLifecycleError::AppliedStateMismatch);
        }
        Ok(BranchExactDeploymentLifecycleWriteOutcome::Applied(current))
    } else if &current == candidate {
        Ok(BranchExactDeploymentLifecycleWriteOutcome::Idempotent(
            current,
        ))
    } else {
        Ok(BranchExactDeploymentLifecycleWriteOutcome::Conflict(current))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidBranchExactDeploymentNoTabletKeyspace(pub String);

impl fmt::Display for InvalidBranchExactDeploymentNoTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "branch-exact deployment LWT keyspace {:?} must end in _no_tablet or _nt",
            self.0
        )
    }
}

impl Error for InvalidBranchExactDeploymentNoTabletKeyspace {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactDeploymentNoTabletKeyspace(CqlKeyspaceName);

impl BranchExactDeploymentNoTabletKeyspace {
    pub fn try_new(
        name: impl Into<String>,
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let name = name.into();
        let keyspace = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(
                BranchExactDeploymentLifecycleError::InvalidNoTabletKeyspace(
                    InvalidBranchExactDeploymentNoTabletKeyspace(name),
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
pub enum BranchExactDeploymentLifecycleQueryId {
    CreateTable = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDeploymentLifecycleQuery {
    id: BranchExactDeploymentLifecycleQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl BranchExactDeploymentLifecycleQuery {
    pub const fn id(&self) -> BranchExactDeploymentLifecycleQueryId {
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
pub struct BranchExactDeploymentLifecycleQueries {
    create_table: BranchExactDeploymentLifecycleQuery,
    read: BranchExactDeploymentLifecycleQuery,
    bootstrap: BranchExactDeploymentLifecycleQuery,
    compare_and_set: BranchExactDeploymentLifecycleQuery,
}

impl BranchExactDeploymentLifecycleQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE}",
            keyspace.as_str()
        );
        Self {
            create_table: BranchExactDeploymentLifecycleQuery {
                id: BranchExactDeploymentLifecycleQueryId::CreateTable,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {table} (deployment_slot blob PRIMARY KEY, revision bigint, lifecycle blob)"
                ),
                bind_shape: &[],
            },
            read: BranchExactDeploymentLifecycleQuery {
                id: BranchExactDeploymentLifecycleQueryId::Read,
                cql: format!(
                    "SELECT deployment_slot, revision, lifecycle FROM {table} WHERE deployment_slot = ?"
                ),
                bind_shape: &["deployment_slot:BLOB"],
            },
            bootstrap: BranchExactDeploymentLifecycleQuery {
                id: BranchExactDeploymentLifecycleQueryId::Bootstrap,
                cql: format!(
                    "INSERT INTO {table} (deployment_slot, revision, lifecycle) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: &[
                    "deployment_slot:BLOB",
                    "candidate_revision:BIGINT",
                    "candidate_lifecycle:BLOB",
                ],
            },
            compare_and_set: BranchExactDeploymentLifecycleQuery {
                id: BranchExactDeploymentLifecycleQueryId::CompareAndSet,
                cql: format!(
                    "UPDATE {table} SET revision = ?, lifecycle = ? WHERE deployment_slot = ? IF revision = ? AND lifecycle = ?"
                ),
                bind_shape: &[
                    "candidate_revision:BIGINT",
                    "candidate_lifecycle:BLOB",
                    "deployment_slot:BLOB",
                    "expected_revision:BIGINT",
                    "expected_lifecycle:BLOB",
                ],
            },
        }
    }

    pub const fn create_table(&self) -> &BranchExactDeploymentLifecycleQuery {
        &self.create_table
    }

    pub const fn read(&self) -> &BranchExactDeploymentLifecycleQuery {
        &self.read
    }

    pub const fn bootstrap(&self) -> &BranchExactDeploymentLifecycleQuery {
        &self.bootstrap
    }

    pub const fn compare_and_set(&self) -> &BranchExactDeploymentLifecycleQuery {
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
pub enum BranchExactDeploymentLifecycleBindValue {
    BigInt(i64),
    Blob(Vec<u8>),
}

impl BranchExactDeploymentLifecycleBindValue {
    #[cfg(test)]
    fn render(&self) -> String {
        match self {
            Self::BigInt(value) => format!("BIGINT:{value}"),
            Self::Blob(value) => format!("BLOB:{}", hex::encode(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct BranchExactDeploymentLifecycleReadBinding {
    deployment_slot: Vec<u8>,
}

impl BranchExactDeploymentLifecycleReadBinding {
    pub fn from_slot(slot: BranchExactDeploymentSlotId) -> Self {
        Self {
            deployment_slot: slot.as_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct BranchExactDeploymentLifecycleBootstrapBinding {
    deployment_slot: Vec<u8>,
    candidate_revision: i64,
    candidate_lifecycle: Vec<u8>,
}

impl BranchExactDeploymentLifecycleBootstrapBinding {
    pub fn from_bootstrap(bootstrap: &BranchExactDeploymentLifecycleBootstrap) -> Self {
        Self {
            deployment_slot: bootstrap.slot().as_bytes().to_vec(),
            candidate_revision: bootstrap.candidate().revision().as_i64(),
            candidate_lifecycle: bootstrap.candidate().payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<BranchExactDeploymentLifecycleBindValue> {
        vec![
            BranchExactDeploymentLifecycleBindValue::Blob(
                self.deployment_slot.clone(),
            ),
            BranchExactDeploymentLifecycleBindValue::BigInt(
                self.candidate_revision,
            ),
            BranchExactDeploymentLifecycleBindValue::Blob(
                self.candidate_lifecycle.clone(),
            ),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct BranchExactDeploymentLifecycleCasBinding {
    candidate_revision: i64,
    candidate_lifecycle: Vec<u8>,
    deployment_slot: Vec<u8>,
    expected_revision: i64,
    expected_lifecycle: Vec<u8>,
}

impl BranchExactDeploymentLifecycleCasBinding {
    pub fn from_sealed(sealed: &SealedBranchExactSchemaVerifiedCas) -> Self {
        Self::from_parts(
            sealed.slot(),
            sealed.expected(),
            sealed.candidate(),
        )
    }

    fn from_parts(
        slot: BranchExactDeploymentSlotId,
        expected: &StoredBranchExactDeploymentLifecycle,
        candidate: &StoredBranchExactDeploymentLifecycle,
    ) -> Self {
        Self {
            candidate_revision: candidate.revision().as_i64(),
            candidate_lifecycle: candidate.payload().to_vec(),
            deployment_slot: slot.as_bytes().to_vec(),
            expected_revision: expected.revision().as_i64(),
            expected_lifecycle: expected.payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<BranchExactDeploymentLifecycleBindValue> {
        vec![
            BranchExactDeploymentLifecycleBindValue::BigInt(
                self.candidate_revision,
            ),
            BranchExactDeploymentLifecycleBindValue::Blob(
                self.candidate_lifecycle.clone(),
            ),
            BranchExactDeploymentLifecycleBindValue::Blob(
                self.deployment_slot.clone(),
            ),
            BranchExactDeploymentLifecycleBindValue::BigInt(
                self.expected_revision,
            ),
            BranchExactDeploymentLifecycleBindValue::Blob(
                self.expected_lifecycle.clone(),
            ),
        ]
    }
}

#[cfg(test)]
fn render_bind_values(values: &[BranchExactDeploymentLifecycleBindValue]) -> String {
    values
        .iter()
        .map(BranchExactDeploymentLifecycleBindValue::render)
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactDeploymentLifecycleLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
}

impl BranchExactDeploymentLifecycleLwtContract {
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
struct BranchExactDeploymentLifecycleDbRow {
    deployment_slot: Vec<u8>,
    revision: Option<i64>,
    lifecycle: Option<Vec<u8>>,
}

pub struct ScyllaBranchExactDeploymentLifecycleStore {
    session: Arc<Session>,
    queries: BranchExactDeploymentLifecycleQueries,
    contract: BranchExactDeploymentLifecycleLwtContract,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaBranchExactDeploymentLifecycleStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), BranchExactDeploymentLifecycleError> {
        let queries = BranchExactDeploymentLifecycleQueries::new(keyspace);
        session
            .query_unpaged(queries.create_table().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, BranchExactDeploymentLifecycleError> {
        let queries = BranchExactDeploymentLifecycleQueries::new(&keyspace);
        let contract = BranchExactDeploymentLifecycleLwtContract::rf3_default();
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

    pub const fn queries(&self) -> &BranchExactDeploymentLifecycleQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> BranchExactDeploymentLifecycleLwtContract {
        self.contract
    }

    pub async fn read(
        &self,
        slot: BranchExactDeploymentSlotId,
    ) -> Result<BranchExactDeploymentLifecycleReadState, BranchExactDeploymentLifecycleError> {
        let result = self
            .session
            .execute_unpaged(
                &self.read,
                BranchExactDeploymentLifecycleReadBinding::from_slot(slot),
            )
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<BranchExactDeploymentLifecycleDbRow>()
            .map_err(cql_error)?;
        match row {
            None => Ok(BranchExactDeploymentLifecycleReadState::Uninitialized),
            Some(row) => Ok(BranchExactDeploymentLifecycleReadState::Current(
                decode_branch_exact_deployment_lifecycle_persisted_cells(
                    slot,
                    &row.deployment_slot,
                    row.revision,
                    row.lifecycle.as_deref(),
                )?,
            )),
        }
    }

    pub async fn bootstrap(
        &self,
        bootstrap: &BranchExactDeploymentLifecycleBootstrap,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                BranchExactDeploymentLifecycleBootstrapBinding::from_bootstrap(bootstrap),
            )
            .await;
        self.finish_write(
            "bootstrap",
            execution,
            bootstrap.slot(),
            bootstrap.candidate(),
            |applied, current| bootstrap.classify_lwt_observation(applied, current),
        )
        .await
    }

    pub async fn mark_schema_verified(
        &self,
        sealed: &SealedBranchExactSchemaVerifiedCas,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        self.execute_transition(
            "mark_schema_verified",
            sealed.slot(),
            sealed.expected(),
            sealed.candidate(),
        )
        .await
    }

    pub async fn plan_backfill(
        &self,
        sealed: &SealedBranchExactBackfillPlanCas,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        self.execute_transition(
            "plan_backfill",
            sealed.slot(),
            sealed.expected(),
            sealed.candidate(),
        )
        .await
    }

    pub async fn record_backfill_chunk(
        &self,
        sealed: &SealedBranchExactBackfillChunkCas,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        self.execute_transition(
            "record_backfill_chunk",
            sealed.slot(),
            sealed.expected(),
            sealed.candidate(),
        )
        .await
    }

    pub async fn mark_backfill_verified(
        &self,
        sealed: &SealedBranchExactBackfillVerifiedCas,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        self.execute_transition(
            "mark_backfill_verified",
            sealed.slot(),
            sealed.expected(),
            sealed.candidate(),
        )
        .await
    }

    async fn execute_transition(
        &self,
        operation: &'static str,
        slot: BranchExactDeploymentSlotId,
        expected: &StoredBranchExactDeploymentLifecycle,
        candidate: &StoredBranchExactDeploymentLifecycle,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError> {
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                BranchExactDeploymentLifecycleCasBinding::from_parts(
                    slot, expected, candidate,
                ),
            )
            .await;
        self.finish_write(
            operation,
            execution,
            slot,
            candidate,
            |applied, current| classify_write(applied, candidate, current),
        )
        .await
    }

    async fn finish_write(
        &self,
        operation: &'static str,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        slot: BranchExactDeploymentSlotId,
        candidate: &StoredBranchExactDeploymentLifecycle,
        classify: impl FnOnce(
            bool,
            StoredBranchExactDeploymentLifecycle,
        ) -> Result<
            BranchExactDeploymentLifecycleWriteOutcome,
            BranchExactDeploymentLifecycleError,
        >,
    ) -> Result<BranchExactDeploymentLifecycleWriteOutcome, BranchExactDeploymentLifecycleError>
    {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = match self.read(slot).await? {
                    BranchExactDeploymentLifecycleReadState::Current(current) => current,
                    BranchExactDeploymentLifecycleReadState::Uninitialized => {
                        return Err(
                            BranchExactDeploymentLifecycleError::CurrentMissingAfterLwt {
                                operation,
                                applied,
                            },
                        );
                    }
                };
                classify(applied, current)
            }
            Err(error) => match self.read(slot).await {
                Ok(BranchExactDeploymentLifecycleReadState::Current(current))
                    if current == *candidate =>
                {
                    Ok(BranchExactDeploymentLifecycleWriteOutcome::Idempotent(
                        current,
                    ))
                }
                Ok(_) => Err(BranchExactDeploymentLifecycleError::IndeterminateWrite {
                    operation,
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(
                    BranchExactDeploymentLifecycleError::IndeterminateReadFailed {
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
    contract: BranchExactDeploymentLifecycleLwtContract,
) -> Result<PreparedStatement, BranchExactDeploymentLifecycleError> {
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
) -> Result<PreparedStatement, BranchExactDeploymentLifecycleError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

pub fn decode_branch_exact_deployment_lifecycle_persisted_cells(
    requested_slot: BranchExactDeploymentSlotId,
    selected_slot: &[u8],
    revision: Option<i64>,
    lifecycle: Option<&[u8]>,
) -> Result<StoredBranchExactDeploymentLifecycle, BranchExactDeploymentLifecycleError> {
    let revision = revision.ok_or(BranchExactDeploymentLifecycleError::MissingRevision)?;
    let lifecycle =
        lifecycle.ok_or(BranchExactDeploymentLifecycleError::MissingLifecyclePayload)?;
    let stored = StoredBranchExactDeploymentLifecycle::decode_persisted(
        selected_slot,
        revision,
        lifecycle,
    )?;
    if stored.slot() != requested_slot {
        return Err(BranchExactDeploymentLifecycleError::SelectedSlotMismatch);
    }
    Ok(stored)
}

fn decode_lwt_applied(
    result: QueryResult,
) -> Result<bool, BranchExactDeploymentLifecycleError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(BranchExactDeploymentLifecycleError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(BranchExactDeploymentLifecycleError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> BranchExactDeploymentLifecycleError {
    BranchExactDeploymentLifecycleError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentLifecycleError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    InvalidNoTabletKeyspace(InvalidBranchExactDeploymentNoTabletKeyspace),
    DeploymentCodec(BranchExactDeploymentError),
    BackfillCodec(BranchExactBackfillError),
    RevisionOutOfRange,
    NegativeRevision(i64),
    MalformedDeploymentSlot,
    SelectedSlotMismatch,
    TruncatedLifecyclePayload,
    UnknownLifecycleKind(u8),
    PhaseRevisionMismatch {
        phase: BranchExactDeploymentLifecyclePhase,
        revision: u64,
    },
    ExpectedIntentPhase,
    VerifiedIntentMismatch,
    AppliedStateMismatch,
    MissingRevision,
    MissingLifecyclePayload,
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

impl From<InvalidCqlKeyspaceName> for BranchExactDeploymentLifecycleError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<BranchExactDeploymentError> for BranchExactDeploymentLifecycleError {
    fn from(value: BranchExactDeploymentError) -> Self {
        Self::DeploymentCodec(value)
    }
}

impl From<BranchExactBackfillError> for BranchExactDeploymentLifecycleError {
    fn from(value: BranchExactBackfillError) -> Self {
        Self::BackfillCodec(value)
    }
}

impl fmt::Display for BranchExactDeploymentLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactDeploymentLifecycleError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        branch_exact_schema::BranchExactSchemaMaterializationPlan,
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
    };

    use super::*;
    use crate::rollback::{
        branch_exact_schema_fingerprint, BranchExactExpectedTopology,
        BranchExactNodeSchemaPostflight, BranchExactSchemaInspection,
        BranchExactSchemaMaterializationRequest, BranchExactSchemaOnlyReceipt,
        BranchExactScyllaNodeId, BranchExactScyllaSchemaVersion,
        BranchExactTopologyAttestation,
    };

    fn authority() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn request(keyspace: &str) -> BranchExactSchemaMaterializationRequest {
        request_with_hash(keyspace, PHash::ZERO)
    }

    fn request_with_hash(
        keyspace: &str,
        checkpoint_hash: PHash,
    ) -> BranchExactSchemaMaterializationRequest {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(checkpoint_hash),
                ),
            ),
        )
        .unwrap();
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            authority(),
            None,
        )
        .unwrap();
        BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new(keyspace).unwrap(),
            plan,
        )
        .unwrap()
    }

    fn topology(seed: u8) -> BranchExactExpectedTopology {
        BranchExactExpectedTopology::try_new(
            [1_u8, 2, 3]
                .map(|value| {
                    BranchExactScyllaNodeId::try_new([value + seed; 16]).unwrap()
                })
                .to_vec(),
        )
        .unwrap()
    }

    fn verified(
        request: &BranchExactSchemaMaterializationRequest,
        topology: BranchExactExpectedTopology,
    ) -> BranchExactVerifiedDeploymentReceipt {
        let fingerprint = branch_exact_schema_fingerprint(authority());
        let receipt = BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            request,
            fingerprint,
        );
        let version = BranchExactScyllaSchemaVersion::try_new([9; 16]).unwrap();
        let observations = topology
            .nodes()
            .iter()
            .copied()
            .map(|node| {
                BranchExactNodeSchemaPostflight::try_new(
                    node,
                    version,
                    BranchExactSchemaInspection::Exact { fingerprint },
                )
                .unwrap()
            })
            .collect();
        let attestation = BranchExactTopologyAttestation::try_new(
            &receipt,
            topology.clone(),
            observations,
        )
        .unwrap();
        BranchExactVerifiedDeploymentReceipt::try_new(
            BranchExactDeploymentIntent::new(request, topology),
            attestation,
        )
        .unwrap()
    }

    fn bootstrap(keyspace: &str) -> BranchExactDeploymentLifecycleBootstrap {
        bootstrap_with_topology(keyspace, 0)
    }

    fn bootstrap_with_topology(
        keyspace: &str,
        topology_seed: u8,
    ) -> BranchExactDeploymentLifecycleBootstrap {
        let request = request(keyspace);
        BranchExactDeploymentLifecycleBootstrap::new(
            BranchExactDeploymentIntent::new(&request, topology(topology_seed)),
        )
    }

    fn sealed(keyspace: &str) -> SealedBranchExactSchemaVerifiedCas {
        let request = request(keyspace);
        let topology = topology(0);
        let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(
            BranchExactDeploymentIntent::new(&request, topology.clone()),
        );
        SealedBranchExactSchemaVerifiedCas::try_new(
            bootstrap.candidate(),
            verified(&request, topology),
        )
        .unwrap()
    }

    #[test]
    fn slot_is_stable_for_schema_identity_but_intent_still_binds_topology() {
        let request = request("psy_h14_realm");
        let first = BranchExactDeploymentIntent::new(&request, topology(0));
        let second = BranchExactDeploymentIntent::new(&request, topology(4));
        let changed_plan_request = request_with_hash(
            "psy_h14_realm",
            PHash::from_values(1, 2, 3, 4),
        );
        let changed_plan = BranchExactDeploymentIntent::new(
            &changed_plan_request,
            topology(0),
        );
        assert_eq!(
            BranchExactDeploymentSlotId::from_intent(&first),
            BranchExactDeploymentSlotId::from_intent(&second)
        );
        assert_ne!(first, second);
        assert_eq!(
            BranchExactDeploymentSlotId::from_intent(&first),
            BranchExactDeploymentSlotId::from_intent(&changed_plan)
        );
        assert_ne!(first, changed_plan);
        assert_ne!(
            BranchExactDeploymentSlotId::from_intent(&first),
            bootstrap("psy_h14_other").slot()
        );
    }

    #[test]
    fn bootstrap_is_revision_zero_intent_and_retry_is_exact() {
        let bootstrap = bootstrap("psy_h14_bootstrap");
        assert_eq!(bootstrap.candidate().revision().get(), 0);
        assert_eq!(
            bootstrap.candidate().state().phase(),
            BranchExactDeploymentLifecyclePhase::Intent
        );
        let decoded = StoredBranchExactDeploymentLifecycle::decode_persisted(
            bootstrap.slot().as_bytes(),
            0,
            bootstrap.candidate().payload(),
        )
        .unwrap();
        assert_eq!(decoded, *bootstrap.candidate());
        assert_eq!(
            bootstrap.classify_lwt_observation(false, decoded.clone()),
            Ok(BranchExactDeploymentLifecycleWriteOutcome::Idempotent(
                decoded
            ))
        );
    }

    #[test]
    fn schema_verified_transition_is_exact_revision_one() {
        let sealed = sealed("psy_h14_verified");
        assert_eq!(sealed.expected().revision().get(), 0);
        assert_eq!(sealed.candidate().revision().get(), 1);
        assert_eq!(
            sealed.candidate().state().phase(),
            BranchExactDeploymentLifecyclePhase::SchemaVerified
        );
        assert_eq!(
            sealed.classify_lwt_observation(false, sealed.candidate().clone()),
            Ok(BranchExactDeploymentLifecycleWriteOutcome::Idempotent(
                sealed.candidate().clone()
            ))
        );
    }

    #[test]
    fn wrong_intent_and_second_transition_fail_closed() {
        let expected = bootstrap("psy_h14_expected");
        let other_request = request("psy_h14_other_intent");
        assert_eq!(
            SealedBranchExactSchemaVerifiedCas::try_new(
                expected.candidate(),
                verified(&other_request, topology(0)),
            ),
            Err(BranchExactDeploymentLifecycleError::VerifiedIntentMismatch)
        );
        let sealed = sealed("psy_h14_once");
        let request = request("psy_h14_once");
        assert_eq!(
            SealedBranchExactSchemaVerifiedCas::try_new(
                sealed.candidate(),
                verified(&request, topology(0)),
            ),
            Err(BranchExactDeploymentLifecycleError::ExpectedIntentPhase)
        );
    }

    #[test]
    fn applied_mismatch_and_conflict_are_distinct() {
        let first = bootstrap_with_topology("psy_h14_conflict", 0);
        let second = bootstrap_with_topology("psy_h14_conflict", 4);
        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.candidate(), second.candidate());
        assert_eq!(
            first.classify_lwt_observation(true, second.candidate().clone()),
            Err(BranchExactDeploymentLifecycleError::AppliedStateMismatch)
        );
        assert_eq!(
            first.classify_lwt_observation(false, second.candidate().clone()),
            Ok(BranchExactDeploymentLifecycleWriteOutcome::Conflict(
                second.candidate().clone()
            ))
        );
    }

    #[test]
    fn revision_cql_range_fail_closed() {
        let maximum = BranchExactDeploymentRevision::try_new(i64::MAX as u64)
            .unwrap();
        assert_eq!(
            maximum.next(),
            Err(BranchExactDeploymentLifecycleError::RevisionOutOfRange)
        );
        assert_eq!(
            BranchExactDeploymentRevision::try_new(i64::MAX as u64 + 1),
            Err(BranchExactDeploymentLifecycleError::RevisionOutOfRange)
        );
    }

    #[test]
    fn malformed_persisted_cells_never_become_current() {
        let primary_bootstrap = bootstrap("psy_h14_decode");
        let other = bootstrap("psy_h14_decode_other");
        assert_eq!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                &[0; 31],
                0,
                primary_bootstrap.candidate().payload(),
            ),
            Err(BranchExactDeploymentLifecycleError::MalformedDeploymentSlot)
        );
        assert_eq!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                primary_bootstrap.slot().as_bytes(),
                -1,
                primary_bootstrap.candidate().payload(),
            ),
            Err(BranchExactDeploymentLifecycleError::NegativeRevision(-1))
        );
        assert_eq!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                other.slot().as_bytes(),
                0,
                primary_bootstrap.candidate().payload(),
            ),
            Err(BranchExactDeploymentLifecycleError::SelectedSlotMismatch)
        );
        assert_eq!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                primary_bootstrap.slot().as_bytes(),
                0,
                &[0, 1],
            ),
            Err(BranchExactDeploymentLifecycleError::TruncatedLifecyclePayload)
        );
        let mut unknown_kind = primary_bootstrap.candidate().payload().to_vec();
        unknown_kind[2] = 99;
        assert_eq!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                primary_bootstrap.slot().as_bytes(),
                0,
                &unknown_kind,
            ),
            Err(BranchExactDeploymentLifecycleError::UnknownLifecycleKind(99))
        );
        assert!(matches!(
            StoredBranchExactDeploymentLifecycle::decode_persisted(
                primary_bootstrap.slot().as_bytes(),
                1,
                primary_bootstrap.candidate().payload(),
            ),
            Err(BranchExactDeploymentLifecycleError::PhaseRevisionMismatch { .. })
        ));
        assert_eq!(
            decode_branch_exact_deployment_lifecycle_persisted_cells(
                primary_bootstrap.slot(),
                primary_bootstrap.slot().as_bytes(),
                None,
                Some(primary_bootstrap.candidate().payload()),
            ),
            Err(BranchExactDeploymentLifecycleError::MissingRevision)
        );
        assert_eq!(
            decode_branch_exact_deployment_lifecycle_persisted_cells(
                primary_bootstrap.slot(),
                primary_bootstrap.slot().as_bytes(),
                Some(0),
                None,
            ),
            Err(BranchExactDeploymentLifecycleError::MissingLifecyclePayload)
        );
    }

    #[test]
    fn queries_require_no_tablet_and_exact_payload_compare() {
        assert!(matches!(
            BranchExactDeploymentNoTabletKeyspace::try_new("psy_h14_regular"),
            Err(BranchExactDeploymentLifecycleError::InvalidNoTabletKeyspace(_))
        ));
        let keyspace =
            BranchExactDeploymentNoTabletKeyspace::try_new("psy_h14_nt").unwrap();
        let queries = BranchExactDeploymentLifecycleQueries::new(&keyspace);
        assert!(queries.bootstrap().cql().ends_with("IF NOT EXISTS"));
        assert!(queries.compare_and_set().cql().contains(
            "IF revision = ? AND lifecycle = ?"
        ));
        assert_eq!(
            queries.compare_and_set().bind_shape(),
            [
                "candidate_revision:BIGINT",
                "candidate_lifecycle:BLOB",
                "deployment_slot:BLOB",
                "expected_revision:BIGINT",
                "expected_lifecycle:BLOB",
            ]
        );
        assert_eq!(
            BranchExactDeploymentLifecycleLwtContract::rf3_default(),
            BranchExactDeploymentLifecycleLwtContract {
                regular: Consistency::Quorum,
                serial: SerialConsistency::LocalSerial,
            }
        );
        assert_eq!(
            queries.render_golden(),
            include_str!(
                "../../tests/golden/rollback_branch_exact_deployment_lifecycle_v1.txt"
            )
        );
    }

    #[test]
    fn bindings_are_deterministic_and_keep_expected_payload() {
        let bootstrap = bootstrap("psy_h14_bind");
        let first = BranchExactDeploymentLifecycleBootstrapBinding::from_bootstrap(
            &bootstrap,
        );
        let second = BranchExactDeploymentLifecycleBootstrapBinding::from_bootstrap(
            &bootstrap,
        );
        assert_eq!(first, second);
        assert_eq!(
            render_bind_values(&first.values()),
            render_bind_values(&second.values())
        );

        let sealed = sealed("psy_h14_cas_bind");
        let binding = BranchExactDeploymentLifecycleCasBinding::from_sealed(&sealed);
        assert_eq!(
            binding.values()[3],
            BranchExactDeploymentLifecycleBindValue::BigInt(0)
        );
        assert_eq!(
            binding.values()[4],
            BranchExactDeploymentLifecycleBindValue::Blob(
                sealed.expected().payload().to_vec()
            )
        );
    }

    #[test]
    fn prototype_is_not_wired_into_production_setup() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE));
        assert!(!setup.contains("ScyllaBranchExactDeploymentLifecycleStore"));
    }
}
