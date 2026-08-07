//! Durable, ABA-safe baseline shadow-audit evidence.
//!
//! This independent no-tablet LWT row intentionally does not advance the h16
//! deployment lifecycle beyond BACKFILL_VERIFIED.  It records whether every
//! h19 artifact row was freshly compared through the h21 old/new reader.  A
//! VERIFIED receipt is only future reader-cutover input; it does not authorize
//! a writer or primary reader by itself.

use std::{error::Error, fmt, sync::Arc};

use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactBackfillArtifact,
    BranchExactBackfillDatasetDigest, BranchExactLegacyExportReceipt,
    BranchExactFrozenLegacyExportPermit,
    BranchExactSchemaReadyDigest, BranchExactShadowAuditDigest,
    BranchExactShadowAuditObservation, BranchExactShadowReadError,
    BranchExactDeploymentNoTabletKeyspace,
    ScyllaBranchExactShadowReader,
};

const TABLE: &str = "branch_exact_shadow_audit_v1";
const STATE_MAGIC: [u8; 8] = *b"PSYBEXSA";
const STATE_CODEC_VERSION: u16 = 1;
const PLAN_DIGEST_DOMAIN: &[u8] = b"psy/rollback/branch-exact-shadow-audit-plan/v1";
const SOURCE_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-shadow-source-receipt/v1";
const VERIFIED_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-shadow-verified/v1";
const BLOCKED_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-shadow-blocked/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactShadowAuditGeneration(u64);

impl BranchExactShadowAuditGeneration {
    pub fn try_new(value: u64) -> Result<Self, BranchExactShadowAuditError> {
        if value > i64::MAX as u64 {
            return Err(BranchExactShadowAuditError::GenerationOutOfRange);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowAuditPlanDigest([u8; 32]);

impl BranchExactShadowAuditPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowSourceReceiptDigest([u8; 32]);

impl BranchExactShadowSourceReceiptDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowAuditSlot([u8; 32]);

impl BranchExactShadowAuditSlot {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowAuditPlan {
    generation: BranchExactShadowAuditGeneration,
    schema_ready_digest: BranchExactSchemaReadyDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    source_receipt_digest: BranchExactShadowSourceReceiptDigest,
    mapping_rows: u64,
    proof_rows: u64,
    digest: BranchExactShadowAuditPlanDigest,
    slot: BranchExactShadowAuditSlot,
}

impl BranchExactShadowAuditPlan {
    pub fn try_new(
        generation: BranchExactShadowAuditGeneration,
        schema_ready_digest: BranchExactSchemaReadyDigest,
        dataset_digest: BranchExactBackfillDatasetDigest,
        source: &BranchExactLegacyExportReceipt,
    ) -> Result<Self, BranchExactShadowAuditError> {
        if source.dataset_digest() != dataset_digest {
            return Err(BranchExactShadowAuditError::DatasetMismatch);
        }
        let source_receipt_digest = source_receipt_digest(source);
        let mut plan = Self {
            generation,
            schema_ready_digest,
            dataset_digest,
            source_receipt_digest,
            mapping_rows: source.pair_rows(),
            proof_rows: source.proof_rows(),
            digest: BranchExactShadowAuditPlanDigest([0; 32]),
            slot: BranchExactShadowAuditSlot([0; 32]),
        };
        plan.digest = plan_digest(&plan);
        plan.slot = slot_digest(plan.digest, generation);
        Ok(plan)
    }

    pub const fn generation(&self) -> BranchExactShadowAuditGeneration {
        self.generation
    }

    pub const fn schema_ready_digest(&self) -> BranchExactSchemaReadyDigest {
        self.schema_ready_digest
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub const fn source_receipt_digest(&self) -> BranchExactShadowSourceReceiptDigest {
        self.source_receipt_digest
    }

    pub const fn mapping_rows(&self) -> u64 {
        self.mapping_rows
    }

    pub const fn proof_rows(&self) -> u64 {
        self.proof_rows
    }

    pub const fn digest(&self) -> BranchExactShadowAuditPlanDigest {
        self.digest
    }

    pub const fn slot(&self) -> BranchExactShadowAuditSlot {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowVerifiedDigest([u8; 32]);

impl BranchExactShadowVerifiedDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowVerifiedReceipt {
    plan: BranchExactShadowAuditPlan,
    observation_digest: BranchExactShadowAuditDigest,
    digest: BranchExactShadowVerifiedDigest,
}

impl BranchExactShadowVerifiedReceipt {
    pub fn try_new(
        plan: BranchExactShadowAuditPlan,
        observation: &BranchExactShadowAuditObservation,
    ) -> Result<Self, BranchExactShadowAuditError> {
        if observation.schema_ready_digest() != plan.schema_ready_digest
            || observation.dataset_digest() != plan.dataset_digest
            || observation.mapping_rows() != plan.mapping_rows
            || observation.proof_rows() != plan.proof_rows
        {
            return Err(BranchExactShadowAuditError::ObservationMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(VERIFIED_DIGEST_DOMAIN);
        hasher.update(plan.digest.as_bytes());
        hasher.update(observation.digest().as_bytes());
        Ok(Self {
            plan,
            observation_digest: observation.digest(),
            digest: BranchExactShadowVerifiedDigest(hasher.finalize().into()),
        })
    }

    pub const fn plan(&self) -> &BranchExactShadowAuditPlan {
        &self.plan
    }

    pub const fn observation_digest(&self) -> BranchExactShadowAuditDigest {
        self.observation_digest
    }

    pub const fn digest(&self) -> BranchExactShadowVerifiedDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowBlockedDigest([u8; 32]);

impl BranchExactShadowBlockedDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowBlockedReceipt {
    plan: BranchExactShadowAuditPlan,
    mismatch_digest: BranchExactShadowBlockedDigest,
}

impl BranchExactShadowBlockedReceipt {
    pub fn from_error(
        plan: BranchExactShadowAuditPlan,
        error: &BranchExactShadowReadError,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(BLOCKED_DIGEST_DOMAIN);
        hasher.update(plan.digest.as_bytes());
        hasher.update(format!("{error:?}").as_bytes());
        Self {
            plan,
            mismatch_digest: BranchExactShadowBlockedDigest(
                hasher.finalize().into(),
            ),
        }
    }

    pub const fn plan(&self) -> &BranchExactShadowAuditPlan {
        &self.plan
    }

    pub const fn mismatch_digest(&self) -> BranchExactShadowBlockedDigest {
        self.mismatch_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowAuditState {
    Comparing(BranchExactShadowAuditPlan),
    Verified(BranchExactShadowVerifiedReceipt),
    Blocked(BranchExactShadowBlockedReceipt),
}

impl BranchExactShadowAuditState {
    pub const fn plan(&self) -> &BranchExactShadowAuditPlan {
        match self {
            Self::Comparing(plan) => plan,
            Self::Verified(receipt) => receipt.plan(),
            Self::Blocked(receipt) => receipt.plan(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBranchExactShadowAudit {
    revision: u64,
    state: BranchExactShadowAuditState,
}

impl StoredBranchExactShadowAudit {
    fn comparing(plan: BranchExactShadowAuditPlan) -> Self {
        Self {
            revision: 0,
            state: BranchExactShadowAuditState::Comparing(plan),
        }
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn state(&self) -> &BranchExactShadowAuditState {
        &self.state
    }

    pub const fn slot(&self) -> BranchExactShadowAuditSlot {
        self.state.plan().slot()
    }

    fn encode_state(&self) -> Vec<u8> {
        encode_state(self)
    }

    fn decode(
        selected_slot: &[u8],
        revision: i64,
        state: &[u8],
    ) -> Result<Self, BranchExactShadowAuditError> {
        if revision < 0 {
            return Err(BranchExactShadowAuditError::NegativeRevision(revision));
        }
        let decoded = decode_state(state)?;
        if decoded.revision != revision as u64
            || selected_slot != decoded.slot().as_bytes()
        {
            return Err(BranchExactShadowAuditError::PersistedIdentityMismatch);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowAuditBootstrap {
    candidate: StoredBranchExactShadowAudit,
}

impl BranchExactShadowAuditBootstrap {
    pub fn new(plan: BranchExactShadowAuditPlan) -> Self {
        Self {
            candidate: StoredBranchExactShadowAudit::comparing(plan),
        }
    }

    pub const fn candidate(&self) -> &StoredBranchExactShadowAudit {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactShadowAuditCas {
    expected: StoredBranchExactShadowAudit,
    candidate: StoredBranchExactShadowAudit,
}

impl SealedBranchExactShadowAuditCas {
    pub fn verify(
        expected: &StoredBranchExactShadowAudit,
        receipt: BranchExactShadowVerifiedReceipt,
    ) -> Result<Self, BranchExactShadowAuditError> {
        if !matches!(expected.state, BranchExactShadowAuditState::Comparing(_))
            || expected.state.plan() != receipt.plan()
        {
            return Err(BranchExactShadowAuditError::IllegalTransition);
        }
        Ok(Self {
            expected: expected.clone(),
            candidate: StoredBranchExactShadowAudit {
                revision: expected
                    .revision
                    .checked_add(1)
                    .ok_or(BranchExactShadowAuditError::RevisionOverflow)?,
                state: BranchExactShadowAuditState::Verified(receipt),
            },
        })
    }

    pub fn block(
        expected: &StoredBranchExactShadowAudit,
        receipt: BranchExactShadowBlockedReceipt,
    ) -> Result<Self, BranchExactShadowAuditError> {
        if matches!(expected.state, BranchExactShadowAuditState::Blocked(_))
            || expected.state.plan() != receipt.plan()
        {
            return Err(BranchExactShadowAuditError::IllegalTransition);
        }
        Ok(Self {
            expected: expected.clone(),
            candidate: StoredBranchExactShadowAudit {
                revision: expected
                    .revision
                    .checked_add(1)
                    .ok_or(BranchExactShadowAuditError::RevisionOverflow)?,
                state: BranchExactShadowAuditState::Blocked(receipt),
            },
        })
    }

    pub const fn expected(&self) -> &StoredBranchExactShadowAudit {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactShadowAudit {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowAuditReadState {
    Uninitialized,
    Current(StoredBranchExactShadowAudit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowAuditWriteOutcome {
    Applied(StoredBranchExactShadowAudit),
    Idempotent(StoredBranchExactShadowAudit),
    Conflict(StoredBranchExactShadowAudit),
}

pub struct ScyllaBranchExactShadowAuditStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowAuditQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl BranchExactShadowAuditQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{TABLE}", keyspace.as_str());
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (audit_slot blob PRIMARY KEY, revision bigint, audit blob)"
            ),
            read: format!(
                "SELECT audit_slot, revision, audit FROM {table} WHERE audit_slot = ?"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (audit_slot, revision, audit) VALUES (?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, audit = ? WHERE audit_slot = ? IF revision = ? AND audit = ?"
            ),
        }
    }

    pub fn create(&self) -> &str { &self.create }
    pub fn read(&self) -> &str { &self.read }
    pub fn bootstrap(&self) -> &str { &self.bootstrap }
    pub fn compare_and_set(&self) -> &str { &self.compare_and_set }

    pub fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BLOB,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.compare_and_set,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowAuditExecutionOutcome {
    Verified(BranchExactShadowVerifiedReceipt),
    Idempotent(BranchExactShadowVerifiedReceipt),
}

pub struct ScyllaBranchExactShadowAuditExecutor;

impl ScyllaBranchExactShadowAuditExecutor {
    /// Run and durably publish one complete frozen-baseline comparison.
    /// Mismatches are terminal for this generation and are persisted before
    /// the original error is returned.
    pub async fn run<Hash: parth_core::protocol::core_types::Q256BitHash>(
        store: &ScyllaBranchExactShadowAuditStore,
        reader: &ScyllaBranchExactShadowReader<Hash>,
        artifact: &BranchExactBackfillArtifact<Hash>,
        source: &BranchExactLegacyExportReceipt,
        freeze: &BranchExactFrozenLegacyExportPermit<Hash>,
        generation: BranchExactShadowAuditGeneration,
    ) -> Result<BranchExactShadowAuditExecutionOutcome, BranchExactShadowAuditRunError> {
        if source.permit_digest() != freeze.digest()
            || freeze.request().plan().authority() != reader.authority()
            || freeze.request().keyspace() != reader.setup_view().keyspace()
        {
            return Err(BranchExactShadowAuditError::FreezePermitMismatch.into());
        }
        let plan = BranchExactShadowAuditPlan::try_new(
            generation,
            reader.setup_view().digest(),
            artifact.dataset_digest(),
            source,
        )?;
        let bootstrap = BranchExactShadowAuditBootstrap::new(plan.clone());
        let current = match store.bootstrap(&bootstrap).await? {
            BranchExactShadowAuditWriteOutcome::Applied(current)
            | BranchExactShadowAuditWriteOutcome::Idempotent(current) => current,
            BranchExactShadowAuditWriteOutcome::Conflict(current) => {
                return existing_terminal(current)
            }
        };
        match current.state() {
            BranchExactShadowAuditState::Verified(receipt) => {
                return Ok(BranchExactShadowAuditExecutionOutcome::Idempotent(
                    receipt.clone(),
                ))
            }
            BranchExactShadowAuditState::Blocked(receipt) => {
                return Err(BranchExactShadowAuditRunError::PreviouslyBlocked(
                    receipt.mismatch_digest(),
                ))
            }
            BranchExactShadowAuditState::Comparing(_) => {}
        }

        match reader.audit_artifact(artifact).await {
            Ok(observation) => {
                let receipt = BranchExactShadowVerifiedReceipt::try_new(
                    plan,
                    &observation,
                )?;
                let sealed = SealedBranchExactShadowAuditCas::verify(
                    &current,
                    receipt.clone(),
                )?;
                match store.compare_and_set(&sealed).await? {
                    BranchExactShadowAuditWriteOutcome::Applied(_) => Ok(
                        BranchExactShadowAuditExecutionOutcome::Verified(receipt),
                    ),
                    BranchExactShadowAuditWriteOutcome::Idempotent(_) => Ok(
                        BranchExactShadowAuditExecutionOutcome::Idempotent(receipt),
                    ),
                    BranchExactShadowAuditWriteOutcome::Conflict(other) => {
                        existing_terminal(other)
                    }
                }
            }
            Err(read_error) => {
                let blocked = BranchExactShadowBlockedReceipt::from_error(
                    plan,
                    &read_error,
                );
                let blocked_digest = blocked.mismatch_digest();
                persist_blocked(store, current, blocked.clone()).await?;
                Err(BranchExactShadowAuditRunError::Comparison {
                    mismatch_digest: blocked_digest,
                    source: read_error,
                })
            }
        }
    }
}

/// A mismatch is monotonic and dominates a concurrently published VERIFIED
/// observation.  This closes the clean-vs-mismatch race without allowing any
/// BLOCKED generation to become VERIFIED again.  A future cutover must reread
/// the durable terminal state; an in-memory receipt alone is never authority.
async fn persist_blocked(
    store: &ScyllaBranchExactShadowAuditStore,
    mut current: StoredBranchExactShadowAudit,
    blocked: BranchExactShadowBlockedReceipt,
) -> Result<(), BranchExactShadowAuditRunError> {
    loop {
        if current.state().plan() != blocked.plan() {
            return Err(BranchExactShadowAuditRunError::ConcurrentConflict);
        }
        if matches!(current.state(), BranchExactShadowAuditState::Blocked(_)) {
            return Ok(());
        }
        let sealed = SealedBranchExactShadowAuditCas::block(
            &current,
            blocked.clone(),
        )?;
        match store.compare_and_set(&sealed).await? {
            BranchExactShadowAuditWriteOutcome::Applied(_)
            | BranchExactShadowAuditWriteOutcome::Idempotent(_) => return Ok(()),
            BranchExactShadowAuditWriteOutcome::Conflict(next) => {
                current = next;
            }
        }
    }
}

fn existing_terminal(
    current: StoredBranchExactShadowAudit,
) -> Result<BranchExactShadowAuditExecutionOutcome, BranchExactShadowAuditRunError> {
    match current.state {
        BranchExactShadowAuditState::Verified(receipt) => Ok(
            BranchExactShadowAuditExecutionOutcome::Idempotent(receipt),
        ),
        BranchExactShadowAuditState::Blocked(receipt) => Err(
            BranchExactShadowAuditRunError::PreviouslyBlocked(
                receipt.mismatch_digest(),
            ),
        ),
        BranchExactShadowAuditState::Comparing(_) => {
            Err(BranchExactShadowAuditRunError::ConcurrentConflict)
        }
    }
}

#[derive(Debug)]
pub enum BranchExactShadowAuditRunError {
    Audit(BranchExactShadowAuditError),
    Comparison {
        mismatch_digest: BranchExactShadowBlockedDigest,
        source: BranchExactShadowReadError,
    },
    PreviouslyBlocked(BranchExactShadowBlockedDigest),
    ConcurrentConflict,
}

impl From<BranchExactShadowAuditError> for BranchExactShadowAuditRunError {
    fn from(error: BranchExactShadowAuditError) -> Self { Self::Audit(error) }
}

impl fmt::Display for BranchExactShadowAuditRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactShadowAuditRunError {}

impl ScyllaBranchExactShadowAuditStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), BranchExactShadowAuditError> {
        let queries = BranchExactShadowAuditQueries::new(keyspace);
        session
            .query_unpaged(queries.create(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, BranchExactShadowAuditError> {
        let queries = BranchExactShadowAuditQueries::new(&keyspace);
        let read = prepare_read(&session, queries.read().to_owned()).await?;
        let bootstrap = prepare_lwt(&session, queries.bootstrap().to_owned()).await?;
        let cas = prepare_lwt(&session, queries.compare_and_set().to_owned()).await?;
        Ok(Self {
            session,
            read,
            bootstrap,
            cas,
        })
    }

    pub async fn read(
        &self,
        slot: BranchExactShadowAuditSlot,
    ) -> Result<BranchExactShadowAuditReadState, BranchExactShadowAuditError> {
        let row = self
            .session
            .execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Vec<u8>, Option<i64>, Option<Vec<u8>>)>()
            .map_err(cql)?;
        match row {
            None => Ok(BranchExactShadowAuditReadState::Uninitialized),
            Some((selected_slot, revision, audit)) => Ok(
                BranchExactShadowAuditReadState::Current(
                    StoredBranchExactShadowAudit::decode(
                        &selected_slot,
                        revision.ok_or(BranchExactShadowAuditError::MissingRevision)?,
                        audit
                            .as_deref()
                            .ok_or(BranchExactShadowAuditError::MissingPayload)?,
                    )?,
                ),
            ),
        }
    }

    pub async fn bootstrap(
        &self,
        bootstrap: &BranchExactShadowAuditBootstrap,
    ) -> Result<BranchExactShadowAuditWriteOutcome, BranchExactShadowAuditError> {
        let candidate = bootstrap.candidate();
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    candidate.slot().as_bytes().as_slice(),
                    candidate.revision as i64,
                    candidate.encode_state(),
                ),
            )
            .await;
        self.finish(execution, candidate).await
    }

    pub async fn compare_and_set(
        &self,
        sealed: &SealedBranchExactShadowAuditCas,
    ) -> Result<BranchExactShadowAuditWriteOutcome, BranchExactShadowAuditError> {
        let candidate = sealed.candidate();
        let expected = sealed.expected();
        let execution = self
            .session
            .execute_unpaged(
                &self.cas,
                (
                    candidate.revision as i64,
                    candidate.encode_state(),
                    candidate.slot().as_bytes().as_slice(),
                    expected.revision as i64,
                    expected.encode_state(),
                ),
            )
            .await;
        self.finish(execution, candidate).await
    }

    /// RF=3 qualification hook for the exact readback path used after an
    /// indeterminate transport outcome.  It performs no write and is absent
    /// from non-test builds.
    #[cfg(test)]
    pub(crate) async fn reconcile_unknown_outcome_for_test(
        &self,
        candidate: &StoredBranchExactShadowAudit,
    ) -> Result<BranchExactShadowAuditWriteOutcome, BranchExactShadowAuditError> {
        match self.read(candidate.slot()).await? {
            BranchExactShadowAuditReadState::Current(current)
                if &current == candidate =>
            {
                Ok(BranchExactShadowAuditWriteOutcome::Idempotent(current))
            }
            BranchExactShadowAuditReadState::Current(current) => {
                Ok(BranchExactShadowAuditWriteOutcome::Conflict(current))
            }
            BranchExactShadowAuditReadState::Uninitialized => {
                Err(BranchExactShadowAuditError::CurrentMissingAfterLwt)
            }
        }
    }

    async fn finish(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredBranchExactShadowAudit,
    ) -> Result<BranchExactShadowAuditWriteOutcome, BranchExactShadowAuditError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => {
                return match self.read(candidate.slot()).await? {
                    BranchExactShadowAuditReadState::Current(current)
                        if &current == candidate =>
                    {
                        Ok(BranchExactShadowAuditWriteOutcome::Idempotent(current))
                    }
                    BranchExactShadowAuditReadState::Current(current) => {
                        Ok(BranchExactShadowAuditWriteOutcome::Conflict(current))
                    }
                    BranchExactShadowAuditReadState::Uninitialized => Err(cql(error)),
                };
            }
        };
        let BranchExactShadowAuditReadState::Current(current) =
            self.read(candidate.slot()).await?
        else {
            return Err(BranchExactShadowAuditError::CurrentMissingAfterLwt);
        };
        if &current == candidate {
            Ok(if applied {
                BranchExactShadowAuditWriteOutcome::Applied(current)
            } else {
                BranchExactShadowAuditWriteOutcome::Idempotent(current)
            })
        } else {
            Ok(BranchExactShadowAuditWriteOutcome::Conflict(current))
        }
    }
}

fn source_receipt_digest(
    source: &BranchExactLegacyExportReceipt,
) -> BranchExactShadowSourceReceiptDigest {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_RECEIPT_DIGEST_DOMAIN);
    hasher.update(source.permit_digest().as_bytes());
    hasher.update(source.catalog_digest().as_bytes());
    hasher.update(source.source_digest().as_bytes());
    hasher.update(source.dataset_digest().as_bytes());
    hasher.update(source.pair_rows().to_be_bytes());
    hasher.update(source.proof_rows().to_be_bytes());
    hasher.update((source.source_chunk_digests().len() as u64).to_be_bytes());
    for digest in source.source_chunk_digests() {
        hasher.update(digest.as_bytes());
    }
    BranchExactShadowSourceReceiptDigest(hasher.finalize().into())
}

fn plan_digest(plan: &BranchExactShadowAuditPlan) -> BranchExactShadowAuditPlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(plan.generation.get().to_be_bytes());
    hasher.update(plan.schema_ready_digest.as_bytes());
    hasher.update(plan.dataset_digest.as_bytes());
    hasher.update(plan.source_receipt_digest.as_bytes());
    hasher.update(plan.mapping_rows.to_be_bytes());
    hasher.update(plan.proof_rows.to_be_bytes());
    BranchExactShadowAuditPlanDigest(hasher.finalize().into())
}

fn slot_digest(
    plan: BranchExactShadowAuditPlanDigest,
    generation: BranchExactShadowAuditGeneration,
) -> BranchExactShadowAuditSlot {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/branch-exact-shadow-audit-slot/v1");
    hasher.update(plan.as_bytes());
    hasher.update(generation.get().to_be_bytes());
    BranchExactShadowAuditSlot(hasher.finalize().into())
}

fn encode_plan(plan: &BranchExactShadowAuditPlan, out: &mut Vec<u8>) {
    out.extend_from_slice(&plan.generation.get().to_be_bytes());
    out.extend_from_slice(plan.schema_ready_digest.as_bytes());
    out.extend_from_slice(plan.dataset_digest.as_bytes());
    out.extend_from_slice(plan.source_receipt_digest.as_bytes());
    out.extend_from_slice(&plan.mapping_rows.to_be_bytes());
    out.extend_from_slice(&plan.proof_rows.to_be_bytes());
    out.extend_from_slice(plan.digest.as_bytes());
    out.extend_from_slice(plan.slot.as_bytes());
}

fn decode_plan(decoder: &mut Decoder<'_>) -> Result<BranchExactShadowAuditPlan, BranchExactShadowAuditError> {
    let plan = BranchExactShadowAuditPlan {
        generation: BranchExactShadowAuditGeneration::try_new(decoder.u64()?)?,
        schema_ready_digest: BranchExactSchemaReadyDigest::from_persisted(decoder.array32()?),
        dataset_digest: BranchExactBackfillDatasetDigest::try_new(decoder.array32()?)
            .map_err(|_| BranchExactShadowAuditError::PlanDigestMismatch)?,
        source_receipt_digest: BranchExactShadowSourceReceiptDigest(decoder.array32()?),
        mapping_rows: decoder.u64()?,
        proof_rows: decoder.u64()?,
        digest: BranchExactShadowAuditPlanDigest(decoder.array32()?),
        slot: BranchExactShadowAuditSlot(decoder.array32()?),
    };
    if plan.digest != plan_digest(&plan)
        || plan.slot != slot_digest(plan.digest, plan.generation)
    {
        return Err(BranchExactShadowAuditError::PlanDigestMismatch);
    }
    Ok(plan)
}

fn encode_state(stored: &StoredBranchExactShadowAudit) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&STATE_MAGIC);
    out.extend_from_slice(&STATE_CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&stored.revision.to_be_bytes());
    match &stored.state {
        BranchExactShadowAuditState::Comparing(plan) => {
            out.push(1);
            encode_plan(plan, &mut out);
        }
        BranchExactShadowAuditState::Verified(receipt) => {
            out.push(2);
            encode_plan(receipt.plan(), &mut out);
            out.extend_from_slice(receipt.observation_digest.as_bytes());
            out.extend_from_slice(receipt.digest.as_bytes());
        }
        BranchExactShadowAuditState::Blocked(receipt) => {
            out.push(3);
            encode_plan(receipt.plan(), &mut out);
            out.extend_from_slice(receipt.mismatch_digest.as_bytes());
        }
    }
    out
}

fn decode_state(bytes: &[u8]) -> Result<StoredBranchExactShadowAudit, BranchExactShadowAuditError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != STATE_MAGIC {
        return Err(BranchExactShadowAuditError::InvalidMagic);
    }
    let version = decoder.u16()?;
    if version != STATE_CODEC_VERSION {
        return Err(BranchExactShadowAuditError::UnknownCodecVersion(version));
    }
    let revision = decoder.u64()?;
    let state = match decoder.u8()? {
        1 => BranchExactShadowAuditState::Comparing(decode_plan(&mut decoder)?),
        2 => {
            let plan = decode_plan(&mut decoder)?;
            let observation_digest = BranchExactShadowAuditDigest::from_persisted(decoder.array32()?);
            let digest = BranchExactShadowVerifiedDigest(decoder.array32()?);
            let mut hasher = Sha256::new();
            hasher.update(VERIFIED_DIGEST_DOMAIN);
            hasher.update(plan.digest.as_bytes());
            hasher.update(observation_digest.as_bytes());
            if digest != BranchExactShadowVerifiedDigest(hasher.finalize().into()) {
                return Err(BranchExactShadowAuditError::ReceiptDigestMismatch);
            }
            BranchExactShadowAuditState::Verified(BranchExactShadowVerifiedReceipt {
                plan,
                observation_digest,
                digest,
            })
        }
        3 => BranchExactShadowAuditState::Blocked(BranchExactShadowBlockedReceipt {
            plan: decode_plan(&mut decoder)?,
            mismatch_digest: BranchExactShadowBlockedDigest(decoder.array32()?),
        }),
        kind => return Err(BranchExactShadowAuditError::UnknownStateKind(kind)),
    };
    if !decoder.is_done() {
        return Err(BranchExactShadowAuditError::TrailingBytes);
    }
    if (revision == 0 && !matches!(state, BranchExactShadowAuditState::Comparing(_)))
        || (revision == 1 && matches!(state, BranchExactShadowAuditState::Comparing(_)))
        || (revision == 2 && !matches!(state, BranchExactShadowAuditState::Blocked(_)))
        || revision > 2
    {
        return Err(BranchExactShadowAuditError::RevisionStateMismatch);
    }
    Ok(StoredBranchExactShadowAudit { revision, state })
}

struct Decoder<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], BranchExactShadowAuditError> {
        let end = self.offset.checked_add(length).ok_or(BranchExactShadowAuditError::TruncatedPayload)?;
        let value = self.bytes.get(self.offset..end).ok_or(BranchExactShadowAuditError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, BranchExactShadowAuditError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, BranchExactShadowAuditError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, BranchExactShadowAuditError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], BranchExactShadowAuditError> { Ok(self.take(32)?.try_into().unwrap()) }
    const fn is_done(&self) -> bool { self.offset == self.bytes.len() }
}

async fn prepare_read(session: &Session, cql_text: String) -> Result<PreparedStatement, BranchExactShadowAuditError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: String) -> Result<PreparedStatement, BranchExactShadowAuditError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, BranchExactShadowAuditError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]").ok_or(BranchExactShadowAuditError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(BranchExactShadowAuditError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> BranchExactShadowAuditError {
    BranchExactShadowAuditError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowAuditError {
    GenerationOutOfRange,
    DatasetMismatch,
    ObservationMismatch,
    IllegalTransition,
    RevisionOverflow,
    NegativeRevision(i64),
    MissingRevision,
    MissingPayload,
    PersistedIdentityMismatch,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownStateKind(u8),
    TruncatedPayload,
    TrailingBytes,
    PlanDigestMismatch,
    ReceiptDigestMismatch,
    RevisionStateMismatch,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    CurrentMissingAfterLwt,
    FreezePermitMismatch,
    Cql(String),
}

impl fmt::Display for BranchExactShadowAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for BranchExactShadowAuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        BranchExactShadowAuditPlan,
        BranchExactShadowAuditObservation,
    ) {
        let dataset = BranchExactBackfillDatasetDigest::try_new([7; 32]).unwrap();
        let ready = BranchExactSchemaReadyDigest::test_fixture(8);
        let source = BranchExactLegacyExportReceipt::test_fixture(dataset, 10, 10);
        let plan = BranchExactShadowAuditPlan::try_new(
            BranchExactShadowAuditGeneration::try_new(3).unwrap(),
            ready,
            dataset,
            &source,
        )
        .unwrap();
        let observation = BranchExactShadowAuditObservation::test_fixture(
            ready, dataset, 10, 10,
        );
        (plan, observation)
    }

    #[test]
    fn generation_is_bounded_by_cql_bigint() {
        assert!(BranchExactShadowAuditGeneration::try_new(i64::MAX as u64).is_ok());
        assert_eq!(
            BranchExactShadowAuditGeneration::try_new(i64::MAX as u64 + 1),
            Err(BranchExactShadowAuditError::GenerationOutOfRange)
        );
    }

    #[test]
    fn malformed_codec_fails_closed() {
        assert_eq!(decode_state(b"short"), Err(BranchExactShadowAuditError::TruncatedPayload));
    }

    #[test]
    fn plan_and_slot_are_deterministic_and_generation_separated() {
        let (first, _) = fixture();
        let dataset = first.dataset_digest();
        let source = BranchExactLegacyExportReceipt::test_fixture(dataset, 10, 10);
        let same = BranchExactShadowAuditPlan::try_new(
            first.generation(),
            first.schema_ready_digest(),
            dataset,
            &source,
        )
        .unwrap();
        let next = BranchExactShadowAuditPlan::try_new(
            BranchExactShadowAuditGeneration::try_new(4).unwrap(),
            first.schema_ready_digest(),
            dataset,
            &source,
        )
        .unwrap();
        assert_eq!(first, same);
        assert_ne!(first.digest(), next.digest());
        assert_ne!(first.slot(), next.slot());
    }

    #[test]
    fn verified_transition_round_trips_and_revision_is_exactly_one() {
        let (plan, observation) = fixture();
        let initial = StoredBranchExactShadowAudit::comparing(plan.clone());
        let receipt = BranchExactShadowVerifiedReceipt::try_new(plan, &observation).unwrap();
        let sealed = SealedBranchExactShadowAuditCas::verify(&initial, receipt).unwrap();
        assert_eq!(sealed.expected().revision(), 0);
        assert_eq!(sealed.candidate().revision(), 1);
        let bytes = sealed.candidate().encode_state();
        let decoded = StoredBranchExactShadowAudit::decode(
            sealed.candidate().slot().as_bytes(),
            1,
            &bytes,
        )
        .unwrap();
        assert_eq!(&decoded, sealed.candidate());
    }

    #[test]
    fn mismatch_monotonically_dominates_verified_but_blocked_is_terminal() {
        let (plan, observation) = fixture();
        let initial = StoredBranchExactShadowAudit::comparing(plan.clone());
        let receipt = BranchExactShadowVerifiedReceipt::try_new(plan, &observation).unwrap();
        let first = SealedBranchExactShadowAuditCas::verify(&initial, receipt).unwrap();
        let blocked = BranchExactShadowBlockedReceipt::from_error(
            first.candidate().state().plan().clone(),
            &BranchExactShadowReadError::DatasetMismatch,
        );
        let dominant = SealedBranchExactShadowAuditCas::block(
            first.candidate(),
            blocked.clone(),
        )
        .unwrap();
        assert_eq!(dominant.expected().revision(), 1);
        assert_eq!(dominant.candidate().revision(), 2);
        assert!(matches!(
            dominant.candidate().state(),
            BranchExactShadowAuditState::Blocked(_)
        ));
        assert_eq!(
            SealedBranchExactShadowAuditCas::block(
                dominant.candidate(),
                blocked,
            ),
            Err(BranchExactShadowAuditError::IllegalTransition)
        );
    }

    #[test]
    fn unknown_version_and_trailing_bytes_fail_closed() {
        let (plan, _) = fixture();
        let stored = StoredBranchExactShadowAudit::comparing(plan);
        let mut unknown = stored.encode_state();
        unknown[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(decode_state(&unknown), Err(BranchExactShadowAuditError::UnknownCodecVersion(2)));
        let mut trailing = stored.encode_state();
        trailing.push(0);
        assert_eq!(decode_state(&trailing), Err(BranchExactShadowAuditError::TrailingBytes));
    }

    #[test]
    fn query_golden_binds_revision_and_payload_against_no_tablet_row() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h21_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = BranchExactShadowAuditQueries::new(&keyspace).golden();
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND audit = ?"));
        assert!(golden.contains("BIGINT,BLOB,BLOB,BIGINT,BLOB"));
        assert!(golden.contains("psy_h21_no_tablet.branch_exact_shadow_audit_v1"));
    }
}
