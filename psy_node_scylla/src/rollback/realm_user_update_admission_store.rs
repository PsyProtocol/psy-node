//! Full-payload LWT store for the Realm claim-admission journal.
//!
//! The independent row is deliberately a crash journal, not a claim/close
//! authority by itself.  A claimant first persists `BucketClaiming`, then the
//! claim store may execute IF NOT EXISTS, and finally this row is advanced to
//! `BucketOpen`.  A closer races the claimant on the same bucket row.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::queue::realm_user_update_admission::{
    RealmUserUpdateAdmissionError, RealmUserUpdateAdmissionKey,
    RealmUserUpdateAdmissionCloseIntent,
    RealmUserUpdateAdmissionPhase, RealmUserUpdateAdmissionShard,
    RealmUserUpdateBucketManifest, StoredRealmUserUpdateAdmission,
};
use psy_node_core::queue::realm_user_update_claim::{
    RealmUserUpdateAdmissionOrdinal, RealmUserUpdateClaimBucket,
    RealmUserUpdateClaimPartition, RealmUserUpdateCreatedAtSeconds,
    StoredRealmUserUpdateClaim,
};
use psy_node_core::queue::realm_user_update_publish::{
    RealmUserUpdatePublishAdmission, RealmUserUpdateRequestDigest,
};
use psy_node_core::store::typed::UserId;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::{
    realm_generation_scope::{bind_realm_generation, RealmGenerationBindError},
    realm_user_update_claim_store::{
        RealmUserUpdateClaimReadState, RealmUserUpdateClaimStoreError,
        RealmUserUpdateClaimWriteOutcome, ScyllaRealmUserUpdateClaimStore,
    },
    BranchExactDeploymentNoTabletKeyspace,
};

pub(super) const REALM_USER_UPDATE_ADMISSION_TABLE: &str =
    "branch_exact_realm_user_update_admission_v1";
const MAX_GATE_STEPS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateAdmissionQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl RealmUserUpdateAdmissionQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            REALM_USER_UPDATE_ADMISSION_TABLE
        );
        let key = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND admission_shard = ?";
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, activation_digest blob, unique_pending_id bigint, proc_checkpoint_id blob, admission_shard smallint, revision bigint, admission_payload blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, admission_shard)))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, admission_shard, revision, admission_payload FROM {table} WHERE {key}"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, admission_shard, revision, admission_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, admission_payload = ? WHERE {key} IF revision = ? AND admission_payload = ?"
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
            "create\n{}\n\nread\n{}\nBIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT\n\nbootstrap\n{}\nBIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BLOB,BIGINT,BLOB,SMALLINT,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.compare_and_set,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateAdmissionReadState<Hash> {
    Uninitialized,
    Current(StoredRealmUserUpdateAdmission<Hash>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateAdmissionWriteDisposition {
    Applied,
    Resumed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateAdmissionWriteOutcome<Hash> {
    Applied {
        current: StoredRealmUserUpdateAdmission<Hash>,
        disposition: RealmUserUpdateAdmissionWriteDisposition,
    },
    Conflict(StoredRealmUserUpdateAdmission<Hash>),
}

impl<Hash> RealmUserUpdateAdmissionWriteOutcome<Hash> {
    pub(crate) fn current(&self) -> &StoredRealmUserUpdateAdmission<Hash> {
        match self {
            Self::Applied { current, .. } | Self::Conflict(current) => current,
        }
    }

    pub(crate) const fn applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// Proof that the exact `BucketClaiming` journal is durable.  There is no
/// public constructor; only successful LWT/readback in this module can mint it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersistedRealmUserUpdateClaimingReceipt<Hash> {
    current: StoredRealmUserUpdateAdmission<Hash>,
}

impl<Hash: Q256BitHash> PersistedRealmUserUpdateClaimingReceipt<Hash> {
    fn try_from_current(
        current: StoredRealmUserUpdateAdmission<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionStoreError> {
        if current.phase() != RealmUserUpdateAdmissionPhase::BucketClaiming
            || current.claiming_candidate().is_none()
        {
            return Err(RealmUserUpdateAdmissionStoreError::NotClaiming);
        }
        Ok(Self { current })
    }

    pub(crate) fn candidate(
        &self,
    ) -> &psy_node_core::queue::realm_user_update_claim::StoredRealmUserUpdateClaim<Hash>
    {
        self.current
            .claiming_candidate()
            .expect("receipt constructor checked the phase")
    }

    pub(crate) const fn journal(&self) -> &StoredRealmUserUpdateAdmission<Hash> {
        &self.current
    }
}

type AdmissionPartitionBind =
    (i64, i8, i64, i32, Vec<u8>, i64, Vec<u8>, i16);

fn bind_partition(
    key: RealmUserUpdateAdmissionKey,
    shard: RealmUserUpdateAdmissionShard,
) -> Result<AdmissionPartitionBind, RealmUserUpdateAdmissionStoreError> {
    let (network, kind, realm, sub, activation, pending, proc_id) =
        bind_realm_generation(key.capture()).map_err(generation_bind)?;
    Ok((
        network,
        kind,
        realm,
        sub,
        activation,
        pending,
        proc_id,
        shard.as_i16().map_err(model)?,
    ))
}

pub(crate) struct ScyllaRealmUserUpdateAdmissionStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaRealmUserUpdateAdmissionStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), RealmUserUpdateAdmissionStoreError> {
        let queries = RealmUserUpdateAdmissionQueries::new(keyspace);
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
    ) -> Result<Self, RealmUserUpdateAdmissionStoreError> {
        let queries = RealmUserUpdateAdmissionQueries::new(&keyspace);
        Ok(Self {
            read: prepare_read(&session, queries.read()).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap()).await?,
            compare_and_set: prepare_lwt(&session, queries.compare_and_set()).await?,
            session,
        })
    }

    pub(crate) async fn read<Hash: Q256BitHash>(
        &self,
        key: RealmUserUpdateAdmissionKey,
        shard: RealmUserUpdateAdmissionShard,
    ) -> Result<RealmUserUpdateAdmissionReadState<Hash>, RealmUserUpdateAdmissionStoreError>
    {
        let bind = bind_partition(key, shard)?;
        let row = self
            .session
            .execute_unpaged(&self.read, bind.clone())
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
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let Some((
            network,
            kind,
            realm,
            sub,
            activation,
            pending,
            proc_id,
            selected_shard,
            revision,
            payload,
        )) = row
        else {
            return Ok(RealmUserUpdateAdmissionReadState::Uninitialized);
        };
        if (
            network,
            kind,
            realm,
            sub,
            activation,
            pending,
            proc_id,
            selected_shard,
        ) != bind
        {
            return Err(RealmUserUpdateAdmissionStoreError::SelectedIdentityMismatch);
        }
        let current = StoredRealmUserUpdateAdmission::decode_selected(
            key,
            selected_shard,
            revision.ok_or(RealmUserUpdateAdmissionStoreError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(RealmUserUpdateAdmissionStoreError::MissingColumn)?,
        )
        .map_err(model)?;
        Ok(RealmUserUpdateAdmissionReadState::Current(current))
    }

    pub(crate) async fn bootstrap<Hash: Q256BitHash>(
        &self,
        candidate: &StoredRealmUserUpdateAdmission<Hash>,
    ) -> Result<RealmUserUpdateAdmissionWriteOutcome<Hash>, RealmUserUpdateAdmissionStoreError>
    {
        if candidate.revision().get() != 1 {
            return Err(RealmUserUpdateAdmissionStoreError::InvalidTransition);
        }
        let (network, kind, realm, sub, activation, pending, proc_id, shard) =
            bind_partition(candidate.key(), candidate.shard())?;
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
                    shard,
                    candidate.revision().as_i64().map_err(model)?,
                    candidate.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish_write(execution, candidate).await
    }

    pub(crate) async fn compare_and_set<Hash: Q256BitHash>(
        &self,
        expected: &StoredRealmUserUpdateAdmission<Hash>,
        candidate: &StoredRealmUserUpdateAdmission<Hash>,
    ) -> Result<RealmUserUpdateAdmissionWriteOutcome<Hash>, RealmUserUpdateAdmissionStoreError>
    {
        if expected.key() != candidate.key()
            || expected.shard() != candidate.shard()
            || candidate.revision().get() != expected.revision().get() + 1
        {
            return Err(RealmUserUpdateAdmissionStoreError::InvalidTransition);
        }
        let (network, kind, realm, sub, activation, pending, proc_id, shard) =
            bind_partition(candidate.key(), candidate.shard())?;
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
                    shard,
                    expected.revision().as_i64().map_err(model)?,
                    expected.to_canonical_bytes(),
                ),
            )
            .await;
        self.finish_write(execution, candidate).await
    }

    async fn finish_write<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredRealmUserUpdateAdmission<Hash>,
    ) -> Result<RealmUserUpdateAdmissionWriteOutcome<Hash>, RealmUserUpdateAdmissionStoreError>
    {
        let was_applied = match execution {
            Ok(result) => Some(decode_applied(result)?),
            Err(execute) => {
                return match self.read(candidate.key(), candidate.shard()).await {
                    Ok(RealmUserUpdateAdmissionReadState::Current(current))
                        if current == *candidate => Ok(applied(current, RealmUserUpdateAdmissionWriteDisposition::Resumed)),
                    Ok(RealmUserUpdateAdmissionReadState::Current(current)) => {
                        Err(RealmUserUpdateAdmissionStoreError::IndeterminateConflict {
                            execute: execute.to_string(),
                            observed_revision: current.revision().get(),
                        })
                    }
                    Ok(RealmUserUpdateAdmissionReadState::Uninitialized) => {
                        Err(RealmUserUpdateAdmissionStoreError::IndeterminateWrite {
                            execute: execute.to_string(),
                        })
                    }
                    Err(read) => Err(RealmUserUpdateAdmissionStoreError::IndeterminateRead {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let RealmUserUpdateAdmissionReadState::Current(current) =
            self.read(candidate.key(), candidate.shard()).await?
        else {
            return Err(RealmUserUpdateAdmissionStoreError::MissingAfterLwt);
        };
        if current == *candidate {
            Ok(applied(
                current,
                if was_applied == Some(true) {
                    RealmUserUpdateAdmissionWriteDisposition::Applied
                } else {
                    RealmUserUpdateAdmissionWriteDisposition::Resumed
                },
            ))
        } else {
            Ok(RealmUserUpdateAdmissionWriteOutcome::Conflict(current))
        }
    }

    pub(crate) fn claiming_receipt<Hash: Q256BitHash>(
        outcome: RealmUserUpdateAdmissionWriteOutcome<Hash>,
    ) -> Result<PersistedRealmUserUpdateClaimingReceipt<Hash>, RealmUserUpdateAdmissionStoreError>
    {
        if !outcome.applied() {
            return Err(RealmUserUpdateAdmissionStoreError::ClaimingConflict);
        }
        PersistedRealmUserUpdateClaimingReceipt::try_from_current(
            outcome.current().clone(),
        )
    }
}

/// Single authorizing path for creation of a Realm user-update claim row.
/// Phase CAS after creation remains in the claim store, but IF NOT EXISTS is
/// unreachable without a durable `BucketClaiming` receipt.
pub(crate) struct ScyllaRealmUserUpdateAdmissionGuard {
    gates: Arc<ScyllaRealmUserUpdateAdmissionStore>,
    claims: Arc<ScyllaRealmUserUpdateClaimStore>,
}

impl ScyllaRealmUserUpdateAdmissionGuard {
    pub(crate) fn new(
        gates: Arc<ScyllaRealmUserUpdateAdmissionStore>,
        claims: Arc<ScyllaRealmUserUpdateClaimStore>,
    ) -> Self {
        Self { gates, claims }
    }

    /// Explicit generation provisioning. Missing is never interpreted as an
    /// empty/open generation by claim or close paths.
    pub(crate) async fn provision_generation<Hash: Q256BitHash>(
        &self,
        key: RealmUserUpdateAdmissionKey,
    ) -> Result<StoredRealmUserUpdateAdmission<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        let candidate = StoredRealmUserUpdateAdmission::generation_open(key)
            .map_err(guard_admission)?;
        let outcome = self
            .gates
            .bootstrap(&candidate)
            .await
            .map_err(guard_gate_store)?;
        if outcome.applied() && outcome.current() == &candidate {
            Ok(candidate)
        } else {
            Err(RealmUserUpdateAdmissionGuardError::GenerationConflict)
        }
    }

    /// Close all 256 lazy bucket gates, recover any winning Claiming journal,
    /// verify every physical claim row and publish one stable generation
    /// manifest. This does not qualify Published/SourceCommitted terminal
    /// evidence; that is the following b3b2c gate.
    pub(crate) async fn close_generation<Hash: Q256BitHash>(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<StoredRealmUserUpdateAdmission<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        let mut header = match self
            .gates
            .read::<Hash>(key, RealmUserUpdateAdmissionShard::Generation)
            .await
            .map_err(guard_gate_store)?
        {
            RealmUserUpdateAdmissionReadState::Current(current) => current,
            RealmUserUpdateAdmissionReadState::Uninitialized => {
                return Err(RealmUserUpdateAdmissionGuardError::GenerationUninitialized)
            }
        };
        match header.phase() {
            RealmUserUpdateAdmissionPhase::GenerationOpen => {
                let closing = StoredRealmUserUpdateAdmission::begin_generation_close(
                    &header,
                    close,
                )
                .map_err(guard_admission)?;
                let outcome = self
                    .gates
                    .compare_and_set(&header, &closing)
                    .await
                    .map_err(guard_gate_store)?;
                if !outcome.applied() || outcome.current() != &closing {
                    return Err(RealmUserUpdateAdmissionGuardError::AdmissionRace);
                }
                header = closing;
            }
            RealmUserUpdateAdmissionPhase::GenerationClosing
                if header.close_intent() == Some(close) => {}
            RealmUserUpdateAdmissionPhase::GenerationClosed
                if header.close_intent() == Some(close) => return Ok(header),
            _ => return Err(RealmUserUpdateAdmissionGuardError::GenerationConflict),
        }

        let mut manifests = Vec::with_capacity(RealmUserUpdateClaimBucket::COUNT as usize);
        for index in 0..RealmUserUpdateClaimBucket::COUNT {
            let bucket = RealmUserUpdateClaimBucket::try_new(index)
                .map_err(guard_model)?;
            manifests.push(self.close_bucket::<Hash>(key, bucket, close).await?);
        }
        let closed = StoredRealmUserUpdateAdmission::close_generation(
            &header,
            close,
            &manifests,
        )
        .map_err(guard_admission)?;
        let outcome = self
            .gates
            .compare_and_set(&header, &closed)
            .await
            .map_err(guard_gate_store)?;
        if outcome.applied() && outcome.current() == &closed {
            Ok(closed)
        } else {
            Err(RealmUserUpdateAdmissionGuardError::AdmissionRace)
        }
    }

    async fn close_bucket<Hash: Q256BitHash>(
        &self,
        key: RealmUserUpdateAdmissionKey,
        bucket: RealmUserUpdateClaimBucket,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<RealmUserUpdateBucketManifest, RealmUserUpdateAdmissionGuardError>
    {
        let shard = RealmUserUpdateAdmissionShard::Bucket(bucket);
        let partition = RealmUserUpdateClaimPartition::try_new(key.capture(), bucket)
            .map_err(guard_model)?;
        for _ in 0..MAX_GATE_STEPS {
            match self
                .gates
                .read::<Hash>(key, shard)
                .await
                .map_err(guard_gate_store)?
            {
                RealmUserUpdateAdmissionReadState::Uninitialized => {
                    let closed = StoredRealmUserUpdateAdmission::<Hash>::bucket_closed(
                        partition,
                        close,
                    )
                    .map_err(guard_admission)?;
                    let _ = self
                        .gates
                        .bootstrap(&closed)
                        .await
                        .map_err(guard_gate_store)?;
                }
                RealmUserUpdateAdmissionReadState::Current(claiming)
                    if claiming.phase()
                        == RealmUserUpdateAdmissionPhase::BucketClaiming =>
                {
                    let receipt =
                        PersistedRealmUserUpdateClaimingReceipt::try_from_current(
                            claiming,
                        )
                        .map_err(guard_gate_store)?;
                    self.persist_receipt(receipt).await?;
                }
                RealmUserUpdateAdmissionReadState::Current(open)
                    if open.phase() == RealmUserUpdateAdmissionPhase::BucketOpen =>
                {
                    let closed = StoredRealmUserUpdateAdmission::close_bucket(
                        &open,
                        close,
                    )
                    .map_err(guard_admission)?;
                    let _ = self
                        .gates
                        .compare_and_set(&open, &closed)
                        .await
                        .map_err(guard_gate_store)?;
                }
                RealmUserUpdateAdmissionReadState::Current(closed)
                    if closed.phase()
                        == RealmUserUpdateAdmissionPhase::BucketClosed
                        && closed.close_intent() == Some(close) =>
                {
                    let claims = self
                        .claims
                        .scan_bucket::<Hash>(partition)
                        .await
                        .map_err(guard_claim_store)?;
                    let manifest = RealmUserUpdateBucketManifest::from_claims(
                        partition,
                        &claims,
                    )
                    .map_err(guard_admission)?;
                    let stable = StoredRealmUserUpdateAdmission::stabilize_bucket(
                        &closed,
                        close,
                        manifest,
                    )
                    .map_err(guard_admission)?;
                    let _ = self
                        .gates
                        .compare_and_set(&closed, &stable)
                        .await
                        .map_err(guard_gate_store)?;
                }
                RealmUserUpdateAdmissionReadState::Current(stable)
                    if stable.phase()
                        == RealmUserUpdateAdmissionPhase::BucketStable
                        && stable.close_intent() == Some(close) =>
                {
                    let claims = self
                        .claims
                        .scan_bucket::<Hash>(partition)
                        .await
                        .map_err(guard_claim_store)?;
                    let observed = RealmUserUpdateBucketManifest::from_claims(
                        partition,
                        &claims,
                    )
                    .map_err(guard_admission)?;
                    if stable.bucket_manifest() != Some(observed) {
                        return Err(
                            RealmUserUpdateAdmissionGuardError::MembershipMismatch,
                        );
                    }
                    return Ok(observed);
                }
                RealmUserUpdateAdmissionReadState::Current(_) => {
                    return Err(RealmUserUpdateAdmissionGuardError::GenerationConflict)
                }
            }
        }
        Err(RealmUserUpdateAdmissionGuardError::StepLimit)
    }

    /// Recover an already-created claim without requiring the live gathering
    /// frontier to remain current. The gate is still verified/recovered first;
    /// a raw point-read hit is never sufficient admission evidence.
    pub(crate) async fn resume_existing<Hash: Q256BitHash>(
        &self,
        admission: RealmUserUpdatePublishAdmission<Hash>,
        user_id: UserId,
        request_digest: RealmUserUpdateRequestDigest,
        created_at: RealmUserUpdateCreatedAtSeconds,
    ) -> Result<Option<StoredRealmUserUpdateClaim<Hash>>, RealmUserUpdateAdmissionGuardError>
    {
        let bucket = RealmUserUpdateClaimBucket::for_user(user_id);
        let partition = RealmUserUpdateClaimPartition::try_new(
            admission.capture(),
            bucket,
        )
        .map_err(guard_model)?;
        let RealmUserUpdateClaimReadState::Current(current) = self
            .claims
            .read(partition, user_id)
            .await
            .map_err(guard_claim_store)?
        else {
            return Ok(None);
        };
        let key = RealmUserUpdateAdmissionKey::try_new(admission.capture())
            .map_err(guard_admission)?;
        if matches!(
            self.gates
                .read::<Hash>(key, RealmUserUpdateAdmissionShard::Generation)
                .await
                .map_err(guard_gate_store)?,
            RealmUserUpdateAdmissionReadState::Uninitialized
        ) {
            return Err(RealmUserUpdateAdmissionGuardError::GenerationUninitialized);
        }
        let gate = self
            .gates
            .read::<Hash>(
                key,
                RealmUserUpdateAdmissionShard::Bucket(bucket),
            )
            .await
            .map_err(guard_gate_store)?;
        self.resume_existing_from_gate(
            gate,
            partition,
            current,
            admission,
            request_digest,
            created_at,
        )
        .await
        .map(Some)
    }

    /// Claim or resume one exact request. Missing generation admission is not
    /// interpreted as open; generation provisioning belongs to the pipeline
    /// lifecycle. Empty bucket rows are created lazily, so a stale claimant
    /// and the closer still compete on one full-payload LWT row.
    pub(crate) async fn claim<Hash: Q256BitHash>(
        &self,
        admission: RealmUserUpdatePublishAdmission<Hash>,
        user_id: UserId,
        request_digest: RealmUserUpdateRequestDigest,
        created_at: RealmUserUpdateCreatedAtSeconds,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        let bucket = RealmUserUpdateClaimBucket::for_user(user_id);
        let partition = RealmUserUpdateClaimPartition::try_new(
            admission.capture(),
            bucket,
        )
        .map_err(guard_model)?;
        let key = RealmUserUpdateAdmissionKey::try_new(admission.capture())
            .map_err(guard_admission)?;

        let existing = self
            .claims
            .read(partition, user_id)
            .await
            .map_err(guard_claim_store)?;
        let header = self
            .gates
            .read::<Hash>(key, RealmUserUpdateAdmissionShard::Generation)
            .await
            .map_err(guard_gate_store)?;
        let header_open = matches!(
            header,
            RealmUserUpdateAdmissionReadState::Current(ref current)
                if current.phase() == RealmUserUpdateAdmissionPhase::GenerationOpen
        );
        if matches!(header, RealmUserUpdateAdmissionReadState::Uninitialized) {
            return Err(RealmUserUpdateAdmissionGuardError::GenerationUninitialized);
        }

        let shard = RealmUserUpdateAdmissionShard::Bucket(bucket);
        let gate = self
            .gates
            .read::<Hash>(key, shard)
            .await
            .map_err(guard_gate_store)?;

        if let RealmUserUpdateClaimReadState::Current(current) = existing {
            return self
                .resume_existing_from_gate(
                    gate,
                    partition,
                    current,
                    admission,
                    request_digest,
                    created_at,
                )
                .await;
        }
        if !header_open {
            return Err(RealmUserUpdateAdmissionGuardError::AdmissionClosed);
        }

        match gate {
            RealmUserUpdateAdmissionReadState::Uninitialized => {
                let candidate = StoredRealmUserUpdateClaim::claimed(
                    admission,
                    user_id,
                    request_digest,
                    created_at,
                    RealmUserUpdateAdmissionOrdinal::FIRST,
                )
                .map_err(guard_model)?;
                let claiming = StoredRealmUserUpdateAdmission::bucket_claiming(candidate)
                    .map_err(guard_admission)?;
                let outcome = self
                    .gates
                    .bootstrap(&claiming)
                    .await
                    .map_err(guard_gate_store)?;
                self.persist_reserved(outcome).await
            }
            RealmUserUpdateAdmissionReadState::Current(open)
                if open.phase() == RealmUserUpdateAdmissionPhase::BucketOpen =>
            {
                let accepted = open
                    .accepted_set()
                    .ok_or(RealmUserUpdateAdmissionGuardError::MalformedGate)?;
                let ordinal = RealmUserUpdateAdmissionOrdinal::try_new(
                    accepted
                        .count()
                        .checked_add(1)
                        .ok_or(RealmUserUpdateAdmissionGuardError::CountOverflow)?,
                )
                .map_err(guard_model)?;
                let candidate = StoredRealmUserUpdateClaim::claimed(
                    admission,
                    user_id,
                    request_digest,
                    created_at,
                    ordinal,
                )
                .map_err(guard_model)?;
                let claiming = StoredRealmUserUpdateAdmission::begin_claim(
                    &open,
                    candidate,
                )
                .map_err(guard_admission)?;
                let outcome = self
                    .gates
                    .compare_and_set(&open, &claiming)
                    .await
                    .map_err(guard_gate_store)?;
                self.persist_reserved(outcome).await
            }
            RealmUserUpdateAdmissionReadState::Current(claiming)
                if claiming.phase()
                    == RealmUserUpdateAdmissionPhase::BucketClaiming =>
            {
                let durable = claiming
                    .claiming_candidate()
                    .ok_or(RealmUserUpdateAdmissionGuardError::MalformedGate)?;
                let retry = StoredRealmUserUpdateClaim::claimed(
                    admission,
                    user_id,
                    request_digest,
                    created_at,
                    durable.admission_ordinal(),
                )
                .map_err(guard_model)?;
                if !durable.same_request_as(&retry) {
                    return Err(if durable.user_id() == user_id {
                        RealmUserUpdateAdmissionGuardError::ClaimConflict
                    } else {
                        RealmUserUpdateAdmissionGuardError::AdmissionRace
                    });
                }
                let receipt =
                    PersistedRealmUserUpdateClaimingReceipt::try_from_current(claiming)
                        .map_err(guard_gate_store)?;
                self.persist_receipt(receipt).await
            }
            RealmUserUpdateAdmissionReadState::Current(current) => Err(
                RealmUserUpdateAdmissionGuardError::GateNotOpen(current.phase()),
            ),
        }
    }

    async fn resume_existing_from_gate<Hash: Q256BitHash>(
        &self,
        gate: RealmUserUpdateAdmissionReadState<Hash>,
        partition: RealmUserUpdateClaimPartition,
        current: StoredRealmUserUpdateClaim<Hash>,
        admission: RealmUserUpdatePublishAdmission<Hash>,
        request_digest: RealmUserUpdateRequestDigest,
        created_at: RealmUserUpdateCreatedAtSeconds,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        let retry = StoredRealmUserUpdateClaim::claimed(
            admission,
            current.user_id(),
            request_digest,
            created_at,
            current.admission_ordinal(),
        )
        .map_err(guard_model)?;
        if !current.same_request_as(&retry) {
            return Err(RealmUserUpdateAdmissionGuardError::ClaimConflict);
        }
        match gate {
            RealmUserUpdateAdmissionReadState::Current(claiming)
                if claiming.phase()
                    == RealmUserUpdateAdmissionPhase::BucketClaiming =>
            {
                let durable = claiming
                    .claiming_candidate()
                    .ok_or(RealmUserUpdateAdmissionGuardError::MalformedGate)?;
                if !durable
                    .same_admitted_identity_as(&current)
                    .map_err(guard_model)?
                {
                    return Err(RealmUserUpdateAdmissionGuardError::ClaimConflict);
                }
                let receipt =
                    PersistedRealmUserUpdateClaimingReceipt::try_from_current(claiming)
                        .map_err(guard_gate_store)?;
                self.persist_receipt(receipt).await
            }
            RealmUserUpdateAdmissionReadState::Current(gate)
                if matches!(
                    gate.phase(),
                    RealmUserUpdateAdmissionPhase::BucketOpen
                        | RealmUserUpdateAdmissionPhase::BucketClosed
                        | RealmUserUpdateAdmissionPhase::BucketStable
                ) =>
            {
                self.verify_bucket_membership(&gate, partition, &current)
                    .await?;
                Ok(current)
            }
            RealmUserUpdateAdmissionReadState::Uninitialized => {
                Err(RealmUserUpdateAdmissionGuardError::OrphanClaim)
            }
            RealmUserUpdateAdmissionReadState::Current(gate) => Err(
                RealmUserUpdateAdmissionGuardError::GateNotOpen(gate.phase()),
            ),
        }
    }

    async fn persist_reserved<Hash: Q256BitHash>(
        &self,
        outcome: RealmUserUpdateAdmissionWriteOutcome<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        if !outcome.applied() {
            return Err(RealmUserUpdateAdmissionGuardError::AdmissionRace);
        }
        let receipt = ScyllaRealmUserUpdateAdmissionStore::claiming_receipt(outcome)
            .map_err(guard_gate_store)?;
        self.persist_receipt(receipt).await
    }

    async fn persist_receipt<Hash: Q256BitHash>(
        &self,
        receipt: PersistedRealmUserUpdateClaimingReceipt<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        let journal = receipt.journal().clone();
        let persisted = match self
            .claims
            .claim(&receipt)
            .await
            .map_err(guard_claim_store)?
        {
            RealmUserUpdateClaimWriteOutcome::Applied(receipt)
            | RealmUserUpdateClaimWriteOutcome::Resumed(receipt) => {
                receipt.current().clone()
            }
            RealmUserUpdateClaimWriteOutcome::Conflict(current) => {
                if let Ok(reopened) =
                    StoredRealmUserUpdateAdmission::abandon_duplicate_claim(
                        &journal,
                        &current,
                    )
                {
                    let outcome = self
                        .gates
                        .compare_and_set(&journal, &reopened)
                        .await
                        .map_err(guard_gate_store)?;
                    if !outcome.applied() || outcome.current() != &reopened {
                        return Err(
                            RealmUserUpdateAdmissionGuardError::AdmissionRace,
                        );
                    }
                    let requested = journal.claiming_candidate().ok_or(
                        RealmUserUpdateAdmissionGuardError::MalformedGate,
                    )?;
                    return if requested.same_request_as(&current) {
                        Ok(current)
                    } else {
                        Err(RealmUserUpdateAdmissionGuardError::ClaimConflict)
                    };
                }
                let blocked = StoredRealmUserUpdateAdmission::block_claim(
                    &journal,
                    *current.state_digest(),
                )
                .map_err(guard_admission)?;
                let _ = self
                    .gates
                    .compare_and_set(&journal, &blocked)
                    .await
                    .map_err(guard_gate_store)?;
                return Err(RealmUserUpdateAdmissionGuardError::ClaimConflict);
            }
        };
        let reopened = StoredRealmUserUpdateAdmission::finish_claim(
            &journal,
            &persisted,
        )
        .map_err(guard_admission)?;
        let outcome = self
            .gates
            .compare_and_set(&journal, &reopened)
            .await
            .map_err(guard_gate_store)?;
        if !outcome.applied() || outcome.current() != &reopened {
            return Err(RealmUserUpdateAdmissionGuardError::AdmissionRace);
        }
        Ok(persisted)
    }

    /// Test-only crash/race resumption hook. Production callers can obtain a
    /// claiming receipt only through `claim`; this exposes the same recovery
    /// step to RF=3 fixtures without creating a second writer implementation.
    #[cfg(test)]
    pub(crate) async fn recover_claiming_fixture<Hash: Q256BitHash>(
        &self,
        receipt: PersistedRealmUserUpdateClaimingReceipt<Hash>,
    ) -> Result<StoredRealmUserUpdateClaim<Hash>, RealmUserUpdateAdmissionGuardError>
    {
        self.persist_receipt(receipt).await
    }

    async fn verify_bucket_membership<Hash: Q256BitHash>(
        &self,
        gate: &StoredRealmUserUpdateAdmission<Hash>,
        partition: RealmUserUpdateClaimPartition,
        current: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<(), RealmUserUpdateAdmissionGuardError> {
        let accepted = gate
            .accepted_set()
            .ok_or(RealmUserUpdateAdmissionGuardError::MalformedGate)?;
        let claims = self
            .claims
            .scan_bucket::<Hash>(partition)
            .await
            .map_err(guard_claim_store)?;
        let manifest = RealmUserUpdateBucketManifest::from_claims(partition, &claims)
            .map_err(guard_admission)?;
        if manifest.accepted() != accepted
            || !claims.iter().any(|claim| {
                claim
                    .same_admitted_identity_as(current)
                    .unwrap_or(false)
            })
        {
            return Err(RealmUserUpdateAdmissionGuardError::MembershipMismatch);
        }
        Ok(())
    }
}

fn applied<Hash>(
    current: StoredRealmUserUpdateAdmission<Hash>,
    disposition: RealmUserUpdateAdmissionWriteDisposition,
) -> RealmUserUpdateAdmissionWriteOutcome<Hash> {
    RealmUserUpdateAdmissionWriteOutcome::Applied {
        current,
        disposition,
    }
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmUserUpdateAdmissionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmUserUpdateAdmissionStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RealmUserUpdateAdmissionStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RealmUserUpdateAdmissionStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmUserUpdateAdmissionStoreError::InvalidAppliedColumn),
    }
}

fn model(error: RealmUserUpdateAdmissionError) -> RealmUserUpdateAdmissionStoreError {
    RealmUserUpdateAdmissionStoreError::Model(error.to_string())
}

fn generation_bind(error: RealmGenerationBindError) -> RealmUserUpdateAdmissionStoreError {
    RealmUserUpdateAdmissionStoreError::Generation(error.to_string())
}

fn cql(error: impl fmt::Display) -> RealmUserUpdateAdmissionStoreError {
    RealmUserUpdateAdmissionStoreError::Cql(error.to_string())
}

fn guard_model(
    error: psy_node_core::queue::realm_user_update_claim::RealmUserUpdateClaimError,
) -> RealmUserUpdateAdmissionGuardError {
    RealmUserUpdateAdmissionGuardError::Claim(error.to_string())
}

fn guard_admission(
    error: RealmUserUpdateAdmissionError,
) -> RealmUserUpdateAdmissionGuardError {
    RealmUserUpdateAdmissionGuardError::Admission(error.to_string())
}

fn guard_gate_store(
    error: RealmUserUpdateAdmissionStoreError,
) -> RealmUserUpdateAdmissionGuardError {
    match error {
        RealmUserUpdateAdmissionStoreError::IndeterminateConflict { .. } => {
            RealmUserUpdateAdmissionGuardError::AdmissionRace
        }
        error => RealmUserUpdateAdmissionGuardError::GateStore(error.to_string()),
    }
}

fn guard_claim_store(
    error: RealmUserUpdateClaimStoreError,
) -> RealmUserUpdateAdmissionGuardError {
    RealmUserUpdateAdmissionGuardError::ClaimStore(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateAdmissionGuardError {
    Claim(String),
    Admission(String),
    GateStore(String),
    ClaimStore(String),
    GenerationUninitialized,
    GenerationConflict,
    AdmissionClosed,
    AdmissionRace,
    ClaimConflict,
    OrphanClaim,
    MalformedGate,
    MembershipMismatch,
    CountOverflow,
    StepLimit,
    GateNotOpen(RealmUserUpdateAdmissionPhase),
}

impl fmt::Display for RealmUserUpdateAdmissionGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateAdmissionGuardError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmUserUpdateAdmissionStoreError {
    Model(String),
    Generation(String),
    Cql(String),
    InvalidTransition,
    NotClaiming,
    ClaimingConflict,
    SelectedIdentityMismatch,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
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

impl fmt::Display for RealmUserUpdateAdmissionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateAdmissionStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_golden_is_full_payload_no_tablet_lwt() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_claim_admission_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = RealmUserUpdateAdmissionQueries::new(&keyspace).golden();
        assert!(golden.contains(REALM_USER_UPDATE_ADMISSION_TABLE));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, activation_digest, unique_pending_id, proc_checkpoint_id, admission_shard))"));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND admission_payload = ?"));
        assert!(!golden.contains("ALLOW FILTERING"));
    }

    #[test]
    fn production_setup_does_not_materialize_the_gate() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(REALM_USER_UPDATE_ADMISSION_TABLE));
        assert!(!setup.contains("ScyllaRealmUserUpdateAdmissionStore"));
    }

    #[test]
    fn observed_lwt_winner_is_a_retryable_admission_race() {
        assert_eq!(
            guard_gate_store(
                RealmUserUpdateAdmissionStoreError::IndeterminateConflict {
                    execute: "timeout".to_owned(),
                    observed_revision: 2,
                },
            ),
            RealmUserUpdateAdmissionGuardError::AdmissionRace,
        );
    }
}
