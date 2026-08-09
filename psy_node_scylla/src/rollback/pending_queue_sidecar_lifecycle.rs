//! Durable deployment lifecycle for the thirteen recoverable-queue sidecars.
//!
//! Deployment is explicit and restart-safe: first persist `Materializing`,
//! idempotently create/inspect all target tables, then full-payload CAS to
//! `Verified`.  Node startup is inspect-only and requires the exact durable
//! row before it can receive an opaque readiness capability.

use std::{error::Error, fmt, sync::Arc};

use psy_data::protocol::chain_context::AuthorityScope;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    pending_queue_sidecar_schema_fingerprint,
    BranchExactDeploymentNoTabletKeyspace,
    PendingQueueSidecarKeyspaces, PendingQueueSidecarSchemaFingerprint,
    PendingQueueSidecarSchemaInspection, PendingQueueSidecarSchemaMaterializer,
    PendingQueueSidecarSchemaOnlyReceipt,
    PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
    PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
};

pub const PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE: &str =
    "branch_exact_pending_queue_sidecar_lifecycle_v1";
const MAGIC: &[u8; 8] = b"PSYQSCAR";
const CODEC_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-sidecar-slot/v1";
const STATE_DOMAIN: &[u8] = b"psy/rollback/pending-queue-sidecar-state/v1";
const READY_DOMAIN: &[u8] = b"psy/rollback/pending-queue-sidecar-ready/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSidecarDeploymentSlot([u8; 32]);

impl PendingQueueSidecarDeploymentSlot {
    pub fn for_keyspaces(keyspaces: &PendingQueueSidecarKeyspaces) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SLOT_DOMAIN);
        update_len(&mut hasher, keyspaces.data().as_str().as_bytes());
        update_len(&mut hasher, keyspaces.control().as_str().as_bytes());
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSidecarDeploymentRevision(u64);

impl PendingQueueSidecarDeploymentRevision {
    pub const MATERIALIZING: Self = Self(1);
    pub const VERIFIED: Self = Self(2);
    pub const fn get(self) -> u64 { self.0 }
    fn as_i64(self) -> i64 { self.0 as i64 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PendingQueueSidecarDeploymentPhase {
    Materializing = 1,
    Verified = 2,
}

impl PendingQueueSidecarDeploymentPhase {
    fn decode(value: u8) -> Result<Self, PendingQueueSidecarLifecycleError> {
        match value {
            1 => Ok(Self::Materializing),
            2 => Ok(Self::Verified),
            _ => Err(PendingQueueSidecarLifecycleError::UnknownPhase),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPendingQueueSidecarDeployment {
    slot: PendingQueueSidecarDeploymentSlot,
    revision: PendingQueueSidecarDeploymentRevision,
    phase: PendingQueueSidecarDeploymentPhase,
    keyspaces: PendingQueueSidecarKeyspaces,
    schema_fingerprint: PendingQueueSidecarSchemaFingerprint,
    state_digest: [u8; 32],
}

impl StoredPendingQueueSidecarDeployment {
    pub fn materializing(keyspaces: PendingQueueSidecarKeyspaces) -> Self {
        Self::new(
            PendingQueueSidecarDeploymentRevision::MATERIALIZING,
            PendingQueueSidecarDeploymentPhase::Materializing,
            keyspaces,
        )
    }

    fn verified_from(expected: &Self) -> Result<Self, PendingQueueSidecarLifecycleError> {
        if expected.phase != PendingQueueSidecarDeploymentPhase::Materializing
            || expected.revision != PendingQueueSidecarDeploymentRevision::MATERIALIZING
        {
            return Err(PendingQueueSidecarLifecycleError::InvalidTransition);
        }
        Ok(Self::new(
            PendingQueueSidecarDeploymentRevision::VERIFIED,
            PendingQueueSidecarDeploymentPhase::Verified,
            expected.keyspaces.clone(),
        ))
    }

    fn new(
        revision: PendingQueueSidecarDeploymentRevision,
        phase: PendingQueueSidecarDeploymentPhase,
        keyspaces: PendingQueueSidecarKeyspaces,
    ) -> Self {
        let slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&keyspaces);
        let schema_fingerprint = pending_queue_sidecar_schema_fingerprint();
        let mut value = Self {
            slot,
            revision,
            phase,
            keyspaces,
            schema_fingerprint,
            state_digest: [0; 32],
        };
        value.state_digest = state_digest(&value);
        value
    }

    pub const fn slot(&self) -> PendingQueueSidecarDeploymentSlot { self.slot }
    pub const fn revision(&self) -> PendingQueueSidecarDeploymentRevision { self.revision }
    pub const fn phase(&self) -> PendingQueueSidecarDeploymentPhase { self.phase }
    pub const fn keyspaces(&self) -> &PendingQueueSidecarKeyspaces { &self.keyspaces }
    pub const fn schema_fingerprint(&self) -> PendingQueueSidecarSchemaFingerprint { self.schema_fingerprint }
    pub const fn state_digest(&self) -> &[u8; 32] { &self.state_digest }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = encode_without_digest(self);
        out.extend_from_slice(&self.state_digest);
        out
    }

    pub fn decode_selected(
        selected_slot: PendingQueueSidecarDeploymentSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueSidecarLifecycleError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC { return Err(PendingQueueSidecarLifecycleError::MalformedPayload); }
        if decoder.u16()? != CODEC_VERSION { return Err(PendingQueueSidecarLifecycleError::UnknownCodecVersion); }
        let revision = decoder.u64()?;
        let phase = PendingQueueSidecarDeploymentPhase::decode(decoder.u8()?)?;
        let schema_version = decoder.u16()?;
        if schema_version != PENDING_QUEUE_SIDECAR_SCHEMA_VERSION { return Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion); }
        if decoder.u16()? as usize != PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT { return Err(PendingQueueSidecarLifecycleError::WrongTableCount); }
        let data = decoder.string()?;
        let control = decoder.string()?;
        let fingerprint = decoder.array32()?;
        let digest = decoder.array32()?;
        if !decoder.done() { return Err(PendingQueueSidecarLifecycleError::TrailingBytes); }
        let revision = match revision {
            1 => PendingQueueSidecarDeploymentRevision::MATERIALIZING,
            2 => PendingQueueSidecarDeploymentRevision::VERIFIED,
            _ => return Err(PendingQueueSidecarLifecycleError::UnknownRevision),
        };
        if selected_revision != revision.as_i64() { return Err(PendingQueueSidecarLifecycleError::SelectedRevisionMismatch); }
        if (phase == PendingQueueSidecarDeploymentPhase::Materializing && revision != PendingQueueSidecarDeploymentRevision::MATERIALIZING)
            || (phase == PendingQueueSidecarDeploymentPhase::Verified && revision != PendingQueueSidecarDeploymentRevision::VERIFIED)
        { return Err(PendingQueueSidecarLifecycleError::InvalidTransition); }
        let keyspaces = PendingQueueSidecarKeyspaces::try_new(data, control).map_err(|error| PendingQueueSidecarLifecycleError::InvalidKeyspace(error.to_string()))?;
        let candidate = Self { slot: selected_slot, revision, phase, keyspaces, schema_fingerprint: PendingQueueSidecarSchemaFingerprint::from_persisted(fingerprint), state_digest: digest };
        if candidate.slot != PendingQueueSidecarDeploymentSlot::for_keyspaces(&candidate.keyspaces) { return Err(PendingQueueSidecarLifecycleError::SelectedSlotMismatch); }
        if candidate.schema_fingerprint != pending_queue_sidecar_schema_fingerprint() { return Err(PendingQueueSidecarLifecycleError::SchemaFingerprintMismatch); }
        if candidate.state_digest != state_digest(&candidate) { return Err(PendingQueueSidecarLifecycleError::DigestMismatch); }
        Ok(candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSidecarVerifiedReceipt {
    stored: StoredPendingQueueSidecarDeployment,
    ready_digest: [u8; 32],
}

impl PendingQueueSidecarVerifiedReceipt {
    fn from_verified(stored: StoredPendingQueueSidecarDeployment) -> Result<Self, PendingQueueSidecarLifecycleError> {
        if stored.phase != PendingQueueSidecarDeploymentPhase::Verified { return Err(PendingQueueSidecarLifecycleError::NotVerified); }
        let mut hasher = Sha256::new();
        hasher.update(READY_DOMAIN);
        hasher.update(stored.slot.as_bytes());
        hasher.update(stored.revision.get().to_be_bytes());
        hasher.update(stored.state_digest());
        Ok(Self { stored, ready_digest: hasher.finalize().into() })
    }

    pub const fn stored(&self) -> &StoredPendingQueueSidecarDeployment { &self.stored }
    pub const fn ready_digest(&self) -> &[u8; 32] { &self.ready_digest }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarDeploymentReadState {
    Uninitialized,
    Current(StoredPendingQueueSidecarDeployment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarDeploymentWriteOutcome {
    Applied(StoredPendingQueueSidecarDeployment),
    Idempotent(StoredPendingQueueSidecarDeployment),
    Conflict(StoredPendingQueueSidecarDeployment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSidecarLifecycleQueries {
    create: String,
    read: String,
    bootstrap: String,
    cas: String,
}

impl PendingQueueSidecarLifecycleQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE);
        Self {
            create: format!("CREATE TABLE IF NOT EXISTS {table} (deployment_slot blob PRIMARY KEY, revision bigint, deployment_payload blob)"),
            read: format!("SELECT deployment_slot, revision, deployment_payload FROM {table} WHERE deployment_slot = ?"),
            bootstrap: format!("INSERT INTO {table} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?) IF NOT EXISTS"),
            cas: format!("UPDATE {table} SET revision = ?, deployment_payload = ? WHERE deployment_slot = ? IF revision = ? AND deployment_payload = ?"),
        }
    }
    pub fn create(&self) -> &str { &self.create }
    pub fn read(&self) -> &str { &self.read }
    pub fn bootstrap(&self) -> &str { &self.bootstrap }
    pub fn cas(&self) -> &str { &self.cas }
}

pub struct ScyllaPendingQueueSidecarLifecycleStore {
    session: Arc<Session>,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaPendingQueueSidecarLifecycleStore {
    pub async fn create_schema(session: &Session, keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Result<(), PendingQueueSidecarLifecycleError> {
        let queries = PendingQueueSidecarLifecycleQueries::new(keyspace);
        session.query_unpaged(queries.create(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(session: Arc<Session>, keyspace: BranchExactDeploymentNoTabletKeyspace) -> Result<Self, PendingQueueSidecarLifecycleError> {
        let queries = PendingQueueSidecarLifecycleQueries::new(&keyspace);
        Ok(Self { read: prepare_read(&session, queries.read()).await?, bootstrap: prepare_lwt(&session, queries.bootstrap()).await?, cas: prepare_lwt(&session, queries.cas()).await?, session })
    }

    pub async fn read(&self, slot: PendingQueueSidecarDeploymentSlot) -> Result<PendingQueueSidecarDeploymentReadState, PendingQueueSidecarLifecycleError> {
        let row = self.session.execute_unpaged(&self.read, (slot.as_bytes().to_vec(),)).await.map_err(cql)?.into_rows_result().map_err(cql)?.maybe_first_row::<(Vec<u8>, Option<i64>, Option<Vec<u8>>)>().map_err(cql)?;
        let Some((selected_slot, revision, payload)) = row else { return Ok(PendingQueueSidecarDeploymentReadState::Uninitialized); };
        let selected_slot: [u8; 32] = selected_slot.try_into().map_err(|_| PendingQueueSidecarLifecycleError::SelectedSlotMismatch)?;
        if selected_slot != *slot.as_bytes() { return Err(PendingQueueSidecarLifecycleError::SelectedSlotMismatch); }
        let stored = StoredPendingQueueSidecarDeployment::decode_selected(slot, revision.ok_or(PendingQueueSidecarLifecycleError::MissingColumn)?, payload.as_deref().ok_or(PendingQueueSidecarLifecycleError::MissingColumn)?)?;
        Ok(PendingQueueSidecarDeploymentReadState::Current(stored))
    }

    pub async fn bootstrap(&self, candidate: &StoredPendingQueueSidecarDeployment) -> Result<PendingQueueSidecarDeploymentWriteOutcome, PendingQueueSidecarLifecycleError> {
        if candidate.phase != PendingQueueSidecarDeploymentPhase::Materializing { return Err(PendingQueueSidecarLifecycleError::InvalidTransition); }
        let execution = self.session.execute_unpaged(&self.bootstrap, (candidate.slot.as_bytes().to_vec(), candidate.revision.as_i64(), candidate.to_canonical_bytes())).await;
        self.finish(execution, candidate).await
    }

    pub async fn mark_verified(&self, expected: &StoredPendingQueueSidecarDeployment, schema: &PendingQueueSidecarSchemaOnlyReceipt) -> Result<PendingQueueSidecarDeploymentWriteOutcome, PendingQueueSidecarLifecycleError> {
        if expected.keyspaces != *schema.keyspaces() || expected.schema_fingerprint != schema.fingerprint() { return Err(PendingQueueSidecarLifecycleError::SchemaFingerprintMismatch); }
        let candidate = StoredPendingQueueSidecarDeployment::verified_from(expected)?;
        let execution = self.session.execute_unpaged(&self.cas, (candidate.revision.as_i64(), candidate.to_canonical_bytes(), candidate.slot.as_bytes().to_vec(), expected.revision.as_i64(), expected.to_canonical_bytes())).await;
        self.finish(execution, &candidate).await
    }

    async fn finish(&self, execution: Result<QueryResult, scylla::errors::ExecutionError>, candidate: &StoredPendingQueueSidecarDeployment) -> Result<PendingQueueSidecarDeploymentWriteOutcome, PendingQueueSidecarLifecycleError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => return match self.read(candidate.slot).await {
                Ok(PendingQueueSidecarDeploymentReadState::Current(current)) if current == *candidate => Ok(PendingQueueSidecarDeploymentWriteOutcome::Idempotent(current)),
                Ok(PendingQueueSidecarDeploymentReadState::Current(current)) => Err(PendingQueueSidecarLifecycleError::IndeterminateWrite { execute: execute.to_string(), observed_revision: Some(current.revision.get()) }),
                Ok(PendingQueueSidecarDeploymentReadState::Uninitialized) => Err(PendingQueueSidecarLifecycleError::IndeterminateWrite { execute: execute.to_string(), observed_revision: None }),
                Err(read) => Err(PendingQueueSidecarLifecycleError::IndeterminateRead { execute: execute.to_string(), read: read.to_string() }),
            },
        };
        let PendingQueueSidecarDeploymentReadState::Current(current) = self.read(candidate.slot).await? else { return Err(PendingQueueSidecarLifecycleError::MissingAfterLwt); };
        if applied {
            if current != *candidate { return Err(PendingQueueSidecarLifecycleError::AppliedStateMismatch); }
            Ok(PendingQueueSidecarDeploymentWriteOutcome::Applied(current))
        } else if current == *candidate {
            Ok(PendingQueueSidecarDeploymentWriteOutcome::Idempotent(current))
        } else {
            Ok(PendingQueueSidecarDeploymentWriteOutcome::Conflict(current))
        }
    }
}

pub struct PendingQueueSidecarDeploymentExecutor;

impl PendingQueueSidecarDeploymentExecutor {
    /// Explicit operator path. The lifecycle table is the only table created
    /// before the durable `Materializing` row exists.
    pub async fn deploy(session: Arc<Session>, keyspaces: PendingQueueSidecarKeyspaces) -> Result<PendingQueueSidecarVerifiedReceipt, PendingQueueSidecarLifecycleError> {
        ScyllaPendingQueueSidecarLifecycleStore::create_schema(&session, keyspaces.control()).await?;
        let store = ScyllaPendingQueueSidecarLifecycleStore::prepare(session.clone(), keyspaces.control().clone()).await?;
        let candidate = StoredPendingQueueSidecarDeployment::materializing(keyspaces.clone());
        let materializing = match store.read(candidate.slot).await? {
            PendingQueueSidecarDeploymentReadState::Uninitialized => match store.bootstrap(&candidate).await? {
                PendingQueueSidecarDeploymentWriteOutcome::Applied(current) | PendingQueueSidecarDeploymentWriteOutcome::Idempotent(current) => current,
                PendingQueueSidecarDeploymentWriteOutcome::Conflict(current) => current,
            },
            PendingQueueSidecarDeploymentReadState::Current(current) => current,
        };
        if materializing.keyspaces != keyspaces || materializing.schema_fingerprint != pending_queue_sidecar_schema_fingerprint() { return Err(PendingQueueSidecarLifecycleError::DeploymentConflict); }
        if materializing.phase == PendingQueueSidecarDeploymentPhase::Verified {
            require_exact_schema(&session, &keyspaces).await?;
            return PendingQueueSidecarVerifiedReceipt::from_verified(materializing);
        }
        let schema = PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &keyspaces).await.map_err(|error| PendingQueueSidecarLifecycleError::Schema(error.to_string()))?;
        let verified = match store.mark_verified(&materializing, &schema).await? {
            PendingQueueSidecarDeploymentWriteOutcome::Applied(current) | PendingQueueSidecarDeploymentWriteOutcome::Idempotent(current) => current,
            PendingQueueSidecarDeploymentWriteOutcome::Conflict(_) => return Err(PendingQueueSidecarLifecycleError::DeploymentConflict),
        };
        PendingQueueSidecarVerifiedReceipt::from_verified(verified)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PendingQueueSidecarSetupMode {
    #[default]
    Disabled,
    RequireVerified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarSetupOutcome {
    Disabled,
    Ready(PendingQueueSidecarReadyView),
    Idempotent(PendingQueueSidecarReadyView),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSidecarReadyView {
    authority: AuthorityScope,
    verified: PendingQueueSidecarVerifiedReceipt,
}

impl PendingQueueSidecarReadyView {
    pub const fn authority(&self) -> AuthorityScope { self.authority }
    pub const fn verified(&self) -> &PendingQueueSidecarVerifiedReceipt { &self.verified }
    pub const fn ready_digest(&self) -> &[u8; 32] { self.verified.ready_digest() }
}

/// Opaque setup capability. It exposes no Session or queue store.
pub struct PendingQueueSidecarReady { view: PendingQueueSidecarReadyView }
impl PendingQueueSidecarReady { pub const fn view(&self) -> &PendingQueueSidecarReadyView { &self.view } }

/// Prepared, inspect-only reader used by startup double sampling. It never
/// creates schema and never advances the lifecycle row.
pub(crate) struct ScyllaPendingQueueSidecarFreshReader {
    session: Arc<Session>,
    keyspaces: PendingQueueSidecarKeyspaces,
    authority: AuthorityScope,
    lifecycle: ScyllaPendingQueueSidecarLifecycleStore,
}

impl ScyllaPendingQueueSidecarFreshReader {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspaces: PendingQueueSidecarKeyspaces,
        authority: AuthorityScope,
    ) -> Result<Self, PendingQueueSidecarLifecycleError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(PendingQueueSidecarLifecycleError::RealmOnly);
        };
        let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
            session.clone(),
            keyspaces.control().clone(),
        )
        .await?;
        Ok(Self { session, keyspaces, authority, lifecycle })
    }

    pub(crate) async fn fresh(
        &self,
    ) -> Result<PendingQueueSidecarReadyView, PendingQueueSidecarLifecycleError> {
        let slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&self.keyspaces);
        let before = require_verified(self.lifecycle.read(slot).await?, &self.keyspaces)?;
        require_exact_schema(&self.session, &self.keyspaces).await?;
        let after = require_verified(self.lifecycle.read(slot).await?, &self.keyspaces)?;
        if before != after {
            return Err(PendingQueueSidecarLifecycleError::ConcurrentMutation);
        }
        Ok(PendingQueueSidecarReadyView {
            authority: self.authority,
            verified: PendingQueueSidecarVerifiedReceipt::from_verified(after)?,
        })
    }
}

pub struct ScyllaPendingQueueSidecarSetupGate;
impl ScyllaPendingQueueSidecarSetupGate {
    pub async fn authorize(session: Arc<Session>, keyspaces: PendingQueueSidecarKeyspaces, authority: AuthorityScope) -> Result<PendingQueueSidecarReady, PendingQueueSidecarLifecycleError> {
        let reader = ScyllaPendingQueueSidecarFreshReader::prepare(
            session,
            keyspaces,
            authority,
        )
        .await?;
        Ok(PendingQueueSidecarReady { view: reader.fresh().await? })
    }
}

async fn require_exact_schema(session: &Session, keyspaces: &PendingQueueSidecarKeyspaces) -> Result<(), PendingQueueSidecarLifecycleError> {
    let inspection = PendingQueueSidecarSchemaMaterializer::inspect_schema(session, keyspaces).await.map_err(|error| PendingQueueSidecarLifecycleError::Schema(error.to_string()))?;
    match inspection {
        PendingQueueSidecarSchemaInspection::Exact { fingerprint } if fingerprint == pending_queue_sidecar_schema_fingerprint() => Ok(()),
        _ => Err(PendingQueueSidecarLifecycleError::SchemaNotExact),
    }
}

fn require_verified(state: PendingQueueSidecarDeploymentReadState, keyspaces: &PendingQueueSidecarKeyspaces) -> Result<StoredPendingQueueSidecarDeployment, PendingQueueSidecarLifecycleError> {
    let PendingQueueSidecarDeploymentReadState::Current(current) = state else { return Err(PendingQueueSidecarLifecycleError::Uninitialized); };
    if current.phase != PendingQueueSidecarDeploymentPhase::Verified { return Err(PendingQueueSidecarLifecycleError::NotVerified); }
    if current.keyspaces != *keyspaces { return Err(PendingQueueSidecarLifecycleError::DeploymentConflict); }
    Ok(current)
}

fn encode_without_digest(value: &StoredPendingQueueSidecarDeployment) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&value.revision.get().to_be_bytes());
    out.push(value.phase as u8);
    out.extend_from_slice(&PENDING_QUEUE_SIDECAR_SCHEMA_VERSION.to_be_bytes());
    out.extend_from_slice(&(PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT as u16).to_be_bytes());
    put_string(&mut out, value.keyspaces.data().as_str());
    put_string(&mut out, value.keyspaces.control().as_str());
    out.extend_from_slice(value.schema_fingerprint.as_bytes());
    out
}
fn state_digest(value: &StoredPendingQueueSidecarDeployment) -> [u8; 32] { let mut hasher = Sha256::new(); hasher.update(STATE_DOMAIN); hasher.update(encode_without_digest(value)); hasher.finalize().into() }
fn put_string(out: &mut Vec<u8>, value: &str) { out.extend_from_slice(&(value.len() as u16).to_be_bytes()); out.extend_from_slice(value.as_bytes()); }
fn update_len(hasher: &mut Sha256, value: &[u8]) { hasher.update((value.len() as u64).to_be_bytes()); hasher.update(value); }

struct Decoder<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueSidecarLifecycleError> { let end = self.offset.checked_add(len).ok_or(PendingQueueSidecarLifecycleError::MalformedPayload)?; let value = self.bytes.get(self.offset..end).ok_or(PendingQueueSidecarLifecycleError::MalformedPayload)?; self.offset = end; Ok(value) }
    fn u8(&mut self) -> Result<u8, PendingQueueSidecarLifecycleError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueSidecarLifecycleError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueSidecarLifecycleError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn string(&mut self) -> Result<String, PendingQueueSidecarLifecycleError> { let len = self.u16()? as usize; String::from_utf8(self.take(len)?.to_vec()).map_err(|_| PendingQueueSidecarLifecycleError::MalformedPayload) }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueSidecarLifecycleError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn done(&self) -> bool { self.offset == self.bytes.len() }
}

async fn prepare_read(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueueSidecarLifecycleError> { let mut statement = session.prepare(cql_text).await.map_err(cql)?; statement.set_consistency(Consistency::Quorum); statement.set_is_idempotent(true); Ok(statement) }
async fn prepare_lwt(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueueSidecarLifecycleError> { let mut statement = session.prepare(cql_text).await.map_err(cql)?; statement.set_consistency(Consistency::Quorum); statement.set_serial_consistency(Some(SerialConsistency::LocalSerial)); statement.set_is_idempotent(true); Ok(statement) }
fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueSidecarLifecycleError> { let rows = result.into_rows_result().map_err(cql)?; let column = rows.column_specs().get_by_name("[applied]").ok_or(PendingQueueSidecarLifecycleError::MissingAppliedColumn)?; let row = rows.single_row::<Row>().map_err(cql)?; match row.columns.get(column.0) { Some(Some(CqlValue::Boolean(value))) => Ok(*value), _ => Err(PendingQueueSidecarLifecycleError::InvalidAppliedColumn) } }
fn cql(error: impl fmt::Display) -> PendingQueueSidecarLifecycleError { PendingQueueSidecarLifecycleError::Cql(error.to_string()) }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarLifecycleError {
    InvalidKeyspace(String), UnknownCodecVersion, UnknownSchemaVersion,
    UnknownRevision, UnknownPhase, WrongTableCount, MalformedPayload,
    TrailingBytes, DigestMismatch, SelectedSlotMismatch,
    SelectedRevisionMismatch, SchemaFingerprintMismatch, InvalidTransition,
    NotVerified, Uninitialized, RealmOnly, DeploymentConflict,
    ConcurrentMutation, SchemaNotExact, MissingColumn, MissingAppliedColumn,
    InvalidAppliedColumn, MissingAfterLwt, AppliedStateMismatch,
    AlreadyInitializedWithDifferentReceipt,
    Schema(String), Cql(String),
    IndeterminateWrite { execute: String, observed_revision: Option<u64> },
    IndeterminateRead { execute: String, read: String },
}
impl fmt::Display for PendingQueueSidecarLifecycleError { fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") } }
impl Error for PendingQueueSidecarLifecycleError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyspaces() -> PendingQueueSidecarKeyspaces { PendingQueueSidecarKeyspaces::try_new("psy_data", "psy_data_no_tablet").unwrap() }

    #[test]
    fn lifecycle_codec_is_deterministic_and_fail_closed() {
        let first = StoredPendingQueueSidecarDeployment::materializing(keyspaces());
        let second = StoredPendingQueueSidecarDeployment::materializing(keyspaces());
        assert_eq!(first, second);
        let bytes = first.to_canonical_bytes();
        assert_eq!(StoredPendingQueueSidecarDeployment::decode_selected(first.slot, 1, &bytes).unwrap(), first);
        let mut tampered = bytes.clone(); tampered[20] ^= 1;
        assert!(StoredPendingQueueSidecarDeployment::decode_selected(first.slot, 1, &tampered).is_err());
        let mut trailing = bytes; trailing.push(0);
        assert_eq!(StoredPendingQueueSidecarDeployment::decode_selected(first.slot, 1, &trailing), Err(PendingQueueSidecarLifecycleError::TrailingBytes));
    }

    #[test]
    fn verified_is_the_only_ready_phase_and_revision_advances_once() {
        let materializing = StoredPendingQueueSidecarDeployment::materializing(keyspaces());
        assert_eq!(PendingQueueSidecarVerifiedReceipt::from_verified(materializing.clone()), Err(PendingQueueSidecarLifecycleError::NotVerified));
        let verified = StoredPendingQueueSidecarDeployment::verified_from(&materializing).unwrap();
        assert_eq!(verified.revision().get(), materializing.revision().get() + 1);
        assert_ne!(verified.state_digest(), materializing.state_digest());
        assert_ne!(PendingQueueSidecarVerifiedReceipt::from_verified(verified).unwrap().ready_digest(), &[0; 32]);
    }

    #[test]
    fn queries_are_full_payload_lwt_and_setup_has_no_implicit_materialize() {
        let control = BranchExactDeploymentNoTabletKeyspace::try_new("psy_no_tablet".to_owned()).unwrap();
        let queries = PendingQueueSidecarLifecycleQueries::new(&control);
        assert!(queries.bootstrap().contains("IF NOT EXISTS"));
        assert!(queries.cas().contains("IF revision = ? AND deployment_payload = ?"));
        let setup = include_str!("../psy_setup.rs").split("#[cfg(test)]").next().unwrap();
        assert!(!setup.contains("PendingQueueSidecarDeploymentExecutor::deploy"));
        assert!(setup.contains("PendingQueueSidecarSetupMode::Disabled"));
        assert!(setup.contains("PendingQueueSidecarSetupMode::RequireVerified"));
    }
}
