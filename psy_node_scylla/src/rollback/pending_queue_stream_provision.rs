//! Durable no-tablet LWT authority for recoverable JetStream provisioning.
//!
//! A `Provisioning` row is persisted before NATS create. Completion binds the
//! exact server-created instance. Once provisioned, retries are observation
//! only: a missing or recreated stream is never created under the old segment
//! identity.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};
use psy_node_core::store::pending_generation_identity::PendingGenerationLedgerKey;
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::{
        PendingQueueSegmentLedgerKey,
    },
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentContractDigest,
        RecoverableNatsSegmentId, RecoverableNatsStreamInstanceId,
        RecoverableNatsStreamSegment,
    },
    recoverable_transport::{
        InstanceBoundRecoverablePendingQueueNatsPublisher,
        RecoverableNatsExistingStreamBinding, RecoverableNatsProvisionedStreamReceipt,
        RecoverableNatsStreamProvisioningOperationId,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    pending_queue_segment_ledger::ScyllaPendingQueueSegmentLedgerStore,
    pending_queue_sidecar_lifecycle::PendingQueueSidecarReady,
    BranchExactDeploymentNoTabletKeyspace,
};

pub(super) const PENDING_QUEUE_STREAM_PROVISION_TABLE: &str =
    "branch_exact_pending_queue_stream_provision_binding_v1";
const MAGIC: &[u8; 8] = b"PSYQSPRV";
const CODEC_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-stream-provision-slot/v1";
const OPERATION_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-stream-provision-operation/v1";
const PAYLOAD_DOMAIN: &[u8] = b"psy/rollback/pending-queue-stream-provision/v1";
const STORE_DOMAIN: &[u8] = b"psy/rollback/pending-queue-stream-provision-store/v1";
const MAX_NAMESPACE_BYTES: usize = 96;
const MAX_PAYLOAD_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueStreamProvisionSlot([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueStreamProvisionDigest([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueStreamProvisionStoreFingerprint([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PendingQueueStreamProvisionPhase {
    Provisioning = 1,
    Provisioned = 2,
}

impl PendingQueueStreamProvisionPhase {
    fn decode(value: u8) -> Result<Self, PendingQueueStreamProvisionError> {
        match value {
            1 => Ok(Self::Provisioning),
            2 => Ok(Self::Provisioned),
            _ => Err(PendingQueueStreamProvisionError::UnknownPhase),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPendingQueueStreamProvision {
    slot: PendingQueueStreamProvisionSlot,
    revision: u64,
    phase: PendingQueueStreamProvisionPhase,
    ledger_key: PendingQueueSegmentLedgerKey,
    segment: RecoverableNatsStreamSegment,
    operation_id: RecoverableNatsStreamProvisioningOperationId,
    instance_id: Option<RecoverableNatsStreamInstanceId>,
    digest: PendingQueueStreamProvisionDigest,
}

impl StoredPendingQueueStreamProvision {
    fn provisioning(
        ledger_key: &PendingQueueSegmentLedgerKey,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        validate_ledger_key_segment(ledger_key, &segment)?;
        let ledger_key = ledger_key.clone();
        let slot = provision_slot(&ledger_key, &segment);
        let operation_id = provision_operation(slot, &segment)?;
        let mut value = Self {
            slot,
            revision: 1,
            phase: PendingQueueStreamProvisionPhase::Provisioning,
            ledger_key,
            segment,
            operation_id,
            instance_id: None,
            digest: PendingQueueStreamProvisionDigest([0; 32]),
        };
        value.digest = value.calculate_digest();
        Ok(value)
    }

    fn complete(
        &self,
        receipt: &RecoverableNatsProvisionedStreamReceipt,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        self.complete_exact(
            receipt.live().segment(),
            receipt.segment_contract_digest(),
            receipt.operation_id(),
            receipt.instance_id(),
        )
    }

    fn complete_exact(
        &self,
        segment: &RecoverableNatsStreamSegment,
        contract_digest: &[u8; 32],
        operation_id: RecoverableNatsStreamProvisioningOperationId,
        instance_id: RecoverableNatsStreamInstanceId,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        if contract_digest != self.segment.digest().as_bytes()
            || operation_id != self.operation_id
            || segment != &self.segment
        {
            return Err(PendingQueueStreamProvisionError::ReceiptMismatch);
        }
        if self.phase == PendingQueueStreamProvisionPhase::Provisioned {
            return if self.instance_id == Some(instance_id) {
                Ok(self.clone())
            } else {
                Err(PendingQueueStreamProvisionError::InstanceConflict)
            };
        }
        let mut candidate = self.clone();
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or(PendingQueueStreamProvisionError::RevisionOverflow)?;
        candidate.phase = PendingQueueStreamProvisionPhase::Provisioned;
        candidate.instance_id = Some(instance_id);
        candidate.digest = candidate.calculate_digest();
        Ok(candidate)
    }

    fn binding(&self) -> Result<RecoverableNatsExistingStreamBinding, PendingQueueStreamProvisionError> {
        if self.phase != PendingQueueStreamProvisionPhase::Provisioned {
            return Err(PendingQueueStreamProvisionError::NotProvisioned);
        }
        RecoverableNatsExistingStreamBinding::try_from_durable(
            &self.segment,
            *self.segment.digest().as_bytes(),
            self.operation_id,
            self.instance_id
                .ok_or(PendingQueueStreamProvisionError::MissingInstance)?,
        )
        .map_err(transport)
    }

    fn calculate_digest(&self) -> PendingQueueStreamProvisionDigest {
        let mut hasher = Sha256::new();
        hasher.update(PAYLOAD_DOMAIN);
        hasher.update(self.bytes_without_digest());
        PendingQueueStreamProvisionDigest(hasher.finalize().into())
    }

    fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes_without_digest();
        bytes.extend_from_slice(&self.digest.0);
        bytes
    }

    fn bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&self.slot.0);
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.push(self.phase as u8);
        encode_ledger_key(&self.ledger_key, &mut out);
        encode_segment(&self.segment, &mut out);
        out.extend_from_slice(self.operation_id.as_bytes());
        match self.instance_id {
            Some(instance) => {
                out.push(1);
                out.extend_from_slice(instance.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    fn decode(
        slot: PendingQueueStreamProvisionSlot,
        cql_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        if cql_revision <= 0 || bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PendingQueueStreamProvisionError::MalformedPayload);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC || decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueStreamProvisionError::MalformedPayload);
        }
        if decoder.array32()? != slot.0 {
            return Err(PendingQueueStreamProvisionError::SlotMismatch);
        }
        let revision = decoder.u64()?;
        if revision != cql_revision as u64 {
            return Err(PendingQueueStreamProvisionError::RevisionMismatch);
        }
        let phase = PendingQueueStreamProvisionPhase::decode(decoder.u8()?)?;
        let ledger_key = decode_ledger_key(&mut decoder)?;
        decoder.last_ledger_key = Some(ledger_key.clone());
        let segment = decode_segment(&mut decoder)?;
        let operation_id = RecoverableNatsStreamProvisioningOperationId::try_new(
            decoder.array32()?,
        )
        .map_err(transport)?;
        let instance_id = match decoder.u8()? {
            0 => None,
            1 => Some(
                RecoverableNatsStreamInstanceId::try_from_bytes(decoder.array32()?)
                    .map_err(segment_error)?,
            ),
            _ => return Err(PendingQueueStreamProvisionError::MalformedPayload),
        };
        let digest = PendingQueueStreamProvisionDigest(decoder.array32()?);
        if !decoder.done() {
            return Err(PendingQueueStreamProvisionError::TrailingBytes);
        }
        let value = Self {
            slot,
            revision,
            phase,
            ledger_key,
            segment,
            operation_id,
            instance_id,
            digest,
        };
        if value.slot != provision_slot(&value.ledger_key, &value.segment)
            || value.operation_id != provision_operation(value.slot, &value.segment)?
            || value.digest != value.calculate_digest()
            || (value.phase == PendingQueueStreamProvisionPhase::Provisioning
                && value.instance_id.is_some())
            || (value.phase == PendingQueueStreamProvisionPhase::Provisioned
                && value.instance_id.is_none())
            || !matches!(
                (value.phase, value.revision),
                (PendingQueueStreamProvisionPhase::Provisioning, 1)
                    | (PendingQueueStreamProvisionPhase::Provisioned, 2)
            )
        {
            return Err(PendingQueueStreamProvisionError::PayloadMismatch);
        }
        Ok(value)
    }
}

fn validate_ledger_key_segment(
    ledger_key: &PendingQueueSegmentLedgerKey,
    segment: &RecoverableNatsStreamSegment,
) -> Result<(), PendingQueueStreamProvisionError> {
    if ledger_key.generation_key() != segment.generation_key()
        || ledger_key.base_namespace() != segment.base_namespace()
    {
        return Err(PendingQueueStreamProvisionError::LedgerSegmentMismatch);
    }
    Ok(())
}

fn provision_slot(
    ledger_key: &PendingQueueSegmentLedgerKey,
    segment: &RecoverableNatsStreamSegment,
) -> PendingQueueStreamProvisionSlot {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(ledger_key.slot().as_bytes());
    hasher.update(segment.segment_id().get().to_be_bytes());
    PendingQueueStreamProvisionSlot(hasher.finalize().into())
}

fn provision_operation(
    slot: PendingQueueStreamProvisionSlot,
    segment: &RecoverableNatsStreamSegment,
) -> Result<RecoverableNatsStreamProvisioningOperationId, PendingQueueStreamProvisionError> {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_DOMAIN);
    hasher.update(slot.0);
    hasher.update(segment.digest().as_bytes());
    RecoverableNatsStreamProvisioningOperationId::try_new(hasher.finalize().into())
        .map_err(transport)
}

fn encode_ledger_key(key: &PendingQueueSegmentLedgerKey, out: &mut Vec<u8>) {
    let generation = key.generation_key();
    out.extend_from_slice(&generation.network().chain_id().to_be_bytes());
    encode_authority(generation.authority(), out);
    out.extend_from_slice(&(key.base_namespace().len() as u16).to_be_bytes());
    out.extend_from_slice(key.base_namespace().as_bytes());
    out.extend_from_slice(key.slot().as_bytes());
}

fn decode_ledger_key(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueSegmentLedgerKey, PendingQueueStreamProvisionError> {
    let network = NetworkId::try_from_chain_id(decoder.u32()?).map_err(protocol)?;
    let authority = decode_authority(decoder)?;
    let namespace_len = decoder.u16()? as usize;
    if namespace_len == 0 || namespace_len > MAX_NAMESPACE_BYTES {
        return Err(PendingQueueStreamProvisionError::MalformedPayload);
    }
    let namespace = std::str::from_utf8(decoder.take(namespace_len)?)
        .map_err(|_| PendingQueueStreamProvisionError::MalformedPayload)?
        .to_owned();
    let encoded_slot = decoder.array32()?;
    let key = PendingQueueSegmentLedgerKey::try_new(
        PendingGenerationLedgerKey::new(network, authority),
        namespace,
    )
    .map_err(assignment)?;
    if key.slot().as_bytes() != &encoded_slot {
        return Err(PendingQueueStreamProvisionError::SlotMismatch);
    }
    Ok(key)
}

fn encode_segment(segment: &RecoverableNatsStreamSegment, out: &mut Vec<u8>) {
    out.extend_from_slice(&segment.segment_id().get().to_be_bytes());
    let retention = segment.retention();
    out.push(retention.stream_replicas() as u8);
    out.extend_from_slice(&retention.max_stream_bytes().to_be_bytes());
    out.extend_from_slice(&retention.generation_admission_budget_bytes().to_be_bytes());
    out.extend_from_slice(&retention.max_live_segments().to_be_bytes());
    out.extend_from_slice(&retention.max_consumers_per_segment().to_be_bytes());
    out.extend_from_slice(segment.digest().as_bytes());
}

fn decode_segment(
    decoder: &mut Decoder<'_>,
) -> Result<RecoverableNatsStreamSegment, PendingQueueStreamProvisionError> {
    let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?).map_err(segment_error)?;
    let retention = RecoverableNatsRetentionContract::try_new(
        usize::from(decoder.u8()?),
        decoder.i64()?,
        decoder.i64()?,
        decoder.u16()?,
        decoder.i32()?,
    )
    .map_err(segment_error)?;
    let expected_digest = RecoverableNatsSegmentContractDigest::try_new(decoder.array32()?)
        .map_err(segment_error)?;
    let key = decoder
        .last_ledger_key
        .as_ref()
        .ok_or(PendingQueueStreamProvisionError::MalformedPayload)?;
    let segment = RecoverableNatsStreamSegment::try_new(
        key.base_namespace().to_owned(),
        key.generation_key(),
        segment_id,
        retention,
    )
    .map_err(segment_error)?;
    if segment.digest() != expected_digest {
        return Err(PendingQueueStreamProvisionError::SegmentDigestMismatch);
    }
    Ok(segment)
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => {
            out.push(1);
            out.extend_from_slice(&0_u32.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
        }
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn decode_authority(decoder: &mut Decoder<'_>) -> Result<AuthorityScope, PendingQueueStreamProvisionError> {
    let kind = decoder.u8()?;
    let realm_id = decoder.u32()?;
    let realm_sub_id = decoder.u16()?;
    match (kind, realm_id, realm_sub_id) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm { realm_id, realm_sub_id }),
        _ => Err(PendingQueueStreamProvisionError::MalformedPayload),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    last_ledger_key: Option<PendingQueueSegmentLedgerKey>,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0, last_ledger_key: None }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueStreamProvisionError> {
        let end = self.offset.checked_add(len).ok_or(PendingQueueStreamProvisionError::MalformedPayload)?;
        let value = self.bytes.get(self.offset..end).ok_or(PendingQueueStreamProvisionError::MalformedPayload)?;
        self.offset = end;
        Ok(value)
    }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueStreamProvisionError> {
        self.take(32)?.try_into().map_err(|_| PendingQueueStreamProvisionError::MalformedPayload)
    }
    fn u8(&mut self) -> Result<u8, PendingQueueStreamProvisionError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueStreamProvisionError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, PendingQueueStreamProvisionError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn i32(&mut self) -> Result<i32, PendingQueueStreamProvisionError> { Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueStreamProvisionError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, PendingQueueStreamProvisionError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn done(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(super) enum PendingQueueStreamProvisionQueryId {
    Create = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueStreamProvisionQuery {
    id: PendingQueueStreamProvisionQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingQueueStreamProvisionQuery {
    pub(super) const fn id(&self) -> PendingQueueStreamProvisionQueryId { self.id }
    pub(super) fn cql(&self) -> &str { &self.cql }
    pub(super) const fn bind_shape(&self) -> &'static [&'static str] { self.bind_shape }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueStreamProvisionQueries([PendingQueueStreamProvisionQuery; 4]);

impl PendingQueueStreamProvisionQueries {
    pub(super) fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{PENDING_QUEUE_STREAM_PROVISION_TABLE}", keyspace.as_str());
        Self([
            query(PendingQueueStreamProvisionQueryId::Create, format!("CREATE TABLE IF NOT EXISTS {table} (provision_slot blob PRIMARY KEY, revision bigint, provision_payload blob)"), &[]),
            query(PendingQueueStreamProvisionQueryId::Read, format!("SELECT revision, provision_payload FROM {table} WHERE provision_slot = ?"), &["provision_slot:BLOB"]),
            query(PendingQueueStreamProvisionQueryId::Bootstrap, format!("INSERT INTO {table} (provision_slot, revision, provision_payload) VALUES (?, ?, ?) IF NOT EXISTS"), &["provision_slot:BLOB", "revision:BIGINT", "provision_payload:BLOB"]),
            query(PendingQueueStreamProvisionQueryId::CompareAndSet, format!("UPDATE {table} SET revision = ?, provision_payload = ? WHERE provision_slot = ? IF revision = ? AND provision_payload = ?"), &["candidate_revision:BIGINT", "candidate_payload:BLOB", "provision_slot:BLOB", "expected_revision:BIGINT", "expected_payload:BLOB"]),
        ])
    }
    pub(super) fn get(&self, id: PendingQueueStreamProvisionQueryId) -> &PendingQueueStreamProvisionQuery { &self.0[id as usize - 1] }
    fn golden(&self) -> String { self.0.iter().map(|q| format!("{:?}|{}\n{}\n", q.id, q.bind_shape.join(","), q.cql)).collect() }
}

fn query(id: PendingQueueStreamProvisionQueryId, cql: String, bind_shape: &'static [&'static str]) -> PendingQueueStreamProvisionQuery { PendingQueueStreamProvisionQuery { id, cql, bind_shape } }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ReadBinding { slot: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct BootstrapBinding { slot: Vec<u8>, revision: i64, payload: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct CasBinding { candidate_revision: i64, candidate_payload: Vec<u8>, slot: Vec<u8>, expected_revision: i64, expected_payload: Vec<u8> }

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct DbRow { revision: i64, provision_payload: Vec<u8> }

pub(super) struct PersistedPendingQueueStreamProvisionedReceipt {
    store_fingerprint: PendingQueueStreamProvisionStoreFingerprint,
    current: StoredPendingQueueStreamProvision,
}

impl PersistedPendingQueueStreamProvisionedReceipt {
    pub(super) fn segment(&self) -> &RecoverableNatsStreamSegment { &self.current.segment }
    pub(super) const fn instance_id(&self) -> RecoverableNatsStreamInstanceId { self.current.instance_id.unwrap() }
    async fn binding(&self, store: &ScyllaPendingQueueStreamProvisionStore) -> Result<RecoverableNatsExistingStreamBinding, PendingQueueStreamProvisionError> {
        store.revalidate_provisioned(self).await?;
        self.current.binding()
    }
    pub(super) async fn open_publisher(&self, store: &ScyllaPendingQueueStreamProvisionStore, nats: &NatsJetStreamClient) -> Result<InstanceBoundRecoverablePendingQueueNatsPublisher, PendingQueueStreamProvisionError> {
        let binding = self.binding(store).await?;
        nats.open_existing_recoverable_pending_publisher(self.current.segment.clone(), &binding).await.map_err(transport)
    }
}

pub(super) struct ScyllaPendingQueueStreamProvisionStore {
    session: Arc<Session>,
    ledger_store: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    fingerprint: PendingQueueStreamProvisionStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaPendingQueueStreamProvisionStore {
    pub(super) async fn create_schema(session: &Session, keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Result<(), PendingQueueStreamProvisionError> {
        let queries = PendingQueueStreamProvisionQueries::new(keyspace);
        session.query_unpaged(queries.get(PendingQueueStreamProvisionQueryId::Create).cql(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare_authorized(
        session: Arc<Session>,
        ready: &PendingQueueSidecarReady,
        ledger_store: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        let keyspace = ready
            .view()
            .verified()
            .stored()
            .keyspaces()
            .control()
            .clone();
        Self::prepare_inner(session, keyspace, ledger_store).await
    }

    #[cfg(test)]
    pub(super) async fn prepare_for_test(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
        ledger_store: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        Self::prepare_inner(session, keyspace, ledger_store).await
    }

    async fn prepare_inner(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
        ledger_store: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    ) -> Result<Self, PendingQueueStreamProvisionError> {
        if !ledger_store.is_bound_to_keyspace(&keyspace) {
            return Err(PendingQueueStreamProvisionError::ReadinessMismatch);
        }
        let queries = PendingQueueStreamProvisionQueries::new(&keyspace);
        let fingerprint = store_fingerprint(
            &keyspace,
            &queries,
            ledger_store.fingerprint().as_bytes(),
        );
        Ok(Self {
            read: prepare_regular(&session, queries.get(PendingQueueStreamProvisionQueryId::Read).cql()).await?,
            bootstrap: prepare_lwt(&session, queries.get(PendingQueueStreamProvisionQueryId::Bootstrap).cql()).await?,
            cas: prepare_lwt(&session, queries.get(PendingQueueStreamProvisionQueryId::CompareAndSet).cql()).await?,
            session,
            ledger_store,
            fingerprint,
        })
    }

    async fn read(&self, slot: PendingQueueStreamProvisionSlot) -> Result<Option<StoredPendingQueueStreamProvision>, PendingQueueStreamProvisionError> {
        let row = self.session.execute_unpaged(&self.read, ReadBinding { slot: slot.0.to_vec() }).await.map_err(cql)?.into_rows_result().map_err(cql)?.maybe_first_row::<DbRow>().map_err(cql)?;
        row.map(|row| StoredPendingQueueStreamProvision::decode(slot, row.revision, &row.provision_payload)).transpose()
    }

    async fn begin(&self, candidate: StoredPendingQueueStreamProvision) -> Result<StoredPendingQueueStreamProvision, PendingQueueStreamProvisionError> {
        if let Some(current) = self.read(candidate.slot).await? { return require_same_provision(&candidate, current); }
        let execution = self.session.execute_unpaged(&self.bootstrap, BootstrapBinding { slot: candidate.slot.0.to_vec(), revision: candidate.revision as i64, payload: candidate.to_persisted_bytes() }).await;
        if let Err(execute) = execution {
            let current = self.read(candidate.slot).await.map_err(|read| PendingQueueStreamProvisionError::Indeterminate(format!("execute={execute}; read={read}")))?.ok_or_else(|| PendingQueueStreamProvisionError::Indeterminate(execute.to_string()))?;
            return require_same_provision(&candidate, current);
        }
        let current = self.read(candidate.slot).await?.ok_or(PendingQueueStreamProvisionError::MissingAfterLwt)?;
        require_same_provision(&candidate, current)
    }

    pub(super) async fn provision(
        &self,
        nats: &NatsJetStreamClient,
        ledger_key: &PendingQueueSegmentLedgerKey,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueStreamProvisionedReceipt, PendingQueueStreamProvisionError> {
        self.ledger_store
            .require_live_segment_exact(ledger_key, &segment)
            .await
            .map_err(ledger)?;
        let candidate = StoredPendingQueueStreamProvision::provisioning(ledger_key, segment)?;
        let current = self.begin(candidate).await?;
        if current.phase == PendingQueueStreamProvisionPhase::Provisioned {
            let receipt = PersistedPendingQueueStreamProvisionedReceipt { store_fingerprint: self.fingerprint, current };
            let _ = receipt.open_publisher(self, nats).await?;
            return Ok(receipt);
        }
        let provisioned = nats.provision_recoverable_segment(current.segment.clone(), current.operation_id).await.map_err(transport)?;
        self.ledger_store
            .require_live_segment_exact(&current.ledger_key, &current.segment)
            .await
            .map_err(ledger)?;
        let durable = match self.complete(&current, &provisioned).await {
            Ok(durable) => durable,
            // Another identical provisioner may have won the completion LWT
            // using its own live readback.  The row, rather than this loser's
            // observation, is authoritative.  Re-read it through the exact
            // ledger/segment key and prove that its bound JetStream instance
            // is still live before treating the retry as idempotent success.
            Err(PendingQueueStreamProvisionError::ProvisionConflict(_)) => {
                self.read_provisioned(&current.ledger_key, &current.segment)
                    .await?
            }
            Err(error) => return Err(error),
        };
        let _ = durable.open_publisher(self, nats).await?;
        Ok(durable)
    }

    async fn complete(&self, expected: &StoredPendingQueueStreamProvision, receipt: &RecoverableNatsProvisionedStreamReceipt) -> Result<PersistedPendingQueueStreamProvisionedReceipt, PendingQueueStreamProvisionError> {
        let candidate = expected.complete(receipt)?;
        let execution = self.session.execute_unpaged(&self.cas, CasBinding { candidate_revision: candidate.revision as i64, candidate_payload: candidate.to_persisted_bytes(), slot: expected.slot.0.to_vec(), expected_revision: expected.revision as i64, expected_payload: expected.to_persisted_bytes() }).await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                let current = self.read(expected.slot).await.map_err(|read| PendingQueueStreamProvisionError::Indeterminate(format!("execute={execute}; read={read}")))?.ok_or_else(|| PendingQueueStreamProvisionError::Indeterminate(execute.to_string()))?;
                return finish_complete(self.fingerprint, &candidate, current);
            }
        };
        let current = self.read(expected.slot).await?.ok_or(PendingQueueStreamProvisionError::MissingAfterLwt)?;
        if applied && current != candidate { return Err(PendingQueueStreamProvisionError::AppliedStateMismatch); }
        finish_complete(self.fingerprint, &candidate, current)
    }

    pub(super) async fn read_provisioned(
        &self,
        ledger_key: &PendingQueueSegmentLedgerKey,
        segment: &RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueStreamProvisionedReceipt, PendingQueueStreamProvisionError> {
        let slot = provision_slot(ledger_key, segment);
        let current = self.read(slot).await?.ok_or(PendingQueueStreamProvisionError::Uninitialized)?;
        if current.ledger_key != *ledger_key || current.segment != *segment || current.phase != PendingQueueStreamProvisionPhase::Provisioned {
            return Err(PendingQueueStreamProvisionError::ProvisionMismatch);
        }
        self.ledger_store
            .require_live_segment_exact(ledger_key, segment)
            .await
            .map_err(ledger)?;
        Ok(PersistedPendingQueueStreamProvisionedReceipt { store_fingerprint: self.fingerprint, current })
    }

    async fn revalidate_provisioned(
        &self,
        receipt: &PersistedPendingQueueStreamProvisionedReceipt,
    ) -> Result<(), PendingQueueStreamProvisionError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(PendingQueueStreamProvisionError::StoreMismatch);
        }
        let current = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueStreamProvisionError::Uninitialized)?;
        if current != receipt.current {
            return Err(PendingQueueStreamProvisionError::StaleReceipt);
        }
        self.ledger_store
            .require_live_segment_exact(&current.ledger_key, &current.segment)
            .await
            .map_err(ledger)
    }

    /// Test-only crash seam: persist the production `Provisioning` row, but
    /// stop before JetStream is touched. The returned operation is the exact
    /// one a restarted production `provision` call must recover.
    #[cfg(test)]
    pub(super) async fn persist_provisioning_without_transport_for_test(
        &self,
        ledger_key: &PendingQueueSegmentLedgerKey,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<RecoverableNatsStreamProvisioningOperationId, PendingQueueStreamProvisionError> {
        self.ledger_store
            .require_live_segment_exact(ledger_key, &segment)
            .await
            .map_err(ledger)?;
        let candidate = StoredPendingQueueStreamProvision::provisioning(ledger_key, segment)?;
        let current = self.begin(candidate).await?;
        if current.phase != PendingQueueStreamProvisionPhase::Provisioning {
            return Err(PendingQueueStreamProvisionError::AlreadyProvisioned);
        }
        Ok(current.operation_id)
    }

    /// Test-only response-loss seam: use the production completion CAS and
    /// deliberately discard its receipt after the durable write succeeds.
    #[cfg(test)]
    pub(super) async fn complete_without_return_for_test(
        &self,
        ledger_key: &PendingQueueSegmentLedgerKey,
        segment: &RecoverableNatsStreamSegment,
        receipt: &RecoverableNatsProvisionedStreamReceipt,
    ) -> Result<(), PendingQueueStreamProvisionError> {
        let expected = StoredPendingQueueStreamProvision::provisioning(
            ledger_key,
            segment.clone(),
        )?;
        let current = self
            .read(expected.slot)
            .await?
            .ok_or(PendingQueueStreamProvisionError::Uninitialized)?;
        if current.phase != PendingQueueStreamProvisionPhase::Provisioning {
            return Err(PendingQueueStreamProvisionError::AlreadyProvisioned);
        }
        self.ledger_store
            .require_live_segment_exact(ledger_key, segment)
            .await
            .map_err(ledger)?;
        let _ = self.complete(&current, receipt).await?;
        Ok(())
    }
}

fn require_same_provision(candidate: &StoredPendingQueueStreamProvision, current: StoredPendingQueueStreamProvision) -> Result<StoredPendingQueueStreamProvision, PendingQueueStreamProvisionError> {
    if current.slot != candidate.slot || current.ledger_key != candidate.ledger_key || current.segment != candidate.segment || current.operation_id != candidate.operation_id { return Err(PendingQueueStreamProvisionError::ProvisionConflict("stable provision identity differs".to_owned())); }
    Ok(current)
}

fn finish_complete(fingerprint: PendingQueueStreamProvisionStoreFingerprint, candidate: &StoredPendingQueueStreamProvision, current: StoredPendingQueueStreamProvision) -> Result<PersistedPendingQueueStreamProvisionedReceipt, PendingQueueStreamProvisionError> {
    if current != *candidate {
        return Err(PendingQueueStreamProvisionError::ProvisionConflict(format!(
            "completion differs: current_revision={} current_phase={:?} current_instance={:?} candidate_revision={} candidate_phase={:?} candidate_instance={:?}",
            current.revision,
            current.phase,
            current.instance_id,
            candidate.revision,
            candidate.phase,
            candidate.instance_id,
        )));
    }
    Ok(PersistedPendingQueueStreamProvisionedReceipt { store_fingerprint: fingerprint, current })
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueStreamProvisionQueries,
    ledger_store_fingerprint: &[u8; 32],
) -> PendingQueueStreamProvisionStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_DOMAIN);
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update(queries.golden().as_bytes());
    hasher.update(ledger_store_fingerprint);
    PendingQueueStreamProvisionStoreFingerprint(hasher.finalize().into())
}

async fn prepare_regular(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueueStreamProvisionError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueueStreamProvisionError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueStreamProvisionError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]").ok_or(PendingQueueStreamProvisionError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) { Some(Some(CqlValue::Boolean(value))) => Ok(*value), _ => Err(PendingQueueStreamProvisionError::InvalidAppliedColumn) }
}

fn cql(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Cql(error.to_string()) }
fn transport(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Transport(error.to_string()) }
fn segment_error(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Segment(error.to_string()) }
fn assignment(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Assignment(error.to_string()) }
fn ledger(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Ledger(error.to_string()) }
fn protocol(error: impl fmt::Display) -> PendingQueueStreamProvisionError { PendingQueueStreamProvisionError::Protocol(error.to_string()) }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingQueueStreamProvisionError {
    Cql(String), Transport(String), Segment(String), Assignment(String), Ledger(String), Protocol(String),
    MalformedPayload, UnknownPhase, SlotMismatch, RevisionMismatch, RevisionOverflow,
    TrailingBytes, PayloadMismatch, SegmentDigestMismatch, LedgerSegmentMismatch,
    SegmentNotInLedger, ReceiptMismatch, InstanceConflict, MissingInstance,
    NotProvisioned, AlreadyProvisioned, StoreMismatch, StaleReceipt,
    ReadinessMismatch, ProvisionMismatch,
    ProvisionConflict(String), Uninitialized,
    MissingAfterLwt, MissingAppliedColumn, InvalidAppliedColumn, AppliedStateMismatch,
    Indeterminate(String),
}

impl fmt::Display for PendingQueueStreamProvisionError { fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") } }
impl Error for PendingQueueStreamProvisionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap, StoredPendingQueueSegmentLedger,
        },
        recoverable_publish::{PendingQueueGenerationBudgetContract, PendingQueuePublisherKind, PendingQueueSourceQuota},
    };

    fn fixture() -> (StoredPendingQueueSegmentLedger, RecoverableNatsStreamSegment) {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let authority = AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 };
        let generation_key = PendingGenerationLedgerKey::new(network, authority);
        let retention = RecoverableNatsRetentionContract::try_new(3, 1024 * 1024 * 1024, 128 * 1024 * 1024, 3, 16).unwrap();
        let segment = RecoverableNatsStreamSegment::try_new("psy", generation_key, RecoverableNatsSegmentId::try_new(1).unwrap(), retention).unwrap();
        let budget = PendingQueueGenerationBudgetContract::try_new(authority, vec![PendingQueueSourceQuota::try_new(PendingQueuePublisherKind::RealmUserUpdate, 1024, 128 * 1024 * 1024 - 1024, 1024).unwrap()], 128 * 1024 * 1024).unwrap();
        let validated = segment.validate_stream_config_structure(&segment.stream_config()).unwrap();
        let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(generation_key, &validated, budget, 16).unwrap();
        (bootstrap.candidate().clone(), segment)
    }

    #[test]
    fn provisioning_payload_is_deterministic_round_trip_and_fail_closed() {
        let (ledger, segment) = fixture();
        let value = StoredPendingQueueStreamProvision::provisioning(ledger.key(), segment).unwrap();
        let bytes = value.to_persisted_bytes();
        assert_eq!(StoredPendingQueueStreamProvision::decode(value.slot, value.revision as i64, &bytes).unwrap(), value);
        assert_eq!(bytes, value.to_persisted_bytes());
        let mut trailing = bytes.clone(); trailing.push(0);
        assert_eq!(StoredPendingQueueStreamProvision::decode(value.slot, value.revision as i64, &trailing), Err(PendingQueueStreamProvisionError::TrailingBytes));
        let mut tampered = bytes; tampered[50] ^= 1;
        assert!(StoredPendingQueueStreamProvision::decode(value.slot, value.revision as i64, &tampered).is_err());
    }

    #[test]
    fn query_golden_is_full_payload_lwt_and_no_tablet_owned() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("psy_control_nt").unwrap();
        let queries = PendingQueueStreamProvisionQueries::new(&keyspace);
        assert_eq!(queries.get(PendingQueueStreamProvisionQueryId::Bootstrap).cql(), "INSERT INTO psy_control_nt.branch_exact_pending_queue_stream_provision_binding_v1 (provision_slot, revision, provision_payload) VALUES (?, ?, ?) IF NOT EXISTS");
        assert!(queries.get(PendingQueueStreamProvisionQueryId::CompareAndSet).cql().contains("IF revision = ? AND provision_payload = ?"));
        assert_eq!(queries.get(PendingQueueStreamProvisionQueryId::CompareAndSet).bind_shape(), &["candidate_revision:BIGINT", "candidate_payload:BLOB", "provision_slot:BLOB", "expected_revision:BIGINT", "expected_payload:BLOB"]);
    }

    #[test]
    fn ledger_scope_and_complete_transition_fail_closed() {
        let (ledger, segment) = fixture();
        let value = StoredPendingQueueStreamProvision::provisioning(ledger.key(), segment.clone()).unwrap();
        assert_eq!(value.revision, 1);
        assert_eq!(value.phase, PendingQueueStreamProvisionPhase::Provisioning);
        let other = RecoverableNatsStreamSegment::try_new("other", segment.generation_key(), segment.segment_id(), segment.retention()).unwrap();
        assert_eq!(StoredPendingQueueStreamProvision::provisioning(ledger.key(), other), Err(PendingQueueStreamProvisionError::LedgerSegmentMismatch));
        assert!(value.binding().is_err());

        let instance = RecoverableNatsStreamInstanceId::try_from_bytes([77; 32]).unwrap();
        let completed = value.complete_exact(
            &segment,
            segment.digest().as_bytes(),
            value.operation_id,
            instance,
        ).unwrap();
        assert_eq!(completed.revision, 2);
        assert_eq!(completed.phase, PendingQueueStreamProvisionPhase::Provisioned);
        assert_eq!(completed.instance_id, Some(instance));
        assert!(completed.binding().is_ok());
        assert_eq!(completed.complete_exact(&segment, segment.digest().as_bytes(), value.operation_id, instance).unwrap(), completed);
        assert_eq!(completed.complete_exact(&segment, segment.digest().as_bytes(), value.operation_id, RecoverableNatsStreamInstanceId::try_from_bytes([78; 32]).unwrap()), Err(PendingQueueStreamProvisionError::InstanceConflict));
    }

    #[test]
    fn stable_slot_forces_same_segment_id_contract_conflicts_into_one_row() {
        let (ledger, segment) = fixture();
        let changed = RecoverableNatsStreamSegment::try_new(
            segment.base_namespace(),
            segment.generation_key(),
            segment.segment_id(),
            RecoverableNatsRetentionContract::try_new(
                3,
                segment.retention().max_stream_bytes() + 1024,
                segment.retention().generation_admission_budget_bytes(),
                segment.retention().max_live_segments(),
                segment.retention().max_consumers_per_segment(),
            ).unwrap(),
        ).unwrap();
        assert_ne!(segment.digest(), changed.digest());
        assert_eq!(provision_slot(ledger.key(), &segment), provision_slot(ledger.key(), &changed));
        assert_ne!(provision_operation(provision_slot(ledger.key(), &segment), &segment).unwrap(), provision_operation(provision_slot(ledger.key(), &changed), &changed).unwrap());
    }
}
