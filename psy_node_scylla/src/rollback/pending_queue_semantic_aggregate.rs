//! Durable fixed-source semantic generation aggregate.
//!
//! This default-off row consumes the exact per-source semantic receipts and
//! persists one immutable Coordinator (3 sources) or Realm (1 source)
//! terminal with an IF-NOT-EXISTS LWT. It deliberately does not advance the
//! pending pipeline and grants no stream rotation or GC authority.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::recoverable_ephemeral::PendingQueueCaptureContextDigest,
    store::pending_generation_pipeline::PendingQueueCloseIntentDigest,
};
use psy_node_nats::{
    recoverable_assignment::PendingQueueSegmentAssignmentDigest,
    recoverable_publish::{
        PendingQueuePublishSourceSlot, PendingQueuePublisherKind,
    },
};
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
    BranchExactDeploymentNoTabletKeyspace, PendingQueueSegmentAssignmentReceipt,
    PersistedPendingQueueCloseReceipt, ScyllaPendingPipelineStore,
    pending_queue_semantic_terminal::{
        PendingQueueSemanticSourceCommitment, PendingQueueSemanticSourceDigest,
        PersistedPendingQueueSemanticSourceReceipt,
    },
};

pub(super) const PENDING_QUEUE_SEMANTIC_GENERATION_TABLE: &str =
    "branch_exact_pending_queue_semantic_generation_v1";
const MAGIC: &[u8; 8] = b"PSYQSGEN";
const CODEC_VERSION: u16 = 1;
const REVISION: u64 = 1;
const SLOT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-generation-slot/v1";
const DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-generation/v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-generation-store/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticGenerationSlot([u8; 32]);

impl PendingQueueSemanticGenerationSlot {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticAggregateError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticAggregateError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticGenerationDigest([u8; 32]);

impl PendingQueueSemanticGenerationDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticAggregateError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticAggregateError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticAggregateStoreFingerprint([u8; 32]);

impl PendingQueueSemanticAggregateStoreFingerprint {
    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticSourceEntry {
    publisher_kind: PendingQueuePublisherKind,
    source_slot: PendingQueuePublishSourceSlot,
    semantic_digest: PendingQueueSemanticSourceDigest,
    data_member_count: u32,
    data_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredPendingQueueSemanticGeneration {
    slot: PendingQueueSemanticGenerationSlot,
    revision: u64,
    network: NetworkId,
    authority: AuthorityScope,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    close_intent: PendingQueueCloseIntentDigest,
    pipeline_close_receipt_digest: [u8; 32],
    publish_store_fingerprint: [u8; 32],
    assignment_store_fingerprint: [u8; 32],
    assignment_ledger_slot: [u8; 32],
    assignment_ledger_revision: u64,
    artifact_store_fingerprint: [u8; 32],
    total_data_members: u64,
    total_data_encoded_bytes: u64,
    sources: Vec<SemanticSourceEntry>,
    digest: PendingQueueSemanticGenerationDigest,
}

struct SemanticGenerationBinding {
    network: NetworkId,
    authority: AuthorityScope,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    close_intent: PendingQueueCloseIntentDigest,
    pipeline_close_receipt_digest: [u8; 32],
    assignment_store_fingerprint: [u8; 32],
    assignment_ledger_slot: [u8; 32],
    assignment_ledger_revision: u64,
}

impl StoredPendingQueueSemanticGeneration {
    pub(super) fn try_from_source_receipts(
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipts: Vec<PersistedPendingQueueSemanticSourceReceipt>,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let assigned = assignment.assignment();
        if !close.matches_context(assigned.context()) {
            return Err(PendingQueueSemanticAggregateError::GenerationMismatch);
        }
        let binding = SemanticGenerationBinding {
            network: assigned.context().key().network(),
            authority: assigned.context().key().authority(),
            context_digest: assigned.context().digest(),
            assignment_digest: assigned.digest(),
            close_intent: close.close_intent(),
            pipeline_close_receipt_digest: *close.receipt_digest(),
            assignment_store_fingerprint: *assignment.store_fingerprint().as_bytes(),
            assignment_ledger_slot: *assignment.ledger_slot().as_bytes(),
            assignment_ledger_revision: assignment.ledger_revision().get(),
        };
        Self::from_commitments(
            binding,
            receipts
                .into_iter()
                .map(PersistedPendingQueueSemanticSourceReceipt::into_commitment)
                .collect(),
        )
    }

    fn from_commitments(
        binding: SemanticGenerationBinding,
        mut commitments: Vec<PendingQueueSemanticSourceCommitment>,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let expected = expected_roles(binding.authority);
        if commitments.len() != expected.len() {
            return Err(PendingQueueSemanticAggregateError::IncompleteSourceSet);
        }
        commitments.sort_by_key(|entry| entry.publisher_kind as u8);
        if commitments
            .iter()
            .map(|entry| entry.publisher_kind)
            .ne(expected.iter().copied())
        {
            return Err(PendingQueueSemanticAggregateError::SourceSetMismatch);
        }
        let common_publish_store = commitments[0].publish_store_fingerprint;
        let common_artifact_store = commitments[0].artifact_store_fingerprint;
        if common_publish_store == [0; 32] || common_artifact_store == [0; 32] {
            return Err(PendingQueueSemanticAggregateError::EmptyDigest);
        }
        let mut total_data_members = 0u64;
        let mut total_data_encoded_bytes = 0u64;
        let mut sources = Vec::with_capacity(commitments.len());
        for source in commitments {
            if source.context_digest != binding.context_digest
                || source.assignment_digest != binding.assignment_digest
                || source.close_intent != binding.close_intent
                || source.pipeline_close_receipt_digest
                    != binding.pipeline_close_receipt_digest
                || source.publish_store_fingerprint != common_publish_store
                || source.assignment_store_fingerprint
                    != binding.assignment_store_fingerprint
                || source.assignment_ledger_slot != binding.assignment_ledger_slot
                || source.assignment_ledger_revision
                    != binding.assignment_ledger_revision
                || source.artifact_store_fingerprint != common_artifact_store
            {
                return Err(PendingQueueSemanticAggregateError::GenerationMismatch);
            }
            total_data_members = total_data_members
                .checked_add(u64::from(source.data_member_count))
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
            total_data_encoded_bytes = total_data_encoded_bytes
                .checked_add(source.data_encoded_bytes)
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
            sources.push(SemanticSourceEntry {
                publisher_kind: source.publisher_kind,
                source_slot: source.source_slot,
                semantic_digest: source.semantic_digest,
                data_member_count: source.data_member_count,
                data_encoded_bytes: source.data_encoded_bytes,
            });
        }
        let slot = generation_slot(
            binding.context_digest,
            binding.assignment_digest,
            binding.close_intent,
        )?;
        let mut aggregate = Self {
            slot,
            revision: REVISION,
            network: binding.network,
            authority: binding.authority,
            context_digest: binding.context_digest,
            assignment_digest: binding.assignment_digest,
            close_intent: binding.close_intent,
            pipeline_close_receipt_digest: binding.pipeline_close_receipt_digest,
            publish_store_fingerprint: common_publish_store,
            assignment_store_fingerprint: binding.assignment_store_fingerprint,
            assignment_ledger_slot: binding.assignment_ledger_slot,
            assignment_ledger_revision: binding.assignment_ledger_revision,
            artifact_store_fingerprint: common_artifact_store,
            total_data_members,
            total_data_encoded_bytes,
            sources,
            digest: PendingQueueSemanticGenerationDigest([1; 32]),
        };
        aggregate.digest = generation_digest(&aggregate.encode_unsigned())?;
        Ok(aggregate)
    }

    pub(super) const fn slot(&self) -> PendingQueueSemanticGenerationSlot { self.slot }

    pub(super) const fn digest(&self) -> PendingQueueSemanticGenerationDigest {
        self.digest
    }

    pub(super) const fn has_work(&self) -> bool { self.total_data_members != 0 }

    fn matches_generation_binding(
        &self,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
    ) -> bool {
        let assigned = assignment.assignment();
        self.network == assigned.context().key().network()
            && self.authority == assigned.context().key().authority()
            && self.context_digest == assigned.context().digest()
            && self.assignment_digest == assigned.digest()
            && self.close_intent == close.close_intent()
            && self.pipeline_close_receipt_digest == *close.receipt_digest()
            && self.assignment_store_fingerprint
                == *assignment.store_fingerprint().as_bytes()
            && self.assignment_ledger_slot == *assignment.ledger_slot().as_bytes()
            && self.assignment_ledger_revision == assignment.ledger_revision().get()
            && close.matches_context(assigned.context())
    }

    pub(super) fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub(super) fn decode_persisted(
        selected_slot: PendingQueueSemanticGenerationSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let revision = u64::try_from(selected_revision)
            .map_err(|_| PendingQueueSemanticAggregateError::RevisionMismatch)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(PendingQueueSemanticAggregateError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueSemanticAggregateError::UnknownCodecVersion);
        }
        let slot = PendingQueueSemanticGenerationSlot::try_new(decoder.array32()?)?;
        if slot != selected_slot {
            return Err(PendingQueueSemanticAggregateError::SlotMismatch);
        }
        let payload_revision = decoder.u64()?;
        if revision != REVISION || payload_revision != revision {
            return Err(PendingQueueSemanticAggregateError::RevisionMismatch);
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::InvalidAuthority)?;
        let authority_kind = decoder.u8()?;
        let realm_id = decoder.u32()?;
        let realm_sub_id = decoder.u16()?;
        let authority = match (authority_kind, realm_id, realm_sub_id) {
            (1, 0, 0) => AuthorityScope::Coordinator,
            (2, realm_id, realm_sub_id) => AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            _ => return Err(PendingQueueSemanticAggregateError::InvalidAuthority),
        };
        let context_digest = PendingQueueCaptureContextDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let close_intent = PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let pipeline_close_receipt_digest = decoder.array32()?;
        let publish_store_fingerprint = decoder.array32()?;
        let assignment_store_fingerprint = decoder.array32()?;
        let assignment_ledger_slot = decoder.array32()?;
        let assignment_ledger_revision = decoder.u64()?;
        let artifact_store_fingerprint = decoder.array32()?;
        if pipeline_close_receipt_digest == [0; 32]
            || publish_store_fingerprint == [0; 32]
            || assignment_store_fingerprint == [0; 32]
            || assignment_ledger_slot == [0; 32]
            || assignment_ledger_revision == 0
            || artifact_store_fingerprint == [0; 32]
        {
            return Err(PendingQueueSemanticAggregateError::EmptyDigest);
        }
        let total_data_members = decoder.u64()?;
        let total_data_encoded_bytes = decoder.u64()?;
        let count = usize::from(decoder.u8()?);
        if count != expected_roles(authority).len() {
            return Err(PendingQueueSemanticAggregateError::IncompleteSourceSet);
        }
        let mut sources = Vec::with_capacity(count);
        for expected in expected_roles(authority) {
            let publisher_kind = decode_publisher(decoder.u8()?)?;
            if publisher_kind != *expected {
                return Err(PendingQueueSemanticAggregateError::SourceSetMismatch);
            }
            sources.push(SemanticSourceEntry {
                publisher_kind,
                source_slot: PendingQueuePublishSourceSlot::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?,
                semantic_digest: PendingQueueSemanticSourceDigest::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?,
                data_member_count: decoder.u32()?,
                data_encoded_bytes: decoder.u64()?,
            });
        }
        let digest = PendingQueueSemanticGenerationDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueSemanticAggregateError::TrailingBytes);
        }
        let aggregate = Self {
            slot,
            revision,
            network,
            authority,
            context_digest,
            assignment_digest,
            close_intent,
            pipeline_close_receipt_digest,
            publish_store_fingerprint,
            assignment_store_fingerprint,
            assignment_ledger_slot,
            assignment_ledger_revision,
            artifact_store_fingerprint,
            total_data_members,
            total_data_encoded_bytes,
            sources,
            digest,
        };
        let (computed_members, computed_bytes) = checked_source_totals(&aggregate.sources)?;
        if generation_slot(context_digest, assignment_digest, close_intent)? != slot
            || generation_digest(&aggregate.encode_unsigned())? != digest
            || computed_members != total_data_members
            || computed_bytes != total_data_encoded_bytes
        {
            return Err(PendingQueueSemanticAggregateError::DigestMismatch);
        }
        Ok(aggregate)
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.network.chain_id().to_be_bytes());
        let (kind, realm, sub) = authority_parts(self.authority);
        out.push(kind);
        out.extend_from_slice(&realm.to_be_bytes());
        out.extend_from_slice(&sub.to_be_bytes());
        out.extend_from_slice(self.context_digest.as_bytes());
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(self.close_intent.as_bytes());
        out.extend_from_slice(&self.pipeline_close_receipt_digest);
        out.extend_from_slice(&self.publish_store_fingerprint);
        out.extend_from_slice(&self.assignment_store_fingerprint);
        out.extend_from_slice(&self.assignment_ledger_slot);
        out.extend_from_slice(&self.assignment_ledger_revision.to_be_bytes());
        out.extend_from_slice(&self.artifact_store_fingerprint);
        out.extend_from_slice(&self.total_data_members.to_be_bytes());
        out.extend_from_slice(&self.total_data_encoded_bytes.to_be_bytes());
        out.push(self.sources.len() as u8);
        for source in &self.sources {
            out.push(source.publisher_kind as u8);
            out.extend_from_slice(source.source_slot.as_bytes());
            out.extend_from_slice(source.semantic_digest.as_bytes());
            out.extend_from_slice(&source.data_member_count.to_be_bytes());
            out.extend_from_slice(&source.data_encoded_bytes.to_be_bytes());
        }
        out
    }
}

fn generation_digest(
    canonical_unsigned: &[u8],
) -> Result<PendingQueueSemanticGenerationDigest, PendingQueueSemanticAggregateError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(canonical_unsigned);
    PendingQueueSemanticGenerationDigest::try_new(hasher.finalize().into())
}

fn checked_source_totals(
    sources: &[SemanticSourceEntry],
) -> Result<(u64, u64), PendingQueueSemanticAggregateError> {
    sources.iter().try_fold((0u64, 0u64), |(members, bytes), source| {
        Ok((
            members
                .checked_add(u64::from(source.data_member_count))
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?,
            bytes
                .checked_add(source.data_encoded_bytes)
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?,
        ))
    })
}

fn generation_slot(
    context: PendingQueueCaptureContextDigest,
    assignment: PendingQueueSegmentAssignmentDigest,
    close: PendingQueueCloseIntentDigest,
) -> Result<PendingQueueSemanticGenerationSlot, PendingQueueSemanticAggregateError> {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(context.as_bytes());
    hasher.update(assignment.as_bytes());
    hasher.update(close.as_bytes());
    PendingQueueSemanticGenerationSlot::try_new(hasher.finalize().into())
}

fn expected_roles(authority: AuthorityScope) -> &'static [PendingQueuePublisherKind] {
    const COORDINATOR: &[PendingQueuePublisherKind] = &[
        PendingQueuePublisherKind::CoordinatorRegistration,
        PendingQueuePublisherKind::CoordinatorDeploy,
        PendingQueuePublisherKind::CoordinatorGuta,
    ];
    const REALM: &[PendingQueuePublisherKind] =
        &[PendingQueuePublisherKind::RealmUserUpdate];
    match authority {
        AuthorityScope::Coordinator => COORDINATOR,
        AuthorityScope::Realm { .. } => REALM,
    }
}

fn authority_parts(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm { realm_id, realm_sub_id } => (2, realm_id, realm_sub_id),
    }
}

fn decode_publisher(value: u8) -> Result<PendingQueuePublisherKind, PendingQueueSemanticAggregateError> {
    match value {
        1 => Ok(PendingQueuePublisherKind::CoordinatorRegistration),
        2 => Ok(PendingQueuePublisherKind::CoordinatorDeploy),
        3 => Ok(PendingQueuePublisherKind::CoordinatorGuta),
        32 => Ok(PendingQueuePublisherKind::RealmUserUpdate),
        _ => Err(PendingQueueSemanticAggregateError::SourceSetMismatch),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueSemanticAggregateQueries {
    create: String,
    read: String,
    bootstrap: String,
}

impl PendingQueueSemanticAggregateQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), PENDING_QUEUE_SEMANTIC_GENERATION_TABLE);
        Self {
            create: format!("CREATE TABLE IF NOT EXISTS {table} (generation_slot blob PRIMARY KEY, revision bigint, aggregate_payload blob)"),
            read: format!("SELECT revision, aggregate_payload FROM {table} WHERE generation_slot = ?"),
            bootstrap: format!("INSERT INTO {table} (generation_slot, revision, aggregate_payload) VALUES (?, ?, ?) IF NOT EXISTS"),
        }
    }

    fn golden(&self) -> String {
        format!("create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n", self.create, self.read, self.bootstrap)
    }
}

pub(super) struct ScyllaPendingQueueSemanticAggregateStore {
    session: Arc<Session>,
    fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueSemanticGenerationReceipt {
    store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    aggregate: StoredPendingQueueSemanticGeneration,
}

impl PersistedPendingQueueSemanticGenerationReceipt {
    pub(super) const fn authority(&self) -> AuthorityScope { self.aggregate.authority }

    pub(super) const fn has_data_work(&self) -> bool { self.aggregate.has_work() }
}

impl ScyllaPendingQueueSemanticAggregateStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        let queries = PendingQueueSemanticAggregateQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let queries = PendingQueueSemanticAggregateQueries::new(&keyspace);
        let fingerprint = store_fingerprint(&keyspace, &queries);
        Ok(Self {
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            session,
            fingerprint,
        })
    }

    async fn read(
        &self,
        slot: PendingQueueSemanticGenerationSlot,
    ) -> Result<Option<StoredPendingQueueSemanticGeneration>, PendingQueueSemanticAggregateError> {
        let row = self.session.execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>().map_err(cql)?;
        let Some((revision, payload)) = row else { return Ok(None) };
        Ok(Some(StoredPendingQueueSemanticGeneration::decode_persisted(
            slot,
            revision.ok_or(PendingQueueSemanticAggregateError::MissingColumn)?,
            payload.as_deref().ok_or(PendingQueueSemanticAggregateError::MissingColumn)?,
        )?))
    }

    pub(super) async fn persist_verified<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        candidate: &StoredPendingQueueSemanticGeneration,
    ) -> Result<PersistedPendingQueueSemanticGenerationReceipt, PendingQueueSemanticAggregateError> {
        if !candidate.matches_generation_binding(assignment, close) {
            return Err(PendingQueueSemanticAggregateError::CandidateBindingMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        let payload = candidate.to_persisted_bytes();
        let execution = self.session.execute_unpaged(
            &self.bootstrap,
            (candidate.slot().as_bytes().as_slice(), REVISION as i64, payload.as_slice()),
        ).await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot()).await {
                Ok(Some(current)) if &current == candidate => false,
                Ok(_) => return Err(PendingQueueSemanticAggregateError::Indeterminate(error.to_string())),
                Err(read) => return Err(PendingQueueSemanticAggregateError::Indeterminate(format!("execute={error}; read={read}"))),
            },
        };
        let current = self.read(candidate.slot()).await?
            .ok_or(PendingQueueSemanticAggregateError::MissingAfterLwt)?;
        if &current != candidate {
            return Err(if applied {
                PendingQueueSemanticAggregateError::AppliedStateMismatch
            } else {
                PendingQueueSemanticAggregateError::Conflict
            });
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        Ok(PersistedPendingQueueSemanticGenerationReceipt {
            store_fingerprint: self.fingerprint,
            aggregate: current,
        })
    }

    pub(super) async fn revalidate_exact<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipt: &PersistedPendingQueueSemanticGenerationReceipt,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        if receipt.store_fingerprint != self.fingerprint
            || !receipt.aggregate.matches_generation_binding(assignment, close)
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        let current = self
            .read(receipt.aggregate.slot())
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        if current != receipt.aggregate {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        Ok(())
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueSemanticAggregateQueries,
) -> PendingQueueSemanticAggregateStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    PendingQueueSemanticAggregateStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueSemanticAggregateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueSemanticAggregateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueSemanticAggregateError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(PendingQueueSemanticAggregateError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueSemanticAggregateError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueSemanticAggregateError {
    PendingQueueSemanticAggregateError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingQueueSemanticAggregateError {
    Cql(String),
    Pipeline(String),
    EmptyDigest,
    InvalidMagic,
    UnknownCodecVersion,
    SlotMismatch,
    RevisionMismatch,
    InvalidAuthority,
    IncompleteSourceSet,
    SourceSetMismatch,
    GenerationMismatch,
    CandidateBindingMismatch,
    ReceiptBindingMismatch,
    ReceiptStale,
    CounterOverflow,
    DigestMismatch,
    TrailingBytes,
    Truncated,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    Conflict,
    Indeterminate(String),
}

impl fmt::Display for PendingQueueSemanticAggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}

impl Error for PendingQueueSemanticAggregateError {}

struct Decoder<'a> { bytes: &'a [u8], cursor: usize }

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueSemanticAggregateError> {
        let end = self.cursor.checked_add(len).ok_or(PendingQueueSemanticAggregateError::Truncated)?;
        let value = self.bytes.get(self.cursor..end).ok_or(PendingQueueSemanticAggregateError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueSemanticAggregateError> { self.take(32)?.try_into().map_err(|_| PendingQueueSemanticAggregateError::Truncated) }
    fn u8(&mut self) -> Result<u8, PendingQueueSemanticAggregateError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueSemanticAggregateError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, PendingQueueSemanticAggregateError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueSemanticAggregateError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(authority: AuthorityScope) -> SemanticGenerationBinding {
        SemanticGenerationBinding {
            network: NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
            context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
            assignment_digest: PendingQueueSegmentAssignmentDigest::try_new([2; 32]).unwrap(),
            close_intent: PendingQueueCloseIntentDigest::try_new([3; 32]).unwrap(),
            pipeline_close_receipt_digest: [4; 32],
            assignment_store_fingerprint: [5; 32],
            assignment_ledger_slot: [6; 32],
            assignment_ledger_revision: 7,
        }
    }

    fn commitment(role: PendingQueuePublisherKind, index: u8) -> PendingQueueSemanticSourceCommitment {
        PendingQueueSemanticSourceCommitment {
            publisher_kind: role,
            context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
            assignment_digest: PendingQueueSegmentAssignmentDigest::try_new([2; 32]).unwrap(),
            close_intent: PendingQueueCloseIntentDigest::try_new([3; 32]).unwrap(),
            pipeline_close_receipt_digest: [4; 32],
            publish_store_fingerprint: [8; 32],
            assignment_store_fingerprint: [5; 32],
            assignment_ledger_slot: [6; 32],
            assignment_ledger_revision: 7,
            artifact_store_fingerprint: [9; 32],
            source_slot: PendingQueuePublishSourceSlot::try_new([index; 32]).unwrap(),
            semantic_digest: PendingQueueSemanticSourceDigest::try_new([index + 10; 32]).unwrap(),
            data_member_count: u32::from(index),
            data_encoded_bytes: u64::from(index) * 100,
        }
    }

    fn coordinator_sources() -> Vec<PendingQueueSemanticSourceCommitment> {
        vec![
            commitment(PendingQueuePublisherKind::CoordinatorGuta, 3),
            commitment(PendingQueuePublisherKind::CoordinatorRegistration, 1),
            commitment(PendingQueuePublisherKind::CoordinatorDeploy, 2),
        ]
    }

    #[test]
    fn fixed_three_and_one_source_sets_are_deterministic() {
        let first = StoredPendingQueueSemanticGeneration::from_commitments(
            binding(AuthorityScope::Coordinator), coordinator_sources(),
        ).unwrap();
        let mut reversed = coordinator_sources();
        reversed.reverse();
        let second = StoredPendingQueueSemanticGeneration::from_commitments(
            binding(AuthorityScope::Coordinator), reversed,
        ).unwrap();
        assert_eq!(first, second);
        assert!(first.has_work());
        let realm = StoredPendingQueueSemanticGeneration::from_commitments(
            binding(AuthorityScope::Realm { realm_id: 3, realm_sub_id: 0 }),
            vec![commitment(PendingQueuePublisherKind::RealmUserUpdate, 1)],
        ).unwrap();
        assert_eq!(realm.sources.len(), 1);
    }

    #[test]
    fn missing_duplicate_extra_and_cross_generation_sources_fail_closed() {
        let mut missing = coordinator_sources();
        missing.pop();
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding(AuthorityScope::Coordinator), missing),
            Err(PendingQueueSemanticAggregateError::IncompleteSourceSet)
        ));
        let duplicate = vec![
            commitment(PendingQueuePublisherKind::CoordinatorRegistration, 1),
            commitment(PendingQueuePublisherKind::CoordinatorRegistration, 2),
            commitment(PendingQueuePublisherKind::CoordinatorGuta, 3),
        ];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding(AuthorityScope::Coordinator), duplicate),
            Err(PendingQueueSemanticAggregateError::SourceSetMismatch)
        ));
        let mut extra = coordinator_sources();
        extra.push(commitment(
            PendingQueuePublisherKind::RealmUserUpdate,
            4,
        ));
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding(AuthorityScope::Coordinator),
                extra
            ),
            Err(PendingQueueSemanticAggregateError::IncompleteSourceSet)
        ));
        let mut wrong = coordinator_sources();
        wrong[0].pipeline_close_receipt_digest = [9; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding(AuthorityScope::Coordinator), wrong),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));
    }

    #[test]
    fn cross_store_source_receipts_fail_closed() {
        let mut wrong_publish_store = coordinator_sources();
        wrong_publish_store[1].publish_store_fingerprint = [88; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding(AuthorityScope::Coordinator),
                wrong_publish_store,
            ),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));

        let mut wrong_artifact_store = coordinator_sources();
        wrong_artifact_store[2].artifact_store_fingerprint = [99; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding(AuthorityScope::Coordinator),
                wrong_artifact_store,
            ),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));
    }

    #[test]
    fn codec_round_trip_tamper_and_trailing_bytes_fail_closed() {
        let aggregate = StoredPendingQueueSemanticGeneration::from_commitments(
            binding(AuthorityScope::Coordinator), coordinator_sources(),
        ).unwrap();
        let bytes = aggregate.to_persisted_bytes();
        assert_eq!(
            StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &bytes).unwrap(),
            aggregate,
        );
        let mut tampered = bytes.clone();
        tampered[100] ^= 1;
        assert!(StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &tampered).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &trailing),
            Err(PendingQueueSemanticAggregateError::TrailingBytes)
        ));
    }

    #[test]
    fn lwt_query_is_immutable_and_production_setup_is_not_wired() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("psy_h22d3_no_tablet".to_owned()).unwrap();
        let golden = PendingQueueSemanticAggregateQueries::new(&keyspace).golden();
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(!golden.contains("UPDATE "));
        assert!(golden.contains(PENDING_QUEUE_SEMANTIC_GENERATION_TABLE));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_SEMANTIC_GENERATION_TABLE));
        assert!(!setup.contains("ScyllaPendingQueueSemanticAggregateStore"));
        let source = include_str!("pending_queue_semantic_aggregate.rs");
        assert!(source.contains("persist_verified<Hash: Q256BitHash>"));
        assert!(source.matches("revalidate_queue_close_exact::<Hash>").count() >= 4);
        assert!(!source.contains("pub(super) async fn persist(\n"));
    }
}
