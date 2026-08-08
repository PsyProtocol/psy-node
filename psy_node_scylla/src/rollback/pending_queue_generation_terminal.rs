//! Immutable queue-generation terminal and pipeline-rotation gate.
//!
//! The row is default-off. It can only be written after the assignment archive,
//! terminal pipeline, Active writer lifecycle, and authority-local head agree.
//! It grants pipeline-generation rotation, never NATS segment rotation or GC.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::{AuthorityObservation, AuthorityScope},
};
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    authority_local_head::{
        AuthorityLocalHeadReadState, StoredAuthorityLocalHead,
    },
    pending_generation::ReservedPendingGeneration,
    pending_generation_identity::PendingGenerationActivationDigest,
    pending_generation_pipeline::{
        PendingProcessingState, SealedPendingPipelineTransition,
        StoredPendingPipeline,
    },
};
use psy_node_nats::recoverable_assignment::PendingQueueSegmentAssignmentDigest;
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
    BranchExactWriterAuthorityKey, BranchExactWriterReadState,
    BranchExactWriterRevision, BranchExactWriterSlot,
    BranchExactWriterState, BranchExactDeploymentNoTabletKeyspace,
    PendingQueueSegmentAssignmentReceipt,
    ScyllaAuthorityLocalHeadStore, ScyllaBranchExactWriterLifecycleStore,
    ScyllaPendingPipelineStore,
    StoredBranchExactWriterLifecycle,
    pending_queue_semantic_aggregate::{
        PendingQueueSemanticAggregateError,
        PendingQueueSemanticAggregateStoreFingerprint,
        PendingQueueSemanticGenerationDigest,
        PendingQueueSemanticGenerationSlot,
        PersistedPendingQueueTerminalArchiveReceipt,
    },
    branch_exact_pending_orchestration::validate_branch_exact_queue_terminal_pair,
    pending_queue_semantic_aggregate::ScyllaPendingQueueSemanticAggregateStore,
};

pub(super) const PENDING_QUEUE_GENERATION_TERMINAL_TABLE: &str =
    "branch_exact_pending_queue_generation_terminal_v1";
const MAGIC: &[u8; 8] = b"PSYQTERM";
const CODEC_VERSION: u16 = 1;
const REVISION: u64 = 1;
const DIGEST_DOMAIN: &[u8] = b"psy/rollback/pending-queue-generation-terminal/v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-generation-terminal-store/v1";
const MAX_COMPONENT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PendingQueueGenerationTerminalKind {
    Published = 1,
    RetiredNoWork = 2,
}

impl PendingQueueGenerationTerminalKind {
    fn from_pipeline<Hash>(
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> Result<Self, PendingQueueGenerationTerminalError> {
        match pipeline.processing_state() {
            PendingProcessingState::Published { .. } => Ok(Self::Published),
            PendingProcessingState::RetiredNoWork { .. } => Ok(Self::RetiredNoWork),
            _ => Err(PendingQueueGenerationTerminalError::PipelineNotTerminal),
        }
    }

    fn try_from_u8(value: u8) -> Result<Self, PendingQueueGenerationTerminalError> {
        match value {
            1 => Ok(Self::Published),
            2 => Ok(Self::RetiredNoWork),
            _ => Err(PendingQueueGenerationTerminalError::InvalidTerminalKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingQueueGenerationTerminalDigest([u8; 32]);

impl PendingQueueGenerationTerminalDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueGenerationTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueGenerationTerminalError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPendingQueueGenerationTerminal {
    archive_slot: PendingQueueSemanticGenerationSlot,
    revision: u64,
    network: NetworkId,
    authority: AuthorityScope,
    activation_digest: PendingGenerationActivationDigest,
    pending_id: u64,
    proc_checkpoint_id: [u8; 16],
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    archive_digest: PendingQueueSemanticGenerationDigest,
    archive_store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    terminal_kind: PendingQueueGenerationTerminalKind,
    pipeline_revision: u64,
    pipeline_payload: Vec<u8>,
    writer_slot: BranchExactWriterSlot,
    writer_revision: BranchExactWriterRevision,
    writer_payload: Vec<u8>,
    head_revision: u64,
    head_payload: Vec<u8>,
    digest: PendingQueueGenerationTerminalDigest,
}

impl StoredPendingQueueGenerationTerminal {
    fn from_verified<Hash: Q256BitHash>(
        archive: &PersistedPendingQueueTerminalArchiveReceipt<Hash>,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
        head: &StoredAuthorityLocalHead<Hash>,
    ) -> Result<Self, PendingQueueGenerationTerminalError> {
        let pipeline = archive.pipeline();
        validate_branch_exact_queue_terminal_pair(pipeline, writer)
            .map_err(|error| PendingQueueGenerationTerminalError::TerminalPair(error.to_string()))?;
        validate_authority_head(pipeline, head)?;
        let writer_payload = writer.to_canonical_bytes();
        let pipeline_payload = pipeline.canonical_payload();
        let head_payload = head.encode_canonical().to_vec();
        if [pipeline_payload.len(), writer_payload.len(), head_payload.len()]
            .into_iter()
            .any(|len| len == 0 || len > MAX_COMPONENT_BYTES || u32::try_from(len).is_err())
        {
            return Err(PendingQueueGenerationTerminalError::ComponentTooLarge);
        }
        let mut terminal = Self {
            archive_slot: archive.aggregate_slot(),
            revision: REVISION,
            network: pipeline.key().network(),
            authority: pipeline.key().authority(),
            activation_digest: pipeline.activation_digest(),
            pending_id: pipeline.processing().pending_id().get(),
            proc_checkpoint_id: *pipeline.processing().proc_checkpoint_id().as_bytes(),
            assignment_digest: archive.assignment_digest(),
            archive_digest: archive.aggregate_digest(),
            archive_store_fingerprint: archive.aggregate_store_fingerprint(),
            terminal_kind: PendingQueueGenerationTerminalKind::from_pipeline(pipeline)?,
            pipeline_revision: pipeline.revision().get(),
            pipeline_payload: pipeline_payload.to_vec(),
            writer_slot: writer.slot(),
            writer_revision: writer.revision(),
            writer_payload,
            head_revision: head.revision().get(),
            head_payload,
            digest: PendingQueueGenerationTerminalDigest([1; 32]),
        };
        terminal.digest = terminal_digest(&terminal.encode_unsigned())?;
        Ok(terminal)
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            256 + self.pipeline_payload.len() + self.writer_payload.len()
                + self.head_payload.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.archive_slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.network.chain_id().to_be_bytes());
        let (kind, realm, sub) = authority_parts(self.authority);
        out.push(kind);
        out.extend_from_slice(&realm.to_be_bytes());
        out.extend_from_slice(&sub.to_be_bytes());
        out.extend_from_slice(self.activation_digest.as_bytes());
        out.extend_from_slice(&self.pending_id.to_be_bytes());
        out.extend_from_slice(&self.proc_checkpoint_id);
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(self.archive_digest.as_bytes());
        out.extend_from_slice(self.archive_store_fingerprint.as_bytes());
        out.push(self.terminal_kind as u8);
        out.extend_from_slice(&self.pipeline_revision.to_be_bytes());
        encode_bytes(&self.pipeline_payload, &mut out);
        out.extend_from_slice(self.writer_slot.as_bytes());
        out.extend_from_slice(&self.writer_revision.get().to_be_bytes());
        encode_bytes(&self.writer_payload, &mut out);
        out.extend_from_slice(&self.head_revision.to_be_bytes());
        encode_bytes(&self.head_payload, &mut out);
        out
    }

    fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(&self.digest.0);
        out
    }

    fn decode_persisted(
        selected_slot: PendingQueueSemanticGenerationSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueGenerationTerminalError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(PendingQueueGenerationTerminalError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueGenerationTerminalError::UnknownCodecVersion);
        }
        let archive_slot = PendingQueueSemanticGenerationSlot::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueGenerationTerminalError::EmptyDigest)?;
        let revision = decoder.u64()?;
        if archive_slot != selected_slot
            || revision != REVISION
            || selected_revision != REVISION as i64
        {
            return Err(PendingQueueGenerationTerminalError::SelectedIdentityMismatch);
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(|_| PendingQueueGenerationTerminalError::InvalidAuthority)?;
        let authority = decode_authority(decoder.u8()?, decoder.u32()?, decoder.u16()?)?;
        let activation_digest = PendingGenerationActivationDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueGenerationTerminalError::EmptyDigest)?;
        let pending_id = decoder.u64()?;
        let proc_checkpoint_id = decoder.array16()?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueGenerationTerminalError::EmptyDigest)?;
        let archive_digest = PendingQueueSemanticGenerationDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueGenerationTerminalError::EmptyDigest)?;
        let archive_store_fingerprint =
            PendingQueueSemanticAggregateStoreFingerprint::try_new(decoder.array32()?)
                .map_err(|_| PendingQueueGenerationTerminalError::EmptyDigest)?;
        let terminal_kind = PendingQueueGenerationTerminalKind::try_from_u8(decoder.u8()?)?;
        let pipeline_revision = decoder.u64()?;
        let pipeline_payload = decoder.bytes()?;
        let selected_writer_slot = decoder.array32()?;
        let writer_slot = BranchExactWriterSlot::for_authority(network, authority);
        if selected_writer_slot != *writer_slot.as_bytes() {
            return Err(PendingQueueGenerationTerminalError::SelectedIdentityMismatch);
        }
        let writer_revision = BranchExactWriterRevision::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueGenerationTerminalError::InvalidRevision)?;
        let writer_payload = decoder.bytes()?;
        let head_revision = decoder.u64()?;
        let head_payload = decoder.bytes()?;
        let digest = PendingQueueGenerationTerminalDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueGenerationTerminalError::TrailingBytes);
        }
        let terminal = Self {
            archive_slot,
            revision,
            network,
            authority,
            activation_digest,
            pending_id,
            proc_checkpoint_id,
            assignment_digest,
            archive_digest,
            archive_store_fingerprint,
            terminal_kind,
            pipeline_revision,
            pipeline_payload,
            writer_slot,
            writer_revision,
            writer_payload,
            head_revision,
            head_payload,
            digest,
        };
        if terminal.pipeline_revision == 0
            || terminal.head_revision == 0
            || terminal_digest(&terminal.encode_unsigned())? != terminal.digest
        {
            return Err(PendingQueueGenerationTerminalError::DigestMismatch);
        }
        Ok(terminal)
    }
}

fn validate_authority_head<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    head: &StoredAuthorityLocalHead<Hash>,
) -> Result<(), PendingQueueGenerationTerminalError> {
    let view = head.head();
    let observed = AuthorityObservation::try_new(
        *view.chain(),
        pipeline.key().authority(),
        view.state_checkpoint(),
        *view.state_root(),
    )
    .map_err(|error| PendingQueueGenerationTerminalError::Head(error.to_string()))?;
    if observed != *pipeline.frontier()
        || view.key().network() != pipeline.key().network()
        || view.key().authority() != pipeline.key().authority()
    {
        return Err(PendingQueueGenerationTerminalError::HeadMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingQueueGenerationTerminalQueries {
    create: String,
    read: String,
    bootstrap: String,
}

impl PendingQueueGenerationTerminalQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{PENDING_QUEUE_GENERATION_TERMINAL_TABLE}",
            keyspace.as_str()
        );
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (archive_slot blob PRIMARY KEY, revision bigint, terminal_payload blob)"
            ),
            read: format!(
                "SELECT revision, terminal_payload FROM {table} WHERE archive_slot = ?"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (archive_slot, revision, terminal_payload) VALUES (?, ?, ?) IF NOT EXISTS"
            ),
        }
    }

    fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingQueueGenerationTerminalStoreFingerprint([u8; 32]);

pub(super) struct ScyllaPendingQueueGenerationTerminalStore {
    session: Arc<Session>,
    fingerprint: PendingQueueGenerationTerminalStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueGenerationTerminalReceipt {
    store_fingerprint: PendingQueueGenerationTerminalStoreFingerprint,
    terminal: StoredPendingQueueGenerationTerminal,
}

impl ScyllaPendingQueueGenerationTerminalStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueGenerationTerminalError> {
        let queries = PendingQueueGenerationTerminalQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueGenerationTerminalError> {
        let queries = PendingQueueGenerationTerminalQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            session,
        })
    }

    async fn read(
        &self,
        slot: PendingQueueSemanticGenerationSlot,
    ) -> Result<Option<StoredPendingQueueGenerationTerminal>, PendingQueueGenerationTerminalError> {
        let row = self.session.execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>().map_err(cql)?;
        let Some((revision, payload)) = row else { return Ok(None) };
        Ok(Some(StoredPendingQueueGenerationTerminal::decode_persisted(
            slot,
            revision.ok_or(PendingQueueGenerationTerminalError::MissingColumn)?,
            payload.as_deref().ok_or(PendingQueueGenerationTerminalError::MissingColumn)?,
        )?))
    }

    async fn observe_verified<Hash: Q256BitHash>(
        &self,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
    ) -> Result<(
        PersistedPendingQueueTerminalArchiveReceipt<Hash>,
        StoredBranchExactWriterLifecycle<Hash>,
        StoredAuthorityLocalHead<Hash>,
        StoredPendingQueueGenerationTerminal,
    ), PendingQueueGenerationTerminalError> {
        let archive = archive_store
            .revalidate_terminal_archive::<Hash>(pipeline_store, assignment)
            .await?;
        let pipeline = archive.pipeline();
        let key = BranchExactWriterAuthorityKey::new(
            pipeline.key().network(),
            pipeline.key().authority(),
        );
        let BranchExactWriterReadState::Current(writer) = writer_store
            .read(key)
            .await
            .map_err(|error| PendingQueueGenerationTerminalError::Writer(error.to_string()))?
        else {
            return Err(PendingQueueGenerationTerminalError::WriterMissing);
        };
        if !matches!(writer.state(), BranchExactWriterState::Active(_)) {
            return Err(PendingQueueGenerationTerminalError::WriterNotActive);
        }
        let head_key = AuthorityTimestampKey::new(
            pipeline.key().network(),
            pipeline.key().authority(),
        );
        let AuthorityLocalHeadReadState::Current(head) = head_store
            .read(head_key)
            .await
            .map_err(|error| PendingQueueGenerationTerminalError::Head(error.to_string()))?
        else {
            return Err(PendingQueueGenerationTerminalError::HeadMissing);
        };
        let terminal = StoredPendingQueueGenerationTerminal::from_verified(
            &archive, &writer, &head,
        )?;
        Ok((archive, writer, head, terminal))
    }

    pub(super) async fn persist_verified<Hash: Q256BitHash>(
        &self,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
    ) -> Result<PersistedPendingQueueGenerationTerminalReceipt, PendingQueueGenerationTerminalError> {
        let (_, _, _, candidate) = self.observe_verified::<Hash>(
            archive_store, pipeline_store, writer_store, head_store, assignment,
        ).await?;
        let payload = candidate.to_persisted_bytes();
        let execution = self.session.execute_unpaged(
            &self.bootstrap,
            (candidate.archive_slot.as_bytes().as_slice(), REVISION as i64, payload.as_slice()),
        ).await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.archive_slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => return Err(PendingQueueGenerationTerminalError::Indeterminate(error.to_string())),
                Err(read) => return Err(PendingQueueGenerationTerminalError::Indeterminate(format!("execute={error}; read={read}"))),
            },
        };
        let current = self.read(candidate.archive_slot).await?
            .ok_or(PendingQueueGenerationTerminalError::MissingAfterLwt)?;
        if current != candidate {
            return Err(if applied {
                PendingQueueGenerationTerminalError::AppliedStateMismatch
            } else {
                PendingQueueGenerationTerminalError::Conflict
            });
        }
        let (_, _, _, after) = self.observe_verified::<Hash>(
            archive_store, pipeline_store, writer_store, head_store, assignment,
        ).await?;
        if after != current {
            return Err(PendingQueueGenerationTerminalError::EvidenceChanged);
        }
        Ok(PersistedPendingQueueGenerationTerminalReceipt {
            store_fingerprint: self.fingerprint,
            terminal: current,
        })
    }

    async fn revalidate_receipt<Hash: Q256BitHash>(
        &self,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        receipt: &PersistedPendingQueueGenerationTerminalReceipt,
    ) -> Result<PersistedPendingQueueTerminalArchiveReceipt<Hash>, PendingQueueGenerationTerminalError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(PendingQueueGenerationTerminalError::ReceiptBindingMismatch);
        }
        let persisted = self.read(receipt.terminal.archive_slot).await?
            .ok_or(PendingQueueGenerationTerminalError::ReceiptStale)?;
        if persisted != receipt.terminal {
            return Err(PendingQueueGenerationTerminalError::ReceiptStale);
        }
        let (archive, _, _, current) = self.observe_verified::<Hash>(
            archive_store, pipeline_store, writer_store, head_store, assignment,
        ).await?;
        archive_store.revalidate_terminal_archive_receipt(
            pipeline_store, assignment, &archive,
        ).await?;
        if current != receipt.terminal {
            return Err(PendingQueueGenerationTerminalError::EvidenceChanged);
        }
        Ok(archive)
    }

    /// Seal (but do not execute) pipeline rotation only after exact durable
    /// terminal revalidation. Segment rotation and NATS deletion are outside
    /// this capability.
    pub(super) async fn seal_pipeline_rotation<Hash: Q256BitHash>(
        &self,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        receipt: &PersistedPendingQueueGenerationTerminalReceipt,
        reserved: ReservedPendingGeneration,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingQueueGenerationTerminalError> {
        let archive = self.revalidate_receipt::<Hash>(
            archive_store, pipeline_store, writer_store, head_store, assignment, receipt,
        ).await?;
        archive.pipeline().seal_rotation(reserved)
            .map_err(|error| PendingQueueGenerationTerminalError::Pipeline(error.to_string()))
    }
}

fn terminal_digest(bytes: &[u8]) -> Result<PendingQueueGenerationTerminalDigest, PendingQueueGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    PendingQueueGenerationTerminalDigest::try_new(hasher.finalize().into())
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueGenerationTerminalQueries,
) -> PendingQueueGenerationTerminalStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    PendingQueueGenerationTerminalStoreFingerprint(hasher.finalize().into())
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn authority_parts(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm { realm_id, realm_sub_id } => (2, realm_id, realm_sub_id),
    }
}

fn decode_authority(kind: u8, realm: u32, sub: u16) -> Result<AuthorityScope, PendingQueueGenerationTerminalError> {
    match (kind, realm, sub) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm { realm_id, realm_sub_id }),
        _ => Err(PendingQueueGenerationTerminalError::InvalidAuthority),
    }
}

async fn prepare_read(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueGenerationTerminalError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueGenerationTerminalError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueGenerationTerminalError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(PendingQueueGenerationTerminalError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueGenerationTerminalError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueGenerationTerminalError {
    PendingQueueGenerationTerminalError::Cql(error.to_string())
}

struct Decoder<'a> { bytes: &'a [u8], cursor: usize }

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueGenerationTerminalError> {
        let end = self.cursor.checked_add(len).ok_or(PendingQueueGenerationTerminalError::Truncated)?;
        let value = self.bytes.get(self.cursor..end).ok_or(PendingQueueGenerationTerminalError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, PendingQueueGenerationTerminalError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueGenerationTerminalError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, PendingQueueGenerationTerminalError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueGenerationTerminalError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array16(&mut self) -> Result<[u8; 16], PendingQueueGenerationTerminalError> { self.take(16)?.try_into().map_err(|_| PendingQueueGenerationTerminalError::Truncated) }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueGenerationTerminalError> { self.take(32)?.try_into().map_err(|_| PendingQueueGenerationTerminalError::Truncated) }
    fn bytes(&mut self) -> Result<Vec<u8>, PendingQueueGenerationTerminalError> {
        let len = usize::try_from(self.u32()?).map_err(|_| PendingQueueGenerationTerminalError::ComponentTooLarge)?;
        if len == 0 || len > MAX_COMPONENT_BYTES { return Err(PendingQueueGenerationTerminalError::ComponentTooLarge); }
        Ok(self.take(len)?.to_vec())
    }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingQueueGenerationTerminalError {
    Cql(String),
    Pipeline(String),
    Writer(String),
    Head(String),
    TerminalPair(String),
    EmptyDigest,
    InvalidMagic,
    UnknownCodecVersion,
    SelectedIdentityMismatch,
    InvalidAuthority,
    InvalidTerminalKind,
    InvalidRevision,
    PipelineNotTerminal,
    WriterMissing,
    WriterNotActive,
    HeadMissing,
    HeadMismatch,
    ComponentTooLarge,
    DigestMismatch,
    TrailingBytes,
    Truncated,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    Conflict,
    EvidenceChanged,
    ReceiptBindingMismatch,
    ReceiptStale,
    Indeterminate(String),
    Archive(PendingQueueSemanticAggregateError),
}

impl From<PendingQueueSemanticAggregateError> for PendingQueueGenerationTerminalError {
    fn from(value: PendingQueueSemanticAggregateError) -> Self { Self::Archive(value) }
}

impl fmt::Display for PendingQueueGenerationTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}

impl Error for PendingQueueGenerationTerminalError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> StoredPendingQueueGenerationTerminal {
        let mut value = StoredPendingQueueGenerationTerminal {
            archive_slot: PendingQueueSemanticGenerationSlot::try_new([1; 32]).unwrap(),
            revision: REVISION,
            network: NetworkId::try_from_chain_id(1337).unwrap(),
            authority: AuthorityScope::Realm { realm_id: 3, realm_sub_id: 0 },
            activation_digest: PendingGenerationActivationDigest::try_new([2; 32]).unwrap(),
            pending_id: 7,
            proc_checkpoint_id: [3; 16],
            assignment_digest: PendingQueueSegmentAssignmentDigest::try_new([4; 32]).unwrap(),
            archive_digest: PendingQueueSemanticGenerationDigest::try_new([5; 32]).unwrap(),
            archive_store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint::try_new([6; 32]).unwrap(),
            terminal_kind: PendingQueueGenerationTerminalKind::Published,
            pipeline_revision: 11,
            pipeline_payload: vec![7; 64],
            writer_slot: BranchExactWriterSlot::for_authority(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Realm { realm_id: 3, realm_sub_id: 0 },
            ),
            writer_revision: BranchExactWriterRevision::try_new(12).unwrap(),
            writer_payload: vec![9; 96],
            head_revision: 13,
            head_payload: vec![10; 128],
            digest: PendingQueueGenerationTerminalDigest([1; 32]),
        };
        value.digest = terminal_digest(&value.encode_unsigned()).unwrap();
        value
    }

    #[test]
    fn terminal_codec_is_deterministic_and_fail_closed() {
        let value = fixture();
        let bytes = value.to_persisted_bytes();
        assert_eq!(
            StoredPendingQueueGenerationTerminal::decode_persisted(
                value.archive_slot, REVISION as i64, &bytes,
            ).unwrap(),
            value,
        );
        let mut tampered = bytes.clone();
        tampered[200] ^= 1;
        assert!(StoredPendingQueueGenerationTerminal::decode_persisted(
            value.archive_slot, REVISION as i64, &tampered,
        ).is_err());
        let mut unknown_version = value.to_persisted_bytes();
        unknown_version[8..10].copy_from_slice(&(CODEC_VERSION + 1).to_be_bytes());
        assert_eq!(
            StoredPendingQueueGenerationTerminal::decode_persisted(
                value.archive_slot,
                REVISION as i64,
                &unknown_version,
            ),
            Err(PendingQueueGenerationTerminalError::UnknownCodecVersion),
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            StoredPendingQueueGenerationTerminal::decode_persisted(
                value.archive_slot, REVISION as i64, &trailing,
            ),
            Err(PendingQueueGenerationTerminalError::TrailingBytes),
        );
    }

    #[test]
    fn terminal_query_is_immutable_default_off_and_rotation_is_confined() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22_terminal_no_tablet".to_owned(),
        ).unwrap();
        let golden = PendingQueueGenerationTerminalQueries::new(&keyspace).golden();
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(!golden.contains("UPDATE "));
        assert!(!golden.contains("DELETE "));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_GENERATION_TERMINAL_TABLE));
        assert!(!setup.contains("ScyllaPendingQueueGenerationTerminalStore"));

        let root = env!("CARGO_MANIFEST_DIR");
        let output = std::process::Command::new("rg")
            .args(["-n", r"\.seal_rotation\(", "src/rollback"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success());
        let matches = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            matches.lines().count(),
            1,
            "pipeline rotation must have one rollback-store authority:\n{matches}",
        );
        assert!(matches.contains("pending_queue_generation_terminal.rs"));
    }
}
