//! Default-off durable segment lifecycle substrate.
//!
//! The default-off lifecycle binds one exact ledger closure and all immutable
//! generation terminals through physical stream seal, message-set scan,
//! quiescent consumer inventory, and a durable delete request. It deliberately
//! exposes no stream deletion, setup activation, or ledger-rotation authority.

#![allow(dead_code)]

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment, PendingQueueSegmentAssignmentDigest,
        PendingQueueSegmentLedgerRevision, PendingQueueSegmentLedgerSlot,
    },
    recoverable_segment::{
        LiveRecoverableNatsStreamInstance, RecoverableNatsSegmentContractDigest,
        RecoverableNatsSegmentId, RecoverableNatsStreamInstanceId,
        RecoverableNatsStreamSegment,
        RecoverableNatsStreamStateSnapshot,
        SealedRecoverableNatsStreamInstance,
    },
    recoverable_publish::RecoverableNatsSourceRoute,
    recoverable_terminal::{
        PendingQueueNatsWholeStreamExpectedManifest,
        PendingQueueNatsWholeStreamManifestDigest,
        PendingQueueNatsWholeStreamScanDigest,
        PendingQueueNatsWholeStreamScanReceipt,
        PendingQueueTerminalError,
    },
    recoverable_transport::{
        RecoverableNatsConsumerInventoryDigest, RecoverableNatsDeleteExpectation,
        RecoverableNatsConsumerInventoryReceipt,
        RecoverableNatsConsumerManifestDigest,
        RecoverableNatsExpectedConsumer,
        RecoverableNatsExpectedConsumerManifest,
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
    pending_queue_generation_terminal::{
        PendingQueueGenerationTerminalError,
        PendingQueueGenerationTerminalSegmentCommitment,
        ScyllaPendingQueueGenerationTerminalStore,
    },
    pending_queue_semantic_aggregate::ScyllaPendingQueueSemanticAggregateStore,
    BranchExactDeploymentNoTabletKeyspace, ScyllaAuthorityLocalHeadStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    ScyllaPendingQueueSegmentLedgerStore,
};
use super::pending_queue_segment_ledger::{
    PendingQueueSegmentClosureDigest, PendingQueueSegmentClosureSnapshot,
    PendingQueueSegmentLedgerStoreFingerprint,
};

pub(super) const PENDING_QUEUE_SEGMENT_LIFECYCLE_TABLE: &str =
    "branch_exact_pending_queue_segment_lifecycle_v1";
const MAGIC: &[u8; 8] = b"PSYQSLIF";
const CODEC_VERSION: u16 = 1;
const SEAL_REQUESTED_REVISION: u64 = 1;
const STREAM_SEALED_REVISION: u64 = 2;
const MESSAGES_SCAN_VERIFIED_REVISION: u64 = 3;
const SCAN_VERIFIED_REVISION: u64 = 4;
const DELETE_REQUESTED_REVISION: u64 = 5;
const DELETED_REVISION: u64 = 6;
const SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-segment-lifecycle-slot/v1";
const DIGEST_DOMAIN: &[u8] = b"psy/rollback/pending-queue-segment-lifecycle/v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-segment-lifecycle-store/v1";
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_ASSIGNMENTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PendingQueueSegmentLifecyclePhase {
    SealRequested = 1,
    StreamSealed = 2,
    MessagesScanVerified = 3,
    ScanVerified = 4,
    DeleteRequested = 5,
    Deleted = 6,
}

impl PendingQueueSegmentLifecyclePhase {
    fn try_from_byte(value: u8) -> Result<Self, PendingQueueSegmentLifecycleError> {
        match value {
            1 => Ok(Self::SealRequested),
            2 => Ok(Self::StreamSealed),
            3 => Ok(Self::MessagesScanVerified),
            4 => Ok(Self::ScanVerified),
            5 => Ok(Self::DeleteRequested),
            6 => Ok(Self::Deleted),
            _ => Err(PendingQueueSegmentLifecycleError::UnknownPhase),
        }
    }

    const fn revision(self) -> u64 {
        match self {
            Self::SealRequested => SEAL_REQUESTED_REVISION,
            Self::StreamSealed => STREAM_SEALED_REVISION,
            Self::MessagesScanVerified => MESSAGES_SCAN_VERIFIED_REVISION,
            Self::ScanVerified => SCAN_VERIFIED_REVISION,
            Self::DeleteRequested => DELETE_REQUESTED_REVISION,
            Self::Deleted => DELETED_REVISION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueSegmentLifecycleSlot([u8; 32]);

impl PendingQueueSegmentLifecycleSlot {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLifecycleError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueSegmentLifecycleDigest([u8; 32]);

impl PendingQueueSegmentLifecycleDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLifecycleError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingQueueSegmentTerminalEntry {
    assignment_payload: Vec<u8>,
    terminal_store_fingerprint: [u8; 32],
    archive_slot: [u8; 32],
    archive_digest: [u8; 32],
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    terminal_digest: [u8; 32],
}

impl PendingQueueSegmentTerminalEntry {
    fn from_verified(
        assignment: &PendingQueueGenerationSegmentAssignment,
        commitment: PendingQueueGenerationTerminalSegmentCommitment,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if commitment.assignment_digest() != assignment.digest() {
            return Err(PendingQueueSegmentLifecycleError::TerminalSetMismatch);
        }
        Ok(Self {
            assignment_payload: assignment.to_canonical_bytes(),
            terminal_store_fingerprint: *commitment.terminal_store_fingerprint(),
            archive_slot: *commitment.archive_slot(),
            archive_digest: *commitment.archive_digest(),
            assignment_digest: commitment.assignment_digest(),
            terminal_digest: *commitment.terminal_digest(),
        })
    }

    fn matches_commitment(
        &self,
        commitment: PendingQueueGenerationTerminalSegmentCommitment,
    ) -> bool {
        self.terminal_store_fingerprint == *commitment.terminal_store_fingerprint()
            && self.archive_slot == *commitment.archive_slot()
            && self.archive_digest == *commitment.archive_digest()
            && self.assignment_digest == commitment.assignment_digest()
            && self.terminal_digest == *commitment.terminal_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPendingQueueSegmentSealRequest {
    slot: PendingQueueSegmentLifecycleSlot,
    revision: u64,
    phase: PendingQueueSegmentLifecyclePhase,
    ledger_store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    ledger_slot: PendingQueueSegmentLedgerSlot,
    ledger_revision: PendingQueueSegmentLedgerRevision,
    ledger_payload_digest: PendingQueueSegmentClosureDigest,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    stream_instance_id: [u8; 32],
    live_state: RecoverableNatsStreamStateSnapshot,
    manifest_digest: PendingQueueNatsWholeStreamManifestDigest,
    scan_digest: Option<PendingQueueNatsWholeStreamScanDigest>,
    consumer_manifest_digest: Option<RecoverableNatsConsumerManifestDigest>,
    consumer_inventory_digest: Option<RecoverableNatsConsumerInventoryDigest>,
    terminals: Vec<PendingQueueSegmentTerminalEntry>,
    digest: PendingQueueSegmentLifecycleDigest,
}

impl StoredPendingQueueSegmentSealRequest {
    fn try_from_verified(
        closure: &PendingQueueSegmentClosureSnapshot,
        live: &LiveRecoverableNatsStreamInstance,
        commitments: Vec<PendingQueueGenerationTerminalSegmentCommitment>,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if live.segment().segment_id() != closure.segment_id()
            || live.segment().digest() != closure.contract_digest()
            || live.segment().generation_key()
                != closure
                    .assignments()
                    .first()
                    .map(|receipt| receipt.assignment().context().key())
                    .unwrap_or_else(|| live.segment().generation_key())
            || commitments.len() != closure.assignments().len()
            || commitments.len() > MAX_ASSIGNMENTS
        {
            return Err(PendingQueueSegmentLifecycleError::ClosureMismatch);
        }
        let assignments = closure
            .assignments()
            .iter()
            .map(|receipt| receipt.assignment().clone())
            .collect::<Vec<_>>();
        validate_assignment_set(
            closure.segment_id(),
            closure.contract_digest(),
            live.state(),
            &assignments,
        )?;
        let terminals = assignments
            .iter()
            .zip(commitments)
            .map(|(assignment, commitment)| {
                PendingQueueSegmentTerminalEntry::from_verified(assignment, commitment)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest_digest =
            PendingQueueNatsWholeStreamManifestDigest::for_instance_assignments(
                live.instance_id(),
                &assignments,
            )
            .map_err(terminal)?;
        let slot = lifecycle_slot(closure.ledger_slot(), closure.segment_id())?;
        let mut state = Self {
            slot,
            revision: SEAL_REQUESTED_REVISION,
            phase: PendingQueueSegmentLifecyclePhase::SealRequested,
            ledger_store_fingerprint: closure.store_fingerprint(),
            ledger_slot: closure.ledger_slot(),
            ledger_revision: closure.ledger_revision(),
            ledger_payload_digest: closure.ledger_payload_digest(),
            segment_id: closure.segment_id(),
            contract_digest: closure.contract_digest(),
            stream_instance_id: *live.instance_id().as_bytes(),
            live_state: live.state(),
            manifest_digest,
            scan_digest: None,
            consumer_manifest_digest: None,
            consumer_inventory_digest: None,
            terminals,
            digest: PendingQueueSegmentLifecycleDigest([1; 32]),
        };
        state.digest = lifecycle_digest(&state.encode_unsigned())?;
        if state.to_persisted_bytes().len() > MAX_PAYLOAD_BYTES {
            return Err(PendingQueueSegmentLifecycleError::PayloadTooLarge);
        }
        Ok(state)
    }

    fn matches_live_instance(&self, live: &LiveRecoverableNatsStreamInstance) -> bool {
        self.segment_id == live.segment().segment_id()
            && self.contract_digest == live.segment().digest()
            && self.stream_instance_id == *live.instance_id().as_bytes()
            && self.live_state == live.state()
    }

    fn matches_sealed_instance(
        &self,
        sealed: &SealedRecoverableNatsStreamInstance,
    ) -> bool {
        self.segment_id == sealed.segment().segment_id()
            && self.contract_digest == sealed.segment().digest()
            && self.stream_instance_id == *sealed.instance_id().as_bytes()
            && self.live_state == sealed.state()
    }

    fn assignments(
        &self,
    ) -> Result<Vec<PendingQueueGenerationSegmentAssignment>, PendingQueueSegmentLifecycleError>
    {
        self.terminals
            .iter()
            .map(|terminal| {
                PendingQueueGenerationSegmentAssignment::decode_canonical(
                    self.ledger_slot,
                    &terminal.assignment_payload,
                )
                .map_err(|_| PendingQueueSegmentLifecycleError::AssignmentDecode)
            })
            .collect()
    }

    fn to_stream_sealed(
        &self,
        sealed: &SealedRecoverableNatsStreamInstance,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if self.phase != PendingQueueSegmentLifecyclePhase::SealRequested
            || self.revision != SEAL_REQUESTED_REVISION
            || !self.matches_sealed_instance(sealed)
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let mut candidate = self.clone();
        candidate.phase = PendingQueueSegmentLifecyclePhase::StreamSealed;
        candidate.revision = STREAM_SEALED_REVISION;
        candidate.scan_digest = None;
        candidate.consumer_manifest_digest = None;
        candidate.consumer_inventory_digest = None;
        candidate.digest = lifecycle_digest(&candidate.encode_unsigned())?;
        Ok(candidate)
    }

    fn to_messages_scan_verified(
        &self,
        receipt: &PendingQueueNatsWholeStreamScanReceipt,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if self.phase != PendingQueueSegmentLifecyclePhase::StreamSealed
            || self.revision != STREAM_SEALED_REVISION
            || self.scan_digest.is_some()
            || self.stream_instance_id != *receipt.instance_id().as_bytes()
            || self.segment_id != receipt.segment_id()
            || self.contract_digest != receipt.contract_digest()
            || self.live_state != receipt.state()
            || self.manifest_digest != receipt.manifest_digest()
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let mut candidate = self.clone();
        candidate.phase = PendingQueueSegmentLifecyclePhase::MessagesScanVerified;
        candidate.revision = MESSAGES_SCAN_VERIFIED_REVISION;
        candidate.scan_digest = Some(receipt.scan_digest());
        candidate.consumer_manifest_digest = None;
        candidate.consumer_inventory_digest = None;
        candidate.digest = lifecycle_digest(&candidate.encode_unsigned())?;
        Ok(candidate)
    }

    fn to_scan_verified(
        &self,
        receipt: &RecoverableNatsConsumerInventoryReceipt,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if self.phase != PendingQueueSegmentLifecyclePhase::MessagesScanVerified
            || self.revision != MESSAGES_SCAN_VERIFIED_REVISION
            || self.scan_digest.is_none()
            || self.consumer_manifest_digest.is_some()
            || self.consumer_inventory_digest.is_some()
            || self.stream_instance_id != *receipt.instance_id()
            || self.live_state.consumer_count() != receipt.consumer_count()
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let mut candidate = self.clone();
        candidate.phase = PendingQueueSegmentLifecyclePhase::ScanVerified;
        candidate.revision = SCAN_VERIFIED_REVISION;
        candidate.consumer_manifest_digest = Some(receipt.manifest_digest());
        candidate.consumer_inventory_digest = Some(receipt.inventory_digest());
        candidate.digest = lifecycle_digest(&candidate.encode_unsigned())?;
        Ok(candidate)
    }

    fn to_delete_requested(
        &self,
        scan: &PendingQueueNatsWholeStreamScanReceipt,
        inventory: &RecoverableNatsConsumerInventoryReceipt,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if !self.matches_reverified_scan(scan)
            || !self.matches_consumer_inventory(inventory)
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.delete_requested_candidate()
    }

    fn delete_requested_candidate(&self) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if self.phase != PendingQueueSegmentLifecyclePhase::ScanVerified
            || self.revision != SCAN_VERIFIED_REVISION
            || self.scan_digest.is_none()
            || self.consumer_manifest_digest.is_none()
            || self.consumer_inventory_digest.is_none()
        {
            return Err(PendingQueueSegmentLifecycleError::InvalidTransition);
        }
        let mut candidate = self.clone();
        candidate.phase = PendingQueueSegmentLifecyclePhase::DeleteRequested;
        candidate.revision = DELETE_REQUESTED_REVISION;
        candidate.digest = lifecycle_digest(&candidate.encode_unsigned())?;
        Ok(candidate)
    }

    fn deleted_candidate(&self) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if self.phase != PendingQueueSegmentLifecyclePhase::DeleteRequested
            || self.revision != DELETE_REQUESTED_REVISION
            || self.scan_digest.is_none()
            || self.consumer_manifest_digest.is_none()
            || self.consumer_inventory_digest.is_none()
        {
            return Err(PendingQueueSegmentLifecycleError::InvalidTransition);
        }
        let mut candidate = self.clone();
        candidate.phase = PendingQueueSegmentLifecyclePhase::Deleted;
        candidate.revision = DELETED_REVISION;
        candidate.digest = lifecycle_digest(&candidate.encode_unsigned())?;
        Ok(candidate)
    }

    fn matches_scan_receipt(&self, receipt: &PendingQueueNatsWholeStreamScanReceipt) -> bool {
        self.phase == PendingQueueSegmentLifecyclePhase::MessagesScanVerified
            && self.revision == MESSAGES_SCAN_VERIFIED_REVISION
            && self.stream_instance_id == *receipt.instance_id().as_bytes()
            && self.segment_id == receipt.segment_id()
            && self.contract_digest == receipt.contract_digest()
            && self.live_state == receipt.state()
            && self.manifest_digest == receipt.manifest_digest()
            && self.scan_digest == Some(receipt.scan_digest())
    }

    fn matches_consumer_inventory(
        &self,
        receipt: &RecoverableNatsConsumerInventoryReceipt,
    ) -> bool {
        self.phase == PendingQueueSegmentLifecyclePhase::ScanVerified
            && self.revision == SCAN_VERIFIED_REVISION
            && self.matches_committed_consumer_inventory(receipt)
    }

    fn matches_delete_requested_consumer_inventory(
        &self,
        receipt: &RecoverableNatsConsumerInventoryReceipt,
    ) -> bool {
        self.phase == PendingQueueSegmentLifecyclePhase::DeleteRequested
            && self.revision == DELETE_REQUESTED_REVISION
            && self.matches_committed_consumer_inventory(receipt)
    }

    fn matches_committed_consumer_inventory(
        &self,
        receipt: &RecoverableNatsConsumerInventoryReceipt,
    ) -> bool {
        self.stream_instance_id == *receipt.instance_id()
            && self.live_state.consumer_count() == receipt.consumer_count()
            && self.consumer_manifest_digest == Some(receipt.manifest_digest())
            && self.consumer_inventory_digest == Some(receipt.inventory_digest())
    }

    fn matches_reverified_scan(&self, receipt: &PendingQueueNatsWholeStreamScanReceipt) -> bool {
        self.phase == PendingQueueSegmentLifecyclePhase::ScanVerified
            && self.revision == SCAN_VERIFIED_REVISION
            && self.stream_instance_id == *receipt.instance_id().as_bytes()
            && self.segment_id == receipt.segment_id()
            && self.contract_digest == receipt.contract_digest()
            && self.live_state == receipt.state()
            && self.manifest_digest == receipt.manifest_digest()
            && self.scan_digest == Some(receipt.scan_digest())
    }

    fn matches_delete_request_evidence(
        &self,
        scan: &PendingQueueNatsWholeStreamScanReceipt,
        inventory: &RecoverableNatsConsumerInventoryReceipt,
    ) -> bool {
        self.phase == PendingQueueSegmentLifecyclePhase::DeleteRequested
            && self.revision == DELETE_REQUESTED_REVISION
            && self.stream_instance_id == *scan.instance_id().as_bytes()
            && self.stream_instance_id == *inventory.instance_id()
            && self.segment_id == scan.segment_id()
            && self.contract_digest == scan.contract_digest()
            && self.live_state == scan.state()
            && self.live_state.consumer_count() == inventory.consumer_count()
            && self.manifest_digest == scan.manifest_digest()
            && self.scan_digest == Some(scan.scan_digest())
            && self.consumer_manifest_digest == Some(inventory.manifest_digest())
            && self.consumer_inventory_digest == Some(inventory.inventory_digest())
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512 + self.terminals.len() * 512);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.push(self.phase as u8);
        out.extend_from_slice(self.ledger_store_fingerprint.as_bytes());
        out.extend_from_slice(self.ledger_slot.as_bytes());
        out.extend_from_slice(&self.ledger_revision.get().to_be_bytes());
        out.extend_from_slice(self.ledger_payload_digest.as_bytes());
        out.extend_from_slice(&self.segment_id.get().to_be_bytes());
        out.extend_from_slice(self.contract_digest.as_bytes());
        out.extend_from_slice(&self.stream_instance_id);
        encode_stream_state(self.live_state, &mut out);
        out.extend_from_slice(self.manifest_digest.as_bytes());
        out.extend_from_slice(&(self.terminals.len() as u32).to_be_bytes());
        for terminal in &self.terminals {
            out.extend_from_slice(&(terminal.assignment_payload.len() as u32).to_be_bytes());
            out.extend_from_slice(&terminal.assignment_payload);
            out.extend_from_slice(&terminal.terminal_store_fingerprint);
            out.extend_from_slice(&terminal.archive_slot);
            out.extend_from_slice(&terminal.archive_digest);
            out.extend_from_slice(terminal.assignment_digest.as_bytes());
            out.extend_from_slice(&terminal.terminal_digest);
        }
        if let Some(scan_digest) = self.scan_digest {
            out.extend_from_slice(scan_digest.as_bytes());
        }
        if let (Some(manifest), Some(inventory)) = (
            self.consumer_manifest_digest,
            self.consumer_inventory_digest,
        ) {
            out.extend_from_slice(manifest.as_bytes());
            out.extend_from_slice(inventory.as_bytes());
        }
        out
    }

    fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    fn decode_persisted(
        selected_slot: PendingQueueSegmentLifecycleSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(PendingQueueSegmentLifecycleError::PayloadTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(PendingQueueSegmentLifecycleError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueSegmentLifecycleError::UnknownCodecVersion);
        }
        let slot = PendingQueueSegmentLifecycleSlot::try_new(decoder.array32()?)?;
        let revision = decoder.u64()?;
        let phase = PendingQueueSegmentLifecyclePhase::try_from_byte(decoder.u8()?)?;
        if slot != selected_slot
            || i64::try_from(revision).ok() != Some(selected_revision)
            || phase.revision() != revision
        {
            return Err(PendingQueueSegmentLifecycleError::SelectedIdentityMismatch);
        }
        let ledger_store_fingerprint = PendingQueueSegmentLedgerStoreFingerprint::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueSegmentLifecycleError::EmptyDigest)?;
        let ledger_slot = PendingQueueSegmentLedgerSlot::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSegmentLifecycleError::EmptyDigest)?;
        let ledger_revision = PendingQueueSegmentLedgerRevision::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueSegmentLifecycleError::InvalidRevision)?;
        let ledger_payload_digest = PendingQueueSegmentClosureDigest::try_new(
            decoder.array32()?,
        )?;
        let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueSegmentLifecycleError::InvalidSegment)?;
        let contract_digest = RecoverableNatsSegmentContractDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSegmentLifecycleError::EmptyDigest)?;
        let stream_instance_id = decoder.array32()?;
        if stream_instance_id == [0; 32] {
            return Err(PendingQueueSegmentLifecycleError::EmptyDigest);
        }
        let live_state = decode_stream_state(&mut decoder)?;
        let manifest_digest = PendingQueueNatsWholeStreamManifestDigest::try_from_bytes(
            decoder.array32()?,
        )
        .map_err(terminal)?;
        let count = decoder.u32()? as usize;
        if count > MAX_ASSIGNMENTS {
            return Err(PendingQueueSegmentLifecycleError::TooManyAssignments);
        }
        let mut terminals = Vec::with_capacity(count);
        let mut assignments = Vec::with_capacity(count);
        for _ in 0..count {
            let assignment_payload = decoder.bytes()?;
            let assignment = PendingQueueGenerationSegmentAssignment::decode_canonical(
                ledger_slot,
                &assignment_payload,
            )
            .map_err(|_| PendingQueueSegmentLifecycleError::AssignmentDecode)?;
            let terminal_store_fingerprint = decoder.array32()?;
            let archive_slot = decoder.array32()?;
            let archive_digest = decoder.array32()?;
            let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(
                decoder.array32()?,
            )
            .map_err(|_| PendingQueueSegmentLifecycleError::EmptyDigest)?;
            let terminal_digest = decoder.array32()?;
            if [terminal_store_fingerprint, archive_slot, archive_digest, terminal_digest]
                .contains(&[0; 32])
                || assignment.digest() != assignment_digest
                || assignment.segment_id() != segment_id
                || assignment.contract_digest() != contract_digest
            {
                return Err(PendingQueueSegmentLifecycleError::TerminalSetMismatch);
            }
            assignments.push(assignment);
            terminals.push(PendingQueueSegmentTerminalEntry {
                assignment_payload,
                terminal_store_fingerprint,
                archive_slot,
                archive_digest,
                assignment_digest,
                terminal_digest,
            });
        }
        let scan_digest = match phase {
            PendingQueueSegmentLifecyclePhase::SealRequested
            | PendingQueueSegmentLifecyclePhase::StreamSealed => None,
            PendingQueueSegmentLifecyclePhase::MessagesScanVerified
            | PendingQueueSegmentLifecyclePhase::ScanVerified
            | PendingQueueSegmentLifecyclePhase::DeleteRequested
            | PendingQueueSegmentLifecyclePhase::Deleted => Some(
                PendingQueueNatsWholeStreamScanDigest::try_from_bytes(decoder.array32()?)
                    .map_err(terminal)?,
            ),
        };
        let (consumer_manifest_digest, consumer_inventory_digest) = match phase {
            PendingQueueSegmentLifecyclePhase::SealRequested
            | PendingQueueSegmentLifecyclePhase::StreamSealed
            | PendingQueueSegmentLifecyclePhase::MessagesScanVerified => (None, None),
            PendingQueueSegmentLifecyclePhase::ScanVerified
            | PendingQueueSegmentLifecyclePhase::DeleteRequested
            | PendingQueueSegmentLifecyclePhase::Deleted => (
                Some(
                    RecoverableNatsConsumerManifestDigest::try_from_bytes(decoder.array32()?)
                        .map_err(transport)?,
                ),
                Some(
                    RecoverableNatsConsumerInventoryDigest::try_from_bytes(decoder.array32()?)
                        .map_err(transport)?,
                ),
            ),
        };
        let digest = PendingQueueSegmentLifecycleDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueSegmentLifecycleError::TrailingBytes);
        }
        validate_assignment_set(segment_id, contract_digest, live_state, &assignments)?;
        if PendingQueueNatsWholeStreamManifestDigest::for_instance_assignments_raw(
            stream_instance_id,
            &assignments,
        )
        .map_err(terminal)?
            != manifest_digest
        {
            return Err(PendingQueueSegmentLifecycleError::ManifestMismatch);
        }
        let state = Self {
            slot,
            revision,
            phase,
            ledger_store_fingerprint,
            ledger_slot,
            ledger_revision,
            ledger_payload_digest,
            segment_id,
            contract_digest,
            stream_instance_id,
            live_state,
            manifest_digest,
            scan_digest,
            consumer_manifest_digest,
            consumer_inventory_digest,
            terminals,
            digest,
        };
        if lifecycle_slot(ledger_slot, segment_id)? != slot
            || lifecycle_digest(&state.encode_unsigned())? != digest
        {
            return Err(PendingQueueSegmentLifecycleError::DigestMismatch);
        }
        Ok(state)
    }
}

fn validate_assignment_set(
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    state: RecoverableNatsStreamStateSnapshot,
    assignments: &[PendingQueueGenerationSegmentAssignment],
) -> Result<(), PendingQueueSegmentLifecycleError> {
    let mut contexts = BTreeSet::new();
    let mut expected_sources = 0_u64;
    let mut previous_revision = None;
    for assignment in assignments {
        let revision = assignment.assigned_at_ledger_revision().get();
        if assignment.segment_id() != segment_id
            || assignment.contract_digest() != contract_digest
            || assignment.expected_source_count() == 0
            || usize::from(assignment.expected_source_count()) != assignment.source_quotas().len()
            || previous_revision.is_some_and(|previous| previous >= revision)
            || !contexts.insert(*assignment.context().digest().as_bytes())
        {
            return Err(PendingQueueSegmentLifecycleError::ClosureMismatch);
        }
        previous_revision = Some(revision);
        expected_sources = expected_sources
            .checked_add(u64::from(assignment.expected_source_count()))
            .ok_or(PendingQueueSegmentLifecycleError::CounterOverflow)?;
    }
    if state.subject_count() != expected_sources || state.messages() < expected_sources {
        return Err(PendingQueueSegmentLifecycleError::StreamStateMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PendingQueueSegmentLifecycleQueries {
    create: String,
    read: String,
    bootstrap: String,
    compare_and_set: String,
}

impl PendingQueueSegmentLifecycleQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), PENDING_QUEUE_SEGMENT_LIFECYCLE_TABLE);
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (lifecycle_slot blob PRIMARY KEY, revision bigint, lifecycle_payload blob)"
            ),
            read: format!(
                "SELECT revision, lifecycle_payload FROM {table} WHERE lifecycle_slot = ?"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (lifecycle_slot, revision, lifecycle_payload) VALUES (?, ?, ?) IF NOT EXISTS"
            ),
            compare_and_set: format!(
                "UPDATE {table} SET revision = ?, lifecycle_payload = ? WHERE lifecycle_slot = ? IF revision = ? AND lifecycle_payload = ?"
            ),
        }
    }

    fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n\ncompare_and_set\n{}\nBIGINT,BLOB,BLOB,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.compare_and_set,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingQueueSegmentLifecycleStoreFingerprint([u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingQueueSegmentLifecycleCasBinding {
    candidate_revision: i64,
    candidate_payload: Vec<u8>,
    lifecycle_slot: [u8; 32],
    expected_revision: i64,
    expected_payload: Vec<u8>,
}

impl PendingQueueSegmentLifecycleCasBinding {
    fn try_new(
        expected: &StoredPendingQueueSegmentSealRequest,
        candidate: &StoredPendingQueueSegmentSealRequest,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        let valid_phase = matches!(
            (expected.phase, candidate.phase),
            (
                PendingQueueSegmentLifecyclePhase::SealRequested,
                PendingQueueSegmentLifecyclePhase::StreamSealed,
            ) | (
                PendingQueueSegmentLifecyclePhase::StreamSealed,
                PendingQueueSegmentLifecyclePhase::MessagesScanVerified,
            ) | (
                PendingQueueSegmentLifecyclePhase::MessagesScanVerified,
                PendingQueueSegmentLifecyclePhase::ScanVerified,
            ) | (
                PendingQueueSegmentLifecyclePhase::ScanVerified,
                PendingQueueSegmentLifecyclePhase::DeleteRequested,
            ) | (
                PendingQueueSegmentLifecyclePhase::DeleteRequested,
                PendingQueueSegmentLifecyclePhase::Deleted,
            )
        );
        if expected.slot != candidate.slot
            || !valid_phase
            || expected.phase.revision() != expected.revision
            || candidate.phase.revision() != candidate.revision
            || candidate.revision != expected.revision + 1
        {
            return Err(PendingQueueSegmentLifecycleError::InvalidTransition);
        }
        Ok(Self {
            candidate_revision: i64::try_from(candidate.revision)
                .map_err(|_| PendingQueueSegmentLifecycleError::InvalidRevision)?,
            candidate_payload: candidate.to_persisted_bytes(),
            lifecycle_slot: *candidate.slot.as_bytes(),
            expected_revision: i64::try_from(expected.revision)
                .map_err(|_| PendingQueueSegmentLifecycleError::InvalidRevision)?,
            expected_payload: expected.to_persisted_bytes(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingQueueSegmentLifecycleCasDisposition {
    Applied,
    Idempotent,
}

fn classify_lifecycle_cas(
    applied: bool,
    candidate: &StoredPendingQueueSegmentSealRequest,
    current: &StoredPendingQueueSegmentSealRequest,
) -> Result<PendingQueueSegmentLifecycleCasDisposition, PendingQueueSegmentLifecycleError> {
    if current == candidate {
        Ok(if applied {
            PendingQueueSegmentLifecycleCasDisposition::Applied
        } else {
            PendingQueueSegmentLifecycleCasDisposition::Idempotent
        })
    } else if applied {
        Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch)
    } else {
        Err(PendingQueueSegmentLifecycleError::Conflict)
    }
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueSealRequestedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueStreamSealedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueMessagesScanVerifiedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueScanVerifiedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

/// Opaque durable authority proving that every non-destructive closure check
/// was freshly repeated immediately before the revision-5 PONR was persisted.
/// It is intentionally non-`Clone` and cannot be constructed outside this
/// module.
#[derive(Debug)]
pub(super) struct PersistedPendingQueueDeleteRequestedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueDeletedReceipt {
    store_fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    current: StoredPendingQueueSegmentSealRequest,
}

impl PersistedPendingQueueScanVerifiedReceipt {
    pub(super) const fn scan_digest(&self) -> Option<PendingQueueNatsWholeStreamScanDigest> {
        self.current.scan_digest
    }

    pub(super) const fn consumer_inventory_digest(
        &self,
    ) -> Option<RecoverableNatsConsumerInventoryDigest> {
        self.current.consumer_inventory_digest
    }
}

impl PersistedPendingQueueMessagesScanVerifiedReceipt {
    pub(super) const fn manifest_digest(&self) -> PendingQueueNatsWholeStreamManifestDigest {
        self.current.manifest_digest
    }

    pub(super) const fn scan_digest(&self) -> Option<PendingQueueNatsWholeStreamScanDigest> {
        self.current.scan_digest
    }
}

impl PersistedPendingQueueStreamSealedReceipt {
    pub(super) fn matches_sealed_instance(
        &self,
        sealed: &SealedRecoverableNatsStreamInstance,
    ) -> bool {
        self.current.phase == PendingQueueSegmentLifecyclePhase::StreamSealed
            && self.current.matches_sealed_instance(sealed)
    }

    pub(super) const fn manifest_digest(&self) -> PendingQueueNatsWholeStreamManifestDigest {
        self.current.manifest_digest
    }

    fn assignments(
        &self,
    ) -> Result<Vec<PendingQueueGenerationSegmentAssignment>, PendingQueueSegmentLifecycleError>
    {
        self.current.assignments()
    }
}

impl PersistedPendingQueueSealRequestedReceipt {
    pub(super) fn matches_live_instance(&self, live: &LiveRecoverableNatsStreamInstance) -> bool {
        self.current.matches_live_instance(live)
    }

    pub(super) const fn manifest_digest(&self) -> PendingQueueNatsWholeStreamManifestDigest {
        self.current.manifest_digest
    }
}

pub(super) struct ScyllaPendingQueueSegmentLifecycleStore {
    session: Arc<Session>,
    fingerprint: PendingQueueSegmentLifecycleStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaPendingQueueSegmentLifecycleStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueSegmentLifecycleError> {
        let queries = PendingQueueSegmentLifecycleQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueSegmentLifecycleError> {
        let queries = PendingQueueSegmentLifecycleQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(&session, &queries.read).await?,
            bootstrap: prepare_lwt(&session, &queries.bootstrap).await?,
            compare_and_set: prepare_lwt(&session, &queries.compare_and_set).await?,
            session,
        })
    }

    async fn read(
        &self,
        slot: PendingQueueSegmentLifecycleSlot,
    ) -> Result<Option<StoredPendingQueueSegmentSealRequest>, PendingQueueSegmentLifecycleError> {
        let row = self
            .session
            .execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>()
            .map_err(cql)?;
        let Some((revision, payload)) = row else {
            return Ok(None);
        };
        Ok(Some(StoredPendingQueueSegmentSealRequest::decode_persisted(
            slot,
            revision.ok_or(PendingQueueSegmentLifecycleError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(PendingQueueSegmentLifecycleError::MissingColumn)?,
        )?))
    }

    #[allow(clippy::too_many_arguments)]
    async fn revalidate_seal_evidence<Hash: Q256BitHash>(
        &self,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        expected: &StoredPendingQueueSegmentSealRequest,
    ) -> Result<(), PendingQueueSegmentLifecycleError> {
        if expected.ledger_store_fingerprint != closure.store_fingerprint()
            || expected.ledger_slot != closure.ledger_slot()
            || expected.ledger_revision != closure.ledger_revision()
            || expected.ledger_payload_digest != closure.ledger_payload_digest()
            || expected.segment_id != closure.segment_id()
            || expected.contract_digest != closure.contract_digest()
            || expected.terminals.len() != closure.assignments().len()
            || expected
                .terminals
                .iter()
                .zip(closure.assignments())
                .any(|(terminal, assignment)| {
                    terminal.assignment_payload != assignment.assignment().to_canonical_bytes()
                })
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        ledger_store.revalidate_segment_closure(closure).await?;
        let current = observe_terminals::<Hash>(
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
        )
        .await?;
        if expected.terminals.len() != current.len()
            || expected
                .terminals
                .iter()
                .zip(current)
                .any(|(entry, commitment)| !entry.matches_commitment(commitment))
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        Ok(())
    }

    async fn build_expected_consumer_manifest(
        &self,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        current: &StoredPendingQueueSegmentSealRequest,
        segment: &RecoverableNatsStreamSegment,
        sealed: SealedRecoverableNatsStreamInstance,
    ) -> Result<RecoverableNatsExpectedConsumerManifest, PendingQueueSegmentLifecycleError> {
        if !current.matches_sealed_instance(&sealed)
            || current.terminals.len() > MAX_ASSIGNMENTS
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let mut expected = Vec::new();
        for terminal in &current.terminals {
            let assignment = PendingQueueGenerationSegmentAssignment::decode_canonical(
                current.ledger_slot,
                &terminal.assignment_payload,
            )
            .map_err(|_| PendingQueueSegmentLifecycleError::AssignmentDecode)?;
            let consumers = archive_store
                .observe_archived_consumers(
                    current.ledger_slot,
                    &assignment,
                    terminal.archive_slot,
                    terminal.archive_digest,
                )
                .await
                .map_err(|error| PendingQueueSegmentLifecycleError::Archive(error.to_string()))?;
            if consumers.len() != usize::from(assignment.expected_source_count())
                || consumers
                    .iter()
                    .map(|consumer| consumer.publisher_kind())
                    .ne(assignment.source_quotas().iter().map(|quota| quota.publisher_kind()))
            {
                return Err(PendingQueueSegmentLifecycleError::TerminalSetMismatch);
            }
            for consumer in consumers {
                let route = RecoverableNatsSourceRoute::try_new(
                    assignment.context(),
                    consumer.publisher_kind(),
                    segment,
                )
                .map_err(transport)?;
                expected.push(
                    RecoverableNatsExpectedConsumer::try_new(
                        route.subject(),
                        consumer.consumer_digest(),
                    )
                    .map_err(transport)?,
                );
            }
        }
        RecoverableNatsExpectedConsumerManifest::try_new(sealed, expected)
            .map_err(transport)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn persist_seal_requested<Hash: Q256BitHash>(
        &self,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        live: &LiveRecoverableNatsStreamInstance,
    ) -> Result<PersistedPendingQueueSealRequestedReceipt, PendingQueueSegmentLifecycleError> {
        ledger_store.revalidate_segment_closure(closure).await?;
        let commitments = observe_terminals::<Hash>(
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
        )
        .await?;
        let candidate = StoredPendingQueueSegmentSealRequest::try_from_verified(
            closure,
            live,
            commitments,
        )?;
        let payload = candidate.to_persisted_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    candidate.slot.as_bytes().as_slice(),
                    SEAL_REQUESTED_REVISION as i64,
                    payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ))
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )))
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        if current != candidate {
            return Err(if applied {
                PendingQueueSegmentLifecycleError::AppliedStateMismatch
            } else {
                PendingQueueSegmentLifecycleError::Conflict
            });
        }
        ledger_store.revalidate_segment_closure(closure).await?;
        let after = observe_terminals::<Hash>(
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
        )
        .await?;
        if !current.matches_live_instance(live)
            || current.terminals.len() != after.len()
            || current
                .terminals
                .iter()
                .zip(after)
                .any(|(entry, commitment)| !entry.matches_commitment(commitment))
        {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        Ok(PersistedPendingQueueSealRequestedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    async fn advance_to_stream_sealed(
        &self,
        expected: &StoredPendingQueueSegmentSealRequest,
        sealed: &SealedRecoverableNatsStreamInstance,
    ) -> Result<PersistedPendingQueueStreamSealedReceipt, PendingQueueSegmentLifecycleError> {
        if expected.phase != PendingQueueSegmentLifecyclePhase::SealRequested
            || expected.revision != SEAL_REQUESTED_REVISION
        {
            return Err(PendingQueueSegmentLifecycleError::InvalidTransition);
        }
        let candidate = expected.to_stream_sealed(sealed)?;
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(expected, &candidate)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    binding.candidate_revision,
                    binding.candidate_payload.as_slice(),
                    binding.lifecycle_slot.as_slice(),
                    binding.expected_revision,
                    binding.expected_payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ))
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )))
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        classify_lifecycle_cas(applied, &candidate, &current)?;
        Ok(PersistedPendingQueueStreamSealedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    async fn advance_to_messages_scan_verified(
        &self,
        expected: &StoredPendingQueueSegmentSealRequest,
        scan: &PendingQueueNatsWholeStreamScanReceipt,
    ) -> Result<PersistedPendingQueueMessagesScanVerifiedReceipt, PendingQueueSegmentLifecycleError>
    {
        let candidate = expected.to_messages_scan_verified(scan)?;
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(expected, &candidate)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    binding.candidate_revision,
                    binding.candidate_payload.as_slice(),
                    binding.lifecycle_slot.as_slice(),
                    binding.expected_revision,
                    binding.expected_payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )));
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        classify_lifecycle_cas(applied, &candidate, &current)?;
        Ok(PersistedPendingQueueMessagesScanVerifiedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    async fn advance_to_scan_verified(
        &self,
        expected: &StoredPendingQueueSegmentSealRequest,
        inventory: &RecoverableNatsConsumerInventoryReceipt,
    ) -> Result<PersistedPendingQueueScanVerifiedReceipt, PendingQueueSegmentLifecycleError> {
        let candidate = expected.to_scan_verified(inventory)?;
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(expected, &candidate)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    binding.candidate_revision,
                    binding.candidate_payload.as_slice(),
                    binding.lifecycle_slot.as_slice(),
                    binding.expected_revision,
                    binding.expected_payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )));
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        classify_lifecycle_cas(applied, &candidate, &current)?;
        Ok(PersistedPendingQueueScanVerifiedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    async fn advance_to_delete_requested(
        &self,
        expected: &StoredPendingQueueSegmentSealRequest,
        scan: &PendingQueueNatsWholeStreamScanReceipt,
        inventory: &RecoverableNatsConsumerInventoryReceipt,
    ) -> Result<PersistedPendingQueueDeleteRequestedReceipt, PendingQueueSegmentLifecycleError>
    {
        let candidate = expected.to_delete_requested(scan, inventory)?;
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(expected, &candidate)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    binding.candidate_revision,
                    binding.candidate_payload.as_slice(),
                    binding.lifecycle_slot.as_slice(),
                    binding.expected_revision,
                    binding.expected_payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )));
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        classify_lifecycle_cas(applied, &candidate, &current)?;
        Ok(PersistedPendingQueueDeleteRequestedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    async fn advance_to_deleted(
        &self,
        expected: &StoredPendingQueueSegmentSealRequest,
    ) -> Result<PersistedPendingQueueDeletedReceipt, PendingQueueSegmentLifecycleError> {
        let candidate = expected.deleted_candidate()?;
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(expected, &candidate)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    binding.candidate_revision,
                    binding.candidate_payload.as_slice(),
                    binding.lifecycle_slot.as_slice(),
                    binding.expected_revision,
                    binding.expected_payload.as_slice(),
                ),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == candidate => false,
                Ok(_) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(
                        error.to_string(),
                    ));
                }
                Err(read) => {
                    return Err(PendingQueueSegmentLifecycleError::Indeterminate(format!(
                        "execute={error}; read={read}",
                    )));
                }
            },
        };
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        classify_lifecycle_cas(applied, &candidate, &current)?;
        Ok(PersistedPendingQueueDeletedReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn seal_requested_stream<Hash: Q256BitHash>(
        &self,
        nats: &NatsJetStreamClient,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        receipt: &PersistedPendingQueueSealRequestedReceipt,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueStreamSealedReceipt, PendingQueueSegmentLifecycleError> {
        if receipt.store_fingerprint != self.fingerprint
            || segment.segment_id() != receipt.current.segment_id
            || segment.digest() != receipt.current.contract_digest
        {
            return Err(PendingQueueSegmentLifecycleError::ReceiptStoreMismatch);
        }
        let durable = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        if durable != receipt.current
            && durable.phase != PendingQueueSegmentLifecyclePhase::StreamSealed
        {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let sealed = match nats
            .observe_recoverable_segment_instance(segment.clone())
            .await
        {
            Ok(live) => {
                if !receipt.matches_live_instance(&live) {
                    return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
                }
                nats.seal_recoverable_segment_instance(&live)
                    .await
                    .map_err(transport)?
                    .sealed()
                    .clone()
            }
            Err(live_error) => nats
                .observe_recoverable_sealed_segment_instance(segment)
                .await
                .map_err(|sealed_error| {
                    PendingQueueSegmentLifecycleError::Transport(format!(
                        "live={live_error}; sealed={sealed_error}",
                    ))
                })?,
        };
        if !receipt.current.matches_sealed_instance(&sealed) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let candidate = receipt.current.to_stream_sealed(&sealed)?;
        let result = if durable == candidate {
            PersistedPendingQueueStreamSealedReceipt {
                store_fingerprint: self.fingerprint,
                current: durable,
            }
        } else if durable == receipt.current {
            self.advance_to_stream_sealed(&receipt.current, &sealed)
                .await?
        } else {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        };
        if !result.matches_sealed_instance(&sealed) {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn scan_stream_sealed_messages<Hash: Q256BitHash>(
        &self,
        nats: &NatsJetStreamClient,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        receipt: &PersistedPendingQueueStreamSealedReceipt,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueMessagesScanVerifiedReceipt, PendingQueueSegmentLifecycleError>
    {
        if receipt.store_fingerprint != self.fingerprint
            || segment.segment_id() != receipt.current.segment_id
            || segment.digest() != receipt.current.contract_digest
        {
            return Err(PendingQueueSegmentLifecycleError::ReceiptStoreMismatch);
        }
        let durable = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        if durable != receipt.current
            && durable.phase != PendingQueueSegmentLifecyclePhase::MessagesScanVerified
        {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let sealed = nats
            .observe_recoverable_sealed_segment_instance(segment)
            .await
            .map_err(transport)?;
        if !receipt.matches_sealed_instance(&sealed) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let manifest = PendingQueueNatsWholeStreamExpectedManifest::try_new(
            sealed,
            receipt.assignments()?,
        )
        .map_err(terminal)?;
        if manifest.digest() != receipt.manifest_digest() {
            return Err(PendingQueueSegmentLifecycleError::ManifestMismatch);
        }
        let scan = nats
            .scan_recoverable_sealed_segment(manifest)
            .await
            .map_err(transport)?;
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let candidate = receipt.current.to_messages_scan_verified(&scan)?;
        let result = if durable == candidate {
            PersistedPendingQueueMessagesScanVerifiedReceipt {
                store_fingerprint: self.fingerprint,
                current: durable,
            }
        } else if durable == receipt.current {
            self.advance_to_messages_scan_verified(&receipt.current, &scan)
                .await?
        } else {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        };
        if result.store_fingerprint != self.fingerprint
            || !result.current.matches_scan_receipt(&scan)
        {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn verify_messages_scanned_consumers<Hash: Q256BitHash>(
        &self,
        nats: &NatsJetStreamClient,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        receipt: &PersistedPendingQueueMessagesScanVerifiedReceipt,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueScanVerifiedReceipt, PendingQueueSegmentLifecycleError> {
        if receipt.store_fingerprint != self.fingerprint
            || segment.segment_id() != receipt.current.segment_id
            || segment.digest() != receipt.current.contract_digest
        {
            return Err(PendingQueueSegmentLifecycleError::ReceiptStoreMismatch);
        }
        let durable = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        if durable != receipt.current
            && durable.phase != PendingQueueSegmentLifecyclePhase::ScanVerified
        {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;
        let sealed = nats
            .observe_recoverable_sealed_segment_instance(segment.clone())
            .await
            .map_err(transport)?;
        let manifest = self
            .build_expected_consumer_manifest(
                archive_store,
                &receipt.current,
                &segment,
                sealed,
            )
            .await?;
        let first = nats
            .inventory_recoverable_sealed_segment_consumers(manifest.clone())
            .await
            .map_err(transport)?;
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;
        let second = nats
            .inventory_recoverable_sealed_segment_consumers(manifest)
            .await
            .map_err(transport)?;
        if first != second {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let candidate = receipt.current.to_scan_verified(&first)?;
        let result = if durable == candidate {
            PersistedPendingQueueScanVerifiedReceipt {
                store_fingerprint: self.fingerprint,
                current: durable,
            }
        } else if durable == receipt.current {
            self.advance_to_scan_verified(&receipt.current, &first)
                .await?
        } else {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        };
        if result.store_fingerprint != self.fingerprint
            || !result.current.matches_consumer_inventory(&first)
        {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        Ok(result)
    }

    /// Freshly repeats the complete, non-destructive message and consumer
    /// closure before durably crossing the logical delete-request PONR. This
    /// method never deletes or purges NATS data.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn request_delete_for_scan_verified<Hash: Q256BitHash>(
        &self,
        nats: &NatsJetStreamClient,
        ledger_store: &ScyllaPendingQueueSegmentLedgerStore,
        terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        pipeline_store: &ScyllaPendingPipelineStore,
        writer_store: &ScyllaBranchExactWriterLifecycleStore,
        head_store: &ScyllaAuthorityLocalHeadStore,
        closure: &PendingQueueSegmentClosureSnapshot,
        receipt: &PersistedPendingQueueScanVerifiedReceipt,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueDeleteRequestedReceipt, PendingQueueSegmentLifecycleError>
    {
        if receipt.store_fingerprint != self.fingerprint
            || segment.segment_id() != receipt.current.segment_id
            || segment.digest() != receipt.current.contract_digest
            || receipt.current.phase != PendingQueueSegmentLifecyclePhase::ScanVerified
            || receipt.current.revision != SCAN_VERIFIED_REVISION
        {
            return Err(PendingQueueSegmentLifecycleError::ReceiptStoreMismatch);
        }
        let durable = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        let durable_candidate = receipt.current.delete_requested_candidate()?;
        if durable == durable_candidate {
            return Ok(PersistedPendingQueueDeleteRequestedReceipt {
                store_fingerprint: self.fingerprint,
                current: durable,
            });
        }
        if durable != receipt.current {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let sealed = nats
            .observe_recoverable_sealed_segment_instance(segment.clone())
            .await
            .map_err(transport)?;
        if !receipt.current.matches_sealed_instance(&sealed) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        let message_manifest = PendingQueueNatsWholeStreamExpectedManifest::try_new(
            sealed.clone(),
            receipt.current.assignments()?,
        )
        .map_err(terminal)?;
        let scan = nats
            .scan_recoverable_sealed_segment(message_manifest)
            .await
            .map_err(transport)?;
        if !receipt.current.matches_reverified_scan(&scan) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let consumer_manifest = self
            .build_expected_consumer_manifest(
                archive_store,
                &receipt.current,
                &segment,
                sealed,
            )
            .await?;
        let first = nats
            .inventory_recoverable_sealed_segment_consumers(consumer_manifest.clone())
            .await
            .map_err(transport)?;
        if !receipt.current.matches_consumer_inventory(&first) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;
        let second = nats
            .inventory_recoverable_sealed_segment_consumers(consumer_manifest)
            .await
            .map_err(transport)?;
        if first != second || !receipt.current.matches_consumer_inventory(&second) {
            return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
        }
        self.revalidate_seal_evidence::<Hash>(
            ledger_store,
            terminal_store,
            archive_store,
            pipeline_store,
            writer_store,
            head_store,
            closure,
            &receipt.current,
        )
        .await?;

        let candidate = receipt.current.to_delete_requested(&scan, &first)?;
        let result = self
            .advance_to_delete_requested(&receipt.current, &scan, &first)
            .await?;
        if result.store_fingerprint != self.fingerprint
            || result.current != candidate
            || !result.current.matches_delete_request_evidence(&scan, &first)
        {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        Ok(result)
    }

    /// Consumes the durable revision-5 PONR, performs the only typed
    /// whole-stream delete, and records revision 6. It never derives delete
    /// authority from NATS absence alone.
    pub(super) async fn delete_requested_stream(
        &self,
        nats: &NatsJetStreamClient,
        archive_store: &ScyllaPendingQueueSemanticAggregateStore,
        receipt: &PersistedPendingQueueDeleteRequestedReceipt,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<PersistedPendingQueueDeletedReceipt, PendingQueueSegmentLifecycleError> {
        if receipt.store_fingerprint != self.fingerprint
            || segment.segment_id() != receipt.current.segment_id
            || segment.digest() != receipt.current.contract_digest
            || receipt.current.phase != PendingQueueSegmentLifecyclePhase::DeleteRequested
            || receipt.current.revision != DELETE_REQUESTED_REVISION
        {
            return Err(PendingQueueSegmentLifecycleError::ReceiptStoreMismatch);
        }
        let durable = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueSegmentLifecycleError::MissingAfterLwt)?;
        let deleted_candidate = receipt.current.deleted_candidate()?;
        if durable == deleted_candidate {
            return Ok(PersistedPendingQueueDeletedReceipt {
                store_fingerprint: self.fingerprint,
                current: durable,
            });
        }
        if durable != receipt.current {
            return Err(PendingQueueSegmentLifecycleError::Conflict);
        }

        let expectation = RecoverableNatsDeleteExpectation::try_new(
            segment.clone(),
            RecoverableNatsStreamInstanceId::try_from_bytes(
                receipt.current.stream_instance_id,
            )
            .map_err(transport)?,
            receipt.current.live_state,
        )
        .map_err(transport)?;

        // If the stream still exists, re-prove the exact consumer inventory
        // immediately before delete. If a prior attempt already deleted it,
        // the typed façade below classifies absence only because revision 5
        // is durably present.
        if let Ok(sealed) = nats
            .observe_recoverable_sealed_segment_instance(segment.clone())
            .await
        {
            if !receipt.current.matches_sealed_instance(&sealed) {
                return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
            }
            let manifest = self
                .build_expected_consumer_manifest(
                    archive_store,
                    &receipt.current,
                    &segment,
                    sealed,
                )
                .await?;
            let inventory = nats
                .inventory_recoverable_sealed_segment_consumers(manifest)
                .await
                .map_err(transport)?;
            if !receipt
                .current
                .matches_delete_requested_consumer_inventory(&inventory)
            {
                return Err(PendingQueueSegmentLifecycleError::EvidenceChanged);
            }
        }

        let deleted = nats
            .delete_recoverable_sealed_segment_instance(&expectation)
            .await
            .map_err(transport)?;
        if deleted.instance_id().as_bytes() != &receipt.current.stream_instance_id {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        let result = self.advance_to_deleted(&receipt.current).await?;
        if result.store_fingerprint != self.fingerprint
            || result.current != deleted_candidate
            || result.current.phase != PendingQueueSegmentLifecyclePhase::Deleted
        {
            return Err(PendingQueueSegmentLifecycleError::AppliedStateMismatch);
        }
        Ok(result)
    }
}

async fn observe_terminals<Hash: Q256BitHash>(
    terminal_store: &ScyllaPendingQueueGenerationTerminalStore,
    archive_store: &ScyllaPendingQueueSemanticAggregateStore,
    pipeline_store: &ScyllaPendingPipelineStore,
    writer_store: &ScyllaBranchExactWriterLifecycleStore,
    head_store: &ScyllaAuthorityLocalHeadStore,
    closure: &PendingQueueSegmentClosureSnapshot,
) -> Result<Vec<PendingQueueGenerationTerminalSegmentCommitment>, PendingQueueSegmentLifecycleError>
{
    let mut commitments = Vec::with_capacity(closure.assignments().len());
    for assignment in closure.assignments() {
        commitments.push(
            terminal_store
                .observe_segment_commitment::<Hash>(
                    archive_store,
                    pipeline_store,
                    writer_store,
                    head_store,
                    assignment,
                )
                .await?,
        );
    }
    Ok(commitments)
}

fn lifecycle_slot(
    ledger_slot: PendingQueueSegmentLedgerSlot,
    segment_id: RecoverableNatsSegmentId,
) -> Result<PendingQueueSegmentLifecycleSlot, PendingQueueSegmentLifecycleError> {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(ledger_slot.as_bytes());
    hasher.update(segment_id.get().to_be_bytes());
    PendingQueueSegmentLifecycleSlot::try_new(hasher.finalize().into())
}

fn lifecycle_digest(bytes: &[u8]) -> Result<PendingQueueSegmentLifecycleDigest, PendingQueueSegmentLifecycleError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    PendingQueueSegmentLifecycleDigest::try_new(hasher.finalize().into())
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueSegmentLifecycleQueries,
) -> PendingQueueSegmentLifecycleStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    PendingQueueSegmentLifecycleStoreFingerprint(hasher.finalize().into())
}

fn encode_stream_state(state: RecoverableNatsStreamStateSnapshot, out: &mut Vec<u8>) {
    out.extend_from_slice(&state.messages().to_be_bytes());
    out.extend_from_slice(&state.bytes().to_be_bytes());
    out.extend_from_slice(&state.first_sequence().to_be_bytes());
    out.extend_from_slice(&state.last_sequence().to_be_bytes());
    out.extend_from_slice(&state.consumer_count().to_be_bytes());
    out.extend_from_slice(&state.subject_count().to_be_bytes());
}

fn decode_stream_state(
    decoder: &mut Decoder<'_>,
) -> Result<RecoverableNatsStreamStateSnapshot, PendingQueueSegmentLifecycleError> {
    RecoverableNatsStreamStateSnapshot::try_new(
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
        decoder.u64()?,
    )
    .map_err(|_| PendingQueueSegmentLifecycleError::StreamStateMismatch)
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueSegmentLifecycleError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueSegmentLifecycleError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueSegmentLifecycleError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingQueueSegmentLifecycleError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueSegmentLifecycleError::InvalidAppliedColumn),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueSegmentLifecycleError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(PendingQueueSegmentLifecycleError::Truncated)?;
        if end > self.bytes.len() {
            return Err(PendingQueueSegmentLifecycleError::Truncated);
        }
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, PendingQueueSegmentLifecycleError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u8(&mut self) -> Result<u8, PendingQueueSegmentLifecycleError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, PendingQueueSegmentLifecycleError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueSegmentLifecycleError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueSegmentLifecycleError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, PendingQueueSegmentLifecycleError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn done(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueSegmentLifecycleError {
    PendingQueueSegmentLifecycleError::Cql(error.to_string())
}

fn terminal(error: PendingQueueTerminalError) -> PendingQueueSegmentLifecycleError {
    PendingQueueSegmentLifecycleError::Nats(error.to_string())
}

fn transport(error: impl fmt::Display) -> PendingQueueSegmentLifecycleError {
    PendingQueueSegmentLifecycleError::Transport(error.to_string())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum PendingQueueSegmentLifecycleError {
    Cql(String),
    Nats(String),
    Transport(String),
    Archive(String),
    Ledger(super::PendingQueueSegmentLedgerStoreError),
    Terminal(PendingQueueGenerationTerminalError),
    EmptyDigest,
    InvalidRevision,
    InvalidTransition,
    InvalidSegment,
    InvalidMagic,
    UnknownCodecVersion,
    UnknownPhase,
    SelectedIdentityMismatch,
    ClosureMismatch,
    StreamStateMismatch,
    TerminalSetMismatch,
    ManifestMismatch,
    AssignmentDecode,
    CounterOverflow,
    TooManyAssignments,
    PayloadTooLarge,
    DigestMismatch,
    Truncated,
    TrailingBytes,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    Conflict,
    ReceiptStoreMismatch,
    EvidenceChanged,
    Indeterminate(String),
}

impl From<super::PendingQueueSegmentLedgerStoreError> for PendingQueueSegmentLifecycleError {
    fn from(value: super::PendingQueueSegmentLedgerStoreError) -> Self {
        Self::Ledger(value)
    }
}

impl From<PendingQueueGenerationTerminalError> for PendingQueueSegmentLifecycleError {
    fn from(value: PendingQueueGenerationTerminalError) -> Self {
        Self::Terminal(value)
    }
}

impl fmt::Display for PendingQueueSegmentLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueSegmentLifecycleError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> StoredPendingQueueSegmentSealRequest {
        let ledger_slot = PendingQueueSegmentLedgerSlot::try_new([2; 32]).unwrap();
        let segment_id = RecoverableNatsSegmentId::try_new(3).unwrap();
        let stream_instance_id = [5; 32];
        let mut value = StoredPendingQueueSegmentSealRequest {
            slot: lifecycle_slot(ledger_slot, segment_id).unwrap(),
            revision: SEAL_REQUESTED_REVISION,
            phase: PendingQueueSegmentLifecyclePhase::SealRequested,
            ledger_store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint::try_new(
                [1; 32],
            )
            .unwrap(),
            ledger_slot,
            ledger_revision: PendingQueueSegmentLedgerRevision::try_new(7).unwrap(),
            ledger_payload_digest: PendingQueueSegmentClosureDigest::try_new([8; 32]).unwrap(),
            segment_id,
            contract_digest: RecoverableNatsSegmentContractDigest::try_new([4; 32]).unwrap(),
            stream_instance_id,
            live_state: RecoverableNatsStreamStateSnapshot::try_new(0, 0, 0, 0, 0, 0)
                .unwrap(),
            manifest_digest:
                PendingQueueNatsWholeStreamManifestDigest::for_instance_assignments_raw(
                    stream_instance_id,
                    &[],
                )
                .unwrap(),
            scan_digest: None,
            consumer_manifest_digest: None,
            consumer_inventory_digest: None,
            terminals: Vec::new(),
            digest: PendingQueueSegmentLifecycleDigest([1; 32]),
        };
        value.digest = lifecycle_digest(&value.encode_unsigned()).unwrap();
        value
    }

    #[test]
    fn queries_are_ifne_no_tablet_and_default_off() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22_segment_lifecycle_nt".to_owned(),
        )
        .unwrap();
        let queries = PendingQueueSegmentLifecycleQueries::new(&keyspace);
        assert!(queries.create.contains("psy_h22_segment_lifecycle_nt."));
        assert!(queries.bootstrap.contains("IF NOT EXISTS"));
        assert_eq!(queries.read.matches("SELECT revision").count(), 1);
        assert!(queries
            .compare_and_set
            .contains("IF revision = ? AND lifecycle_payload = ?"));
        assert!(!queries.golden().contains("DELETE "));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_SEGMENT_LIFECYCLE_TABLE));
        assert!(!setup.contains("ScyllaPendingQueueSegmentLifecycleStore"));
    }

    #[test]
    fn seal_request_codec_is_deterministic_and_fail_closed() {
        let value = fixture();
        let bytes = value.to_persisted_bytes();
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                value.slot,
                SEAL_REQUESTED_REVISION as i64,
                &bytes,
            )
            .unwrap(),
            value,
        );
        assert_eq!(value.to_persisted_bytes(), bytes);

        let mut stream_sealed = value.clone();
        stream_sealed.revision = STREAM_SEALED_REVISION;
        stream_sealed.phase = PendingQueueSegmentLifecyclePhase::StreamSealed;
        stream_sealed.digest = lifecycle_digest(&stream_sealed.encode_unsigned()).unwrap();
        let stream_sealed_bytes = stream_sealed.to_persisted_bytes();
        let binding = PendingQueueSegmentLifecycleCasBinding::try_new(
            &value,
            &stream_sealed,
        )
        .unwrap();
        assert_eq!(binding.candidate_revision, 2);
        assert_eq!(binding.expected_revision, 1);
        assert_eq!(binding.lifecycle_slot, *value.slot.as_bytes());
        assert_eq!(binding.candidate_payload, stream_sealed_bytes);
        assert_eq!(binding.expected_payload, bytes);
        assert_eq!(
            classify_lifecycle_cas(true, &stream_sealed, &stream_sealed).unwrap(),
            PendingQueueSegmentLifecycleCasDisposition::Applied,
        );
        assert_eq!(
            classify_lifecycle_cas(false, &stream_sealed, &stream_sealed).unwrap(),
            PendingQueueSegmentLifecycleCasDisposition::Idempotent,
        );
        assert_eq!(
            classify_lifecycle_cas(false, &stream_sealed, &value),
            Err(PendingQueueSegmentLifecycleError::Conflict),
        );
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                stream_sealed.slot,
                STREAM_SEALED_REVISION as i64,
                &stream_sealed_bytes,
            )
            .unwrap(),
            stream_sealed,
        );
        assert!(StoredPendingQueueSegmentSealRequest::decode_persisted(
            value.slot,
            SEAL_REQUESTED_REVISION as i64,
            &stream_sealed_bytes,
        )
        .is_err());

        let mut messages_scanned = stream_sealed.clone();
        messages_scanned.revision = MESSAGES_SCAN_VERIFIED_REVISION;
        messages_scanned.phase =
            PendingQueueSegmentLifecyclePhase::MessagesScanVerified;
        messages_scanned.scan_digest = Some(
            PendingQueueNatsWholeStreamScanDigest::try_from_bytes([9; 32]).unwrap(),
        );
        messages_scanned.digest =
            lifecycle_digest(&messages_scanned.encode_unsigned()).unwrap();
        let messages_scanned_bytes = messages_scanned.to_persisted_bytes();
        let scan_binding = PendingQueueSegmentLifecycleCasBinding::try_new(
            &stream_sealed,
            &messages_scanned,
        )
        .unwrap();
        assert_eq!(scan_binding.expected_revision, 2);
        assert_eq!(scan_binding.candidate_revision, 3);
        assert_eq!(scan_binding.expected_payload, stream_sealed_bytes);
        assert_eq!(scan_binding.candidate_payload, messages_scanned_bytes);
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                messages_scanned.slot,
                MESSAGES_SCAN_VERIFIED_REVISION as i64,
                &messages_scanned_bytes,
            )
            .unwrap(),
            messages_scanned,
        );
        assert_eq!(
            PendingQueueSegmentLifecycleCasBinding::try_new(&value, &messages_scanned),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );

        let mut scan_verified = messages_scanned.clone();
        scan_verified.revision = SCAN_VERIFIED_REVISION;
        scan_verified.phase = PendingQueueSegmentLifecyclePhase::ScanVerified;
        scan_verified.consumer_manifest_digest = Some(
            RecoverableNatsConsumerManifestDigest::try_from_bytes([10; 32]).unwrap(),
        );
        scan_verified.consumer_inventory_digest = Some(
            RecoverableNatsConsumerInventoryDigest::try_from_bytes([11; 32]).unwrap(),
        );
        scan_verified.digest = lifecycle_digest(&scan_verified.encode_unsigned()).unwrap();
        let scan_verified_bytes = scan_verified.to_persisted_bytes();
        let consumer_binding = PendingQueueSegmentLifecycleCasBinding::try_new(
            &messages_scanned,
            &scan_verified,
        )
        .unwrap();
        assert_eq!(consumer_binding.expected_revision, 3);
        assert_eq!(consumer_binding.candidate_revision, 4);
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                scan_verified.slot,
                SCAN_VERIFIED_REVISION as i64,
                &scan_verified_bytes,
            )
            .unwrap(),
            scan_verified,
        );
        assert_eq!(
            PendingQueueSegmentLifecycleCasBinding::try_new(
                &stream_sealed,
                &scan_verified,
            ),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );

        let mut delete_requested = scan_verified.clone();
        delete_requested.revision = DELETE_REQUESTED_REVISION;
        delete_requested.phase = PendingQueueSegmentLifecyclePhase::DeleteRequested;
        delete_requested.digest =
            lifecycle_digest(&delete_requested.encode_unsigned()).unwrap();
        assert_eq!(
            scan_verified.delete_requested_candidate().unwrap(),
            delete_requested,
        );
        let mut missing_inventory = scan_verified.clone();
        missing_inventory.consumer_inventory_digest = None;
        assert_eq!(
            missing_inventory.delete_requested_candidate(),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );
        let delete_requested_bytes = delete_requested.to_persisted_bytes();
        let delete_binding = PendingQueueSegmentLifecycleCasBinding::try_new(
            &scan_verified,
            &delete_requested,
        )
        .unwrap();
        assert_eq!(delete_binding.expected_revision, 4);
        assert_eq!(delete_binding.candidate_revision, 5);
        assert_eq!(delete_binding.expected_payload, scan_verified_bytes);
        assert_eq!(delete_binding.candidate_payload, delete_requested_bytes);
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                delete_requested.slot,
                DELETE_REQUESTED_REVISION as i64,
                &delete_requested_bytes,
            )
            .unwrap(),
            delete_requested,
        );
        assert_eq!(
            PendingQueueSegmentLifecycleCasBinding::try_new(
                &messages_scanned,
                &delete_requested,
            ),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );
        assert_eq!(
            PendingQueueSegmentLifecycleCasBinding::try_new(&value, &delete_requested),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );

        let deleted = delete_requested.deleted_candidate().unwrap();
        assert_eq!(deleted.revision, DELETED_REVISION);
        assert_eq!(deleted.phase, PendingQueueSegmentLifecyclePhase::Deleted);
        assert_eq!(deleted.stream_instance_id, delete_requested.stream_instance_id);
        assert_eq!(deleted.scan_digest, delete_requested.scan_digest);
        assert_eq!(
            deleted.consumer_inventory_digest,
            delete_requested.consumer_inventory_digest,
        );
        let deleted_bytes = deleted.to_persisted_bytes();
        let deleted_binding = PendingQueueSegmentLifecycleCasBinding::try_new(
            &delete_requested,
            &deleted,
        )
        .unwrap();
        assert_eq!(deleted_binding.expected_revision, 5);
        assert_eq!(deleted_binding.candidate_revision, 6);
        assert_eq!(deleted_binding.expected_payload, delete_requested_bytes);
        assert_eq!(deleted_binding.candidate_payload, deleted_bytes);
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                deleted.slot,
                DELETED_REVISION as i64,
                &deleted_bytes,
            )
            .unwrap(),
            deleted,
        );
        assert_eq!(
            PendingQueueSegmentLifecycleCasBinding::try_new(&scan_verified, &deleted),
            Err(PendingQueueSegmentLifecycleError::InvalidTransition),
        );

        let mut recreated = value.clone();
        recreated.stream_instance_id = [6; 32];
        recreated.manifest_digest =
            PendingQueueNatsWholeStreamManifestDigest::for_instance_assignments_raw(
                recreated.stream_instance_id,
                &[],
            )
            .unwrap();
        recreated.digest = lifecycle_digest(&recreated.encode_unsigned()).unwrap();
        assert_eq!(recreated.slot, value.slot);
        assert_ne!(recreated.to_persisted_bytes(), value.to_persisted_bytes());

        let mut tampered = bytes.clone();
        tampered[180] ^= 1;
        assert!(StoredPendingQueueSegmentSealRequest::decode_persisted(
            value.slot,
            SEAL_REQUESTED_REVISION as i64,
            &tampered,
        )
        .is_err());
        let mut unknown = bytes.clone();
        unknown[8..10].copy_from_slice(&(CODEC_VERSION + 1).to_be_bytes());
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                value.slot,
                SEAL_REQUESTED_REVISION as i64,
                &unknown,
            ),
            Err(PendingQueueSegmentLifecycleError::UnknownCodecVersion),
        );
        let mut unknown_phase = bytes.clone();
        unknown_phase[50] = 99;
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                value.slot,
                SEAL_REQUESTED_REVISION as i64,
                &unknown_phase,
            ),
            Err(PendingQueueSegmentLifecycleError::UnknownPhase),
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            StoredPendingQueueSegmentSealRequest::decode_persisted(
                value.slot,
                SEAL_REQUESTED_REVISION as i64,
                &trailing,
            ),
            Err(PendingQueueSegmentLifecycleError::TrailingBytes),
        );
    }
}
