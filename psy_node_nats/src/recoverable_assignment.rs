//! Driver-independent, default-off generation-to-segment assignment model.
//!
//! Capacity is reserved once per pending generation, not once per queue
//! source. Coordinator's three expected sources and Realm's one source then
//! bind the same immutable assignment receipt. Rotation and release are
//! intentionally absent until c2b2/c2b3 can prove encoded Data/Seal bytes and
//! a complete terminal member manifest.

use std::{error::Error, fmt};

use psy_data::protocol::{
    canonical_chain::{CanonicalChainRefCodecError, NetworkId},
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::recoverable_ephemeral::{
        PendingQueueCaptureContext, PendingQueueCaptureContextDigest,
    },
    store::pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
};
use sha2::{Digest, Sha256};

use crate::recoverable_segment::{
    RecoverableNatsSegmentContractDigest, StructurallyValidatedRecoverableNatsSegment,
    RecoverableNatsSegmentId, RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES,
};
use crate::recoverable_publish::{
    PendingQueueGenerationBudgetContract, PendingQueueGenerationBudgetDigest,
    PendingQueueSourceQuota,
};

pub const PENDING_QUEUE_SEGMENT_LEDGER_CODEC_VERSION: u16 = 2;
pub const MAX_PENDING_QUEUE_SEGMENT_LEDGER_BYTES: usize = 1024 * 1024;
pub const MAX_GENERATIONS_PER_LIVE_SEGMENT: u32 = 4096;
const LEDGER_SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-segment-ledger-slot/v1";
const ASSIGNMENT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-segment-assignment/v1";
const MAX_BASE_NAMESPACE_BYTES: usize = 96;
const MAX_LIVE_SEGMENTS: u16 = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSegmentLedgerSlot([u8; 32]);

impl PendingQueueSegmentLedgerSlot {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLedgerError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLedgerError::EmptyLedgerSlot)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSegmentLedgerRevision(u64);

impl PendingQueueSegmentLedgerRevision {
    pub const fn try_new(value: u64) -> Result<Self, PendingQueueSegmentLedgerError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(PendingQueueSegmentLedgerError::RevisionOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, PendingQueueSegmentLedgerError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(PendingQueueSegmentLedgerError::RevisionOverflow)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSegmentAssignmentDigest([u8; 32]);

impl PendingQueueSegmentAssignmentDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSegmentLedgerError> {
        if bytes == [0; 32] {
            Err(PendingQueueSegmentLedgerError::EmptyAssignmentDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSegmentLedgerKey {
    generation_key: PendingGenerationLedgerKey,
    base_namespace: String,
    slot: PendingQueueSegmentLedgerSlot,
}

impl PendingQueueSegmentLedgerKey {
    pub fn try_new(
        generation_key: PendingGenerationLedgerKey,
        base_namespace: impl Into<String>,
    ) -> Result<Self, PendingQueueSegmentLedgerError> {
        let base_namespace = base_namespace.into();
        validate_base_namespace(&base_namespace)?;
        let canonical = encode_key_components(generation_key, &base_namespace);
        let mut hasher = Sha256::new();
        hasher.update(LEDGER_SLOT_DOMAIN);
        hasher.update((canonical.len() as u64).to_be_bytes());
        hasher.update(canonical);
        let slot = PendingQueueSegmentLedgerSlot::try_new(hasher.finalize().into())?;
        Ok(Self {
            generation_key,
            base_namespace,
            slot,
        })
    }

    pub const fn generation_key(&self) -> PendingGenerationLedgerKey {
        self.generation_key
    }

    pub fn base_namespace(&self) -> &str {
        &self.base_namespace
    }

    pub const fn slot(&self) -> PendingQueueSegmentLedgerSlot {
        self.slot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueLiveSegment {
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    max_stream_bytes: i64,
    reserved_bytes: i64,
    generation_count: u32,
}

impl PendingQueueLiveSegment {
    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub const fn max_stream_bytes(&self) -> i64 {
        self.max_stream_bytes
    }

    pub const fn reserved_bytes(&self) -> i64 {
        self.reserved_bytes
    }

    pub const fn generation_count(&self) -> u32 {
        self.generation_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueGenerationSegmentAssignment {
    context: PendingQueueCaptureContext,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    reserved_bytes: i64,
    expected_source_count: u8,
    budget_digest: PendingQueueGenerationBudgetDigest,
    source_quotas: Vec<PendingQueueSourceQuota>,
    digest: PendingQueueSegmentAssignmentDigest,
}

impl PendingQueueGenerationSegmentAssignment {
    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub const fn reserved_bytes(&self) -> i64 {
        self.reserved_bytes
    }

    pub const fn expected_source_count(&self) -> u8 {
        self.expected_source_count
    }

    pub const fn budget_digest(&self) -> PendingQueueGenerationBudgetDigest {
        self.budget_digest
    }

    pub fn source_quotas(&self) -> &[PendingQueueSourceQuota] {
        &self.source_quotas
    }

    pub const fn digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPendingQueueSegmentLedger {
    key: PendingQueueSegmentLedgerKey,
    revision: PendingQueueSegmentLedgerRevision,
    active_segment_id: RecoverableNatsSegmentId,
    highest_segment_id: RecoverableNatsSegmentId,
    max_live_segments: u16,
    max_generations_per_segment: u32,
    generation_admission_budget_bytes: i64,
    generation_budget: PendingQueueGenerationBudgetContract,
    capacity_headroom_bytes: i64,
    live_segments: Vec<PendingQueueLiveSegment>,
    assignments: Vec<PendingQueueGenerationSegmentAssignment>,
}

impl StoredPendingQueueSegmentLedger {
    pub const fn key(&self) -> &PendingQueueSegmentLedgerKey {
        &self.key
    }

    pub const fn revision(&self) -> PendingQueueSegmentLedgerRevision {
        self.revision
    }

    pub const fn active_segment_id(&self) -> RecoverableNatsSegmentId {
        self.active_segment_id
    }

    pub const fn highest_segment_id(&self) -> RecoverableNatsSegmentId {
        self.highest_segment_id
    }

    pub const fn generation_admission_budget_bytes(&self) -> i64 {
        self.generation_admission_budget_bytes
    }

    pub const fn generation_budget(&self) -> &PendingQueueGenerationBudgetContract {
        &self.generation_budget
    }

    pub fn live_segments(&self) -> &[PendingQueueLiveSegment] {
        &self.live_segments
    }

    pub fn assignments(&self) -> &[PendingQueueGenerationSegmentAssignment] {
        &self.assignments
    }

    pub fn assignment_for(
        &self,
        context: PendingQueueCaptureContext,
    ) -> Option<&PendingQueueGenerationSegmentAssignment> {
        self.assignments
            .iter()
            .find(|assignment| assignment.context.digest() == context.digest())
    }

    pub fn reserve_generation(
        &self,
        context: PendingQueueCaptureContext,
    ) -> Result<PendingQueueSegmentReservationPlan, PendingQueueSegmentLedgerError> {
        if context.key() != self.key.generation_key {
            return Err(PendingQueueSegmentLedgerError::GenerationKeyMismatch);
        }
        if let Some(existing) = self.assignment_for(context) {
            if existing.context != context {
                return Err(PendingQueueSegmentLedgerError::ContextDigestCollision);
            }
            return Ok(PendingQueueSegmentReservationPlan::Idempotent(
                existing.clone(),
            ));
        }
        if self.assignments.iter().any(|assignment| {
            assignment.context.processing() == context.processing()
                && assignment.context != context
        }) {
            return Err(PendingQueueSegmentLedgerError::GenerationIdentityConflict);
        }
        let active_index = self
            .live_segments
            .iter()
            .position(|segment| segment.segment_id == self.active_segment_id)
            .ok_or(PendingQueueSegmentLedgerError::ActiveSegmentMissing)?;
        let active = &self.live_segments[active_index];
        if active.generation_count >= self.max_generations_per_segment {
            return Err(PendingQueueSegmentLedgerError::GenerationLimitReached);
        }
        if self.assignments.last().is_some_and(|last| {
            last.context.processing().pending_id().get()
                >= context.processing().pending_id().get()
        }) {
            return Err(PendingQueueSegmentLedgerError::NonMonotonicGeneration);
        }
        let reserved_bytes = active
            .reserved_bytes
            .checked_add(self.generation_admission_budget_bytes)
            .ok_or(PendingQueueSegmentLedgerError::CapacityOverflow)?;
        let required_capacity = reserved_bytes
            .checked_add(self.capacity_headroom_bytes)
            .ok_or(PendingQueueSegmentLedgerError::CapacityOverflow)?;
        if required_capacity > active.max_stream_bytes {
            return Err(PendingQueueSegmentLedgerError::SegmentCapacityExceeded);
        }
        let expected_source_count = expected_source_count(self.key.generation_key.authority());
        let source_quotas = self.generation_budget.sources().to_vec();
        let assignment = PendingQueueGenerationSegmentAssignment {
            context,
            segment_id: active.segment_id,
            contract_digest: active.contract_digest,
            reserved_bytes: self.generation_admission_budget_bytes,
            expected_source_count,
            budget_digest: self.generation_budget.digest(),
            source_quotas: source_quotas.clone(),
            digest: assignment_digest(
                self.key.slot,
                context,
                active.segment_id,
                active.contract_digest,
                self.generation_admission_budget_bytes,
                expected_source_count,
                self.generation_budget.digest(),
                &source_quotas,
            )?,
        };
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.live_segments[active_index].reserved_bytes = reserved_bytes;
        candidate.live_segments[active_index].generation_count = active
            .generation_count
            .checked_add(1)
            .ok_or(PendingQueueSegmentLedgerError::CapacityOverflow)?;
        candidate.assignments.push(assignment.clone());
        candidate.validate()?;
        Ok(PendingQueueSegmentReservationPlan::Advance {
            expected: self.clone(),
            candidate,
            assignment,
        })
    }

    pub fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024 + self.assignments.len() * 160);
        out.extend_from_slice(b"PSYQSEGL");
        out.extend_from_slice(&PENDING_QUEUE_SEGMENT_LEDGER_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.key.slot.as_bytes());
        encode_key(&self.key, &mut out);
        out.extend_from_slice(&self.revision.get().to_be_bytes());
        out.extend_from_slice(&self.active_segment_id.get().to_be_bytes());
        out.extend_from_slice(&self.highest_segment_id.get().to_be_bytes());
        out.extend_from_slice(&self.max_live_segments.to_be_bytes());
        out.extend_from_slice(&self.max_generations_per_segment.to_be_bytes());
        out.extend_from_slice(&self.generation_admission_budget_bytes.to_be_bytes());
        let budget = self.generation_budget.to_canonical_bytes();
        out.extend_from_slice(&(budget.len() as u16).to_be_bytes());
        out.extend_from_slice(&budget);
        out.extend_from_slice(&self.capacity_headroom_bytes.to_be_bytes());
        out.extend_from_slice(&(self.live_segments.len() as u16).to_be_bytes());
        for segment in &self.live_segments {
            out.extend_from_slice(&segment.segment_id.get().to_be_bytes());
            out.extend_from_slice(segment.contract_digest.as_bytes());
            out.extend_from_slice(&segment.max_stream_bytes.to_be_bytes());
            out.extend_from_slice(&segment.reserved_bytes.to_be_bytes());
            out.extend_from_slice(&segment.generation_count.to_be_bytes());
        }
        out.extend_from_slice(&(self.assignments.len() as u32).to_be_bytes());
        for assignment in &self.assignments {
            encode_context(assignment.context, &mut out);
            out.extend_from_slice(&assignment.segment_id.get().to_be_bytes());
            out.extend_from_slice(assignment.contract_digest.as_bytes());
            out.extend_from_slice(&assignment.reserved_bytes.to_be_bytes());
            out.push(assignment.expected_source_count);
            out.extend_from_slice(assignment.budget_digest.as_bytes());
            out.push(assignment.source_quotas.len() as u8);
            for quota in &assignment.source_quotas {
                encode_quota(*quota, &mut out);
            }
            out.extend_from_slice(assignment.digest.as_bytes());
        }
        out
    }

    pub fn decode_persisted(
        partition_slot: PendingQueueSegmentLedgerSlot,
        revision_column: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueSegmentLedgerError> {
        if bytes.len() > MAX_PENDING_QUEUE_SEGMENT_LEDGER_BYTES {
            return Err(PendingQueueSegmentLedgerError::PayloadTooLarge(bytes.len()));
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != b"PSYQSEGL" {
            return Err(PendingQueueSegmentLedgerError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != PENDING_QUEUE_SEGMENT_LEDGER_CODEC_VERSION {
            return Err(PendingQueueSegmentLedgerError::UnknownCodecVersion(version));
        }
        let encoded_slot = PendingQueueSegmentLedgerSlot::try_new(decoder.array32()?)?;
        if encoded_slot != partition_slot {
            return Err(PendingQueueSegmentLedgerError::PartitionSlotMismatch);
        }
        let key = decode_key(&mut decoder)?;
        if key.slot != partition_slot {
            return Err(PendingQueueSegmentLedgerError::KeySlotMismatch);
        }
        decoder.generation_key = Some(key.generation_key());
        let revision = PendingQueueSegmentLedgerRevision::try_new(decoder.u64()?)?;
        if revision.as_i64() != revision_column {
            return Err(PendingQueueSegmentLedgerError::RevisionColumnMismatch);
        }
        let active_segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)?;
        let highest_segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)?;
        let max_live_segments = decoder.u16()?;
        let max_generations_per_segment = decoder.u32()?;
        let generation_admission_budget_bytes = decoder.i64()?;
        let budget_len = decoder.u16()? as usize;
        let generation_budget = PendingQueueGenerationBudgetContract::decode_canonical(
            decoder.take(budget_len)?,
        )
        .map_err(|error| PendingQueueSegmentLedgerError::Budget(error.to_string()))?;
        let capacity_headroom_bytes = decoder.i64()?;
        let live_count = decoder.u16()? as usize;
        let mut live_segments = Vec::with_capacity(live_count);
        for _ in 0..live_count {
            live_segments.push(PendingQueueLiveSegment {
                segment_id: RecoverableNatsSegmentId::try_new(decoder.u64()?)?,
                contract_digest: RecoverableNatsSegmentContractDigest::try_new(
                    decoder.array32()?,
                )?,
                max_stream_bytes: decoder.i64()?,
                reserved_bytes: decoder.i64()?,
                generation_count: decoder.u32()?,
            });
        }
        let assignment_count = decoder.u32()? as usize;
        if assignment_count > MAX_GENERATIONS_PER_LIVE_SEGMENT as usize {
            return Err(PendingQueueSegmentLedgerError::GenerationLimitReached);
        }
        let mut assignments = Vec::with_capacity(assignment_count);
        for _ in 0..assignment_count {
            let context = decode_context(&mut decoder)?;
            let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)?;
            let contract_digest = RecoverableNatsSegmentContractDigest::try_new(
                decoder.array32()?,
            )?;
            let reserved_bytes = decoder.i64()?;
            let expected_source_count = decoder.u8()?;
            let budget_digest = PendingQueueGenerationBudgetDigest::try_new(
                decoder.array32()?,
            )
            .map_err(|error| PendingQueueSegmentLedgerError::Budget(error.to_string()))?;
            let quota_count = decoder.u8()? as usize;
            if quota_count == 0 || quota_count > 3 {
                return Err(PendingQueueSegmentLedgerError::AssignmentMismatch);
            }
            let mut source_quotas = Vec::with_capacity(quota_count);
            for _ in 0..quota_count {
                source_quotas.push(decode_quota(&mut decoder)?);
            }
            assignments.push(PendingQueueGenerationSegmentAssignment {
                context,
                segment_id,
                contract_digest,
                reserved_bytes,
                expected_source_count,
                budget_digest,
                source_quotas,
                digest: PendingQueueSegmentAssignmentDigest::try_new(decoder.array32()?)?,
            });
        }
        if !decoder.is_done() {
            return Err(PendingQueueSegmentLedgerError::TrailingBytes);
        }
        let state = Self {
            key,
            revision,
            active_segment_id,
            highest_segment_id,
            max_live_segments,
            max_generations_per_segment,
            generation_admission_budget_bytes,
            generation_budget,
            capacity_headroom_bytes,
            live_segments,
            assignments,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), PendingQueueSegmentLedgerError> {
        if !(2..=MAX_LIVE_SEGMENTS).contains(&self.max_live_segments)
            // c2b1 deliberately models the initial segment only. Rotation
            // requires c2b2 byte accounting plus c2b3 terminal manifests.
            || self.live_segments.len() != 1
            || self.live_segments.len() > usize::from(self.max_live_segments)
        {
            return Err(PendingQueueSegmentLedgerError::InvalidLiveSegmentSet);
        }
        if self.max_generations_per_segment == 0
            || self.max_generations_per_segment > MAX_GENERATIONS_PER_LIVE_SEGMENT
            || self.assignments.len() > self.max_generations_per_segment as usize
            || self.generation_admission_budget_bytes <= 0
            || self.capacity_headroom_bytes <= 0
        {
            return Err(PendingQueueSegmentLedgerError::InvalidCapacityContract);
        }
        if self.generation_budget.authority() != self.key.generation_key.authority()
            || i64::try_from(self.generation_budget.max_generation_stored_bytes())
                .map_err(|_| PendingQueueSegmentLedgerError::InvalidCapacityContract)?
                != self.generation_admission_budget_bytes
        {
            return Err(PendingQueueSegmentLedgerError::BudgetMismatch);
        }
        let active = self
            .live_segments
            .iter()
            .find(|segment| segment.segment_id == self.active_segment_id)
            .ok_or(PendingQueueSegmentLedgerError::ActiveSegmentMissing)?;
        if self.highest_segment_id.get()
            < self
                .live_segments
                .iter()
                .map(|segment| segment.segment_id.get())
                .max()
                .unwrap_or(0)
        {
            return Err(PendingQueueSegmentLedgerError::HighestSegmentRegressed);
        }
        for pair in self.live_segments.windows(2) {
            if pair[0].segment_id.get() >= pair[1].segment_id.get() {
                return Err(PendingQueueSegmentLedgerError::InvalidLiveSegmentSet);
            }
        }
        let mut summed_reserved = 0_i64;
        for assignment in &self.assignments {
            if assignment.context.key() != self.key.generation_key
                || assignment.segment_id != active.segment_id
                || assignment.contract_digest != active.contract_digest
                || assignment.reserved_bytes != self.generation_admission_budget_bytes
                || assignment.expected_source_count
                    != expected_source_count(self.key.generation_key.authority())
                || assignment.budget_digest != self.generation_budget.digest()
                || assignment.source_quotas != self.generation_budget.sources()
                || assignment.digest
                    != assignment_digest(
                        self.key.slot,
                        assignment.context,
                        assignment.segment_id,
                        assignment.contract_digest,
                        assignment.reserved_bytes,
                        assignment.expected_source_count,
                        assignment.budget_digest,
                        &assignment.source_quotas,
                    )?
            {
                return Err(PendingQueueSegmentLedgerError::AssignmentMismatch);
            }
            summed_reserved = summed_reserved
                .checked_add(assignment.reserved_bytes)
                .ok_or(PendingQueueSegmentLedgerError::CapacityOverflow)?;
        }
        for pair in self.assignments.windows(2) {
            if pair[0].context.processing().pending_id().get()
                >= pair[1].context.processing().pending_id().get()
            {
                return Err(PendingQueueSegmentLedgerError::NonMonotonicGeneration);
            }
        }
        if active.reserved_bytes != summed_reserved
            || active.generation_count as usize != self.assignments.len()
            || active
                .reserved_bytes
                .checked_add(self.capacity_headroom_bytes)
                .ok_or(PendingQueueSegmentLedgerError::CapacityOverflow)?
                > active.max_stream_bytes
        {
            return Err(PendingQueueSegmentLedgerError::CapacityAccountingMismatch);
        }
        let encoded_len = self.to_persisted_bytes().len();
        if encoded_len > MAX_PENDING_QUEUE_SEGMENT_LEDGER_BYTES {
            return Err(PendingQueueSegmentLedgerError::PayloadTooLarge(encoded_len));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSegmentLedgerBootstrap {
    candidate: StoredPendingQueueSegmentLedger,
}

impl PendingQueueSegmentLedgerBootstrap {
    pub fn try_new(
        generation_key: PendingGenerationLedgerKey,
        validated_segment: &StructurallyValidatedRecoverableNatsSegment,
        generation_budget: PendingQueueGenerationBudgetContract,
        max_generations_per_segment: u32,
    ) -> Result<Self, PendingQueueSegmentLedgerError> {
        let segment = validated_segment.segment();
        let key = PendingQueueSegmentLedgerKey::try_new(
            generation_key,
            segment.base_namespace(),
        )?;
        if max_generations_per_segment == 0
            || max_generations_per_segment > MAX_GENERATIONS_PER_LIVE_SEGMENT
        {
            return Err(PendingQueueSegmentLedgerError::InvalidCapacityContract);
        }
        let retention = segment.retention();
        if generation_budget.authority() != generation_key.authority()
            || i64::try_from(generation_budget.max_generation_stored_bytes())
                .map_err(|_| PendingQueueSegmentLedgerError::InvalidCapacityContract)?
                != retention.generation_admission_budget_bytes()
        {
            return Err(PendingQueueSegmentLedgerError::BudgetMismatch);
        }
        let candidate = StoredPendingQueueSegmentLedger {
            key,
            revision: PendingQueueSegmentLedgerRevision::try_new(1)?,
            active_segment_id: segment.segment_id(),
            highest_segment_id: segment.segment_id(),
            max_live_segments: retention.max_live_segments(),
            max_generations_per_segment,
            generation_admission_budget_bytes: retention
                .generation_admission_budget_bytes(),
            generation_budget,
            capacity_headroom_bytes: RECOVERABLE_NATS_CAPACITY_HEADROOM_BYTES,
            live_segments: vec![PendingQueueLiveSegment {
                segment_id: segment.segment_id(),
                contract_digest: segment.digest(),
                max_stream_bytes: retention.max_stream_bytes(),
                reserved_bytes: 0,
                generation_count: 0,
            }],
            assignments: Vec::new(),
        };
        candidate.validate()?;
        Ok(Self { candidate })
    }

    pub const fn candidate(&self) -> &StoredPendingQueueSegmentLedger {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSegmentReservationPlan {
    Idempotent(PendingQueueGenerationSegmentAssignment),
    Advance {
        expected: StoredPendingQueueSegmentLedger,
        candidate: StoredPendingQueueSegmentLedger,
        assignment: PendingQueueGenerationSegmentAssignment,
    },
}

impl PendingQueueSegmentReservationPlan {
    pub const fn assignment(&self) -> &PendingQueueGenerationSegmentAssignment {
        match self {
            Self::Idempotent(assignment) | Self::Advance { assignment, .. } => assignment,
        }
    }

    pub const fn transition(
        &self,
    ) -> Option<(&StoredPendingQueueSegmentLedger, &StoredPendingQueueSegmentLedger)> {
        match self {
            Self::Idempotent(_) => None,
            Self::Advance {
                expected,
                candidate,
                ..
            } => Some((expected, candidate)),
        }
    }
}

fn assignment_digest(
    ledger_slot: PendingQueueSegmentLedgerSlot,
    context: PendingQueueCaptureContext,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    reserved_bytes: i64,
    expected_source_count: u8,
    budget_digest: PendingQueueGenerationBudgetDigest,
    source_quotas: &[PendingQueueSourceQuota],
) -> Result<PendingQueueSegmentAssignmentDigest, PendingQueueSegmentLedgerError> {
    let mut hasher = Sha256::new();
    hasher.update(ASSIGNMENT_DOMAIN);
    hasher.update(ledger_slot.as_bytes());
    hasher.update(context.digest().as_bytes());
    hasher.update(segment_id.get().to_be_bytes());
    hasher.update(contract_digest.as_bytes());
    hasher.update(reserved_bytes.to_be_bytes());
    hasher.update([expected_source_count]);
    hasher.update(budget_digest.as_bytes());
    hasher.update([source_quotas.len() as u8]);
    for quota in source_quotas {
        let mut encoded = Vec::with_capacity(21);
        encode_quota(*quota, &mut encoded);
        hasher.update(encoded);
    }
    PendingQueueSegmentAssignmentDigest::try_new(hasher.finalize().into())
}

fn expected_source_count(authority: AuthorityScope) -> u8 {
    match authority {
        AuthorityScope::Coordinator => 3,
        AuthorityScope::Realm { .. } => 1,
    }
}

fn encode_quota(quota: PendingQueueSourceQuota, out: &mut Vec<u8>) {
    out.push(quota.publisher_kind() as u8);
    out.extend_from_slice(&quota.max_data_members().to_be_bytes());
    out.extend_from_slice(&quota.max_data_stored_bytes().to_be_bytes());
    out.extend_from_slice(&quota.max_seal_stored_bytes().to_be_bytes());
}

fn decode_quota(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueSourceQuota, PendingQueueSegmentLedgerError> {
    let kind = crate::recoverable_publish::PendingQueuePublisherKind::try_from_u8(
        decoder.u8()?,
    )
    .map_err(|error| PendingQueueSegmentLedgerError::Budget(error.to_string()))?;
    PendingQueueSourceQuota::try_new(
        kind,
        decoder.u32()?,
        decoder.u64()?,
        decoder.u64()?,
    )
    .map_err(|error| PendingQueueSegmentLedgerError::Budget(error.to_string()))
}

fn validate_base_namespace(value: &str) -> Result<(), PendingQueueSegmentLedgerError> {
    if value.is_empty()
        || value.len() > MAX_BASE_NAMESPACE_BYTES
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains('*')
        || value.contains('>')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(PendingQueueSegmentLedgerError::InvalidBaseNamespace);
    }
    Ok(())
}

fn encode_key_components(
    key: PendingGenerationLedgerKey,
    base_namespace: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + base_namespace.len());
    out.extend_from_slice(&key.network().chain_id().to_be_bytes());
    let (kind, realm_id, realm_sub_id) = encode_authority(key.authority());
    out.push(kind);
    out.extend_from_slice(&realm_id.to_be_bytes());
    out.extend_from_slice(&realm_sub_id.to_be_bytes());
    out.extend_from_slice(&(base_namespace.len() as u16).to_be_bytes());
    out.extend_from_slice(base_namespace.as_bytes());
    out
}

fn encode_key(key: &PendingQueueSegmentLedgerKey, out: &mut Vec<u8>) {
    out.extend_from_slice(&encode_key_components(
        key.generation_key,
        &key.base_namespace,
    ));
}

fn decode_key(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueSegmentLedgerKey, PendingQueueSegmentLedgerError> {
    let network = NetworkId::try_from_chain_id(decoder.u32()?)?;
    let authority = decode_authority(decoder.u8()?, decoder.u32()?, decoder.u16()?)?;
    let base_namespace = decoder.string_u16()?;
    PendingQueueSegmentLedgerKey::try_new(
        PendingGenerationLedgerKey::new(network, authority),
        base_namespace,
    )
}

fn encode_context(context: PendingQueueCaptureContext, out: &mut Vec<u8>) {
    out.extend_from_slice(context.activation().as_bytes());
    out.extend_from_slice(&context.processing().pending_id().get().to_be_bytes());
    out.extend_from_slice(&context.processing().proc_checkpoint_id().as_u128().to_be_bytes());
    out.extend_from_slice(context.digest().as_bytes());
}

fn decode_context(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueCaptureContext, PendingQueueSegmentLedgerError> {
    let activation = PendingGenerationActivationDigest::try_new(decoder.array32()?)?;
    let processing = PendingGenerationContext::try_from_legacy(
        decoder.u64()?,
        decoder.u128()?,
    )?;
    let encoded_digest = PendingQueueCaptureContextDigest::try_new(decoder.array32()?)?;
    // The ledger key is supplied by the caller after decode_key. To avoid a
    // second wire copy, Decoder temporarily carries it through this field.
    let key = decoder
        .generation_key
        .ok_or(PendingQueueSegmentLedgerError::MissingDecodeKey)?;
    let context = PendingQueueCaptureContext::try_new(key, activation, processing)?;
    if context.digest() != encoded_digest {
        return Err(PendingQueueSegmentLedgerError::ContextDigestMismatch);
    }
    Ok(context)
}

fn encode_authority(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (2, realm_id, realm_sub_id),
    }
}

fn decode_authority(
    kind: u8,
    realm_id: u32,
    realm_sub_id: u16,
) -> Result<AuthorityScope, PendingQueueSegmentLedgerError> {
    match (kind, realm_id, realm_sub_id) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        }),
        _ => Err(PendingQueueSegmentLedgerError::InvalidAuthority),
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    generation_key: Option<PendingGenerationLedgerKey>,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            generation_key: None,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueSegmentLedgerError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PendingQueueSegmentLedgerError::TruncatedPayload)?;
        if end > self.bytes.len() {
            return Err(PendingQueueSegmentLedgerError::TruncatedPayload);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueSegmentLedgerError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PendingQueueSegmentLedgerError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, PendingQueueSegmentLedgerError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueSegmentLedgerError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u128(&mut self) -> Result<u128, PendingQueueSegmentLedgerError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, PendingQueueSegmentLedgerError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueSegmentLedgerError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn string_u16(&mut self) -> Result<String, PendingQueueSegmentLedgerError> {
        let len = self.u16()? as usize;
        if len == 0 || len > MAX_BASE_NAMESPACE_BYTES {
            return Err(PendingQueueSegmentLedgerError::InvalidBaseNamespace);
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| PendingQueueSegmentLedgerError::InvalidBaseNamespace)
    }

    const fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSegmentLedgerError {
    EmptyLedgerSlot,
    EmptyAssignmentDigest,
    InvalidBaseNamespace,
    InvalidAuthority,
    RevisionOutOfRange(u64),
    RevisionOverflow,
    InvalidCapacityContract,
    InvalidLiveSegmentSet,
    ActiveSegmentMissing,
    HighestSegmentRegressed,
    GenerationKeyMismatch,
    ContextDigestCollision,
    ContextDigestMismatch,
    GenerationIdentityConflict,
    NonMonotonicGeneration,
    GenerationLimitReached,
    SegmentCapacityExceeded,
    CapacityOverflow,
    CapacityAccountingMismatch,
    AssignmentMismatch,
    BudgetMismatch,
    Budget(String),
    InvalidMagic,
    UnknownCodecVersion(u16),
    PartitionSlotMismatch,
    KeySlotMismatch,
    RevisionColumnMismatch,
    MissingDecodeKey,
    TruncatedPayload,
    TrailingBytes,
    PayloadTooLarge(usize),
    Network(CanonicalChainRefCodecError),
    Segment(String),
    GenerationIdentity(String),
    RecoverableQueue(String),
}

impl From<CanonicalChainRefCodecError> for PendingQueueSegmentLedgerError {
    fn from(value: CanonicalChainRefCodecError) -> Self {
        Self::Network(value)
    }
}

impl From<crate::recoverable_segment::RecoverableNatsSegmentError>
    for PendingQueueSegmentLedgerError
{
    fn from(value: crate::recoverable_segment::RecoverableNatsSegmentError) -> Self {
        Self::Segment(value.to_string())
    }
}

impl From<psy_node_core::store::pending_generation_identity::PendingGenerationIdentityError>
    for PendingQueueSegmentLedgerError
{
    fn from(
        value: psy_node_core::store::pending_generation_identity::PendingGenerationIdentityError,
    ) -> Self {
        Self::GenerationIdentity(value.to_string())
    }
}

impl From<psy_node_core::queue::recoverable_ephemeral::RecoverableQueueError>
    for PendingQueueSegmentLedgerError
{
    fn from(
        value: psy_node_core::queue::recoverable_ephemeral::RecoverableQueueError,
    ) -> Self {
        Self::RecoverableQueue(value.to_string())
    }
}

impl fmt::Display for PendingQueueSegmentLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueSegmentLedgerError {}

#[cfg(test)]
mod tests {
    use async_nats::jetstream::stream::Config as StreamConfig;

    use super::*;
    use crate::recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueuePublisherKind,
        PendingQueueSourceQuota,
    };
    use crate::recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsStreamSegment,
    };

    fn key(authority: AuthorityScope) -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        )
    }

    fn bootstrap(authority: AuthorityScope) -> PendingQueueSegmentLedgerBootstrap {
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
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention,
        )
        .unwrap();
        let attested = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let mib = 1024 * 1024_u64;
        let sources = match authority {
            AuthorityScope::Coordinator => vec![
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
            AuthorityScope::Realm { .. } => vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::RealmUserUpdate,
                    50_000,
                    127 * mib,
                    mib,
                )
                .unwrap(),
            ],
        };
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            sources,
            128 * mib,
        )
        .unwrap();
        PendingQueueSegmentLedgerBootstrap::try_new(
            key(authority),
            &attested,
            budget,
            8,
        )
        .unwrap()
    }

    fn context(authority: AuthorityScope, pending: u64) -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            key(authority),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(pending, u128::from(pending) + 1000)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn generation_reservation_is_once_per_context_and_authority_cardinality() {
        let initial = bootstrap(AuthorityScope::Coordinator).candidate().clone();
        let first_context = context(AuthorityScope::Coordinator, 1);
        let PendingQueueSegmentReservationPlan::Advance {
            candidate,
            assignment,
            ..
        } = initial.reserve_generation(first_context).unwrap()
        else {
            panic!("first reservation must advance")
        };
        assert_eq!(assignment.expected_source_count(), 3);
        assert_eq!(candidate.assignments().len(), 1);
        assert_eq!(
            candidate.live_segments()[0].reserved_bytes(),
            candidate.generation_admission_budget_bytes()
        );
        assert!(matches!(
            candidate.reserve_generation(first_context).unwrap(),
            PendingQueueSegmentReservationPlan::Idempotent(_)
        ));

        let realm = bootstrap(AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        });
        let realm_context = context(
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            1,
        );
        assert_eq!(
            realm
                .candidate()
                .reserve_generation(realm_context)
                .unwrap()
                .assignment()
                .expected_source_count(),
            1
        );
    }

    #[test]
    fn codec_round_trip_and_tamper_fail_closed() {
        let initial = bootstrap(AuthorityScope::Coordinator).candidate().clone();
        let PendingQueueSegmentReservationPlan::Advance { candidate, .. } =
            initial
                .reserve_generation(context(AuthorityScope::Coordinator, 1))
                .unwrap()
        else {
            unreachable!()
        };
        let bytes = candidate.to_persisted_bytes();
        let payload_digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            payload_digest,
            [
                172, 88, 59, 120, 80, 224, 7, 169, 5, 109, 69, 130, 66, 239,
                251, 113, 242, 133, 219, 94, 102, 188, 153, 45, 36, 78, 183,
                80, 139, 167, 36, 181,
            ],
        );
        let decoded = StoredPendingQueueSegmentLedger::decode_persisted(
            candidate.key().slot(),
            candidate.revision().as_i64(),
            &bytes,
        )
        .unwrap();
        assert_eq!(decoded, candidate);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            StoredPendingQueueSegmentLedger::decode_persisted(
                candidate.key().slot(),
                candidate.revision().as_i64(),
                &trailing,
            ),
            Err(PendingQueueSegmentLedgerError::TrailingBytes)
        );
        assert!(StoredPendingQueueSegmentLedger::decode_persisted(
            candidate.key().slot(),
            candidate.revision().as_i64() + 1,
            &bytes,
        )
        .is_err());
    }

    #[test]
    fn capacity_generation_and_identity_conflicts_fail_closed() {
        let initial = bootstrap(AuthorityScope::Coordinator).candidate().clone();
        assert_eq!(
            initial.reserve_generation(context(
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 2,
                },
                1,
            )),
            Err(PendingQueueSegmentLedgerError::GenerationKeyMismatch)
        );
        let mut state = initial;
        for pending in 1..=7 {
            let PendingQueueSegmentReservationPlan::Advance { candidate, .. } = state
                .reserve_generation(context(AuthorityScope::Coordinator, pending))
                .unwrap()
            else {
                unreachable!()
            };
            state = candidate;
        }
        assert_eq!(
            state.reserve_generation(context(AuthorityScope::Coordinator, 8)),
            Err(PendingQueueSegmentLedgerError::SegmentCapacityExceeded)
        );
        let initial = bootstrap(AuthorityScope::Coordinator).candidate().clone();
        let PendingQueueSegmentReservationPlan::Advance { candidate, .. } = initial
            .reserve_generation(context(AuthorityScope::Coordinator, 2))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            candidate.reserve_generation(context(AuthorityScope::Coordinator, 1)),
            Err(PendingQueueSegmentLedgerError::NonMonotonicGeneration)
        );
    }

    #[test]
    fn unattested_or_drifted_stream_cannot_bootstrap() {
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
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention,
        )
        .unwrap();
        let mut drifted: StreamConfig = segment.stream_config();
        drifted.max_bytes += 1;
        assert!(segment.validate_stream_config_structure(&drifted).is_err());
    }
}
