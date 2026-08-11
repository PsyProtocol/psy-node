//! Durable, driver-independent commitments for Realm generation rotation.
//!
//! A predecessor-keyed terminal/rotation intent preserves the exact expected
//! and candidate pending-pipeline rows. A successor-keyed carryover row lets a
//! restarted Processor find the predecessor application archive after the
//! pipeline eventually rotates. These values are immutable plans only: they
//! do not grant terminal, writer, head, or pipeline-mutation authority.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation::ReservedPendingGeneration,
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
        PendingGenerationContext, PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{
        PendingPipelineTransitionKind, PendingProcessingState,
        SealedPendingPipelineTransition, StoredPendingPipeline,
        PENDING_PIPELINE_V2_LEN,
    },
};

use super::{
    realm_processor_application_archive::{
        RealmProcessorApplicationArchiveDigest, RealmProcessorApplicationArchiveSlot,
    },
    realm_processor_generation_continuation::{
        RealmProcessorApplicationContinuation, RealmProcessorDeferredCarryoverDigest,
        RealmProcessorGenerationContinuationError,
    },
    realm_processor_semantic_output::RealmProcessorSemanticOutputDigest,
};

const TERMINAL_MAGIC: &[u8; 8] = b"PSYRGTER";
const CARRYOVER_MAGIC: &[u8; 8] = b"PSYRCARY";
const CODEC_VERSION: u16 = 1;
const RECORD_REVISION: u64 = 1;
const TERMINAL_SLOT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-generation-terminal-slot/v1";
const ROTATION_INTENT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-rotation-intent/v1";
const TERMINAL_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-generation-terminal/v1";
const CARRYOVER_SLOT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-deferred-carryover-slot/v1";
const CARRYOVER_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-deferred-carryover-record/v1";
const BOOTSTRAP_EMPTY_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-bootstrap-empty-carryover/v1";
pub const REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES: usize = 1024 * 1024;
pub const REALM_GENERATION_TERMINAL_MAX_PAYLOAD_BYTES: usize =
    2 * PENDING_PIPELINE_V2_LEN + REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES + 1024;
pub const REALM_DEFERRED_CARRYOVER_MAX_PAYLOAD_BYTES: usize = 4096;

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmGenerationTerminalError> {
                if bytes == [0; 32] {
                    Err(RealmGenerationTerminalError::EmptyDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

digest_type!(RealmProcessorGenerationTerminalSlot);
digest_type!(RealmProcessorGenerationTerminalDigest);
digest_type!(RealmProcessorGenerationTerminalStoreFingerprint);
digest_type!(RealmProcessorRotationIntentDigest);
digest_type!(RealmProcessorTerminalAuthorizationDigest);
digest_type!(RealmProcessorDeferredCarryoverSlot);
digest_type!(RealmProcessorDeferredCarryoverRecordDigest);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RealmProcessorGenerationTerminalKind {
    Published = 1,
    RetiredNoWork = 2,
}

impl RealmProcessorGenerationTerminalKind {
    fn from_pipeline<Hash>(
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> Result<Self, RealmGenerationTerminalError> {
        match pipeline.processing_state() {
            PendingProcessingState::Published { .. } => Ok(Self::Published),
            PendingProcessingState::RetiredNoWork { .. } => Ok(Self::RetiredNoWork),
            _ => Err(RealmGenerationTerminalError::PipelineNotTerminal),
        }
    }

    fn try_from_u8(value: u8) -> Result<Self, RealmGenerationTerminalError> {
        match value {
            1 => Ok(Self::Published),
            2 => Ok(Self::RetiredNoWork),
            _ => Err(RealmGenerationTerminalError::InvalidTerminalKind),
        }
    }

    const fn expects_work(self) -> bool {
        matches!(self, Self::Published)
    }
}

/// Immutable predecessor-keyed terminal and future rotation intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorGenerationTerminal<Hash> {
    slot: RealmProcessorGenerationTerminalSlot,
    revision: u64,
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    source: PendingGenerationContext,
    successor: PendingGenerationContext,
    reserved_next_gathering: PendingGenerationContext,
    kind: RealmProcessorGenerationTerminalKind,
    assignment_digest: [u8; 32],
    application_store_fingerprint: [u8; 32],
    application: RealmProcessorApplicationContinuation,
    expected_pipeline: StoredPendingPipeline<Hash>,
    candidate_pipeline: StoredPendingPipeline<Hash>,
    terminal_authorization: Vec<u8>,
    terminal_authorization_digest: RealmProcessorTerminalAuthorizationDigest,
    rotation_intent_digest: RealmProcessorRotationIntentDigest,
    digest: RealmProcessorGenerationTerminalDigest,
}

impl<Hash: Q256BitHash> RealmProcessorGenerationTerminal<Hash> {
    /// Build a durable plan from an already terminal pipeline and a typed
    /// monotonic reservation. The authorization bytes are a commitment only;
    /// a future storage-private c4f receipt must verify their writer/head
    /// provenance before this plan may participate in a pipeline CAS.
    pub fn try_new(
        terminal_pipeline: &StoredPendingPipeline<Hash>,
        reserved: ReservedPendingGeneration,
        assignment_digest: [u8; 32],
        application_store_fingerprint: [u8; 32],
        application: RealmProcessorApplicationContinuation,
        terminal_authorization: Vec<u8>,
    ) -> Result<Self, RealmGenerationTerminalError> {
        if assignment_digest == [0; 32] || application_store_fingerprint == [0; 32] {
            return Err(RealmGenerationTerminalError::EmptyDigest);
        }
        if terminal_authorization.is_empty()
            || terminal_authorization.len()
                > REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES
        {
            return Err(RealmGenerationTerminalError::AuthorizationSize);
        }
        require_realm(terminal_pipeline.key())?;
        let kind = RealmProcessorGenerationTerminalKind::from_pipeline(terminal_pipeline)?;
        validate_application(kind, terminal_pipeline, application)?;
        let sealed = terminal_pipeline
            .seal_rotation(reserved)
            .map_err(|error| RealmGenerationTerminalError::Pipeline(error.to_string()))?;
        if sealed.kind() != PendingPipelineTransitionKind::Rotate {
            return Err(RealmGenerationTerminalError::NotRotation);
        }
        let key = terminal_pipeline.key();
        let source = terminal_pipeline.processing();
        let successor = terminal_pipeline.gathering();
        let reserved_next_gathering = sealed.candidate().gathering();
        let slot = terminal_slot(key, terminal_pipeline.activation_digest(), source)?;
        let terminal_authorization_digest = digest_authorization(&terminal_authorization)?;
        let rotation_intent_digest = rotation_intent_digest(
            slot,
            assignment_digest,
            application_store_fingerprint,
            application,
            &sealed,
            terminal_authorization_digest,
        )?;
        let mut terminal = Self {
            slot,
            revision: RECORD_REVISION,
            key,
            activation_digest: terminal_pipeline.activation_digest(),
            source,
            successor,
            reserved_next_gathering,
            kind,
            assignment_digest,
            application_store_fingerprint,
            application,
            expected_pipeline: sealed.expected().clone(),
            candidate_pipeline: sealed.candidate().clone(),
            terminal_authorization,
            terminal_authorization_digest,
            rotation_intent_digest,
            digest: RealmProcessorGenerationTerminalDigest([1; 32]),
        };
        terminal.digest = terminal_digest(&terminal.encode_unsigned())?;
        Ok(terminal)
    }

    pub const fn slot(&self) -> RealmProcessorGenerationTerminalSlot { self.slot }
    pub const fn revision(&self) -> u64 { self.revision }
    pub const fn key(&self) -> PendingGenerationLedgerKey { self.key }
    pub const fn activation_digest(&self) -> PendingGenerationActivationDigest { self.activation_digest }
    pub const fn source(&self) -> PendingGenerationContext { self.source }
    pub const fn successor(&self) -> PendingGenerationContext { self.successor }
    pub const fn reserved_next_gathering(&self) -> PendingGenerationContext { self.reserved_next_gathering }
    pub const fn kind(&self) -> RealmProcessorGenerationTerminalKind { self.kind }
    pub const fn assignment_digest(&self) -> &[u8; 32] { &self.assignment_digest }
    pub const fn application_store_fingerprint(&self) -> &[u8; 32] { &self.application_store_fingerprint }
    pub const fn application(&self) -> RealmProcessorApplicationContinuation { self.application }
    pub const fn expected_pipeline(&self) -> &StoredPendingPipeline<Hash> { &self.expected_pipeline }
    pub const fn candidate_pipeline(&self) -> &StoredPendingPipeline<Hash> { &self.candidate_pipeline }
    pub fn terminal_authorization(&self) -> &[u8] { &self.terminal_authorization }
    pub const fn terminal_authorization_digest(&self) -> RealmProcessorTerminalAuthorizationDigest { self.terminal_authorization_digest }
    pub const fn rotation_intent_digest(&self) -> RealmProcessorRotationIntentDigest { self.rotation_intent_digest }
    pub const fn digest(&self) -> RealmProcessorGenerationTerminalDigest { self.digest }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub fn decode_selected(
        selected_slot: RealmProcessorGenerationTerminalSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, RealmGenerationTerminalError> {
        if bytes.len() > REALM_GENERATION_TERMINAL_MAX_PAYLOAD_BYTES {
            return Err(RealmGenerationTerminalError::PayloadTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != TERMINAL_MAGIC {
            return Err(RealmGenerationTerminalError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(RealmGenerationTerminalError::UnknownCodecVersion);
        }
        let slot = RealmProcessorGenerationTerminalSlot::try_new(decoder.array32()?)?;
        let revision = decoder.u64()?;
        if slot != selected_slot
            || revision != RECORD_REVISION
            || selected_revision != RECORD_REVISION as i64
        {
            return Err(RealmGenerationTerminalError::SelectedIdentityMismatch);
        }
        let key = decode_key(&mut decoder)?;
        require_realm(key)?;
        let activation_digest = PendingGenerationActivationDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmGenerationTerminalError::EmptyDigest)?;
        let source = decoder.context()?;
        let successor = decoder.context()?;
        let reserved_next_gathering = decoder.context()?;
        let kind = RealmProcessorGenerationTerminalKind::try_from_u8(decoder.u8()?)?;
        let assignment_digest = decoder.nonzero32()?;
        let application_store_fingerprint = decoder.nonzero32()?;
        let application = decode_application(&mut decoder)?;
        let expected_revision = decoder.i64()?;
        let expected_payload = decoder.bytes(PENDING_PIPELINE_V2_LEN)?;
        let candidate_revision = decoder.i64()?;
        let candidate_payload = decoder.bytes(PENDING_PIPELINE_V2_LEN)?;
        let terminal_authorization = decoder.bytes(
            REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES,
        )?;
        if terminal_authorization.is_empty() {
            return Err(RealmGenerationTerminalError::AuthorizationSize);
        }
        let terminal_authorization_digest =
            RealmProcessorTerminalAuthorizationDigest::try_new(decoder.array32()?)?;
        let rotation_intent_digest =
            RealmProcessorRotationIntentDigest::try_new(decoder.array32()?)?;
        let digest = RealmProcessorGenerationTerminalDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmGenerationTerminalError::TrailingBytes);
        }
        let expected_pipeline = StoredPendingPipeline::<Hash>::decode_persisted(
            key,
            expected_revision,
            &expected_payload,
        )
        .map_err(|error| RealmGenerationTerminalError::Pipeline(error.to_string()))?;
        let candidate_pipeline = StoredPendingPipeline::<Hash>::decode_persisted(
            key,
            candidate_revision,
            &candidate_payload,
        )
        .map_err(|error| RealmGenerationTerminalError::Pipeline(error.to_string()))?;
        let terminal = Self {
            slot,
            revision,
            key,
            activation_digest,
            source,
            successor,
            reserved_next_gathering,
            kind,
            assignment_digest,
            application_store_fingerprint,
            application,
            expected_pipeline,
            candidate_pipeline,
            terminal_authorization,
            terminal_authorization_digest,
            rotation_intent_digest,
            digest,
        };
        terminal.validate_decoded()?;
        Ok(terminal)
    }

    fn validate_decoded(&self) -> Result<(), RealmGenerationTerminalError> {
        if self.slot != terminal_slot(self.key, self.activation_digest, self.source)?
            || self.expected_pipeline.key() != self.key
            || self.expected_pipeline.activation_digest() != self.activation_digest
            || self.expected_pipeline.processing() != self.source
            || self.expected_pipeline.gathering() != self.successor
            || self.candidate_pipeline.processing() != self.successor
            || self.candidate_pipeline.gathering() != self.reserved_next_gathering
            || self.kind != RealmProcessorGenerationTerminalKind::from_pipeline(&self.expected_pipeline)?
        {
            return Err(RealmGenerationTerminalError::BindingMismatch);
        }
        validate_application(self.kind, &self.expected_pipeline, self.application)?;
        let reserved = ReservedPendingGeneration::try_new(
            self.reserved_next_gathering.pending_id().get(),
            self.reserved_next_gathering.proc_checkpoint_id().as_u128(),
        )
        .map_err(|_| RealmGenerationTerminalError::BindingMismatch)?;
        let sealed = self.expected_pipeline.seal_rotation(reserved)
            .map_err(|error| RealmGenerationTerminalError::Pipeline(error.to_string()))?;
        if sealed.candidate() != &self.candidate_pipeline
            || sealed.candidate_payload() != &self.candidate_pipeline.canonical_payload()
            || digest_authorization(&self.terminal_authorization)?
                != self.terminal_authorization_digest
            || rotation_intent_digest(
                self.slot,
                self.assignment_digest,
                self.application_store_fingerprint,
                self.application,
                &sealed,
                self.terminal_authorization_digest,
            )? != self.rotation_intent_digest
            || terminal_digest(&self.encode_unsigned())? != self.digest
        {
            return Err(RealmGenerationTerminalError::DigestMismatch);
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            512 + 2 * PENDING_PIPELINE_V2_LEN + self.terminal_authorization.len(),
        );
        out.extend_from_slice(TERMINAL_MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        encode_key(&mut out, self.key);
        out.extend_from_slice(self.activation_digest.as_bytes());
        encode_context(&mut out, self.source);
        encode_context(&mut out, self.successor);
        encode_context(&mut out, self.reserved_next_gathering);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.assignment_digest);
        out.extend_from_slice(&self.application_store_fingerprint);
        encode_application(&mut out, self.application);
        out.extend_from_slice(&self.expected_pipeline.revision().as_i64().to_be_bytes());
        encode_bytes(&mut out, &self.expected_pipeline.canonical_payload());
        out.extend_from_slice(&self.candidate_pipeline.revision().as_i64().to_be_bytes());
        encode_bytes(&mut out, &self.candidate_pipeline.canonical_payload());
        encode_bytes(&mut out, &self.terminal_authorization);
        out.extend_from_slice(self.terminal_authorization_digest.as_bytes());
        out.extend_from_slice(self.rotation_intent_digest.as_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorDeferredCarryoverSource {
    Predecessor {
        predecessor: PendingGenerationContext,
        terminal_slot: RealmProcessorGenerationTerminalSlot,
        terminal_store_fingerprint: RealmProcessorGenerationTerminalStoreFingerprint,
        terminal_digest: RealmProcessorGenerationTerminalDigest,
        rotation_intent_digest: RealmProcessorRotationIntentDigest,
        assignment_digest: [u8; 32],
        application_store_fingerprint: [u8; 32],
        application: RealmProcessorApplicationContinuation,
    },
    BootstrapEmpty {
        reason: PendingGenerationBootstrapReason,
    },
}

/// Explicit successor-keyed locator. Missing rows are never interpreted as
/// an empty carryover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorDeferredCarryover {
    slot: RealmProcessorDeferredCarryoverSlot,
    revision: u64,
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    successor: PendingGenerationContext,
    source: RealmProcessorDeferredCarryoverSource,
    deferred_count: u32,
    deferred_digest: RealmProcessorDeferredCarryoverDigest,
    digest: RealmProcessorDeferredCarryoverRecordDigest,
}

impl RealmProcessorDeferredCarryover {
    /// Build a locator commitment from a terminal record and the exact store
    /// identity in which that record will be selected. This value is still a
    /// model object, not persistence authority: the storage layer must only
    /// call it after obtaining and revalidating its private terminal receipt.
    pub fn try_from_terminal_commitment<Hash: Q256BitHash>(
        terminal: &RealmProcessorGenerationTerminal<Hash>,
        terminal_store_fingerprint: RealmProcessorGenerationTerminalStoreFingerprint,
    ) -> Result<Self, RealmGenerationTerminalError> {
        let application = terminal.application();
        let source = RealmProcessorDeferredCarryoverSource::Predecessor {
            predecessor: terminal.source(),
            terminal_slot: terminal.slot(),
            terminal_store_fingerprint,
            terminal_digest: terminal.digest(),
            rotation_intent_digest: terminal.rotation_intent_digest(),
            assignment_digest: *terminal.assignment_digest(),
            application_store_fingerprint: *terminal.application_store_fingerprint(),
            application,
        };
        Self::build(
            terminal.key(),
            terminal.activation_digest(),
            terminal.successor(),
            source,
            application.deferred_count(),
            application.deferred_digest(),
        )
    }

    pub fn try_bootstrap_empty(
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        successor: PendingGenerationContext,
        reason: PendingGenerationBootstrapReason,
    ) -> Result<Self, RealmGenerationTerminalError> {
        require_realm(key)?;
        let deferred_digest = bootstrap_empty_digest(key, activation_digest, successor, reason)?;
        Self::build(
            key,
            activation_digest,
            successor,
            RealmProcessorDeferredCarryoverSource::BootstrapEmpty { reason },
            0,
            deferred_digest,
        )
    }

    fn build(
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        successor: PendingGenerationContext,
        source: RealmProcessorDeferredCarryoverSource,
        deferred_count: u32,
        deferred_digest: RealmProcessorDeferredCarryoverDigest,
    ) -> Result<Self, RealmGenerationTerminalError> {
        require_realm(key)?;
        let slot = carryover_slot(key, activation_digest, successor)?;
        let mut carryover = Self {
            slot,
            revision: RECORD_REVISION,
            key,
            activation_digest,
            successor,
            source,
            deferred_count,
            deferred_digest,
            digest: RealmProcessorDeferredCarryoverRecordDigest([1; 32]),
        };
        carryover.digest = carryover_digest(&carryover.encode_unsigned())?;
        Ok(carryover)
    }

    pub const fn slot(&self) -> RealmProcessorDeferredCarryoverSlot { self.slot }
    pub const fn revision(&self) -> u64 { self.revision }
    pub const fn key(&self) -> PendingGenerationLedgerKey { self.key }
    pub const fn activation_digest(&self) -> PendingGenerationActivationDigest { self.activation_digest }
    pub const fn successor(&self) -> PendingGenerationContext { self.successor }
    pub const fn source(&self) -> RealmProcessorDeferredCarryoverSource { self.source }
    pub const fn deferred_count(&self) -> u32 { self.deferred_count }
    pub const fn deferred_digest(&self) -> RealmProcessorDeferredCarryoverDigest { self.deferred_digest }
    pub const fn digest(&self) -> RealmProcessorDeferredCarryoverRecordDigest { self.digest }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub fn decode_selected(
        selected_slot: RealmProcessorDeferredCarryoverSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, RealmGenerationTerminalError> {
        if bytes.len() > REALM_DEFERRED_CARRYOVER_MAX_PAYLOAD_BYTES {
            return Err(RealmGenerationTerminalError::PayloadTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != CARRYOVER_MAGIC {
            return Err(RealmGenerationTerminalError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(RealmGenerationTerminalError::UnknownCodecVersion);
        }
        let slot = RealmProcessorDeferredCarryoverSlot::try_new(decoder.array32()?)?;
        let revision = decoder.u64()?;
        if slot != selected_slot
            || revision != RECORD_REVISION
            || selected_revision != RECORD_REVISION as i64
        {
            return Err(RealmGenerationTerminalError::SelectedIdentityMismatch);
        }
        let key = decode_key(&mut decoder)?;
        require_realm(key)?;
        let activation_digest = PendingGenerationActivationDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmGenerationTerminalError::EmptyDigest)?;
        let successor = decoder.context()?;
        let source = match decoder.u8()? {
            1 => RealmProcessorDeferredCarryoverSource::Predecessor {
                predecessor: decoder.context()?,
                terminal_slot: RealmProcessorGenerationTerminalSlot::try_new(decoder.array32()?)?,
                terminal_store_fingerprint:
                    RealmProcessorGenerationTerminalStoreFingerprint::try_new(
                        decoder.array32()?,
                    )?,
                terminal_digest: RealmProcessorGenerationTerminalDigest::try_new(decoder.array32()?)?,
                rotation_intent_digest: RealmProcessorRotationIntentDigest::try_new(decoder.array32()?)?,
                assignment_digest: decoder.nonzero32()?,
                application_store_fingerprint: decoder.nonzero32()?,
                application: decode_application(&mut decoder)?,
            },
            2 => RealmProcessorDeferredCarryoverSource::BootstrapEmpty {
                reason: decode_bootstrap_reason(decoder.u8()?)?,
            },
            _ => return Err(RealmGenerationTerminalError::InvalidCarryoverSource),
        };
        let deferred_count = decoder.u32()?;
        let deferred_digest = RealmProcessorDeferredCarryoverDigest::try_new(decoder.array32()?)
            .map_err(map_continuation)?;
        let digest = RealmProcessorDeferredCarryoverRecordDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmGenerationTerminalError::TrailingBytes);
        }
        let carryover = Self {
            slot,
            revision,
            key,
            activation_digest,
            successor,
            source,
            deferred_count,
            deferred_digest,
            digest,
        };
        carryover.validate_decoded()?;
        Ok(carryover)
    }

    fn validate_decoded(&self) -> Result<(), RealmGenerationTerminalError> {
        if self.slot != carryover_slot(self.key, self.activation_digest, self.successor)? {
            return Err(RealmGenerationTerminalError::BindingMismatch);
        }
        match self.source {
            RealmProcessorDeferredCarryoverSource::Predecessor {
                predecessor,
                terminal_slot: selected_terminal_slot,
                application,
                ..
            } if selected_terminal_slot
                    == terminal_slot(self.key, self.activation_digest, predecessor)?
                && application.deferred_count() == self.deferred_count
                    && application.deferred_digest() == self.deferred_digest => {}
            RealmProcessorDeferredCarryoverSource::BootstrapEmpty { reason }
                if self.deferred_count == 0
                    && bootstrap_empty_digest(
                        self.key,
                        self.activation_digest,
                        self.successor,
                        reason,
                    )? == self.deferred_digest => {}
            _ => return Err(RealmGenerationTerminalError::BindingMismatch),
        }
        if carryover_digest(&self.encode_unsigned())? != self.digest {
            return Err(RealmGenerationTerminalError::DigestMismatch);
        }
        Ok(())
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(CARRYOVER_MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        encode_key(&mut out, self.key);
        out.extend_from_slice(self.activation_digest.as_bytes());
        encode_context(&mut out, self.successor);
        match self.source {
            RealmProcessorDeferredCarryoverSource::Predecessor {
                predecessor,
                terminal_slot,
                terminal_store_fingerprint,
                terminal_digest,
                rotation_intent_digest,
                assignment_digest,
                application_store_fingerprint,
                application,
            } => {
                out.push(1);
                encode_context(&mut out, predecessor);
                out.extend_from_slice(terminal_slot.as_bytes());
                out.extend_from_slice(terminal_store_fingerprint.as_bytes());
                out.extend_from_slice(terminal_digest.as_bytes());
                out.extend_from_slice(rotation_intent_digest.as_bytes());
                out.extend_from_slice(&assignment_digest);
                out.extend_from_slice(&application_store_fingerprint);
                encode_application(&mut out, application);
            }
            RealmProcessorDeferredCarryoverSource::BootstrapEmpty { reason } => {
                out.push(2);
                out.push(reason as u8);
            }
        }
        out.extend_from_slice(&self.deferred_count.to_be_bytes());
        out.extend_from_slice(self.deferred_digest.as_bytes());
        out
    }
}

fn validate_application<Hash>(
    kind: RealmProcessorGenerationTerminalKind,
    pipeline: &StoredPendingPipeline<Hash>,
    application: RealmProcessorApplicationContinuation,
) -> Result<(), RealmGenerationTerminalError> {
    if application.has_application_work() != kind.expects_work() {
        return Err(RealmGenerationTerminalError::ApplicationWorkMismatch);
    }
    let selected = match pipeline.processing_state() {
        PendingProcessingState::Published { capture, .. } => *capture.as_bytes(),
        PendingProcessingState::RetiredNoWork { seal, .. } => *seal.as_bytes(),
        _ => return Err(RealmGenerationTerminalError::PipelineNotTerminal),
    };
    if &selected != application.archive_slot().as_bytes() {
        return Err(RealmGenerationTerminalError::ApplicationSlotMismatch);
    }
    Ok(())
}

fn terminal_slot(
    key: PendingGenerationLedgerKey,
    activation: PendingGenerationActivationDigest,
    source: PendingGenerationContext,
) -> Result<RealmProcessorGenerationTerminalSlot, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_SLOT_DOMAIN);
    hash_key(&mut hasher, key);
    hasher.update(activation.as_bytes());
    hash_context(&mut hasher, source);
    RealmProcessorGenerationTerminalSlot::try_new(hasher.finalize().into())
}

fn carryover_slot(
    key: PendingGenerationLedgerKey,
    activation: PendingGenerationActivationDigest,
    successor: PendingGenerationContext,
) -> Result<RealmProcessorDeferredCarryoverSlot, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(CARRYOVER_SLOT_DOMAIN);
    hash_key(&mut hasher, key);
    hasher.update(activation.as_bytes());
    hash_context(&mut hasher, successor);
    RealmProcessorDeferredCarryoverSlot::try_new(hasher.finalize().into())
}

fn digest_authorization(bytes: &[u8]) -> Result<RealmProcessorTerminalAuthorizationDigest, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/realm-processor-terminal-authorization/v1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    RealmProcessorTerminalAuthorizationDigest::try_new(hasher.finalize().into())
}

fn rotation_intent_digest<Hash: Q256BitHash>(
    slot: RealmProcessorGenerationTerminalSlot,
    assignment_digest: [u8; 32],
    application_store_fingerprint: [u8; 32],
    application: RealmProcessorApplicationContinuation,
    sealed: &SealedPendingPipelineTransition<Hash>,
    authorization_digest: RealmProcessorTerminalAuthorizationDigest,
) -> Result<RealmProcessorRotationIntentDigest, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(ROTATION_INTENT_DOMAIN);
    hasher.update(slot.as_bytes());
    hasher.update(assignment_digest);
    hasher.update(application_store_fingerprint);
    hash_application(&mut hasher, application);
    hasher.update(sealed.expected().revision().get().to_be_bytes());
    hasher.update(sealed.expected_payload());
    hasher.update(sealed.candidate().revision().get().to_be_bytes());
    hasher.update(sealed.candidate_payload());
    hasher.update(authorization_digest.as_bytes());
    RealmProcessorRotationIntentDigest::try_new(hasher.finalize().into())
}

fn terminal_digest(bytes: &[u8]) -> Result<RealmProcessorGenerationTerminalDigest, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_DIGEST_DOMAIN);
    hasher.update(bytes);
    RealmProcessorGenerationTerminalDigest::try_new(hasher.finalize().into())
}

fn carryover_digest(bytes: &[u8]) -> Result<RealmProcessorDeferredCarryoverRecordDigest, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(CARRYOVER_DIGEST_DOMAIN);
    hasher.update(bytes);
    RealmProcessorDeferredCarryoverRecordDigest::try_new(hasher.finalize().into())
}

fn bootstrap_empty_digest(
    key: PendingGenerationLedgerKey,
    activation: PendingGenerationActivationDigest,
    successor: PendingGenerationContext,
    reason: PendingGenerationBootstrapReason,
) -> Result<RealmProcessorDeferredCarryoverDigest, RealmGenerationTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(BOOTSTRAP_EMPTY_DOMAIN);
    hash_key(&mut hasher, key);
    hasher.update(activation.as_bytes());
    hash_context(&mut hasher, successor);
    hasher.update([reason as u8]);
    RealmProcessorDeferredCarryoverDigest::try_new(hasher.finalize().into())
        .map_err(map_continuation)
}

fn require_realm(key: PendingGenerationLedgerKey) -> Result<(), RealmGenerationTerminalError> {
    match key.authority() {
        AuthorityScope::Realm { .. } => Ok(()),
        AuthorityScope::Coordinator => Err(RealmGenerationTerminalError::RealmRequired),
    }
}

fn encode_key(out: &mut Vec<u8>, key: PendingGenerationLedgerKey) {
    out.extend_from_slice(&key.network().chain_id().to_be_bytes());
    let (kind, realm, sub) = authority_parts(key.authority());
    out.push(kind);
    out.extend_from_slice(&realm.to_be_bytes());
    out.extend_from_slice(&sub.to_be_bytes());
}

fn hash_key(hasher: &mut Sha256, key: PendingGenerationLedgerKey) {
    hasher.update(key.network().chain_id().to_be_bytes());
    let (kind, realm, sub) = authority_parts(key.authority());
    hasher.update([kind]);
    hasher.update(realm.to_be_bytes());
    hasher.update(sub.to_be_bytes());
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<PendingGenerationLedgerKey, RealmGenerationTerminalError> {
    let network = NetworkId::try_from_chain_id(decoder.u32()?)
        .map_err(|_| RealmGenerationTerminalError::InvalidNetwork)?;
    let authority = decode_authority(decoder.u8()?, decoder.u32()?, decoder.u16()?)?;
    Ok(PendingGenerationLedgerKey::new(network, authority))
}

fn authority_parts(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm { realm_id, realm_sub_id } => (2, realm_id, realm_sub_id),
    }
}

fn decode_authority(kind: u8, realm: u32, sub: u16) -> Result<AuthorityScope, RealmGenerationTerminalError> {
    match (kind, realm, sub) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm { realm_id, realm_sub_id }),
        _ => Err(RealmGenerationTerminalError::InvalidAuthority),
    }
}

fn encode_context(out: &mut Vec<u8>, context: PendingGenerationContext) {
    out.extend_from_slice(&context.pending_id().get().to_be_bytes());
    out.extend_from_slice(context.proc_checkpoint_id().as_bytes());
}

fn hash_context(hasher: &mut Sha256, context: PendingGenerationContext) {
    hasher.update(context.pending_id().get().to_be_bytes());
    hasher.update(context.proc_checkpoint_id().as_bytes());
}

fn encode_application(out: &mut Vec<u8>, application: RealmProcessorApplicationContinuation) {
    out.extend_from_slice(application.archive_slot().as_bytes());
    out.extend_from_slice(application.archive_digest().as_bytes());
    out.extend_from_slice(application.semantic_digest().as_bytes());
    out.push(u8::from(application.has_application_work()));
    out.extend_from_slice(&application.deferred_count().to_be_bytes());
    out.extend_from_slice(application.deferred_digest().as_bytes());
}

fn hash_application(hasher: &mut Sha256, application: RealmProcessorApplicationContinuation) {
    hasher.update(application.archive_slot().as_bytes());
    hasher.update(application.archive_digest().as_bytes());
    hasher.update(application.semantic_digest().as_bytes());
    hasher.update([u8::from(application.has_application_work())]);
    hasher.update(application.deferred_count().to_be_bytes());
    hasher.update(application.deferred_digest().as_bytes());
}

fn decode_application(decoder: &mut Decoder<'_>) -> Result<RealmProcessorApplicationContinuation, RealmGenerationTerminalError> {
    RealmProcessorApplicationContinuation::try_from_committed_parts(
        RealmProcessorApplicationArchiveSlot::try_new(decoder.array32()?)
            .map_err(|_| RealmGenerationTerminalError::EmptyDigest)?,
        RealmProcessorApplicationArchiveDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmGenerationTerminalError::EmptyDigest)?,
        RealmProcessorSemanticOutputDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmGenerationTerminalError::EmptyDigest)?,
        match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(RealmGenerationTerminalError::InvalidBoolean),
        },
        decoder.u32()?,
        RealmProcessorDeferredCarryoverDigest::try_new(decoder.array32()?)
            .map_err(map_continuation)?,
    )
    .map_err(map_continuation)
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_bootstrap_reason(value: u8) -> Result<PendingGenerationBootstrapReason, RealmGenerationTerminalError> {
    match value {
        1 => Ok(PendingGenerationBootstrapReason::Genesis),
        2 => Ok(PendingGenerationBootstrapReason::LegacyActivation),
        _ => Err(RealmGenerationTerminalError::InvalidBootstrapReason),
    }
}

fn map_continuation(_: RealmProcessorGenerationContinuationError) -> RealmGenerationTerminalError {
    RealmGenerationTerminalError::InvalidApplication
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmGenerationTerminalError> {
        let end = self.cursor.checked_add(len).ok_or(RealmGenerationTerminalError::Truncated)?;
        let value = self.bytes.get(self.cursor..end).ok_or(RealmGenerationTerminalError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], RealmGenerationTerminalError> {
        self.take(N)?.try_into().map_err(|_| RealmGenerationTerminalError::Truncated)
    }
    fn array32(&mut self) -> Result<[u8; 32], RealmGenerationTerminalError> { self.array() }
    fn nonzero32(&mut self) -> Result<[u8; 32], RealmGenerationTerminalError> {
        let value = self.array32()?;
        if value == [0; 32] { Err(RealmGenerationTerminalError::EmptyDigest) } else { Ok(value) }
    }
    fn u8(&mut self) -> Result<u8, RealmGenerationTerminalError> { Ok(self.array::<1>()?[0]) }
    fn u16(&mut self) -> Result<u16, RealmGenerationTerminalError> { Ok(u16::from_be_bytes(self.array()?)) }
    fn u32(&mut self) -> Result<u32, RealmGenerationTerminalError> { Ok(u32::from_be_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, RealmGenerationTerminalError> { Ok(u64::from_be_bytes(self.array()?)) }
    fn i64(&mut self) -> Result<i64, RealmGenerationTerminalError> { Ok(i64::from_be_bytes(self.array()?)) }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, RealmGenerationTerminalError> {
        let len = self.u32()? as usize;
        if len > max { return Err(RealmGenerationTerminalError::ComponentTooLarge) }
        Ok(self.take(len)?.to_vec())
    }
    fn context(&mut self) -> Result<PendingGenerationContext, RealmGenerationTerminalError> {
        PendingGenerationContext::try_from_legacy(
            self.u64()?,
            u128::from_be_bytes(self.array()?),
        )
        .map_err(|error| RealmGenerationTerminalError::Context(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmGenerationTerminalError {
    EmptyDigest,
    InvalidNetwork,
    InvalidAuthority,
    RealmRequired,
    InvalidTerminalKind,
    PipelineNotTerminal,
    ApplicationWorkMismatch,
    ApplicationSlotMismatch,
    AuthorizationSize,
    PayloadTooLarge,
    NotRotation,
    BindingMismatch,
    DigestMismatch,
    SelectedIdentityMismatch,
    InvalidMagic,
    UnknownCodecVersion,
    InvalidBoolean,
    InvalidBootstrapReason,
    InvalidCarryoverSource,
    InvalidApplication,
    ComponentTooLarge,
    Truncated,
    TrailingBytes,
    Context(String),
    Pipeline(String),
}

impl fmt::Display for RealmGenerationTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmGenerationTerminalError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef,
        },
        chain_context::{
            AuthorityObservation, AuthorityStateCheckpointId,
            AuthorityStateRoot,
        },
    };

    use crate::store::{
        pending_generation::ProcNamespacePrefix,
        pending_generation_pipeline::{
            PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
            PendingPipelineBootstrap, PendingPipelineIntentDigest,
            PendingPublishReceiptDigest, PendingQueueCloseIntentDigest,
            PendingWorkCaptureDigest,
        },
    };

    use super::*;

    fn key() -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
        )
    }

    fn activation() -> PendingGenerationActivationDigest {
        PendingGenerationActivationDigest::try_new([7; 32]).unwrap()
    }

    fn prefix() -> ProcNamespacePrefix {
        ProcNamespacePrefix::for_authority(key().network(), key().authority())
    }

    fn context(pending: u64) -> PendingGenerationContext {
        PendingGenerationContext::try_from_legacy(
            pending,
            prefix().derive_proc_id(
                crate::store::typed::UniquePendingId::try_new(pending).unwrap(),
            ).as_u128(),
        )
        .unwrap()
    }

    fn observation(checkpoint: u64, state_checkpoint: u64) -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                key().network(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        checkpoint,
                        checkpoint + 1,
                        checkpoint + 2,
                        checkpoint + 3,
                    )),
                ),
            ),
            key().authority(),
            AuthorityStateCheckpointId::new(state_checkpoint),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(
                state_checkpoint,
                state_checkpoint + 1,
                state_checkpoint + 2,
                state_checkpoint + 3,
            )),
        )
        .unwrap()
    }

    fn ready() -> StoredPendingPipeline<PHash> {
        let baseline = PendingPipelineBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(1),
            context(2),
            observation(1, 1),
            1,
        )
        .unwrap()
        .candidate()
        .clone();
        baseline
            .seal_rotation(ReservedPendingGeneration::try_from_prefix(3, prefix()).unwrap())
            .unwrap()
            .candidate()
            .clone()
    }

    fn application(slot_byte: u8, work: bool, deferred_count: u32) -> RealmProcessorApplicationContinuation {
        RealmProcessorApplicationContinuation::try_from_committed_parts(
            RealmProcessorApplicationArchiveSlot::try_new([slot_byte; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([22; 32]).unwrap(),
            RealmProcessorSemanticOutputDigest::try_new([23; 32]).unwrap(),
            work,
            deferred_count,
            RealmProcessorDeferredCarryoverDigest::try_new([24; 32]).unwrap(),
        )
        .unwrap()
    }

    fn published() -> (StoredPendingPipeline<PHash>, RealmProcessorApplicationContinuation) {
        let application = application(21, true, 2);
        let sealing = ready()
            .seal_begin_queue_close(PendingQueueCloseIntentDigest::try_new([20; 32]).unwrap())
            .unwrap()
            .candidate()
            .clone();
        let captured = sealing
            .seal_capture_work(
                PendingQueueCloseIntentDigest::try_new([20; 32]).unwrap(),
                PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let inflight = captured
            .seal_begin_processing(
                PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes()).unwrap(),
                PendingPipelineIntentDigest::try_new([25; 32]).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let terminal = inflight
            .seal_publish(
                PendingPipelineIntentDigest::try_new([25; 32]).unwrap(),
                PendingPublishReceiptDigest::try_new([26; 32]).unwrap(),
                observation(2, 2),
            )
            .unwrap()
            .candidate()
            .clone();
        (terminal, application)
    }

    fn retired() -> (StoredPendingPipeline<PHash>, RealmProcessorApplicationContinuation) {
        let application = application(31, false, 0);
        let sealing = ready()
            .seal_begin_queue_close(PendingQueueCloseIntentDigest::try_new([30; 32]).unwrap())
            .unwrap()
            .candidate()
            .clone();
        let empty = sealing
            .seal_empty_queue(
                PendingQueueCloseIntentDigest::try_new([30; 32]).unwrap(),
                PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes()).unwrap(),
            )
            .unwrap()
            .candidate()
            .clone();
        let terminal = empty
            .seal_retire_no_work(
                PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes()).unwrap(),
                PendingNoWorkReceiptDigest::try_new([32; 32]).unwrap(),
                ready().frontier().clone(),
            )
            .unwrap()
            .candidate()
            .clone();
        (terminal, application)
    }

    fn terminal(
        pipeline: &StoredPendingPipeline<PHash>,
        application: RealmProcessorApplicationContinuation,
    ) -> RealmProcessorGenerationTerminal<PHash> {
        RealmProcessorGenerationTerminal::try_new(
            pipeline,
            ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
            [40; 32],
            [41; 32],
            application,
            vec![42; 96],
        )
        .unwrap()
    }

    fn terminal_store_fingerprint() -> RealmProcessorGenerationTerminalStoreFingerprint {
        RealmProcessorGenerationTerminalStoreFingerprint::try_new([43; 32]).unwrap()
    }

    #[test]
    fn terminal_and_rotation_intent_bind_exact_pipeline_and_application() {
        for (pipeline, application, kind) in [
            {
                let (pipeline, application) = published();
                (pipeline, application, RealmProcessorGenerationTerminalKind::Published)
            },
            {
                let (pipeline, application) = retired();
                (pipeline, application, RealmProcessorGenerationTerminalKind::RetiredNoWork)
            },
        ] {
            let terminal = terminal(&pipeline, application);
            assert_eq!(terminal.kind(), kind);
            assert_eq!(terminal.source(), context(2));
            assert_eq!(terminal.successor(), context(3));
            assert_eq!(terminal.reserved_next_gathering(), context(4));
            assert_eq!(terminal.expected_pipeline(), &pipeline);
            assert_eq!(terminal.candidate_pipeline().processing(), context(3));
            assert_eq!(terminal.candidate_pipeline().gathering(), context(4));
            let bytes = terminal.to_canonical_bytes();
            assert_eq!(
                RealmProcessorGenerationTerminal::<PHash>::decode_selected(
                    terminal.slot(),
                    terminal.revision() as i64,
                    &bytes,
                )
                .unwrap(),
                terminal,
            );
            assert_eq!(terminal.to_canonical_bytes(), bytes);
            let carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
                &terminal,
                terminal_store_fingerprint(),
            )
            .unwrap();
            if kind == RealmProcessorGenerationTerminalKind::RetiredNoWork {
                assert_eq!(carryover.deferred_count(), 0);
                assert_ne!(carryover.deferred_digest().as_bytes(), &[0; 32]);
            }
        }
    }

    #[test]
    fn successor_locator_is_explicit_deterministic_and_conflicts_by_content() {
        let (pipeline, application) = published();
        let first_terminal = terminal(&pipeline, application);
        let first = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &first_terminal,
            terminal_store_fingerprint(),
        )
        .unwrap();
        let second = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &first_terminal,
            terminal_store_fingerprint(),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.successor(), context(3));
        assert_eq!(first.deferred_count(), 2);
        assert_eq!(
            RealmProcessorDeferredCarryover::decode_selected(
                first.slot(),
                first.revision() as i64,
                &first.to_canonical_bytes(),
            )
            .unwrap(),
            first,
        );

        let mut cross_generation = first;
        if let RealmProcessorDeferredCarryoverSource::Predecessor {
            predecessor,
            ref mut terminal_slot,
            ..
        } = cross_generation.source
        {
            *terminal_slot = super::terminal_slot(
                cross_generation.key,
                cross_generation.activation_digest,
                PendingGenerationContext::try_from_legacy(
                    predecessor.pending_id().get() + 10,
                    predecessor.proc_checkpoint_id().as_u128() + 10,
                )
                .unwrap(),
            )
            .unwrap();
        }
        cross_generation.digest = carryover_digest(&cross_generation.encode_unsigned()).unwrap();
        assert_eq!(
            RealmProcessorDeferredCarryover::decode_selected(
                cross_generation.slot(),
                1,
                &cross_generation.to_canonical_bytes(),
            ),
            Err(RealmGenerationTerminalError::BindingMismatch),
        );

        let different_terminal = RealmProcessorGenerationTerminal::try_new(
            &pipeline,
            ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
            [40; 32],
            [41; 32],
            application,
            vec![99; 96],
        )
        .unwrap();
        let different = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &different_terminal,
            terminal_store_fingerprint(),
        )
        .unwrap();
        assert_eq!(first.slot(), different.slot());
        assert_ne!(first.digest(), different.digest());
    }

    #[test]
    fn bootstrap_empty_is_a_real_row_and_missing_or_tamper_cannot_be_empty() {
        let bootstrap = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            key(),
            activation(),
            context(1),
            PendingGenerationBootstrapReason::Genesis,
        )
        .unwrap();
        assert_eq!(bootstrap.deferred_count(), 0);
        assert_ne!(bootstrap.deferred_digest().as_bytes(), &[0; 32]);
        let bytes = bootstrap.to_canonical_bytes();
        assert_eq!(
            RealmProcessorDeferredCarryover::decode_selected(
                bootstrap.slot(),
                1,
                &bytes,
            )
            .unwrap(),
            bootstrap,
        );
        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            RealmProcessorDeferredCarryover::decode_selected(
                bootstrap.slot(),
                1,
                &tampered,
            ),
            Err(RealmGenerationTerminalError::DigestMismatch),
        );
    }

    #[test]
    fn wrong_phase_work_slot_codec_and_authorization_fail_closed() {
        let selected_application = application(21, true, 0);
        assert_eq!(
            RealmProcessorGenerationTerminal::try_new(
                &ready(),
                ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
                [40; 32],
                [41; 32],
                selected_application,
                vec![1],
            ),
            Err(RealmGenerationTerminalError::PipelineNotTerminal),
        );
        let (pipeline, _) = published();
        assert_eq!(
            RealmProcessorGenerationTerminal::try_new(
                &pipeline,
                ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
                [40; 32],
                [41; 32],
                application(21, false, 0),
                vec![1],
            ),
            Err(RealmGenerationTerminalError::ApplicationWorkMismatch),
        );
        assert_eq!(
            RealmProcessorGenerationTerminal::try_new(
                &pipeline,
                ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
                [40; 32],
                [41; 32],
                application(99, true, 0),
                vec![1],
            ),
            Err(RealmGenerationTerminalError::ApplicationSlotMismatch),
        );
        assert_eq!(
            RealmProcessorGenerationTerminal::try_new(
                &pipeline,
                ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
                [40; 32],
                [41; 32],
                selected_application,
                vec![],
            ),
            Err(RealmGenerationTerminalError::AuthorizationSize),
        );
        assert_eq!(
            RealmProcessorGenerationTerminal::try_new(
                &pipeline,
                ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
                [40; 32],
                [41; 32],
                selected_application,
                vec![0; REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES + 1],
            ),
            Err(RealmGenerationTerminalError::AuthorizationSize),
        );
        let terminal = terminal(&pipeline, selected_application);
        let mut bytes = terminal.to_canonical_bytes();
        bytes.push(0);
        assert_eq!(
            RealmProcessorGenerationTerminal::<PHash>::decode_selected(
                terminal.slot(),
                1,
                &bytes,
            ),
            Err(RealmGenerationTerminalError::TrailingBytes),
        );
        assert_eq!(
            RealmProcessorDeferredCarryover::decode_selected(
                RealmProcessorDeferredCarryoverSlot::try_new([1; 32]).unwrap(),
                1,
                &vec![0; REALM_DEFERRED_CARRYOVER_MAX_PAYLOAD_BYTES + 1],
            ),
            Err(RealmGenerationTerminalError::PayloadTooLarge),
        );
        let mut unknown = terminal.to_canonical_bytes();
        unknown[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            RealmProcessorGenerationTerminal::<PHash>::decode_selected(
                terminal.slot(),
                1,
                &unknown,
            ),
            Err(RealmGenerationTerminalError::UnknownCodecVersion),
        );
    }
}
