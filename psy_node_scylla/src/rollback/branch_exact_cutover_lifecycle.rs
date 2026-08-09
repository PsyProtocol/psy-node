//! Reversible, driver-independent branch-exact serving-route lifecycle.
//!
//! h22e3a deliberately models only the interval in which legacy storage is
//! retained and every normal write remains dual-written.  It does not expose
//! target-only writing, legacy retirement, a production reader switch, or the
//! chain rollback point of no return.  The later durable adapter may only
//! accept the sealed transitions defined here.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_local_head::StoredAuthorityLocalHead,
    branch_pending_mapping::BranchPendingMapping,
    typed::UniquePendingId,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactShadowConsumedReceipt, BranchExactWriterState,
    StoredBranchExactWriterLifecycle,
};

const MAGIC: [u8; 8] = *b"PSYBEXCO";
const CODEC_VERSION: u16 = 1;
const BINDING_DOMAIN: &[u8] = b"psy/rollback/branch-exact-cutover-binding/v1";
const DECISION_DOMAIN: &[u8] = b"psy/rollback/branch-exact-cutover-decision/v1";
const STATE_DOMAIN: &[u8] = b"psy/rollback/branch-exact-cutover-state/v1";

/// Monotonic namespace for one complete cutover attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactCutoverGeneration(u64);

impl BranchExactCutoverGeneration {
    pub const fn try_new(value: u64) -> Result<Self, BranchExactCutoverError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(BranchExactCutoverError::GenerationOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// ABA fence for the cutover control row.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactCutoverRevision(u64);

impl BranchExactCutoverRevision {
    pub const fn try_new(value: u64) -> Result<Self, BranchExactCutoverError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(BranchExactCutoverError::RevisionOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn checked_next(self) -> Result<Self, BranchExactCutoverError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(BranchExactCutoverError::RevisionOverflow)?,
        )
    }
}

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            fn from_checked(bytes: [u8; 32]) -> Result<Self, BranchExactCutoverError> {
                if bytes == [0; 32] {
                    Err(BranchExactCutoverError::ZeroEvidence)
                } else {
                    Ok(Self(bytes))
                }
            }
        }
    };
}

digest_type!(BranchExactCutoverBindingDigest);
digest_type!(BranchExactCutoverDecisionDigest);
digest_type!(BranchExactCutoverStateDigest);
digest_type!(BranchExactCutoverSchemaDigest);
digest_type!(BranchExactCutoverBackfillDigest);
digest_type!(BranchExactCutoverShadowConsumedDigest);
digest_type!(BranchExactCutoverWriterActivationDigest);
digest_type!(BranchExactCutoverWriterStateDigest);
digest_type!(BranchExactCutoverAuthorityHeadDigest);

/// Physical writer mode is intentionally closed to dual-write in h22e3.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BranchExactCutoverWriterMode {
    DualWrite = 1,
}

/// Legacy retention cannot be disabled by this lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BranchExactLegacyRetention {
    Required = 1,
}

/// Reversible serving-route states. Quiescing states admit no new work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BranchExactCutoverPhase {
    LegacyPrimaryDualWrite = 1,
    QuiescingToTarget = 2,
    TargetPrimaryDualWrite = 3,
    QuiescingToLegacy = 4,
}

impl BranchExactCutoverPhase {
    fn try_from_u8(value: u8) -> Result<Self, BranchExactCutoverError> {
        match value {
            1 => Ok(Self::LegacyPrimaryDualWrite),
            2 => Ok(Self::QuiescingToTarget),
            3 => Ok(Self::TargetPrimaryDualWrite),
            4 => Ok(Self::QuiescingToLegacy),
            value => Err(BranchExactCutoverError::UnknownPhase(value)),
        }
    }
}

/// Exact route identity persisted inside an h22 WritePrepared row. This is
/// the crash-retry fence: a prepared intent can only resume under the same
/// cutover generation, revision, full binding/state digest, and serving phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterCutoverFence {
    generation: BranchExactCutoverGeneration,
    revision: BranchExactCutoverRevision,
    binding_digest: BranchExactCutoverBindingDigest,
    state_digest: BranchExactCutoverStateDigest,
    phase: BranchExactCutoverPhase,
}

impl BranchExactWriterCutoverFence {
    pub(crate) fn try_from_current<Hash: Q256BitHash>(
        current: &StoredBranchExactCutover<Hash>,
    ) -> Result<Self, BranchExactCutoverError> {
        if !matches!(
            current.phase(),
            BranchExactCutoverPhase::LegacyPrimaryDualWrite
                | BranchExactCutoverPhase::TargetPrimaryDualWrite
        ) {
            return Err(BranchExactCutoverError::RouteQuiescing);
        }
        Ok(Self {
            generation: current.binding().generation(),
            revision: current.revision(),
            binding_digest: current.binding().digest(),
            state_digest: current.state_digest(),
            phase: current.phase(),
        })
    }

    pub(crate) fn matches<Hash: Q256BitHash>(
        &self,
        current: &StoredBranchExactCutover<Hash>,
    ) -> bool {
        self.generation == current.binding().generation()
            && self.revision == current.revision()
            && self.binding_digest == current.binding().digest()
            && self.state_digest == current.state_digest()
            && self.phase == current.phase()
    }

    pub const fn generation(&self) -> BranchExactCutoverGeneration {
        self.generation
    }

    pub const fn revision(&self) -> BranchExactCutoverRevision {
        self.revision
    }

    pub const fn binding_digest(&self) -> BranchExactCutoverBindingDigest {
        self.binding_digest
    }

    pub const fn state_digest(&self) -> BranchExactCutoverStateDigest {
        self.state_digest
    }

    pub const fn phase(&self) -> BranchExactCutoverPhase {
        self.phase
    }

    pub(crate) fn encode_canonical(&self) -> [u8; 81] {
        let mut bytes = [0u8; 81];
        bytes[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.revision.get().to_be_bytes());
        bytes[16..48].copy_from_slice(self.binding_digest.as_bytes());
        bytes[48..80].copy_from_slice(self.state_digest.as_bytes());
        bytes[80] = self.phase as u8;
        bytes
    }

    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, BranchExactCutoverError> {
        if bytes.len() != 81 {
            return Err(BranchExactCutoverError::InvalidWriterFenceLength(bytes.len()));
        }
        let generation = BranchExactCutoverGeneration::try_new(u64::from_be_bytes(
            bytes[..8].try_into().expect("fixed fence generation"),
        ))?;
        let revision = BranchExactCutoverRevision::try_new(u64::from_be_bytes(
            bytes[8..16].try_into().expect("fixed fence revision"),
        ))?;
        let binding_digest = BranchExactCutoverBindingDigest::from_checked(
            bytes[16..48].try_into().expect("fixed binding digest"),
        )?;
        let state_digest = BranchExactCutoverStateDigest::from_checked(
            bytes[48..80].try_into().expect("fixed state digest"),
        )?;
        let phase = BranchExactCutoverPhase::try_from_u8(bytes[80])?;
        if !matches!(
            phase,
            BranchExactCutoverPhase::LegacyPrimaryDualWrite
                | BranchExactCutoverPhase::TargetPrimaryDualWrite
        ) {
            return Err(BranchExactCutoverError::RouteQuiescing);
        }
        Ok(Self {
            generation,
            revision,
            binding_digest,
            state_digest,
            phase,
        })
    }
}

/// Exact h20+h21+h22+authority-head evidence selected for one cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverBinding<Hash> {
    generation: BranchExactCutoverGeneration,
    authority: AuthorityScope,
    watermark: BranchPendingMapping<Hash>,
    schema_digest: BranchExactCutoverSchemaDigest,
    backfill_digest: BranchExactCutoverBackfillDigest,
    shadow_consumed_digest: BranchExactCutoverShadowConsumedDigest,
    writer_activation_digest: BranchExactCutoverWriterActivationDigest,
    writer_revision: u64,
    writer_state_digest: BranchExactCutoverWriterStateDigest,
    authority_head_revision: u64,
    authority_head_digest: BranchExactCutoverAuthorityHeadDigest,
    digest: BranchExactCutoverBindingDigest,
}

impl<Hash: Q256BitHash> BranchExactCutoverBinding<Hash> {
    /// Build a binding only from a live Realm writer Active state, its exact
    /// consumed shadow evidence, and the matching authority-local head.
    pub fn try_from_current(
        generation: BranchExactCutoverGeneration,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
        consumed: &BranchExactShadowConsumedReceipt,
        authority_head: &StoredAuthorityLocalHead<Hash>,
    ) -> Result<Self, BranchExactCutoverError> {
        let plan = writer.plan();
        let AuthorityScope::Realm { .. } = plan.authority() else {
            return Err(BranchExactCutoverError::CoordinatorNotQualified);
        };
        let BranchExactWriterState::Active(active) = writer.state() else {
            return Err(BranchExactCutoverError::WriterNotActive);
        };
        if consumed.writer_activation_digest() != plan.digest()
            || consumed.verified().digest() != plan.shadow_verified_digest()
            || consumed.verified().plan().slot() != plan.shadow_audit_slot()
        {
            return Err(BranchExactCutoverError::ShadowEvidenceMismatch);
        }
        if authority_head.head().key().authority() != plan.authority()
            || authority_head.head().key().network()
                != active.watermark().canonical_chain().network_id()
            || authority_head.head().chain() != active.watermark().canonical_chain()
        {
            return Err(BranchExactCutoverError::AuthorityHeadMismatch);
        }

        let writer_bytes = writer.to_canonical_bytes();
        let head_bytes = authority_head.encode_canonical();
        let mut binding = Self {
            generation,
            authority: plan.authority(),
            watermark: *active.watermark(),
            schema_digest: BranchExactCutoverSchemaDigest::from_checked(
                *plan.schema_ready_digest().as_bytes(),
            )?,
            backfill_digest: BranchExactCutoverBackfillDigest::from_checked(
                *plan.backfill_receipt().digest().as_bytes(),
            )?,
            shadow_consumed_digest:
                BranchExactCutoverShadowConsumedDigest::from_checked(
                    *consumed.digest().as_bytes(),
                )?,
            writer_activation_digest:
                BranchExactCutoverWriterActivationDigest::from_checked(
                    *plan.digest().as_bytes(),
                )?,
            writer_revision: writer.revision().get(),
            writer_state_digest: BranchExactCutoverWriterStateDigest::from_checked(
                Sha256::digest(writer_bytes).into(),
            )?,
            authority_head_revision: authority_head.revision().get(),
            authority_head_digest:
                BranchExactCutoverAuthorityHeadDigest::from_checked(
                    Sha256::digest(head_bytes).into(),
                )?,
            digest: BranchExactCutoverBindingDigest([1; 32]),
        };
        binding.digest = binding_digest(&binding);
        Ok(binding)
    }

    pub const fn generation(&self) -> BranchExactCutoverGeneration {
        self.generation
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn watermark(&self) -> &BranchPendingMapping<Hash> {
        &self.watermark
    }

    pub const fn network(&self) -> NetworkId {
        self.watermark.canonical_chain().network_id()
    }

    pub const fn digest(&self) -> BranchExactCutoverBindingDigest {
        self.digest
    }

    pub const fn writer_revision(&self) -> u64 {
        self.writer_revision
    }

    pub const fn writer_activation_digest_bytes(&self) -> &[u8; 32] {
        self.writer_activation_digest.as_bytes()
    }

    pub const fn authority_head_revision(&self) -> u64 {
        self.authority_head_revision
    }
}

/// One atomic cutover control payload plus its ABA revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBranchExactCutover<Hash> {
    revision: BranchExactCutoverRevision,
    binding: BranchExactCutoverBinding<Hash>,
    phase: BranchExactCutoverPhase,
    last_decision: BranchExactCutoverDecisionDigest,
    state_digest: BranchExactCutoverStateDigest,
}

impl<Hash: Q256BitHash> StoredBranchExactCutover<Hash> {
    pub const fn revision(&self) -> BranchExactCutoverRevision {
        self.revision
    }

    pub const fn binding(&self) -> &BranchExactCutoverBinding<Hash> {
        &self.binding
    }

    pub const fn phase(&self) -> BranchExactCutoverPhase {
        self.phase
    }

    pub const fn writer_mode(&self) -> BranchExactCutoverWriterMode {
        BranchExactCutoverWriterMode::DualWrite
    }

    pub const fn legacy_retention(&self) -> BranchExactLegacyRetention {
        BranchExactLegacyRetention::Required
    }

    pub const fn state_digest(&self) -> BranchExactCutoverStateDigest {
        self.state_digest
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_stored(self)
    }

    pub fn decode_persisted(
        selected_generation: i64,
        selected_revision: i64,
        payload: &[u8],
    ) -> Result<Self, BranchExactCutoverError> {
        let generation = u64::try_from(selected_generation)
            .map_err(|_| BranchExactCutoverError::NegativeGeneration(selected_generation))?;
        let revision = u64::try_from(selected_revision)
            .map_err(|_| BranchExactCutoverError::NegativeRevision(selected_revision))?;
        let decoded = decode_stored(payload)?;
        if decoded.binding.generation.get() != generation
            || decoded.revision.get() != revision
            || decoded.to_canonical_bytes() != payload
        {
            return Err(BranchExactCutoverError::PersistedIdentityMismatch);
        }
        Ok(decoded)
    }

    pub(crate) fn decode_selected(
        selected_network: NetworkId,
        selected_authority: AuthorityScope,
        selected_revision: i64,
        payload: &[u8],
    ) -> Result<Self, BranchExactCutoverError> {
        let revision = u64::try_from(selected_revision)
            .map_err(|_| BranchExactCutoverError::NegativeRevision(selected_revision))?;
        let decoded = decode_stored(payload)?;
        if decoded.binding.network() != selected_network
            || decoded.binding.authority != selected_authority
            || decoded.revision.get() != revision
            || decoded.to_canonical_bytes() != payload
        {
            return Err(BranchExactCutoverError::PersistedIdentityMismatch);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverBootstrap<Hash> {
    candidate: StoredBranchExactCutover<Hash>,
}

impl<Hash: Q256BitHash> BranchExactCutoverBootstrap<Hash> {
    pub(super) fn seal(binding: BranchExactCutoverBinding<Hash>) -> Self {
        let decision = decision_digest(
            binding.digest,
            BranchExactCutoverRevision(0),
            BranchExactCutoverPhase::LegacyPrimaryDualWrite,
        );
        let mut candidate = StoredBranchExactCutover {
            revision: BranchExactCutoverRevision(0),
            binding,
            phase: BranchExactCutoverPhase::LegacyPrimaryDualWrite,
            last_decision: decision,
            state_digest: BranchExactCutoverStateDigest([1; 32]),
        };
        candidate.state_digest = state_digest(&candidate);
        Self { candidate }
    }

    pub const fn candidate(&self) -> &StoredBranchExactCutover<Hash> {
        &self.candidate
    }
}

/// Processor-owned drain evidence. It is bound to one exact state and becomes
/// stale after any CAS, including an A -> B -> A phase cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCutoverPermit {
    generation: BranchExactCutoverGeneration,
    revision: BranchExactCutoverRevision,
    binding_digest: BranchExactCutoverBindingDigest,
    state_digest: BranchExactCutoverStateDigest,
    decision_digest: BranchExactCutoverDecisionDigest,
}

impl BranchExactCutoverPermit {
    pub(super) fn after_processor_drain<Hash: Q256BitHash>(
        current: &StoredBranchExactCutover<Hash>,
        decision_nonce: [u8; 32],
    ) -> Result<Self, BranchExactCutoverError> {
        if decision_nonce == [0; 32] {
            return Err(BranchExactCutoverError::ZeroDecisionNonce);
        }
        let mut hasher = Sha256::new();
        hasher.update(DECISION_DOMAIN);
        hasher.update(current.binding.digest.as_bytes());
        hasher.update(current.revision.get().to_be_bytes());
        hasher.update([current.phase as u8]);
        hasher.update(current.state_digest.as_bytes());
        hasher.update(decision_nonce);
        Ok(Self {
            generation: current.binding.generation,
            revision: current.revision,
            binding_digest: current.binding.digest,
            state_digest: current.state_digest,
            decision_digest: BranchExactCutoverDecisionDigest(
                hasher.finalize().into(),
            ),
        })
    }
}

/// The only legal h22e3 route transitions. Constructors are crate-private so
/// future runtime composition must first produce a Processor drain permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactCutoverCas<Hash> {
    expected: StoredBranchExactCutover<Hash>,
    candidate: StoredBranchExactCutover<Hash>,
}

impl<Hash: Q256BitHash> SealedBranchExactCutoverCas<Hash> {
    pub(super) fn prepare_target(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::LegacyPrimaryDualWrite,
            BranchExactCutoverPhase::QuiescingToTarget,
        )
    }

    pub(super) fn publish_target(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::QuiescingToTarget,
            BranchExactCutoverPhase::TargetPrimaryDualWrite,
        )
    }

    pub(super) fn abort_target(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::QuiescingToTarget,
            BranchExactCutoverPhase::LegacyPrimaryDualWrite,
        )
    }

    pub(super) fn prepare_legacy(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::TargetPrimaryDualWrite,
            BranchExactCutoverPhase::QuiescingToLegacy,
        )
    }

    pub(super) fn publish_legacy(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::QuiescingToLegacy,
            BranchExactCutoverPhase::LegacyPrimaryDualWrite,
        )
    }

    pub(super) fn abort_legacy(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
    ) -> Result<Self, BranchExactCutoverError> {
        Self::transition(
            expected,
            permit,
            BranchExactCutoverPhase::QuiescingToLegacy,
            BranchExactCutoverPhase::TargetPrimaryDualWrite,
        )
    }

    fn transition(
        expected: &StoredBranchExactCutover<Hash>,
        permit: &BranchExactCutoverPermit,
        required: BranchExactCutoverPhase,
        candidate_phase: BranchExactCutoverPhase,
    ) -> Result<Self, BranchExactCutoverError> {
        if expected.phase != required {
            return Err(BranchExactCutoverError::IllegalTransition {
                from: expected.phase,
                to: candidate_phase,
            });
        }
        if permit.generation != expected.binding.generation
            || permit.revision != expected.revision
            || permit.binding_digest != expected.binding.digest
            || permit.state_digest != expected.state_digest
        {
            return Err(BranchExactCutoverError::StalePermit);
        }
        let revision = expected.revision.checked_next()?;
        let mut candidate = StoredBranchExactCutover {
            revision,
            binding: expected.binding.clone(),
            phase: candidate_phase,
            last_decision: permit.decision_digest,
            state_digest: BranchExactCutoverStateDigest([1; 32]),
        };
        candidate.state_digest = state_digest(&candidate);
        Ok(Self {
            expected: expected.clone(),
            candidate,
        })
    }

    pub const fn expected(&self) -> &StoredBranchExactCutover<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactCutover<Hash> {
        &self.candidate
    }
}

fn binding_digest<Hash: Q256BitHash>(
    binding: &BranchExactCutoverBinding<Hash>,
) -> BranchExactCutoverBindingDigest {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update(encode_binding(binding));
    BranchExactCutoverBindingDigest(hasher.finalize().into())
}

fn decision_digest(
    binding: BranchExactCutoverBindingDigest,
    revision: BranchExactCutoverRevision,
    phase: BranchExactCutoverPhase,
) -> BranchExactCutoverDecisionDigest {
    let mut hasher = Sha256::new();
    hasher.update(DECISION_DOMAIN);
    hasher.update(binding.as_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update([phase as u8]);
    BranchExactCutoverDecisionDigest(hasher.finalize().into())
}

fn state_digest<Hash: Q256BitHash>(
    state: &StoredBranchExactCutover<Hash>,
) -> BranchExactCutoverStateDigest {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DOMAIN);
    hasher.update(state.revision.get().to_be_bytes());
    hasher.update(state.binding.digest.as_bytes());
    hasher.update([state.phase as u8]);
    hasher.update([state.writer_mode() as u8]);
    hasher.update([state.legacy_retention() as u8]);
    hasher.update(state.last_decision.as_bytes());
    BranchExactCutoverStateDigest(hasher.finalize().into())
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn encode_binding<Hash: Q256BitHash>(
    binding: &BranchExactCutoverBinding<Hash>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&binding.generation.get().to_be_bytes());
    encode_authority(binding.authority, &mut bytes);
    bytes.extend_from_slice(&binding.watermark.canonical_chain_bytes());
    bytes.extend_from_slice(&binding.watermark.pending_id().get().to_be_bytes());
    bytes.extend_from_slice(binding.schema_digest.as_bytes());
    bytes.extend_from_slice(binding.backfill_digest.as_bytes());
    bytes.extend_from_slice(binding.shadow_consumed_digest.as_bytes());
    bytes.extend_from_slice(binding.writer_activation_digest.as_bytes());
    bytes.extend_from_slice(&binding.writer_revision.to_be_bytes());
    bytes.extend_from_slice(binding.writer_state_digest.as_bytes());
    bytes.extend_from_slice(&binding.authority_head_revision.to_be_bytes());
    bytes.extend_from_slice(binding.authority_head_digest.as_bytes());
    bytes
}

fn encode_stored<Hash: Q256BitHash>(state: &StoredBranchExactCutover<Hash>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&state.revision.get().to_be_bytes());
    out.extend_from_slice(&encode_binding(&state.binding));
    out.extend_from_slice(state.binding.digest.as_bytes());
    out.push(state.phase as u8);
    out.push(state.writer_mode() as u8);
    out.push(state.legacy_retention() as u8);
    out.extend_from_slice(state.last_decision.as_bytes());
    out.extend_from_slice(state.state_digest.as_bytes());
    out
}

fn decode_stored<Hash: Q256BitHash>(
    payload: &[u8],
) -> Result<StoredBranchExactCutover<Hash>, BranchExactCutoverError> {
    let mut decoder = Decoder::new(payload);
    if decoder.array::<8>()? != MAGIC {
        return Err(BranchExactCutoverError::InvalidMagic);
    }
    let version = decoder.u16()?;
    if version != CODEC_VERSION {
        return Err(BranchExactCutoverError::UnknownCodecVersion(version));
    }
    let revision = BranchExactCutoverRevision::try_new(decoder.u64()?)?;
    let generation = BranchExactCutoverGeneration::try_new(decoder.u64()?)?;
    let authority = match decoder.u8()? {
        1 => {
            if decoder.array::<6>()? != [0; 6] {
                return Err(BranchExactCutoverError::NonCanonicalAuthority);
            }
            AuthorityScope::Coordinator
        }
        2 => AuthorityScope::Realm {
            realm_id: decoder.u32()?,
            realm_sub_id: decoder.u16()?,
        },
        value => return Err(BranchExactCutoverError::UnknownAuthority(value)),
    };
    if matches!(authority, AuthorityScope::Coordinator) {
        return Err(BranchExactCutoverError::CoordinatorNotQualified);
    }
    let chain = decoder.array::<CANONICAL_CHAIN_REF_V1_LEN>()?;
    let pending = UniquePendingId::try_new(decoder.u64()?)
        .map_err(|_| BranchExactCutoverError::InvalidPendingId)?;
    let watermark = BranchPendingMapping::from_canonical_chain_bytes(&chain, pending)
        .map_err(|_| BranchExactCutoverError::InvalidCanonicalRef)?;
    let schema_digest = BranchExactCutoverSchemaDigest::from_checked(decoder.array()?)?;
    let backfill_digest = BranchExactCutoverBackfillDigest::from_checked(decoder.array()?)?;
    let shadow_consumed_digest =
        BranchExactCutoverShadowConsumedDigest::from_checked(decoder.array()?)?;
    let writer_activation_digest =
        BranchExactCutoverWriterActivationDigest::from_checked(decoder.array()?)?;
    let writer_revision = decoder.u64()?;
    let writer_state_digest =
        BranchExactCutoverWriterStateDigest::from_checked(decoder.array()?)?;
    let authority_head_revision = decoder.u64()?;
    let authority_head_digest =
        BranchExactCutoverAuthorityHeadDigest::from_checked(decoder.array()?)?;
    let encoded_binding_digest =
        BranchExactCutoverBindingDigest::from_checked(decoder.array()?)?;
    let phase = BranchExactCutoverPhase::try_from_u8(decoder.u8()?)?;
    if decoder.u8()? != BranchExactCutoverWriterMode::DualWrite as u8
        || decoder.u8()? != BranchExactLegacyRetention::Required as u8
    {
        return Err(BranchExactCutoverError::UnsupportedCapability);
    }
    let last_decision = BranchExactCutoverDecisionDigest::from_checked(decoder.array()?)?;
    let encoded_state_digest = BranchExactCutoverStateDigest::from_checked(decoder.array()?)?;
    decoder.finish()?;

    let mut binding = BranchExactCutoverBinding {
        generation,
        authority,
        watermark,
        schema_digest,
        backfill_digest,
        shadow_consumed_digest,
        writer_activation_digest,
        writer_revision,
        writer_state_digest,
        authority_head_revision,
        authority_head_digest,
        digest: encoded_binding_digest,
    };
    let actual_binding_digest = binding_digest(&binding);
    if actual_binding_digest != encoded_binding_digest {
        return Err(BranchExactCutoverError::BindingDigestMismatch);
    }
    binding.digest = actual_binding_digest;
    let state = StoredBranchExactCutover {
        revision,
        binding,
        phase,
        last_decision,
        state_digest: encoded_state_digest,
    };
    if state_digest(&state) != encoded_state_digest {
        return Err(BranchExactCutoverError::StateDigestMismatch);
    }
    Ok(state)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BranchExactCutoverError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(BranchExactCutoverError::TruncatedPayload)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactCutoverError::TruncatedPayload)?;
        self.offset = end;
        Ok(bytes.try_into().expect("fixed decoder slice"))
    }

    fn u8(&mut self) -> Result<u8, BranchExactCutoverError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, BranchExactCutoverError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BranchExactCutoverError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, BranchExactCutoverError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), BranchExactCutoverError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BranchExactCutoverError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactCutoverError {
    GenerationOutOfRange(u64),
    RevisionOutOfRange(u64),
    RevisionOverflow,
    NegativeGeneration(i64),
    NegativeRevision(i64),
    CoordinatorNotQualified,
    WriterNotActive,
    ShadowEvidenceMismatch,
    AuthorityHeadMismatch,
    ZeroEvidence,
    ZeroDecisionNonce,
    StalePermit,
    IllegalTransition {
        from: BranchExactCutoverPhase,
        to: BranchExactCutoverPhase,
    },
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownPhase(u8),
    UnknownAuthority(u8),
    NonCanonicalAuthority,
    InvalidPendingId,
    InvalidCanonicalRef,
    UnsupportedCapability,
    BindingDigestMismatch,
    StateDigestMismatch,
    PersistedIdentityMismatch,
    TruncatedPayload,
    TrailingBytes,
    RouteQuiescing,
    InvalidWriterFenceLength(usize),
}

impl fmt::Display for BranchExactCutoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "branch-exact cutover rejected: {self:?}")
    }
}

impl Error for BranchExactCutoverError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        protocol::core_types::Q256BitHash, PHash,
    };
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };

    use super::*;
    use crate::rollback::{
        BranchExactCutoverRouteFence, BranchExactCutoverRuntimeError,
    };

    fn binding(seed: u8) -> BranchExactCutoverBinding<PHash> {
        let chain = CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(7),
            CheckpointRef::new(
                CheckpointId::new(100),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes(
                    [seed; 32],
                )),
            ),
        );
        let mut binding = BranchExactCutoverBinding {
            generation: BranchExactCutoverGeneration::try_new(9).unwrap(),
            authority: AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
            watermark: BranchPendingMapping::new(
                chain,
                UniquePendingId::try_new(500).unwrap(),
            ),
            schema_digest: BranchExactCutoverSchemaDigest([1; 32]),
            backfill_digest: BranchExactCutoverBackfillDigest([2; 32]),
            shadow_consumed_digest: BranchExactCutoverShadowConsumedDigest([3; 32]),
            writer_activation_digest: BranchExactCutoverWriterActivationDigest([4; 32]),
            writer_revision: 12,
            writer_state_digest: BranchExactCutoverWriterStateDigest([5; 32]),
            authority_head_revision: 13,
            authority_head_digest: BranchExactCutoverAuthorityHeadDigest([6; 32]),
            digest: BranchExactCutoverBindingDigest([7; 32]),
        };
        binding.digest = binding_digest(&binding);
        binding
    }

    fn bootstrap() -> StoredBranchExactCutover<PHash> {
        BranchExactCutoverBootstrap::seal(binding(8))
            .candidate()
            .clone()
    }

    fn permit(state: &StoredBranchExactCutover<PHash>, seed: u8) -> BranchExactCutoverPermit {
        BranchExactCutoverPermit::after_processor_drain(state, [seed; 32]).unwrap()
    }

    #[test]
    fn codec_is_deterministic_and_branch_exact() {
        let state = bootstrap();
        let a = state.to_canonical_bytes();
        let b = state.to_canonical_bytes();
        assert_eq!(a, b);
        let decoded = StoredBranchExactCutover::<PHash>::decode_persisted(9, 0, &a).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(decoded.binding().watermark().canonical_chain().chain_epoch().get(), 7);
        assert_eq!(decoded.binding().watermark().pending_id().get(), 500);
    }

    #[test]
    fn persisted_identity_and_codec_fail_closed() {
        let state = bootstrap();
        let bytes = state.to_canonical_bytes();
        assert_eq!(
            StoredBranchExactCutover::<PHash>::decode_persisted(10, 0, &bytes),
            Err(BranchExactCutoverError::PersistedIdentityMismatch)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            StoredBranchExactCutover::<PHash>::decode_persisted(9, 0, &trailing),
            Err(BranchExactCutoverError::TrailingBytes)
        );
        let mut version = bytes;
        version[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            StoredBranchExactCutover::<PHash>::decode_persisted(9, 0, &version),
            Err(BranchExactCutoverError::UnknownCodecVersion(2))
        );
    }

    #[test]
    fn target_route_can_publish_or_abort() {
        let legacy = bootstrap();
        let prepared = SealedBranchExactCutoverCas::prepare_target(
            &legacy,
            &permit(&legacy, 1),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(prepared.phase(), BranchExactCutoverPhase::QuiescingToTarget);
        let target = SealedBranchExactCutoverCas::publish_target(
            &prepared,
            &permit(&prepared, 2),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(target.phase(), BranchExactCutoverPhase::TargetPrimaryDualWrite);

        let aborted = SealedBranchExactCutoverCas::abort_target(
            &prepared,
            &permit(&prepared, 3),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(aborted.phase(), BranchExactCutoverPhase::LegacyPrimaryDualWrite);
    }

    #[test]
    fn target_route_can_return_to_legacy_or_abort_return() {
        let legacy = bootstrap();
        let prepared = SealedBranchExactCutoverCas::prepare_target(
            &legacy,
            &permit(&legacy, 1),
        )
        .unwrap()
        .candidate()
        .clone();
        let target = SealedBranchExactCutoverCas::publish_target(
            &prepared,
            &permit(&prepared, 2),
        )
        .unwrap()
        .candidate()
        .clone();
        let fallback = SealedBranchExactCutoverCas::prepare_legacy(
            &target,
            &permit(&target, 3),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(fallback.phase(), BranchExactCutoverPhase::QuiescingToLegacy);
        assert_eq!(
            SealedBranchExactCutoverCas::publish_legacy(
                &fallback,
                &permit(&fallback, 4),
            )
            .unwrap()
            .candidate()
            .phase(),
            BranchExactCutoverPhase::LegacyPrimaryDualWrite
        );
        assert_eq!(
            SealedBranchExactCutoverCas::abort_legacy(
                &fallback,
                &permit(&fallback, 5),
            )
            .unwrap()
            .candidate()
            .phase(),
            BranchExactCutoverPhase::TargetPrimaryDualWrite
        );
    }

    #[test]
    fn stale_permit_and_aba_are_rejected() {
        let legacy_a = bootstrap();
        let stale = permit(&legacy_a, 1);
        let prepared = SealedBranchExactCutoverCas::prepare_target(&legacy_a, &stale)
            .unwrap()
            .candidate()
            .clone();
        let legacy_b = SealedBranchExactCutoverCas::abort_target(
            &prepared,
            &permit(&prepared, 2),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(legacy_a.phase(), legacy_b.phase());
        assert_ne!(legacy_a.revision(), legacy_b.revision());
        assert_eq!(
            SealedBranchExactCutoverCas::prepare_target(&legacy_b, &stale),
            Err(BranchExactCutoverError::StalePermit)
        );
    }

    #[test]
    fn illegal_skip_is_rejected_and_retention_is_closed() {
        let legacy = bootstrap();
        assert_eq!(legacy.writer_mode(), BranchExactCutoverWriterMode::DualWrite);
        assert_eq!(legacy.legacy_retention(), BranchExactLegacyRetention::Required);
        assert!(matches!(
            SealedBranchExactCutoverCas::publish_target(&legacy, &permit(&legacy, 1)),
            Err(BranchExactCutoverError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn revision_and_generation_bounds_fail_closed() {
        assert_eq!(
            BranchExactCutoverGeneration::try_new(i64::MAX as u64 + 1),
            Err(BranchExactCutoverError::GenerationOutOfRange(
                i64::MAX as u64 + 1
            ))
        );
        assert_eq!(
            BranchExactCutoverRevision::try_new(i64::MAX as u64 + 1),
            Err(BranchExactCutoverError::RevisionOutOfRange(
                i64::MAX as u64 + 1
            ))
        );
    }

    #[test]
    fn runtime_route_fence_rejects_quiescing_and_detects_stale_state() {
        let legacy = bootstrap();
        let fence = BranchExactCutoverRouteFence::try_from_current(&legacy).unwrap();
        assert!(fence.matches(&legacy));
        let durable = fence.writer_fence();
        assert_eq!(
            BranchExactWriterCutoverFence::decode_canonical(&durable.encode_canonical()),
            Ok(durable)
        );

        let prepared = SealedBranchExactCutoverCas::prepare_target(
            &legacy,
            &permit(&legacy, 1),
        )
        .unwrap()
        .candidate()
        .clone();
        assert!(!fence.matches(&prepared));
        assert_eq!(
            BranchExactCutoverRouteFence::try_from_current(&prepared),
            Err(BranchExactCutoverRuntimeError::RouteQuiescing)
        );
    }
}
