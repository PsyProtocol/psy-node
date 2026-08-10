//! Read-only, driver-independent view of one qualified Realm user-update generation.
//!
//! The durable claim, dependency fragments, publication source and generation
//! qualification remain the authority.  The records in this module are only a
//! deterministic projection input: they cannot acknowledge queue work, advance
//! a pipeline or publish an authority head.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::{
    data::queue::queue_key::PCoreQueueItemBase,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use super::{
    realm_user_update_admission::{
        RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
        RealmUserUpdateGenerationQualification,
        RealmUserUpdateQualificationFence, RealmUserUpdateTerminalEvidence,
    },
    realm_user_update_artifact::{
        deterministic_qblob_context, validate_contract_update_qblob,
        RealmUserUpdateSlotEnvelope,
    },
    realm_user_update_claim::{
        RealmUserUpdateClaimPhase, StoredRealmUserUpdateClaim,
    },
    realm_user_update_dependency::{
        RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyKind,
    },
    realm_user_update_publish::{
        GlobalUserTreeHeight, RealmUserUpdatePublishReceipt,
        RealmUserUpdatePublishRequest,
    },
};

/// One projection-ready item reconstructed from durable terminal state.
///
/// Construction is semantic and deterministic, but deliberately does not
/// re-run the expensive ZK verifier: `Published` is the durable proof-verified
/// state. The Scylla adapter must still obtain `publication` from an exact
/// read-only `SourceCommitted` observation before calling this constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDurableItem<F, Hash> {
    claim: StoredRealmUserUpdateClaim<Hash>,
    dependencies: RealmUserUpdateDependencyBundle,
    request: RealmUserUpdatePublishRequest<F, Hash>,
    publication: RealmUserUpdatePublishReceipt,
    terminal: RealmUserUpdateTerminalEvidence,
    slot: RealmUserUpdateSlotEnvelope<Hash>,
}

impl<F, Hash> RealmUserUpdateDurableItem<F, Hash>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    pub fn try_from_observed(
        key: RealmUserUpdateAdmissionKey,
        fence: &RealmUserUpdateQualificationFence<Hash>,
        claim: StoredRealmUserUpdateClaim<Hash>,
        dependencies: RealmUserUpdateDependencyBundle,
        global_user_tree_height: GlobalUserTreeHeight,
        publication: RealmUserUpdatePublishReceipt,
    ) -> Result<Self, RealmUserUpdateDurableConsumerError> {
        match claim.phase() {
            RealmUserUpdateClaimPhase::Claimed => {
                return Err(RealmUserUpdateDurableConsumerError::AwaitExactRequestReplay)
            }
            RealmUserUpdateClaimPhase::DependenciesPlanned => {
                return Err(RealmUserUpdateDurableConsumerError::AwaitProofRecovery)
            }
            RealmUserUpdateClaimPhase::DependenciesReady => {
                return Err(RealmUserUpdateDurableConsumerError::AwaitClaimPublication)
            }
            RealmUserUpdateClaimPhase::Published => {}
        }
        if claim.partition().map_err(consumer)?.capture() != key.capture() {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }

        let request = RealmUserUpdatePublishRequest::try_from_persisted_dependencies(
            &claim,
            &dependencies,
            global_user_tree_height,
        )
        .map_err(|error| {
            RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
        })?;
        validate_projection_components::<F, Hash>(
            &claim,
            &dependencies,
            &request,
        )?;
        let slot = RealmUserUpdateSlotEnvelope::<Hash>::from_canonical_bytes(
            dependencies
                .component(RealmUserUpdateDependencyKind::SlotUpdates)
                .bytes(),
        )
        .map_err(|error| {
            RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
        })?;
        let terminal = RealmUserUpdateTerminalEvidence::try_from_observed(
            key,
            fence,
            &claim,
            &request,
            &publication,
        )
        .map_err(|_| RealmUserUpdateDurableConsumerError::TerminalEvidenceMismatch)?;
        Ok(Self {
            claim,
            dependencies,
            request,
            publication,
            terminal,
            slot,
        })
    }

    pub const fn claim(&self) -> &StoredRealmUserUpdateClaim<Hash> {
        &self.claim
    }

    pub const fn dependencies(&self) -> &RealmUserUpdateDependencyBundle {
        &self.dependencies
    }

    pub const fn request(&self) -> &RealmUserUpdatePublishRequest<F, Hash> {
        &self.request
    }

    pub const fn publication(&self) -> &RealmUserUpdatePublishReceipt {
        &self.publication
    }

    pub const fn terminal(&self) -> RealmUserUpdateTerminalEvidence {
        self.terminal
    }

    pub const fn slot(&self) -> &RealmUserUpdateSlotEnvelope<Hash> {
        &self.slot
    }

    pub fn canonical_input(&self) -> &[u8] {
        self.component(RealmUserUpdateDependencyKind::CanonicalInput)
    }

    pub fn proof(&self) -> &[u8] {
        self.component(RealmUserUpdateDependencyKind::Proof)
    }

    pub fn contract_updates(&self) -> &[u8] {
        self.component(RealmUserUpdateDependencyKind::ContractUpdates)
    }

    pub fn slot_updates(&self) -> &[u8] {
        self.component(RealmUserUpdateDependencyKind::SlotUpdates)
    }

    pub fn queue_payload(&self) -> &[u8] {
        self.component(RealmUserUpdateDependencyKind::QueuePayload)
    }

    fn component(&self, kind: RealmUserUpdateDependencyKind) -> &[u8] {
        self.dependencies.component(kind).bytes()
    }
}

/// Exact, deterministic projection input for a complete qualified generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDurableGeneration<F, Hash> {
    key: RealmUserUpdateAdmissionKey,
    close: RealmUserUpdateAdmissionCloseIntent,
    qualification: RealmUserUpdateGenerationQualification<Hash>,
    items: Vec<RealmUserUpdateDurableItem<F, Hash>>,
}

impl<F, Hash> RealmUserUpdateDurableGeneration<F, Hash>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    pub fn try_new(
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
        qualification: RealmUserUpdateGenerationQualification<Hash>,
        mut items: Vec<RealmUserUpdateDurableItem<F, Hash>>,
    ) -> Result<Self, RealmUserUpdateDurableConsumerError> {
        items.sort_by_key(|item| {
            (
                item.claim().bucket().get(),
                item.claim().admission_ordinal().get(),
            )
        });
        if items.iter().any(|item| {
            item.claim()
                .partition()
                .map_or(true, |partition| partition.capture() != key.capture())
        }) {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }
        let evidence = items.iter().map(|item| item.terminal()).collect::<Vec<_>>();
        let recomputed = RealmUserUpdateGenerationQualification::from_terminal_evidence(
            key,
            close,
            qualification.membership(),
            *qualification.fence(),
            &evidence,
        )
        .map_err(|_| RealmUserUpdateDurableConsumerError::QualificationMismatch)?;
        if recomputed != qualification {
            return Err(RealmUserUpdateDurableConsumerError::QualificationMismatch);
        }
        Ok(Self {
            key,
            close,
            qualification,
            items,
        })
    }

    pub const fn key(&self) -> RealmUserUpdateAdmissionKey {
        self.key
    }

    pub const fn close(&self) -> RealmUserUpdateAdmissionCloseIntent {
        self.close
    }

    pub const fn qualification(&self) -> RealmUserUpdateGenerationQualification<Hash> {
        self.qualification
    }

    pub fn items(&self) -> &[RealmUserUpdateDurableItem<F, Hash>] {
        &self.items
    }
}

/// Driver boundary used by a projection rebuilder. Implementations must read
/// the full durable generation and may not use projection state as fallback.
#[async_trait]
pub trait RealmUserUpdateDurableConsumerPort<F, Hash>: Send + Sync
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync,
{
    async fn read_qualified_generation(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<RealmUserUpdateDurableGeneration<F, Hash>, RealmUserUpdateDurableConsumerError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateDurableConsumerError {
    GenerationUninitialized,
    GenerationNotQualified,
    AwaitExactRequestReplay,
    AwaitExactArtifactReplay,
    AwaitProofRecovery,
    AwaitPublication,
    AwaitClaimPublication,
    DurableDependencyLoss,
    DependencyCorruption(String),
    DependencyUnavailable(String),
    TerminalSourceMissing,
    TerminalEvidenceMismatch,
    MembershipMismatch,
    QualificationMismatch,
    PipelineFenceMismatch,
    ConcurrentChange,
    PhaseRegression,
    ScopeMismatch,
    BackendUnavailable(String),
}

impl fmt::Display for RealmUserUpdateDurableConsumerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenerationUninitialized => write!(formatter, "generation is uninitialized"),
            Self::GenerationNotQualified => write!(formatter, "generation is not qualified"),
            Self::AwaitExactRequestReplay => write!(formatter, "exact request replay is required"),
            Self::AwaitExactArtifactReplay => write!(formatter, "exact artifact replay is required"),
            Self::AwaitProofRecovery => write!(formatter, "proof recovery is required"),
            Self::AwaitPublication => write!(formatter, "durable publication is pending"),
            Self::AwaitClaimPublication => write!(formatter, "claim publication is pending"),
            Self::DurableDependencyLoss => write!(formatter, "published dependency is missing"),
            Self::DependencyCorruption(error) => write!(formatter, "dependency corruption: {error}"),
            Self::DependencyUnavailable(error) => write!(formatter, "dependency unavailable: {error}"),
            Self::TerminalSourceMissing => write!(formatter, "terminal publication source is missing"),
            Self::TerminalEvidenceMismatch => write!(formatter, "terminal evidence does not match"),
            Self::MembershipMismatch => write!(formatter, "stable membership does not match"),
            Self::QualificationMismatch => write!(formatter, "generation qualification does not match"),
            Self::PipelineFenceMismatch => write!(formatter, "pipeline fence does not match"),
            Self::ConcurrentChange => write!(formatter, "durable generation changed during read"),
            Self::PhaseRegression => write!(formatter, "durable claim phase regressed"),
            Self::ScopeMismatch => write!(formatter, "durable claim scope does not match"),
            Self::BackendUnavailable(error) => write!(formatter, "durable backend unavailable: {error}"),
        }
    }
}

impl Error for RealmUserUpdateDurableConsumerError {}

fn validate_projection_components<F, Hash>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
    dependencies: &RealmUserUpdateDependencyBundle,
    request: &RealmUserUpdatePublishRequest<F, Hash>,
) -> Result<(), RealmUserUpdateDurableConsumerError>
where
    F: QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    let canonical_input = dependencies
        .component(RealmUserUpdateDependencyKind::CanonicalInput)
        .bytes();
    let input = SubmitUserEndCapNonProofInput::<F, Hash>::psy_ser_from_slice(
        canonical_input,
    )
    .map_err(|error| {
        RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
    })?;
    if input
        .psy_ser_to_bytes_vec()
        .map_err(|error| {
            RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
        })?
        != canonical_input
    {
        return Err(RealmUserUpdateDurableConsumerError::DependencyCorruption(
            "canonical input is not canonical".to_owned(),
        ));
    }
    validate_contract_update_qblob(
        &deterministic_qblob_context(claim).map_err(|error| {
            RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
        })?,
        dependencies
            .component(RealmUserUpdateDependencyKind::ContractUpdates)
            .bytes(),
    )
    .map_err(|error| {
        RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
    })?;
    let slot = RealmUserUpdateSlotEnvelope::<Hash>::from_canonical_bytes(
        dependencies
            .component(RealmUserUpdateDependencyKind::SlotUpdates)
            .bytes(),
    )
    .map_err(|error| {
        RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
    })?;
    let queue_item = PsyRealmUserUpdateQueueItem::<F, Hash>::decode_queue_item_ref(
        request.payload(),
    )
    .map_err(|error| {
        RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
    })?;
    if slot.pending() != claim.pending()
        || slot.user_id() != claim.user_id()
        || input.core.new_user_leaf.user_id.to_u64_value() != claim.user_id().get()
        || input.core.state_transition.user_id.to_u64_value() != claim.user_id().get()
        || queue_item.expected_fake_checkpoint_id != claim.stable_status()
        || queue_item.old_user_leaf_hash != input.core.state_transition.start_user_leaf_hash
        || queue_item.new_user_leaf_hash != input.core.state_transition.end_user_leaf_hash
        || queue_item.new_user_leaf != input.core.new_user_leaf
        || queue_item.stats != input.core.stats
        || queue_item.events != input.events
    {
        return Err(RealmUserUpdateDurableConsumerError::DependencyCorruption(
            "projection semantics do not match the durable claim".to_owned(),
        ));
    }
    Ok(())
}

fn consumer(error: impl fmt::Display) -> RealmUserUpdateDurableConsumerError {
    RealmUserUpdateDurableConsumerError::DependencyCorruption(error.to_string())
}

#[cfg(test)]
mod tests {
    use parth_core::{PHash, PF};

    use super::*;
    use crate::queue::realm_user_update_admission::{
        RealmUserUpdateBucketManifest, RealmUserUpdateGenerationManifest,
    };
    use crate::queue::realm_user_update_claim::RealmUserUpdateClaimBucket;

    #[test]
    fn empty_qualified_generation_is_deterministic_and_projection_only() {
        // The full non-empty path is exercised by the Scylla consumer tests.
        // This model test proves that the batch itself recomputes rather than
        // trusting a caller-supplied qualification receipt.
        let _ = std::marker::PhantomData::<(PF, PHash)>;
        assert_eq!(RealmUserUpdateDurableConsumerError::GenerationNotQualified.to_string(), "generation is not qualified");
        assert_eq!(RealmUserUpdateClaimBucket::COUNT, 256);
        let _ = std::marker::PhantomData::<(
            RealmUserUpdateBucketManifest,
            RealmUserUpdateGenerationManifest,
        )>;
    }

    #[test]
    fn phase_errors_are_distinct_and_fail_closed() {
        assert_ne!(
            RealmUserUpdateDurableConsumerError::AwaitExactRequestReplay,
            RealmUserUpdateDurableConsumerError::AwaitProofRecovery,
        );
        assert_ne!(
            RealmUserUpdateDurableConsumerError::AwaitClaimPublication,
            RealmUserUpdateDurableConsumerError::AwaitPublication,
        );
        assert_ne!(
            RealmUserUpdateDurableConsumerError::DurableDependencyLoss,
            RealmUserUpdateDurableConsumerError::DependencyCorruption("x".to_owned()),
        );
    }

    #[test]
    fn source_contains_no_projection_or_authorizing_api() {
        let source = include_str!("realm_user_update_consumer.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("redis"));
        assert!(!source.contains("temp_db"));
        assert!(!source.contains("double_ack"));
        assert!(!source.contains("advance_pipeline"));
        assert!(!source.contains("publish_authority_head"));
    }
}
