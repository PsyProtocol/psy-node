//! Typed hand-off between durable rollback coordination and process-local
//! checkpoint/tree reconstruction.
//!
//! These values are observations, not storage capabilities.  A backend must
//! freshly revalidate every binding before accepting a completion report.

use std::{error::Error, fmt};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, ChainEpoch, NetworkId},
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use super::pending_generation_identity::PendingGenerationContext;
use super::pending_generation::ProcNamespacePrefix;
use super::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
};

const DIRECTIVE_DOMAIN: &[u8] = b"psy.rollback.runtime-rebuild-directive.v1\0";
const REPORT_DOMAIN: &[u8] = b"psy.rollback.runtime-rebuild-report.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackRuntimeRebuildDirective<Hash> {
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    global_restore_barrier_slot: [u8; 32],
    global_restore_barrier_digest: [u8; 32],
    participant_restore_slot: [u8; 32],
    participant_restore_digest: [u8; 32],
    processing: Option<PendingGenerationContext>,
    gathering: Option<PendingGenerationContext>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RollbackRuntimeRebuildDirective<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_storage(
        authority: AuthorityScope,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        global_restore_barrier_slot: [u8; 32],
        global_restore_barrier_digest: [u8; 32],
        participant_restore_slot: [u8; 32],
        participant_restore_digest: [u8; 32],
        processing: Option<PendingGenerationContext>,
        gathering: Option<PendingGenerationContext>,
    ) -> Result<Self, RollbackRuntimeRebuildError> {
        if [
            participant_plan_digest,
            global_restore_barrier_slot,
            global_restore_barrier_digest,
            participant_restore_slot,
            participant_restore_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(RollbackRuntimeRebuildError::ZeroCommitment);
        }
        let (Some(processing), Some(gathering)) = (processing, gathering) else {
            return Err(RollbackRuntimeRebuildError::MissingPendingContexts);
        };
        if gathering.pending_id().get()
            != processing
                .pending_id()
                .get()
                .checked_add(1)
                .ok_or(RollbackRuntimeRebuildError::PendingOverflow)?
        {
            return Err(RollbackRuntimeRebuildError::NonAdjacentPendingContexts);
        }
        let prefix = ProcNamespacePrefix::for_authority(target.network_id(), authority);
        if processing.proc_checkpoint_id() != prefix.derive_proc_id(processing.pending_id())
            || gathering.proc_checkpoint_id() != prefix.derive_proc_id(gathering.pending_id())
        {
            return Err(RollbackRuntimeRebuildError::ProcNamespaceMismatch);
        }
        let digest = directive_digest(
            authority,
            &target,
            &participant_plan_digest,
            &global_restore_barrier_slot,
            &global_restore_barrier_digest,
            &participant_restore_slot,
            &participant_restore_digest,
            Some(processing),
            Some(gathering),
        );
        Ok(Self {
            authority,
            target,
            participant_plan_digest,
            global_restore_barrier_slot,
            global_restore_barrier_digest,
            participant_restore_slot,
            participant_restore_digest,
            processing: Some(processing),
            gathering: Some(gathering),
            digest,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub const fn participant_plan_digest(&self) -> &[u8; 32] {
        &self.participant_plan_digest
    }

    pub const fn global_restore_barrier_slot(&self) -> &[u8; 32] {
        &self.global_restore_barrier_slot
    }

    pub const fn global_restore_barrier_digest(&self) -> &[u8; 32] {
        &self.global_restore_barrier_digest
    }

    pub const fn participant_restore_slot(&self) -> &[u8; 32] {
        &self.participant_restore_slot
    }

    pub const fn participant_restore_digest(&self) -> &[u8; 32] {
        &self.participant_restore_digest
    }

    pub const fn processing(&self) -> Option<PendingGenerationContext> {
        self.processing
    }

    pub const fn gathering(&self) -> Option<PendingGenerationContext> {
        self.gathering
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackRuntimeRebuildReport<Hash> {
    directive_digest: [u8; 32],
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    backup_min_checkpoint: u64,
    backup_next_checkpoint: u64,
    backup_root: Hash,
    processor_checkpoint: u64,
    authority_state_checkpoint: u64,
    authority_state_root: Hash,
    processing: Option<PendingGenerationContext>,
    gathering: Option<PendingGenerationContext>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RollbackRuntimeRebuildReport<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_after_exact_rebuild(
        directive: &RollbackRuntimeRebuildDirective<Hash>,
        backup_min_checkpoint: u64,
        backup_next_checkpoint: u64,
        backup_root: Hash,
        processor_checkpoint: u64,
        authority_state_checkpoint: u64,
        authority_state_root: Hash,
        processing: Option<PendingGenerationContext>,
        gathering: Option<PendingGenerationContext>,
    ) -> Result<Self, RollbackRuntimeRebuildError> {
        let target_checkpoint = directive.target.checkpoint().checkpoint_id().get();
        let expected_next = target_checkpoint
            .checked_add(1)
            .ok_or(RollbackRuntimeRebuildError::CheckpointOverflow)?;
        // A genesis database may deliberately contain no materialized leaf;
        // all non-genesis rebuilds must end exactly one past the target.
        let backup_range_exact = backup_next_checkpoint == expected_next
            || (target_checkpoint == 0 && backup_next_checkpoint == 0);
        if !backup_range_exact
            || backup_min_checkpoint > backup_next_checkpoint
            || backup_min_checkpoint > target_checkpoint
            || processor_checkpoint != target_checkpoint
            || authority_state_checkpoint > target_checkpoint
            || processing != directive.processing
            || gathering != directive.gathering
        {
            return Err(RollbackRuntimeRebuildError::RuntimeStateMismatch);
        }
        let digest = report_digest(
            directive.digest,
            directive.authority,
            &directive.target,
            backup_min_checkpoint,
            backup_next_checkpoint,
            backup_root,
            processor_checkpoint,
            authority_state_checkpoint,
            authority_state_root,
            processing,
            gathering,
        );
        Ok(Self {
            directive_digest: directive.digest,
            authority: directive.authority,
            target: directive.target,
            backup_min_checkpoint,
            backup_next_checkpoint,
            backup_root,
            processor_checkpoint,
            authority_state_checkpoint,
            authority_state_root,
            processing,
            gathering,
            digest,
        })
    }

    pub const fn directive_digest(&self) -> &[u8; 32] {
        &self.directive_digest
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub const fn backup_min_checkpoint(&self) -> u64 {
        self.backup_min_checkpoint
    }

    pub const fn backup_next_checkpoint(&self) -> u64 {
        self.backup_next_checkpoint
    }

    pub const fn backup_root(&self) -> Hash {
        self.backup_root
    }

    pub const fn processor_checkpoint(&self) -> u64 {
        self.processor_checkpoint
    }

    pub const fn authority_state_checkpoint(&self) -> u64 {
        self.authority_state_checkpoint
    }

    pub const fn authority_state_root(&self) -> Hash {
        self.authority_state_root
    }

    pub const fn processing(&self) -> Option<PendingGenerationContext> {
        self.processing
    }

    pub const fn gathering(&self) -> Option<PendingGenerationContext> {
        self.gathering
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn directive_digest<Hash: Q256BitHash>(
    authority: AuthorityScope,
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    global_restore_barrier_slot: &[u8; 32],
    global_restore_barrier_digest: &[u8; 32],
    participant_restore_slot: &[u8; 32],
    participant_restore_digest: &[u8; 32],
    processing: Option<PendingGenerationContext>,
    gathering: Option<PendingGenerationContext>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIRECTIVE_DOMAIN);
    hasher.update(encode_authority(authority));
    hasher.update(target.to_canonical_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(global_restore_barrier_slot);
    hasher.update(global_restore_barrier_digest);
    hasher.update(participant_restore_slot);
    hasher.update(participant_restore_digest);
    encode_context(&mut hasher, processing);
    encode_context(&mut hasher, gathering);
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn report_digest<Hash: Q256BitHash>(
    directive_digest: [u8; 32],
    authority: AuthorityScope,
    target: &CanonicalChainRef<Hash>,
    backup_min_checkpoint: u64,
    backup_next_checkpoint: u64,
    backup_root: Hash,
    processor_checkpoint: u64,
    authority_state_checkpoint: u64,
    authority_state_root: Hash,
    processing: Option<PendingGenerationContext>,
    gathering: Option<PendingGenerationContext>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REPORT_DOMAIN);
    hasher.update(directive_digest);
    hasher.update(encode_authority(authority));
    hasher.update(target.to_canonical_bytes());
    hasher.update(backup_min_checkpoint.to_be_bytes());
    hasher.update(backup_next_checkpoint.to_be_bytes());
    hasher.update(backup_root.into_owned_32bytes());
    hasher.update(processor_checkpoint.to_be_bytes());
    hasher.update(authority_state_checkpoint.to_be_bytes());
    hasher.update(authority_state_root.into_owned_32bytes());
    encode_context(&mut hasher, processing);
    encode_context(&mut hasher, gathering);
    hasher.finalize().into()
}

fn encode_context(hasher: &mut Sha256, context: Option<PendingGenerationContext>) {
    match context {
        None => hasher.update([0]),
        Some(context) => {
            hasher.update([1]);
            hasher.update(context.pending_id().get().to_be_bytes());
            hasher.update(context.proc_checkpoint_id().as_u128().to_be_bytes());
        }
    }
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    match authority {
        AuthorityScope::Coordinator => [0; 7],
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            let mut encoded = [0; 7];
            encoded[0] = 1;
            encoded[1..5].copy_from_slice(&realm_id.to_be_bytes());
            encoded[5..7].copy_from_slice(&realm_sub_id.to_be_bytes());
            encoded
        }
    }
}

pub fn restored_target<Hash: Q256BitHash>(
    old_target: CanonicalChainRef<Hash>,
) -> Result<CanonicalChainRef<Hash>, RollbackRuntimeRebuildError> {
    Ok(CanonicalChainRef::new(
        old_target.network_id(),
        ChainEpoch::new(
            old_target
                .chain_epoch()
                .get()
                .checked_add(1)
                .ok_or(RollbackRuntimeRebuildError::EpochOverflow)?,
        ),
        *old_target.checkpoint(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackRuntimeRebuildError {
    ZeroCommitment,
    MissingPendingContexts,
    NonAdjacentPendingContexts,
    ProcNamespaceMismatch,
    PendingOverflow,
    EpochOverflow,
    CheckpointOverflow,
    RuntimeStateMismatch,
}

impl fmt::Display for RollbackRuntimeRebuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "rollback runtime rebuild error: {self:?}")
    }
}

impl Error for RollbackRuntimeRebuildError {}

/// Storage boundary used by a Coordinator process to select its immutable
/// VERIFYING task, append the exact process-local rebuild result, and ask the
/// backend to storage-select the complete fixed Realm report set. Only the
/// final method may publish the canonical target; it accepts no caller-supplied
/// participant list or report.
#[async_trait]
pub trait CoordinatorRollbackRuntimeRebuildStore<Hash>: Send + Sync
where
    Hash: Q256BitHash,
{
    async fn read_selected_coordinator_runtime_rebuild(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<Option<RollbackRuntimeRebuildDirective<Hash>>>;

    async fn persist_coordinator_runtime_rebuild_report(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> anyhow::Result<()>;

    /// Storage-select every plan participant's exact rebuild report and, only
    /// when the complete immutable set exists, publish the restored target.
    /// A caller cannot supply or truncate the Realm set.
    async fn try_publish_restored_runtime(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CoordinatorRollbackRuntimePublication<Hash>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorRollbackRuntimePublication<Hash> {
    AwaitingRealmReports {
        completed: u64,
        expected: u64,
    },
    Published(StoredCanonicalHead<Hash>),
}

/// Storage-selected Realm rebuild work.  This is a read-only observation:
/// only the Coordinator control store may select the exact VERIFYING head and
/// its matching immutable directive, and this value grants no head mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRealmRollbackRuntimeRebuild<Hash> {
    verifying_head: StoredCanonicalHead<Hash>,
    directive: RollbackRuntimeRebuildDirective<Hash>,
}

impl<Hash: Q256BitHash> SelectedRealmRollbackRuntimeRebuild<Hash> {
    pub fn try_from_storage(
        verifying_head: StoredCanonicalHead<Hash>,
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<Self, RollbackRuntimeRebuildError> {
        let request = match verifying_head.rollback_control() {
            RollbackControlState::Verifying(request) => request,
            _ => return Err(RollbackRuntimeRebuildError::RuntimeStateMismatch),
        };
        if !matches!(directive.authority(), AuthorityScope::Realm { .. })
            || directive.target().network_id()
                != verifying_head.canonical_ref().network_id()
            || directive.target().chain_epoch()
                != verifying_head.canonical_ref().chain_epoch()
            || directive.target().checkpoint() != request.target()
            || directive.participant_plan_digest() != request.plan_digest().as_bytes()
        {
            return Err(RollbackRuntimeRebuildError::RuntimeStateMismatch);
        }
        Ok(Self {
            verifying_head,
            directive,
        })
    }

    pub const fn verifying_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.verifying_head
    }

    pub const fn directive(&self) -> &RollbackRuntimeRebuildDirective<Hash> {
        &self.directive
    }
}

/// Realm-side control-plane boundary backed by the Coordinator's existing
/// canonical-head and rollback archive tables.  It deliberately contains no
/// DDL or canonical-head write operation.
#[async_trait]
pub trait RealmRollbackRuntimeControl<Hash>: Send + Sync
where
    Hash: Q256BitHash,
{
    /// Advance this Realm's storage-local participant work for the current
    /// Coordinator-selected rollback phase. The caller supplies only its
    /// immutable authority identity; target/plan/phase are selected from the
    /// Coordinator control namespace.
    async fn progress_realm_rollback_participant(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> anyhow::Result<RealmRollbackParticipantProgress<Hash>>;

    async fn read_realm_rollback_control_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<Hash>>;

    async fn read_selected_realm_runtime_rebuild(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> anyhow::Result<Option<SelectedRealmRollbackRuntimeRebuild<Hash>>>;

    async fn persist_realm_runtime_rebuild_report(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> anyhow::Result<()>;

    /// Returns true only after the exact restored target is globally
    /// published as Idle.  VERIFYING and ALL_REALMS_READY remain false.
    async fn is_realm_runtime_rebuild_published(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
    ) -> anyhow::Result<bool>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmRollbackParticipantProgress<Hash> {
    AwaitingCoordinator(StoredCanonicalHead<Hash>),
    ArchivePrepared {
        head: StoredCanonicalHead<Hash>,
        entry_count: u64,
    },
    DeletePrepared {
        head: StoredCanonicalHead<Hash>,
        physical_delete_count: u64,
        restored_row_count: u64,
    },
    RestorePrepared {
        head: StoredCanonicalHead<Hash>,
        final_rows_digest: [u8; 32],
    },
    ReadyForRuntimeRebuild(StoredCanonicalHead<Hash>),
}

#[cfg(test)]
mod tests {
    use parth_core::data::hash::hash256::Hash256;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };

    use super::*;
    use crate::store::typed::UniquePendingId;

    type Hash = Hash256;

    fn target() -> CanonicalChainRef<Hash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(8),
            CheckpointRef::new(
                CheckpointId::new(40),
                CheckpointHash::from_last_chain_hash(Hash256([9; 32])),
            ),
        )
    }

    fn realm_directive() -> RollbackRuntimeRebuildDirective<Hash> {
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let prefix = ProcNamespacePrefix::for_authority(target().network_id(), authority);
        let processing = PendingGenerationContext::try_from_legacy(
            71,
            prefix
                .derive_proc_id(UniquePendingId::try_new(71).unwrap())
                .as_u128(),
        )
        .unwrap();
        let gathering = PendingGenerationContext::try_from_legacy(
            72,
            prefix
                .derive_proc_id(UniquePendingId::try_new(72).unwrap())
                .as_u128(),
        )
        .unwrap();
        RollbackRuntimeRebuildDirective::try_from_storage(
            authority,
            target(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            Some(processing),
            Some(gathering),
        )
        .unwrap()
    }

    #[test]
    fn realm_directive_requires_exact_adjacent_contexts() {
        let directive = realm_directive();
        assert_eq!(directive.target(), &target());
        assert_eq!(directive.processing().unwrap().pending_id().get(), 71);
        assert_eq!(directive.gathering().unwrap().pending_id().get(), 72);
        assert_ne!(directive.digest(), &[0; 32]);

        let authority = directive.authority();
        let prefix = ProcNamespacePrefix::for_authority(target().network_id(), authority);
        let processing = PendingGenerationContext::try_from_legacy(
            71,
            prefix.derive_proc_id(directive.processing().unwrap().pending_id()).as_u128(),
        )
        .unwrap();
        let non_adjacent = PendingGenerationContext::try_from_legacy(
            73,
            prefix
                .derive_proc_id(UniquePendingId::try_new(73).unwrap())
                .as_u128(),
        )
        .unwrap();
        assert_eq!(
            RollbackRuntimeRebuildDirective::try_from_storage(
                authority,
                target(),
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
                Some(processing),
                Some(non_adjacent),
            ),
            Err(RollbackRuntimeRebuildError::NonAdjacentPendingContexts)
        );
    }

    #[test]
    fn coordinator_directive_requires_fresh_authority_contexts() {
        let target = target();
        let prefix = ProcNamespacePrefix::for_authority(
            target.network_id(),
            AuthorityScope::Coordinator,
        );
        let processing_pending = UniquePendingId::try_new(71).unwrap();
        let gathering_pending = UniquePendingId::try_new(72).unwrap();
        let processing = PendingGenerationContext::try_from_legacy(
            71,
            prefix.derive_proc_id(processing_pending).as_u128(),
        )
        .unwrap();
        let gathering = PendingGenerationContext::try_from_legacy(
            72,
            prefix.derive_proc_id(gathering_pending).as_u128(),
        )
        .unwrap();
        let directive = RollbackRuntimeRebuildDirective::try_from_storage(
            AuthorityScope::Coordinator,
            target,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            Some(processing),
            Some(gathering),
        )
        .unwrap();
        assert_eq!(directive.processing(), Some(processing));
        assert_eq!(directive.gathering(), Some(gathering));

        let forged = PendingGenerationContext::try_from_legacy(71, 701).unwrap();
        assert_eq!(
            RollbackRuntimeRebuildDirective::try_from_storage(
                AuthorityScope::Coordinator,
                target,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
                Some(forged),
                Some(gathering),
            ),
            Err(RollbackRuntimeRebuildError::ProcNamespaceMismatch)
        );

        assert_eq!(
            RollbackRuntimeRebuildDirective::try_from_storage(
                AuthorityScope::Coordinator,
                target,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
                None,
                None,
            ),
            Err(RollbackRuntimeRebuildError::MissingPendingContexts)
        );
    }

    #[test]
    fn report_is_bound_to_target_range_roots_and_contexts() {
        let directive = realm_directive();
        let report = RollbackRuntimeRebuildReport::try_after_exact_rebuild(
            &directive,
            8,
            41,
            Hash256([6; 32]),
            40,
            39,
            Hash256([7; 32]),
            directive.processing(),
            directive.gathering(),
        )
        .unwrap();
        assert_eq!(report.directive_digest(), directive.digest());
        assert_eq!(report.backup_next_checkpoint(), 41);
        assert_ne!(report.digest(), &[0; 32]);

        assert_eq!(
            RollbackRuntimeRebuildReport::try_after_exact_rebuild(
                &directive,
                8,
                42,
                Hash256([6; 32]),
                40,
                39,
                Hash256([7; 32]),
                directive.processing(),
                directive.gathering(),
            ),
            Err(RollbackRuntimeRebuildError::RuntimeStateMismatch)
        );
    }

    #[test]
    fn restored_target_advances_epoch_without_changing_checkpoint() {
        let restored = restored_target(target()).unwrap();
        assert_eq!(restored.chain_epoch().get(), 9);
        assert_eq!(restored.checkpoint(), target().checkpoint());
    }
}
