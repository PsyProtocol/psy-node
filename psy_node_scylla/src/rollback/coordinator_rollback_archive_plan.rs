//! Driver-independent Coordinator suffix-archive plan for in-place rollback.
//!
//! This module is deliberately pre-PONR.  It resolves the explicit rollback
//! request against the exhaustive key-domain registry and commits the exact
//! `(target, requested_head]` archive scope, but it cannot persist archive
//! rows, delete hot rows, publish the target head, or authorize any of those
//! operations.  A blocked domain remains in the plan as a typed blocker rather
//! than being silently skipped.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::rollback_control::{
    RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
};
use sha2::{Digest, Sha256};

use super::{
    DeleteStrategy, DomainPreparedUpdateCoverage, RecoveryAction,
    RegistryBlocker, RegistryReadiness, RollbackPolicy, ScyllaKeyDomain,
    ScyllaPhysicalTableId, VersionAxis, key_domain_registry,
    physical_descriptor,
};

const PLAN_MAGIC: [u8; 8] = *b"PSYCRAR1";
const PLAN_VERSION: u16 = 1;
const PLAN_DIGEST_DOMAIN: &[u8] = b"psy/coordinator-rollback-archive-plan/v1";

/// The exact hot-table treatment required for one Coordinator-visible key
/// domain before the global destructive barrier may be crossed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CoordinatorRollbackArchiveAction {
    /// Enumerate checkpoint-keyed partitions in `(target, requested_head]`.
    ArchiveCheckpointPartitions = 1,
    /// Enumerate manifest-selected partitions and archive the checkpoint
    /// clustering range `(target, requested_head]` inside each partition.
    ArchiveCheckpointClusteringRanges = 2,
    /// Archive manifest-selected derived rows born on the discarded suffix.
    ArchiveManifestPointRowsAndRebuild = 3,
    /// Archive checkpoint partitions, then rebuild the derived projection from
    /// authoritative target state after deletion.
    ArchiveCheckpointPartitionsAndRebuild = 4,
    /// Archive clustering suffixes, then rebuild the derived projection.
    ArchiveCheckpointClusteringRangesAndRebuild = 5,
    /// Archive the current singleton and later restore its exact target value.
    ArchiveSingletonAndRestoreTarget = 6,
    /// Operational identity survives checkpoint rollback and is not deleted.
    PreserveOperational = 7,
    /// Pending-keyed operational state must move to a new namespace instead of
    /// being interpreted as checkpoint suffix data.
    RotateOperationalNamespace = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorRollbackArchiveDomainPlan {
    key_domain: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
    action: CoordinatorRollbackArchiveAction,
}

impl CoordinatorRollbackArchiveDomainPlan {
    pub const fn key_domain(self) -> ScyllaKeyDomain {
        self.key_domain
    }

    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn action(self) -> CoordinatorRollbackArchiveAction {
        self.action
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorRollbackArchivePlanBlocker {
    SnapshotReplayNotSupported,
    RegistryBlocked {
        key_domain: ScyllaKeyDomain,
        blocker: RegistryBlocker,
    },
    RetireCandidate {
        key_domain: ScyllaKeyDomain,
    },
    UnsupportedDomainContract {
        key_domain: ScyllaKeyDomain,
        version_axis: VersionAxis,
        rollback_policy: RollbackPolicy,
        recovery_action: RecoveryAction,
    },
    RequiredDeleteStrategyMissing {
        key_domain: ScyllaKeyDomain,
        required: DeleteStrategy,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorRollbackArchivePlanDigest([u8; 32]);

impl CoordinatorRollbackArchivePlanDigest {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(super) fn try_from_archive_bytes(
        bytes: [u8; 32],
    ) -> Result<Self, CoordinatorRollbackArchivePlanDigestError> {
        if bytes == [0; 32] {
            Err(CoordinatorRollbackArchivePlanDigestError::ZeroDigest)
        } else {
            Ok(Self(bytes))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoordinatorRollbackArchivePlanDigestError {
    ZeroDigest,
}

impl fmt::Display for CoordinatorRollbackArchivePlanDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator archive-plan digest: {self:?}")
    }
}

impl Error for CoordinatorRollbackArchivePlanDigestError {}

/// Deterministic, non-executable Coordinator participant plan.
///
/// `global_plan_digest` binds this participant to the explicit product-level
/// request.  It is intentionally distinct from `digest`, which commits only
/// this Coordinator participant plan; the later global orchestrator must bind
/// the Coordinator and every Realm participant digest before admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorRollbackArchivePlan<Hash> {
    request: RollbackRequest<Hash>,
    domains: Vec<CoordinatorRollbackArchiveDomainPlan>,
    blockers: Vec<CoordinatorRollbackArchivePlanBlocker>,
    canonical_bytes: Vec<u8>,
    digest: CoordinatorRollbackArchivePlanDigest,
}

impl<Hash: Q256BitHash> CoordinatorRollbackArchivePlan<Hash> {
    pub fn resolve(request: RollbackRequest<Hash>) -> Self {
        let mut domains = Vec::new();
        let mut blockers = Vec::new();

        if request.execution_mode() != RollbackExecutionMode::InPlace {
            blockers.push(
                CoordinatorRollbackArchivePlanBlocker::SnapshotReplayNotSupported,
            );
        }

        for descriptor in key_domain_registry() {
            if descriptor.prepared_coverage.coordinator
                == DomainPreparedUpdateCoverage::NotApplicable
            {
                continue;
            }
            match descriptor.readiness {
                RegistryReadiness::Blocked(blocker) => {
                    blockers.push(
                        CoordinatorRollbackArchivePlanBlocker::RegistryBlocked {
                            key_domain: descriptor.id,
                            blocker,
                        },
                    );
                    continue;
                }
                RegistryReadiness::RetireCandidate => {
                    blockers.push(
                        CoordinatorRollbackArchivePlanBlocker::RetireCandidate {
                            key_domain: descriptor.id,
                        },
                    );
                    continue;
                }
                RegistryReadiness::Ready => {}
            }

            let physical = physical_descriptor(descriptor.physical_table);
            match resolve_action(
                descriptor.id,
                descriptor.version_axis,
                descriptor.rollback_policy,
                descriptor.recovery_action,
                physical.delete_candidates,
            ) {
                Ok(action) => domains.push(CoordinatorRollbackArchiveDomainPlan {
                    key_domain: descriptor.id,
                    physical_table: descriptor.physical_table,
                    action,
                }),
                Err(blocker) => blockers.push(blocker),
            }
        }

        let canonical_bytes = encode_plan(&request, &domains, &blockers);
        let digest = digest_plan(&canonical_bytes);
        Self {
            request,
            domains,
            blockers,
            canonical_bytes,
            digest,
        }
    }

    pub const fn request(&self) -> &RollbackRequest<Hash> {
        &self.request
    }

    pub const fn global_plan_digest(&self) -> RollbackPlanDigest {
        self.request.plan_digest()
    }

    pub fn domains(&self) -> &[CoordinatorRollbackArchiveDomainPlan] {
        &self.domains
    }

    pub fn blockers(&self) -> &[CoordinatorRollbackArchivePlanBlocker] {
        &self.blockers
    }

    pub const fn suffix_start_exclusive(&self) -> u64 {
        self.request.target().checkpoint_id().get()
    }

    pub const fn suffix_end_inclusive(&self) -> u64 {
        self.request.requested_head().checkpoint_id().get()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> CoordinatorRollbackArchivePlanDigest {
        self.digest
    }

    pub fn require_pre_archive_ready(
        &self,
    ) -> Result<(), CoordinatorRollbackArchivePlanNotReady> {
        if self.blockers.is_empty() {
            Ok(())
        } else {
            Err(CoordinatorRollbackArchivePlanNotReady {
                blockers: self.blockers.clone(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorRollbackArchivePlanNotReady {
    blockers: Vec<CoordinatorRollbackArchivePlanBlocker>,
}

impl CoordinatorRollbackArchivePlanNotReady {
    pub fn blockers(&self) -> &[CoordinatorRollbackArchivePlanBlocker] {
        &self.blockers
    }
}

impl fmt::Display for CoordinatorRollbackArchivePlanNotReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Coordinator rollback pre-archive plan has {} blocker(s)",
            self.blockers.len()
        )
    }
}

impl Error for CoordinatorRollbackArchivePlanNotReady {}

fn resolve_action(
    key_domain: ScyllaKeyDomain,
    version_axis: VersionAxis,
    rollback_policy: RollbackPolicy,
    recovery_action: RecoveryAction,
    delete_candidates: &[DeleteStrategy],
) -> Result<CoordinatorRollbackArchiveAction, CoordinatorRollbackArchivePlanBlocker>
{
    use CoordinatorRollbackArchiveAction as A;
    use RecoveryAction as R;
    use VersionAxis as V;

    let (action, required_delete) = match (recovery_action, version_axis) {
        (R::ArchiveAndSnapshot, V::CheckpointPartition) => {
            (A::ArchiveCheckpointPartitions, Some(DeleteStrategy::VersionPartition))
        }
        (R::ArchiveAndSnapshot, V::CheckpointClustering) => (
            A::ArchiveCheckpointClusteringRanges,
            Some(DeleteStrategy::BoundedRange),
        ),
        (R::ArchiveAndRebuild, V::CheckpointPartition) => (
            A::ArchiveCheckpointPartitionsAndRebuild,
            Some(DeleteStrategy::VersionPartition),
        ),
        (R::ArchiveAndRebuild, V::RootBirthPartition)
        | (R::ArchiveAndRebuild, V::ContentBirth)
        | (R::RebuildFromAuthoritative, V::ContentBirth)
        | (R::RebuildFromAuthoritative, V::ImtBirthOrdinaryColumn) => (
            A::ArchiveManifestPointRowsAndRebuild,
            Some(DeleteStrategy::Point),
        ),
        (R::RebuildFromAuthoritative, V::CheckpointClustering) => (
            A::ArchiveCheckpointClusteringRangesAndRebuild,
            Some(DeleteStrategy::BoundedRange),
        ),
        (R::RestoreFromTargetManifest, V::Singleton)
        | (R::RestoreFromTargetManifest, V::MutableCursor) => {
            (A::ArchiveSingletonAndRestoreTarget, None)
        }
        (R::PreserveOperational, _)
            if rollback_policy == RollbackPolicy::PreserveOperational =>
        {
            (A::PreserveOperational, None)
        }
        (R::RotateNamespace, _) => (A::RotateOperationalNamespace, None),
        _ => {
            return Err(
                CoordinatorRollbackArchivePlanBlocker::UnsupportedDomainContract {
                    key_domain,
                    version_axis,
                    rollback_policy,
                    recovery_action,
                },
            );
        }
    };

    if let Some(required) = required_delete {
        if !delete_candidates.contains(&required) {
            return Err(
                CoordinatorRollbackArchivePlanBlocker::RequiredDeleteStrategyMissing {
                    key_domain,
                    required,
                },
            );
        }
    }
    Ok(action)
}

fn encode_plan<Hash: Q256BitHash>(
    request: &RollbackRequest<Hash>,
    domains: &[CoordinatorRollbackArchiveDomainPlan],
    blockers: &[CoordinatorRollbackArchivePlanBlocker],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(160 + domains.len() * 6 + blockers.len() * 8);
    encoded.extend_from_slice(&PLAN_MAGIC);
    encoded.extend_from_slice(&PLAN_VERSION.to_be_bytes());
    encoded.extend_from_slice(request.plan_digest().as_bytes());
    encoded.push(request.execution_mode() as u8);
    encode_checkpoint(&mut encoded, request.requested_head());
    encode_checkpoint(&mut encoded, request.target());
    let fence = request.fence_window();
    encoded.extend_from_slice(
        &fence
            .delete_fence()
            .orphan_write_max()
            .as_i64()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&fence.delete_fence().as_i64().to_be_bytes());
    encoded.extend_from_slice(
        &fence
            .new_branch_write()
            .as_commit_timestamp()
            .as_i64()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&(domains.len() as u16).to_be_bytes());
    for domain in domains {
        encoded.extend_from_slice(&domain.key_domain.stable_id().to_be_bytes());
        encoded.extend_from_slice(&domain.physical_table.stable_id().to_be_bytes());
        encoded.push(domain.action as u8);
    }
    encoded.extend_from_slice(&(blockers.len() as u16).to_be_bytes());
    for blocker in blockers {
        encode_blocker(&mut encoded, *blocker);
    }
    encoded
}

fn encode_checkpoint<Hash: Q256BitHash>(
    encoded: &mut Vec<u8>,
    checkpoint: &psy_data::protocol::canonical_chain::CheckpointRef<Hash>,
) {
    encoded.extend_from_slice(&checkpoint.checkpoint_id().get().to_be_bytes());
    encoded.extend_from_slice(
        &checkpoint
            .checkpoint_hash()
            .as_inner()
            .into_owned_32bytes(),
    );
}

fn encode_blocker(
    encoded: &mut Vec<u8>,
    blocker: CoordinatorRollbackArchivePlanBlocker,
) {
    use CoordinatorRollbackArchivePlanBlocker as B;
    match blocker {
        B::SnapshotReplayNotSupported => encoded.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        B::RegistryBlocked { key_domain, blocker } => {
            encoded.push(2);
            encoded.extend_from_slice(&key_domain.stable_id().to_be_bytes());
            encoded.push(registry_blocker_tag(blocker));
            encoded.extend_from_slice(&[0, 0, 0]);
        }
        B::RetireCandidate { key_domain } => {
            encoded.push(3);
            encoded.extend_from_slice(&key_domain.stable_id().to_be_bytes());
            encoded.extend_from_slice(&[0, 0, 0, 0]);
        }
        B::UnsupportedDomainContract {
            key_domain,
            version_axis,
            rollback_policy,
            recovery_action,
        } => {
            encoded.push(4);
            encoded.extend_from_slice(&key_domain.stable_id().to_be_bytes());
            encoded.push(version_axis_tag(version_axis));
            encoded.push(rollback_policy_tag(rollback_policy));
            encoded.push(recovery_action_tag(recovery_action));
            encoded.push(0);
        }
        B::RequiredDeleteStrategyMissing { key_domain, required } => {
            encoded.push(5);
            encoded.extend_from_slice(&key_domain.stable_id().to_be_bytes());
            encoded.push(delete_strategy_tag(required));
            encoded.extend_from_slice(&[0, 0, 0]);
        }
    }
}

fn digest_plan(canonical_bytes: &[u8]) -> CoordinatorRollbackArchivePlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update((canonical_bytes.len() as u64).to_be_bytes());
    hasher.update(canonical_bytes);
    CoordinatorRollbackArchivePlanDigest(hasher.finalize().into())
}

const fn registry_blocker_tag(value: RegistryBlocker) -> u8 {
    match value {
        RegistryBlocker::MixedCheckpointPendingAxis => 1,
        RegistryBlocker::ReusableCheckpointHeightKey => 2,
        RegistryBlocker::PendingSuffixReadThrough => 3,
    }
}

const fn delete_strategy_tag(value: DeleteStrategy) -> u8 {
    match value {
        DeleteStrategy::Point => 1,
        DeleteStrategy::VersionPartition => 2,
        DeleteStrategy::BoundedRange => 3,
        DeleteStrategy::SnapshotOnly => 4,
    }
}

const fn version_axis_tag(value: VersionAxis) -> u8 {
    match value {
        VersionAxis::CheckpointPartition => 1,
        VersionAxis::CheckpointClustering => 2,
        VersionAxis::RootBirthPartition => 3,
        VersionAxis::Singleton => 4,
        VersionAxis::MonotonicCounter => 5,
        VersionAxis::ReusedCheckpointPartition => 6,
        VersionAxis::UniquePendingPartition => 7,
        VersionAxis::ProcUuidPartition => 8,
        VersionAxis::UniquePendingClustering => 9,
        VersionAxis::ContentBirth => 10,
        VersionAxis::MixedCheckpointPendingClustering => 11,
        VersionAxis::ImtBirthOrdinaryColumn => 12,
        VersionAxis::MutableCursor => 13,
        VersionAxis::NoActiveAxis => 14,
    }
}

const fn rollback_policy_tag(value: RollbackPolicy) -> u8 {
    match value {
        RollbackPolicy::ArchiveVersioned => 1,
        RollbackPolicy::DerivedBirth => 2,
        RollbackPolicy::RestoreSingleton => 3,
        RollbackPolicy::PreserveOperational => 4,
        RollbackPolicy::ByKeyDomain => 5,
        RollbackPolicy::RetireUnused => 6,
    }
}

const fn recovery_action_tag(value: RecoveryAction) -> u8 {
    match value {
        RecoveryAction::ArchiveAndSnapshot => 1,
        RecoveryAction::ArchiveAndRebuild => 2,
        RecoveryAction::RestoreFromTargetManifest => 3,
        RecoveryAction::PreserveOperational => 4,
        RecoveryAction::RotateNamespace => 5,
        RecoveryAction::RebuildFromAuthoritative => 6,
        RecoveryAction::Retire => 7,
        RecoveryAction::BlockedUntilMigration => 8,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::timestamp::{
        CommitWriteTimestampUs, TimestampFenceWindow,
    };

    use super::*;

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
            )),
        )
    }

    fn request(mode: RollbackExecutionMode) -> RollbackRequest<PHash> {
        RollbackRequest::try_new(
            checkpoint(100, 10),
            checkpoint(90, 20),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            mode,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn coordinator_plan_is_exhaustive_deterministic_and_pre_ponr() {
        let first = CoordinatorRollbackArchivePlan::resolve(request(
            RollbackExecutionMode::InPlace,
        ));
        let second = CoordinatorRollbackArchivePlan::resolve(request(
            RollbackExecutionMode::InPlace,
        ));
        assert_eq!(first, second);
        assert_eq!(first.suffix_start_exclusive(), 90);
        assert_eq!(first.suffix_end_inclusive(), 100);
        assert_eq!(first.global_plan_digest().as_bytes(), &[0xA5; 32]);
        assert_eq!(first.digest(), second.digest());

        let planned: BTreeSet<_> = first
            .domains()
            .iter()
            .map(|domain| domain.key_domain())
            .collect();
        let blocked: BTreeSet<_> = first
            .blockers()
            .iter()
            .filter_map(|blocker| match blocker {
                CoordinatorRollbackArchivePlanBlocker::RegistryBlocked {
                    key_domain,
                    ..
                }
                | CoordinatorRollbackArchivePlanBlocker::RetireCandidate {
                    key_domain,
                }
                | CoordinatorRollbackArchivePlanBlocker::UnsupportedDomainContract {
                    key_domain,
                    ..
                }
                | CoordinatorRollbackArchivePlanBlocker::RequiredDeleteStrategyMissing {
                    key_domain,
                    ..
                } => Some(*key_domain),
                CoordinatorRollbackArchivePlanBlocker::SnapshotReplayNotSupported => None,
            })
            .collect();
        let expected: BTreeSet<_> = key_domain_registry()
            .into_iter()
            .filter(|descriptor| {
                descriptor.prepared_coverage.coordinator
                    != DomainPreparedUpdateCoverage::NotApplicable
            })
            .map(|descriptor| descriptor.id)
            .collect();
        assert!(planned.is_disjoint(&blocked));
        assert_eq!(planned.union(&blocked).copied().collect::<BTreeSet<_>>(), expected);

        // This slice intentionally remains blocked instead of skipping the two
        // known Coordinator-visible domains whose legacy keying is unsafe.
        assert_eq!(
            first.blockers(),
            &[
                CoordinatorRollbackArchivePlanBlocker::RegistryBlocked {
                    key_domain: ScyllaKeyDomain::CheckpointToPending,
                    blocker: RegistryBlocker::ReusableCheckpointHeightKey,
                },
                CoordinatorRollbackArchivePlanBlocker::RegistryBlocked {
                    key_domain: ScyllaKeyDomain::RealmRewardNode,
                    blocker: RegistryBlocker::PendingSuffixReadThrough,
                },
            ]
        );
        assert!(first.require_pre_archive_ready().is_err());
    }

    #[test]
    fn snapshot_mode_is_explicitly_rejected_and_never_downgraded_to_in_place() {
        let plan = CoordinatorRollbackArchivePlan::resolve(request(
            RollbackExecutionMode::SnapshotReplay,
        ));
        assert_eq!(
            plan.blockers().first(),
            Some(&CoordinatorRollbackArchivePlanBlocker::SnapshotReplayNotSupported)
        );
        assert!(plan.require_pre_archive_ready().is_err());
    }

    #[test]
    fn plan_digest_binds_request_range_hashes_fence_and_global_plan() {
        let baseline = CoordinatorRollbackArchivePlan::resolve(request(
            RollbackExecutionMode::InPlace,
        ));
        let changed_target = CoordinatorRollbackArchivePlan::resolve(
            RollbackRequest::try_new(
                checkpoint(100, 10),
                checkpoint(89, 21),
                request(RollbackExecutionMode::InPlace).fence_window(),
                RollbackExecutionMode::InPlace,
                RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
            )
            .unwrap(),
        );
        let changed_global = CoordinatorRollbackArchivePlan::resolve(
            RollbackRequest::try_new(
                checkpoint(100, 10),
                checkpoint(90, 20),
                request(RollbackExecutionMode::InPlace).fence_window(),
                RollbackExecutionMode::InPlace,
                RollbackPlanDigest::try_new([0x5A; 32]).unwrap(),
            )
            .unwrap(),
        );
        assert_ne!(baseline.digest(), changed_target.digest());
        assert_ne!(baseline.digest(), changed_global.digest());
        assert_ne!(baseline.canonical_bytes(), changed_target.canonical_bytes());
    }

    #[test]
    fn ready_actions_never_select_snapshot_only_deletion() {
        let plan = CoordinatorRollbackArchivePlan::resolve(request(
            RollbackExecutionMode::InPlace,
        ));
        for domain in plan.domains() {
            let physical = physical_descriptor(domain.physical_table());
            match domain.action() {
                CoordinatorRollbackArchiveAction::ArchiveCheckpointPartitions
                | CoordinatorRollbackArchiveAction::ArchiveCheckpointPartitionsAndRebuild => {
                    assert!(
                        physical
                            .delete_candidates
                            .contains(&DeleteStrategy::VersionPartition)
                    );
                }
                CoordinatorRollbackArchiveAction::ArchiveCheckpointClusteringRanges
                | CoordinatorRollbackArchiveAction::ArchiveCheckpointClusteringRangesAndRebuild => {
                    assert!(
                        physical
                            .delete_candidates
                            .contains(&DeleteStrategy::BoundedRange)
                    );
                }
                CoordinatorRollbackArchiveAction::ArchiveManifestPointRowsAndRebuild => {
                    assert!(physical.delete_candidates.contains(&DeleteStrategy::Point));
                }
                CoordinatorRollbackArchiveAction::ArchiveSingletonAndRestoreTarget
                | CoordinatorRollbackArchiveAction::PreserveOperational
                | CoordinatorRollbackArchiveAction::RotateOperationalNamespace => {}
            }
        }
    }
}
