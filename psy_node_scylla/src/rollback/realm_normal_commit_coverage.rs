//! Scylla resolution and activation gate for Realm normal-commit coverage.
//!
//! This module does not execute CQL. It proves that the production call graph
//! can be expanded to the registered semantic key domains and physical tables,
//! then refuses durable PREPARED activation while any schema or writer
//! capability remains incomplete.

use std::{collections::BTreeSet, error::Error, fmt};

use psy_node_core::store::realm_normal_commit_coverage::{
    IgnoredRealmPreparedField, RealmNormalCommitCoveragePlan,
    RealmNormalCommitWriteDomain,
};

use super::{
    PRODUCTION_CQL_CAPABILITIES, RegistryBlocker, RegistryReadiness,
    ScyllaKeyDomain, ScyllaPhysicalTableId, key_domain_descriptor,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedRealmNormalCommitDomain {
    write_domain: RealmNormalCommitWriteDomain,
    key_domain: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
}

impl ResolvedRealmNormalCommitDomain {
    pub const fn write_domain(self) -> RealmNormalCommitWriteDomain {
        self.write_domain
    }

    pub const fn key_domain(self) -> ScyllaKeyDomain {
        self.key_domain
    }

    pub const fn physical_table(self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn writer_symbol(self) -> &'static str {
        self.write_domain.writer_symbol()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmNormalCommitDurabilityBlocker {
    Registry {
        write_domain: RealmNormalCommitWriteDomain,
        blocker: RegistryBlocker,
    },
    RetireCandidate {
        write_domain: RealmNormalCommitWriteDomain,
    },
    /// The physical pending-keyed row does not collide, but its stored value
    /// contains only a reusable checkpoint height. It cannot identify the
    /// canonical branch occurrence after rollback.
    LegacyHeightOnlyReverseMapping {
        write_domain: RealmNormalCommitWriteDomain,
    },
    IgnoredPreparedPayload(IgnoredRealmPreparedField),
    ExplicitProductionWriteTimestampIncomplete,
    ProductionWriterCoverageIncomplete {
        covered_domains: usize,
        required_domains: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmNormalCommitCoverageReport {
    resolved: Vec<ResolvedRealmNormalCommitDomain>,
    distinct_physical_tables: usize,
    production_writer_covered_domains: usize,
    blockers: Vec<RealmNormalCommitDurabilityBlocker>,
}

impl RealmNormalCommitCoverageReport {
    pub fn resolved(&self) -> &[ResolvedRealmNormalCommitDomain] {
        &self.resolved
    }

    pub const fn distinct_physical_table_count(&self) -> usize {
        self.distinct_physical_tables
    }

    pub const fn production_writer_covered_domain_count(&self) -> usize {
        self.production_writer_covered_domains
    }

    pub fn blockers(&self) -> &[RealmNormalCommitDurabilityBlocker] {
        &self.blockers
    }

    pub fn require_durable_prepared_ready(
        &self,
    ) -> Result<(), RealmNormalCommitDurabilityError> {
        if self.blockers.is_empty() {
            Ok(())
        } else {
            Err(RealmNormalCommitDurabilityError {
                blockers: self.blockers.clone(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmNormalCommitDurabilityError {
    blockers: Vec<RealmNormalCommitDurabilityBlocker>,
}

impl RealmNormalCommitDurabilityError {
    pub fn blockers(&self) -> &[RealmNormalCommitDurabilityBlocker] {
        &self.blockers
    }
}

impl fmt::Display for RealmNormalCommitDurabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Realm durable PREPARED is blocked by {} coverage/readiness issue(s)",
            self.blockers.len()
        )
    }
}

impl Error for RealmNormalCommitDurabilityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmNormalCommitCoverageResolutionError {
    PhysicalMappingMismatch {
        write_domain: RealmNormalCommitWriteDomain,
        key_domain: ScyllaKeyDomain,
        expected: ScyllaPhysicalTableId,
        registry: ScyllaPhysicalTableId,
    },
}

impl fmt::Display for RealmNormalCommitCoverageResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmNormalCommitCoverageResolutionError {}

/// Resolve the driver-independent production call graph against the exhaustive
/// Scylla registry. The result remains blocked until the production writer
/// migration and the two affected schema migrations have actually landed.
pub fn resolve_realm_normal_commit_coverage(
    plan: RealmNormalCommitCoveragePlan,
) -> Result<RealmNormalCommitCoverageReport, RealmNormalCommitCoverageResolutionError>
{
    let mut blockers = Vec::new();
    let mut resolved = Vec::new();
    let mut physical_tables = BTreeSet::new();
    let mut production_writer_covered_domains = 0;

    for write_domain in plan.domains() {
        let key_domain = key_domain_for(write_domain);
        let expected = expected_physical_table(write_domain);
        let descriptor = key_domain_descriptor(key_domain);
        if descriptor.physical_table != expected {
            return Err(
                RealmNormalCommitCoverageResolutionError::PhysicalMappingMismatch {
                    write_domain,
                    key_domain,
                    expected,
                    registry: descriptor.physical_table,
                },
            );
        }
        match descriptor.readiness {
            RegistryReadiness::Ready => {}
            RegistryReadiness::Blocked(blocker) => {
                blockers.push(RealmNormalCommitDurabilityBlocker::Registry {
                    write_domain,
                    blocker,
                });
            }
            RegistryReadiness::RetireCandidate => blockers.push(
                RealmNormalCommitDurabilityBlocker::RetireCandidate {
                    write_domain,
                },
            ),
        }
        if write_domain == RealmNormalCommitWriteDomain::PendingToCheckpoint {
            blockers.push(
                RealmNormalCommitDurabilityBlocker::LegacyHeightOnlyReverseMapping {
                    write_domain,
                },
            );
        }
        if production_writer_is_typed_timestamped(write_domain) {
            production_writer_covered_domains += 1;
        }
        physical_tables.insert(expected);
        resolved.push(ResolvedRealmNormalCommitDomain {
            write_domain,
            key_domain,
            physical_table: expected,
        });
    }

    blockers.extend(
        plan.ignored_prepared_fields()
            .map(RealmNormalCommitDurabilityBlocker::IgnoredPreparedPayload),
    );
    if !PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp {
        blockers.push(
            RealmNormalCommitDurabilityBlocker::ExplicitProductionWriteTimestampIncomplete,
        );
    }
    if production_writer_covered_domains != resolved.len() {
        blockers.push(
            RealmNormalCommitDurabilityBlocker::ProductionWriterCoverageIncomplete {
                covered_domains: production_writer_covered_domains,
                required_domains: resolved.len(),
            },
        );
    }

    Ok(RealmNormalCommitCoverageReport {
        resolved,
        distinct_physical_tables: physical_tables.len(),
        production_writer_covered_domains,
        blockers,
    })
}

const fn key_domain_for(
    domain: RealmNormalCommitWriteDomain,
) -> ScyllaKeyDomain {
    use RealmNormalCommitWriteDomain as W;
    use ScyllaKeyDomain as K;
    match domain {
        W::PendingToCheckpoint => K::PendingToCheckpoint,
        W::CheckpointToPending => K::CheckpointToPending,
        W::PendingToProc => K::PendingToProc,
        W::ProcToPending => K::ProcToPending,
        W::GlobalUserTopProofAtCheckpoint => K::CheckpointedGlobalUserProof,
        W::RewardsTopProofAtPending => K::CheckpointedRewardsProofAtPending,
        W::CheckpointStateRoots => K::CheckpointStateRoots,
        W::CheckpointLeaf => K::CheckpointLeaf,
        W::GlobalCheckpointMerkle => K::GlobalCheckpointMerkle,
        W::CheckpointRootByHash => K::CheckpointRootByHash,
        W::CheckpointRootByCheckpoint => K::CheckpointRootByCheckpoint,
        W::L2BlockState => K::L2BlockState,
        W::UserLeaf => K::UserLeaf,
        W::ContractStateMerkle => K::ContractStateMerkle,
        W::ImtLeaf => K::ImtLeaf,
        W::ImtKeyIndex => K::ImtKeyIndex,
        W::ImtCursor => K::ImtCursor,
        W::UserContractMerkle => K::UserContractMerkle,
        W::GlobalUserMerkle => K::GlobalUserMerkle,
        W::LatestCheckpoint => K::U64Singleton,
        W::LatestL2BlockState => K::LatestInfo,
        W::RealmAuthorityObservation => K::RealmAuthorityObservation,
    }
}

const fn expected_physical_table(
    domain: RealmNormalCommitWriteDomain,
) -> ScyllaPhysicalTableId {
    use RealmNormalCommitWriteDomain as W;
    use ScyllaPhysicalTableId as P;
    match domain {
        W::PendingToCheckpoint => P::PendingIdToCheckpointId,
        W::CheckpointToPending => P::CheckpointIdToPendingId,
        W::PendingToProc => P::PendingIdToPendingProcIdU64ToU128,
        W::ProcToPending => P::PendingIdToPendingProcIdU128ToU64,
        W::GlobalUserTopProofAtCheckpoint | W::RewardsTopProofAtPending => {
            P::CheckpointedObject
        }
        W::CheckpointStateRoots => P::CheckpointStateRoots,
        W::CheckpointLeaf => P::CheckpointLeaf,
        W::GlobalCheckpointMerkle => P::GlobalCheckpointTree,
        W::CheckpointRootByHash => P::CheckpointRootToCheckpointIdK1,
        W::CheckpointRootByCheckpoint => P::CheckpointRootToCheckpointIdK2,
        W::L2BlockState => P::L2BlockState,
        W::UserLeaf => P::UserLeaf,
        W::ContractStateMerkle => P::ContractStateTree,
        W::ImtLeaf => P::ImtLeaf,
        W::ImtKeyIndex => P::ImtKeyIndex,
        W::ImtCursor => P::ImtNextAppendIndex,
        W::UserContractMerkle => P::UserContractTree,
        W::GlobalUserMerkle => P::GlobalUserTree,
        W::LatestCheckpoint => P::U64Singleton,
        W::LatestL2BlockState | W::RealmAuthorityObservation => P::LatestInfo,
    }
}

/// D-02T adapters are still isolated prototypes. No production Realm writer
/// has crossed the typed/timestamped confinement boundary yet. Keeping this
/// match exhaustive makes adding a new semantic domain fail closed.
const fn production_writer_is_typed_timestamped(
    domain: RealmNormalCommitWriteDomain,
) -> bool {
    use RealmNormalCommitWriteDomain as W;
    match domain {
        W::PendingToCheckpoint
        | W::CheckpointToPending
        | W::PendingToProc
        | W::ProcToPending
        | W::GlobalUserTopProofAtCheckpoint
        | W::RewardsTopProofAtPending
        | W::CheckpointStateRoots
        | W::CheckpointLeaf
        | W::GlobalCheckpointMerkle
        | W::CheckpointRootByHash
        | W::CheckpointRootByCheckpoint
        | W::L2BlockState
        | W::UserLeaf
        | W::ContractStateMerkle
        | W::ImtLeaf
        | W::ImtKeyIndex
        | W::ImtCursor
        | W::UserContractMerkle
        | W::GlobalUserMerkle
        | W::LatestCheckpoint
        | W::LatestL2BlockState
        | W::RealmAuthorityObservation => false,
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash, QCoreProcCheckpointUniqueId,
        protocol::core_types::Q256BitHash,
    };
    use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

    use super::*;

    fn prepared() -> PsyPreparedRealmBlockStateUpdates<PHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 1,
            realm_sub_id: 2,
            unique_pending_id: 3,
            proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(4_u128),
            old_realm_root: PHash::from_owned_32bytes([1; 32]),
            new_realm_root: PHash::from_owned_32bytes([2; 32]),
            update_global_user_tree_nodes_ffs: vec![1],
            update_user_contract_tree_nodes_ffs: vec![2],
            update_contract_state_tree_nodes_ffs: vec![3],
            update_user_leaves_ffs: vec![4],
            update_contract_state_imt_leaves_ffs: vec![5],
        }
    }

    #[test]
    fn full_commit_resolves_22_domains_to_20_physical_tables() {
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared());
        let report = resolve_realm_normal_commit_coverage(plan).unwrap();
        assert_eq!(report.resolved().len(), 22);
        assert_eq!(report.distinct_physical_table_count(), 20);
        assert_eq!(report.production_writer_covered_domain_count(), 0);
    }

    #[test]
    fn no_imt_resolves_19_domains_to_17_physical_tables() {
        let mut prepared = prepared();
        prepared.update_contract_state_imt_leaves_ffs.clear();
        let report = resolve_realm_normal_commit_coverage(
            RealmNormalCommitCoveragePlan::from_prepared(&prepared),
        )
        .unwrap();
        assert_eq!(report.resolved().len(), 19);
        assert_eq!(report.distinct_physical_table_count(), 17);
    }

    #[test]
    fn no_state_branch_resolves_15_domains_to_13_physical_tables() {
        let mut prepared = prepared();
        prepared.update_global_user_tree_nodes_ffs.clear();
        prepared.update_user_contract_tree_nodes_ffs.clear();
        prepared.update_contract_state_tree_nodes_ffs.clear();
        prepared.update_user_leaves_ffs.clear();
        prepared.update_contract_state_imt_leaves_ffs.clear();
        let report = resolve_realm_normal_commit_coverage(
            RealmNormalCommitCoveragePlan::from_prepared(&prepared),
        )
        .unwrap();
        assert_eq!(report.resolved().len(), 15);
        assert_eq!(report.distinct_physical_table_count(), 13);
    }

    #[test]
    fn helper_fanout_and_shared_physical_tables_are_not_collapsed() {
        let report = resolve_realm_normal_commit_coverage(
            RealmNormalCommitCoveragePlan::from_prepared(&prepared()),
        )
        .unwrap();
        let resolved = report.resolved();
        assert!(resolved.contains(&ResolvedRealmNormalCommitDomain {
            write_domain: RealmNormalCommitWriteDomain::PendingToProc,
            key_domain: ScyllaKeyDomain::PendingToProc,
            physical_table: ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
        }));
        assert!(resolved.contains(&ResolvedRealmNormalCommitDomain {
            write_domain: RealmNormalCommitWriteDomain::ProcToPending,
            key_domain: ScyllaKeyDomain::ProcToPending,
            physical_table: ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
        }));
        assert_eq!(
            resolved
                .iter()
                .filter(|entry| entry.physical_table() == ScyllaPhysicalTableId::CheckpointedObject)
                .count(),
            2
        );
        assert_eq!(
            resolved
                .iter()
                .filter(|entry| entry.physical_table() == ScyllaPhysicalTableId::LatestInfo)
                .count(),
            2
        );
    }

    #[test]
    fn durable_prepared_is_fail_closed_on_current_schema_and_writers() {
        let report = resolve_realm_normal_commit_coverage(
            RealmNormalCommitCoveragePlan::from_prepared(&prepared()),
        )
        .unwrap();
        let blockers = report.blockers();
        assert!(blockers.contains(&RealmNormalCommitDurabilityBlocker::Registry {
            write_domain: RealmNormalCommitWriteDomain::CheckpointToPending,
            blocker: RegistryBlocker::ReusableCheckpointHeightKey,
        }));
        assert!(blockers.contains(
            &RealmNormalCommitDurabilityBlocker::LegacyHeightOnlyReverseMapping {
                write_domain: RealmNormalCommitWriteDomain::PendingToCheckpoint,
            }
        ));
        assert!(blockers.contains(&RealmNormalCommitDurabilityBlocker::Registry {
            write_domain: RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint,
            blocker: RegistryBlocker::MixedCheckpointPendingAxis,
        }));
        assert!(blockers.contains(&RealmNormalCommitDurabilityBlocker::Registry {
            write_domain: RealmNormalCommitWriteDomain::RewardsTopProofAtPending,
            blocker: RegistryBlocker::MixedCheckpointPendingAxis,
        }));
        assert!(blockers.contains(&RealmNormalCommitDurabilityBlocker::ExplicitProductionWriteTimestampIncomplete));
        assert!(blockers.contains(&RealmNormalCommitDurabilityBlocker::ProductionWriterCoverageIncomplete {
            covered_domains: 0,
            required_domains: 22,
        }));
        assert!(report.require_durable_prepared_ready().is_err());
    }

    #[test]
    fn ignored_prepared_payload_is_an_additional_activation_blocker() {
        let mut prepared = prepared();
        prepared.update_user_leaves_ffs.clear();
        let report = resolve_realm_normal_commit_coverage(
            RealmNormalCommitCoveragePlan::from_prepared(&prepared),
        )
        .unwrap();
        assert!(report.blockers().contains(
            &RealmNormalCommitDurabilityBlocker::IgnoredPreparedPayload(
                IgnoredRealmPreparedField::ContractStateImtLeaves,
            ),
        ));
    }

    #[test]
    fn every_domain_keeps_a_real_production_writer_evidence_symbol() {
        const COMMIT_SOURCE: &str = include_str!(
            "../../../psy_node_common/src/realm/processor/db/commit.rs"
        );
        const FULL_STORE_SOURCE: &str = include_str!(
            "../../../psy_node_core/src/psy_core_db/v3_implementation/full.rs"
        );
        for domain in RealmNormalCommitWriteDomain::ALL {
            let symbol = domain.writer_symbol();
            assert!(
                COMMIT_SOURCE.contains(symbol) || FULL_STORE_SOURCE.contains(symbol),
                "missing production writer evidence for {domain:?}: {symbol}"
            );
        }
    }
}
