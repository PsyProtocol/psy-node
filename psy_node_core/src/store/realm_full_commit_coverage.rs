//! Exhaustive, driver-independent coverage commitment for one Realm commit.
//!
//! This is the first h23c4e boundary. It proves that every semantic write
//! domain selected by the real `commit_state` branch predicates has exactly
//! one non-empty physical-mutation batch commitment and that all batches use
//! one explicit authority timestamp. It does not execute storage writes and
//! is not an authority or publish receipt.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::{
    realm_normal_commit_coverage::{
        RealmNormalCommitCoveragePlan, RealmNormalCommitWriteDomain,
    },
    timestamp::CommitWriteTimestampUs,
};

const COVERAGE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-coverage.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmCommitDomainMutationCommitment {
    domain: RealmNormalCommitWriteDomain,
    mutation_count: u64,
    mutation_digest: [u8; 32],
    write_timestamp: CommitWriteTimestampUs,
}

impl RealmCommitDomainMutationCommitment {
    pub fn try_new(
        domain: RealmNormalCommitWriteDomain,
        mutation_count: u64,
        mutation_digest: [u8; 32],
        write_timestamp: CommitWriteTimestampUs,
    ) -> Result<Self, RealmFullCommitCoverageError> {
        if mutation_count == 0 {
            return Err(RealmFullCommitCoverageError::EmptyDomainBatch {
                domain,
            });
        }
        if mutation_digest == [0; 32] {
            return Err(RealmFullCommitCoverageError::ZeroMutationDigest {
                domain,
            });
        }
        Ok(Self {
            domain,
            mutation_count,
            mutation_digest,
            write_timestamp,
        })
    }

    pub const fn domain(self) -> RealmNormalCommitWriteDomain {
        self.domain
    }

    pub const fn mutation_count(self) -> u64 {
        self.mutation_count
    }

    pub const fn mutation_digest(self) -> [u8; 32] {
        self.mutation_digest
    }

    pub const fn write_timestamp(self) -> CommitWriteTimestampUs {
        self.write_timestamp
    }
}

/// Canonical completeness commitment for one path-specific Realm commit.
///
/// The constructor is intentionally public because this is a checked model,
/// not a storage capability. Production mutation authority must later be
/// minted by a storage-private assembler from exact physical batches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmFullCommitCoverage {
    domains: Vec<RealmCommitDomainMutationCommitment>,
    write_timestamp: CommitWriteTimestampUs,
    total_mutation_count: u64,
    digest: [u8; 32],
}

impl RealmFullCommitCoverage {
    pub fn try_new(
        plan: RealmNormalCommitCoveragePlan,
        mut domains: Vec<RealmCommitDomainMutationCommitment>,
    ) -> Result<Self, RealmFullCommitCoverageError> {
        if plan.has_ignored_prepared_payload() {
            return Err(RealmFullCommitCoverageError::IgnoredPreparedPayload);
        }
        let expected = plan.domains().collect::<Vec<_>>();
        domains.sort_by_key(|commitment| commitment.domain);

        for pair in domains.windows(2) {
            if pair[0].domain == pair[1].domain {
                return Err(RealmFullCommitCoverageError::DuplicateDomain {
                    domain: pair[0].domain,
                });
            }
        }

        let actual = domains
            .iter()
            .map(|commitment| commitment.domain)
            .collect::<Vec<_>>();
        if actual != expected {
            let missing = expected
                .iter()
                .copied()
                .find(|domain| actual.binary_search(domain).is_err());
            if let Some(domain) = missing {
                return Err(RealmFullCommitCoverageError::MissingDomain {
                    domain,
                });
            }
            let unexpected = actual
                .iter()
                .copied()
                .find(|domain| expected.binary_search(domain).is_err())
                .expect("different sorted domain sets have an unexpected member");
            return Err(RealmFullCommitCoverageError::UnexpectedDomain {
                domain: unexpected,
            });
        }

        let write_timestamp = domains
            .first()
            .ok_or(RealmFullCommitCoverageError::MissingAllDomains)?
            .write_timestamp;
        if let Some(commitment) = domains
            .iter()
            .find(|commitment| commitment.write_timestamp != write_timestamp)
        {
            return Err(RealmFullCommitCoverageError::MixedWriteTimestamp {
                domain: commitment.domain,
                expected: write_timestamp,
                actual: commitment.write_timestamp,
            });
        }

        let total_mutation_count = domains.iter().try_fold(0_u64, |total, domain| {
            total.checked_add(domain.mutation_count).ok_or(
                RealmFullCommitCoverageError::MutationCountOverflow,
            )
        })?;
        let digest = coverage_digest(write_timestamp, total_mutation_count, &domains);
        Ok(Self {
            domains,
            write_timestamp,
            total_mutation_count,
            digest,
        })
    }

    pub fn domains(&self) -> &[RealmCommitDomainMutationCommitment] {
        &self.domains
    }

    pub const fn write_timestamp(&self) -> CommitWriteTimestampUs {
        self.write_timestamp
    }

    pub const fn total_mutation_count(&self) -> u64 {
        self.total_mutation_count
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn coverage_digest(
    write_timestamp: CommitWriteTimestampUs,
    total_mutation_count: u64,
    domains: &[RealmCommitDomainMutationCommitment],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COVERAGE_DIGEST_DOMAIN);
    hasher.update(write_timestamp.as_i64().to_be_bytes());
    hasher.update(total_mutation_count.to_be_bytes());
    hasher.update((domains.len() as u32).to_be_bytes());
    for commitment in domains {
        hasher.update([domain_id(commitment.domain)]);
        hasher.update(commitment.mutation_count.to_be_bytes());
        hasher.update(commitment.mutation_digest);
    }
    hasher.finalize().into()
}

/// Stable manifest identity for the 22 semantic domains. Adding or reordering
/// enum variants cannot silently change persisted coverage bytes.
pub const fn domain_id(domain: RealmNormalCommitWriteDomain) -> u8 {
    use RealmNormalCommitWriteDomain as D;
    match domain {
        D::PendingToCheckpoint => 1,
        D::CheckpointToPending => 2,
        D::PendingToProc => 3,
        D::ProcToPending => 4,
        D::GlobalUserTopProofAtCheckpoint => 5,
        D::RewardsTopProofAtPending => 6,
        D::CheckpointStateRoots => 7,
        D::CheckpointLeaf => 8,
        D::GlobalCheckpointMerkle => 9,
        D::CheckpointRootByHash => 10,
        D::CheckpointRootByCheckpoint => 11,
        D::L2BlockState => 12,
        D::UserLeaf => 13,
        D::ContractStateMerkle => 14,
        D::ImtLeaf => 15,
        D::ImtKeyIndex => 16,
        D::ImtCursor => 17,
        D::UserContractMerkle => 18,
        D::GlobalUserMerkle => 19,
        D::LatestCheckpoint => 20,
        D::LatestL2BlockState => 21,
        D::RealmAuthorityObservation => 22,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmFullCommitCoverageError {
    EmptyDomainBatch {
        domain: RealmNormalCommitWriteDomain,
    },
    ZeroMutationDigest {
        domain: RealmNormalCommitWriteDomain,
    },
    DuplicateDomain {
        domain: RealmNormalCommitWriteDomain,
    },
    MissingDomain {
        domain: RealmNormalCommitWriteDomain,
    },
    UnexpectedDomain {
        domain: RealmNormalCommitWriteDomain,
    },
    MixedWriteTimestamp {
        domain: RealmNormalCommitWriteDomain,
        expected: CommitWriteTimestampUs,
        actual: CommitWriteTimestampUs,
    },
    MissingAllDomains,
    IgnoredPreparedPayload,
    MutationCountOverflow,
}

impl fmt::Display for RealmFullCommitCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full-commit coverage: {self:?}")
    }
}

impl Error for RealmFullCommitCoverageError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        protocol::core_types::Q256BitHash, PHash,
        QCoreProcCheckpointUniqueId,
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

    fn commitments(
        plan: RealmNormalCommitCoveragePlan,
        timestamp: CommitWriteTimestampUs,
    ) -> Vec<RealmCommitDomainMutationCommitment> {
        plan.domains()
            .map(|domain| {
                RealmCommitDomainMutationCommitment::try_new(
                    domain,
                    u64::from(domain_id(domain)),
                    [domain_id(domain); 32],
                    timestamp,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn full_state_manifest_is_exactly_22_domains_and_one_timestamp() {
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared());
        let timestamp = CommitWriteTimestampUs::try_from_i128(41).unwrap();
        let mut rows = commitments(plan, timestamp);
        rows.reverse();
        let manifest = RealmFullCommitCoverage::try_new(plan, rows).unwrap();
        assert_eq!(manifest.domains().len(), 22);
        assert_eq!(manifest.write_timestamp(), timestamp);
        assert_eq!(
            manifest.total_mutation_count(),
            (1_u64..=22).sum::<u64>()
        );
        assert_ne!(manifest.digest(), &[0; 32]);
        assert_eq!(
            manifest
                .domains()
                .iter()
                .map(|entry| domain_id(entry.domain()))
                .collect::<Vec<_>>(),
            (1_u8..=22).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn path_specific_manifest_requires_exact_selected_domains() {
        let mut no_imt = prepared();
        no_imt.update_contract_state_imt_leaves_ffs.clear();
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&no_imt);
        let timestamp = CommitWriteTimestampUs::try_from_i128(42).unwrap();
        let manifest = RealmFullCommitCoverage::try_new(
            plan,
            commitments(plan, timestamp),
        )
        .unwrap();
        assert_eq!(manifest.domains().len(), 19);

        let mut missing = commitments(plan, timestamp);
        missing.retain(|entry| {
            entry.domain() != RealmNormalCommitWriteDomain::CheckpointLeaf
        });
        assert_eq!(
            RealmFullCommitCoverage::try_new(plan, missing),
            Err(RealmFullCommitCoverageError::MissingDomain {
                domain: RealmNormalCommitWriteDomain::CheckpointLeaf,
            }),
        );

        let mut unexpected = commitments(plan, timestamp);
        unexpected.push(
            RealmCommitDomainMutationCommitment::try_new(
                RealmNormalCommitWriteDomain::ImtLeaf,
                1,
                [99; 32],
                timestamp,
            )
            .unwrap(),
        );
        assert_eq!(
            RealmFullCommitCoverage::try_new(plan, unexpected),
            Err(RealmFullCommitCoverageError::UnexpectedDomain {
                domain: RealmNormalCommitWriteDomain::ImtLeaf,
            }),
        );
    }

    #[test]
    fn duplicate_mixed_timestamp_and_empty_batches_fail_closed() {
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared());
        let timestamp = CommitWriteTimestampUs::try_from_i128(43).unwrap();
        let mut duplicate = commitments(plan, timestamp);
        duplicate.push(duplicate[0]);
        assert!(matches!(
            RealmFullCommitCoverage::try_new(plan, duplicate),
            Err(RealmFullCommitCoverageError::DuplicateDomain { .. })
        ));

        let mut mixed = commitments(plan, timestamp);
        let last = mixed.pop().unwrap();
        mixed.push(
            RealmCommitDomainMutationCommitment::try_new(
                last.domain(),
                last.mutation_count(),
                last.mutation_digest(),
                CommitWriteTimestampUs::try_from_i128(44).unwrap(),
            )
            .unwrap(),
        );
        assert!(matches!(
            RealmFullCommitCoverage::try_new(plan, mixed),
            Err(RealmFullCommitCoverageError::MixedWriteTimestamp { .. })
        ));

        assert!(matches!(
            RealmCommitDomainMutationCommitment::try_new(
                RealmNormalCommitWriteDomain::CheckpointLeaf,
                0,
                [1; 32],
                timestamp,
            ),
            Err(RealmFullCommitCoverageError::EmptyDomainBatch { .. })
        ));
        assert!(matches!(
            RealmCommitDomainMutationCommitment::try_new(
                RealmNormalCommitWriteDomain::CheckpointLeaf,
                1,
                [0; 32],
                timestamp,
            ),
            Err(RealmFullCommitCoverageError::ZeroMutationDigest { .. })
        ));
    }

    #[test]
    fn hidden_payload_and_digest_drift_fail_or_change_commitment() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(45).unwrap();
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared());
        let first = RealmFullCommitCoverage::try_new(
            plan,
            commitments(plan, timestamp),
        )
        .unwrap();
        let mut changed = commitments(plan, timestamp);
        let entry = changed[0];
        changed[0] = RealmCommitDomainMutationCommitment::try_new(
            entry.domain(),
            entry.mutation_count() + 1,
            entry.mutation_digest(),
            timestamp,
        )
        .unwrap();
        let second = RealmFullCommitCoverage::try_new(plan, changed).unwrap();
        assert_ne!(first.digest(), second.digest());

        let mut hidden = prepared();
        hidden.update_user_leaves_ffs.clear();
        let hidden_plan = RealmNormalCommitCoveragePlan::from_prepared(&hidden);
        assert_eq!(
            RealmFullCommitCoverage::try_new(
                hidden_plan,
                commitments(hidden_plan, timestamp),
            ),
            Err(RealmFullCommitCoverageError::IgnoredPreparedPayload),
        );
    }
}
