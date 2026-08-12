//! Storage-private assembly of one exhaustive Realm commit mutation plan.
//!
//! The h22 branch-exact writer already owns the five operational semantic
//! domains which fan out to eight legacy/target mutations. Every other domain
//! must arrive as registry-resolved, explicitly timestamped PUTs. Only after
//! those concrete inputs agree with the driver-independent path plan can this
//! module mint a complete coverage commitment. This module does not execute
//! CQL and its result is not a publish or authority-head receipt.

use std::{collections::BTreeSet, error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    branch_exact_dual_write::{
        BranchExactDualWriteIntent, BranchExactDualWriteMutationKind,
    },
    branch_exact_schema::AuthorityScope,
    realm_full_commit_coverage::{
        RealmCommitDomainMutationCommitment, RealmFullCommitCoverage,
        RealmFullCommitCoverageError, domain_id,
    },
    realm_normal_commit_coverage::{
        H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE, RealmNormalCommitCoveragePlan,
        RealmNormalCommitWriteDomain,
        realm_normal_commit_domain_for_branch_exact_mutation,
    },
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, ScyllaKeyDomain, ScyllaPhysicalTableId,
    SealedTimestampedPut, TimestampedWriteKind,
    expected_physical_table, key_domain_for,
};

const NARROW_BATCH_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-narrow-batch.v1\0";
const TYPED_BATCH_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-typed-batch.v1\0";

/// A concrete batch for exactly one non-h22 semantic domain.
///
/// Construction is crate-private and still does not imply completeness. The
/// full assembler validates every member against the registry before retaining
/// the executable PUTs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmCommitPhysicalDomainBatch {
    domain: RealmNormalCommitWriteDomain,
    puts: Vec<SealedTimestampedPut>,
    cutover_prepared_digest: Option<[u8; 32]>,
}

impl RealmCommitPhysicalDomainBatch {
    pub(crate) fn new(
        domain: RealmNormalCommitWriteDomain,
        puts: Vec<SealedTimestampedPut>,
    ) -> Self {
        Self {
            domain,
            puts,
            cutover_prepared_digest: None,
        }
    }

    /// Build the sole mixed-axis exception from the exact prepared h22
    /// identity. The assembler later compares this digest with its own narrow
    /// capability, so a PUT sealed under another cutover cannot be replayed.
    pub(crate) fn global_user_proof_after_cutover<Hash: Q256BitHash>(
        prepared: &BranchExactWriterPrepared<Hash>,
        key: psy_node_core::store::typed::TypedTableKey,
        value: psy_node_core::store::typed::MutationValue,
    ) -> Result<Self, super::TimestampedMutationError> {
        Ok(Self {
            domain: RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint,
            puts: vec![super::seal_realm_global_user_proof_after_cutover(
                prepared, key, value,
            )?],
            cutover_prepared_digest: Some(*prepared.digest()),
        })
    }

    pub(crate) const fn domain(&self) -> RealmNormalCommitWriteDomain {
        self.domain
    }

    pub(crate) fn puts(&self) -> &[SealedTimestampedPut] {
        &self.puts
    }
}

/// Complete storage-private physical input for one Realm commit.
///
/// The narrow writer remains a separate affine lifecycle capability; this
/// plan commits to its exact prepared identity rather than copying or
/// re-exposing its raw execution receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitPhysicalPlan {
    coverage: RealmFullCommitCoverage,
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    remaining: Vec<RealmCommitPhysicalDomainBatch>,
}

impl RealmFullCommitPhysicalPlan {
    pub(crate) fn try_assemble<Hash: Q256BitHash>(
        coverage_plan: RealmNormalCommitCoveragePlan,
        narrow: &BranchExactWriterPrepared<Hash>,
        remaining: Vec<RealmCommitPhysicalDomainBatch>,
    ) -> Result<Self, RealmFullCommitPhysicalPlanError> {
        assemble(
            coverage_plan,
            narrow.intent(),
            narrow.timestamp(),
            *narrow.digest(),
            remaining,
        )
    }

    pub(crate) const fn coverage(&self) -> &RealmFullCommitCoverage {
        &self.coverage
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn narrow_intent_digest(&self) -> &[u8; 32] {
        &self.narrow_intent_digest
    }

    pub(crate) fn remaining(&self) -> &[RealmCommitPhysicalDomainBatch] {
        &self.remaining
    }
}

fn assemble<Hash: Q256BitHash>(
    coverage_plan: RealmNormalCommitCoveragePlan,
    narrow: &BranchExactDualWriteIntent<Hash>,
    timestamp: CommitWriteTimestampUs,
    narrow_prepared_digest: [u8; 32],
    mut remaining: Vec<RealmCommitPhysicalDomainBatch>,
) -> Result<RealmFullCommitPhysicalPlan, RealmFullCommitPhysicalPlanError> {
    if !matches!(narrow.authority(), AuthorityScope::Realm { .. }) {
        return Err(RealmFullCommitPhysicalPlanError::RealmNarrowIntentRequired);
    }
    if narrow_prepared_digest == [0; 32] {
        return Err(RealmFullCommitPhysicalPlanError::ZeroNarrowPreparedDigest);
    }

    let mut commitments = narrow_commitments(narrow, timestamp)?;
    let mut seen_domains = BTreeSet::new();
    let mut seen_locators = BTreeSet::new();

    for batch in &remaining {
        if H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE.contains(&batch.domain) {
            return Err(RealmFullCommitPhysicalPlanError::NarrowDomainSuppliedAsTypedBatch {
                domain: batch.domain,
            });
        }
        if !seen_domains.insert(batch.domain) {
            return Err(RealmFullCommitPhysicalPlanError::DuplicateTypedDomain {
                domain: batch.domain,
            });
        }
        if batch.puts.is_empty() {
            return Err(RealmFullCommitPhysicalPlanError::EmptyTypedDomainBatch {
                domain: batch.domain,
            });
        }
        if batch.domain == RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint {
            if batch.cutover_prepared_digest != Some(narrow_prepared_digest) {
                return Err(
                    RealmFullCommitPhysicalPlanError::CutoverPreparedIdentityMismatch,
                );
            }
        } else if batch.cutover_prepared_digest.is_some() {
            return Err(RealmFullCommitPhysicalPlanError::UnexpectedCutoverPreparedIdentity {
                domain: batch.domain,
            });
        }

        let expected_key_domain = key_domain_for(batch.domain);
        let expected_table = expected_physical_table(batch.domain);
        for put in &batch.puts {
            if put.write_kind() != TimestampedWriteKind::AuthorityCommit {
                return Err(RealmFullCommitPhysicalPlanError::WrongWriteKind {
                    domain: batch.domain,
                    actual: put.write_kind(),
                });
            }
            if put.timestamp() != timestamp {
                return Err(RealmFullCommitPhysicalPlanError::MixedWriteTimestamp {
                    domain: batch.domain,
                    expected: timestamp,
                    actual: put.timestamp(),
                });
            }
            let mutation = put.resolved().mutation();
            if mutation.key_domain() != expected_key_domain
                || mutation.physical_table() != expected_table
            {
                return Err(RealmFullCommitPhysicalPlanError::PhysicalDomainMismatch {
                    domain: batch.domain,
                    expected_key_domain,
                    actual_key_domain: mutation.key_domain(),
                    expected_table,
                    actual_table: mutation.physical_table(),
                });
            }
            let locator = (
                mutation.physical_table(),
                put.resolved().locator_bytes().to_vec(),
            );
            if !seen_locators.insert(locator) {
                return Err(RealmFullCommitPhysicalPlanError::DuplicatePhysicalLocator {
                    domain: batch.domain,
                });
            }
        }

        let mutation_count = u64::try_from(batch.puts.len())
            .map_err(|_| RealmFullCommitPhysicalPlanError::MutationCountOutOfRange {
                domain: batch.domain,
            })?;
        commitments.push(RealmCommitDomainMutationCommitment::try_new(
            batch.domain,
            mutation_count,
            typed_batch_digest(batch),
            timestamp,
        )?);
    }

    let coverage = RealmFullCommitCoverage::try_new(coverage_plan, commitments)?;
    remaining.sort_by_key(|batch| batch.domain);
    Ok(RealmFullCommitPhysicalPlan {
        coverage,
        narrow_prepared_digest,
        narrow_intent_digest: *narrow.intent_digest().as_bytes(),
        remaining,
    })
}

fn narrow_commitments<Hash: Q256BitHash>(
    narrow: &BranchExactDualWriteIntent<Hash>,
    timestamp: CommitWriteTimestampUs,
) -> Result<Vec<RealmCommitDomainMutationCommitment>, RealmFullCommitPhysicalPlanError> {
    let actual_kinds = narrow
        .mutations()
        .iter()
        .map(|mutation| mutation.kind())
        .collect::<Vec<_>>();
    if actual_kinds != BranchExactDualWriteMutationKind::REALM {
        return Err(RealmFullCommitPhysicalPlanError::NarrowMutationSetMismatch);
    }

    H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE
        .into_iter()
        .map(|domain| {
            let mutations = narrow
                .mutations()
                .iter()
                .filter(|mutation| {
                    realm_normal_commit_domain_for_branch_exact_mutation(mutation.kind())
                        == domain
                })
                .collect::<Vec<_>>();
            let count = u64::try_from(mutations.len()).map_err(|_| {
                RealmFullCommitPhysicalPlanError::MutationCountOutOfRange { domain }
            })?;
            let mut hasher = Sha256::new();
            hasher.update(NARROW_BATCH_DIGEST_DOMAIN);
            hasher.update([domain_id(domain)]);
            hasher.update(count.to_be_bytes());
            for mutation in mutations {
                hasher.update([mutation.kind() as u8]);
                hasher.update(mutation.digest().as_bytes());
            }
            RealmCommitDomainMutationCommitment::try_new(
                domain,
                count,
                hasher.finalize().into(),
                timestamp,
            )
            .map_err(Into::into)
        })
        .collect()
}

fn typed_batch_digest(batch: &RealmCommitPhysicalDomainBatch) -> [u8; 32] {
    let mut members = batch
        .puts
        .iter()
        .map(|put| put.canonical_bytes())
        .collect::<Vec<_>>();
    members.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(TYPED_BATCH_DIGEST_DOMAIN);
    hasher.update([domain_id(batch.domain)]);
    hasher.update((members.len() as u64).to_be_bytes());
    for member in members {
        hasher.update((member.len() as u32).to_be_bytes());
        hasher.update(member);
    }
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RealmFullCommitPhysicalPlanError {
    RealmNarrowIntentRequired,
    ZeroNarrowPreparedDigest,
    NarrowMutationSetMismatch,
    NarrowDomainSuppliedAsTypedBatch {
        domain: RealmNormalCommitWriteDomain,
    },
    DuplicateTypedDomain {
        domain: RealmNormalCommitWriteDomain,
    },
    EmptyTypedDomainBatch {
        domain: RealmNormalCommitWriteDomain,
    },
    WrongWriteKind {
        domain: RealmNormalCommitWriteDomain,
        actual: TimestampedWriteKind,
    },
    MixedWriteTimestamp {
        domain: RealmNormalCommitWriteDomain,
        expected: CommitWriteTimestampUs,
        actual: CommitWriteTimestampUs,
    },
    PhysicalDomainMismatch {
        domain: RealmNormalCommitWriteDomain,
        expected_key_domain: ScyllaKeyDomain,
        actual_key_domain: ScyllaKeyDomain,
        expected_table: ScyllaPhysicalTableId,
        actual_table: ScyllaPhysicalTableId,
    },
    DuplicatePhysicalLocator {
        domain: RealmNormalCommitWriteDomain,
    },
    MutationCountOutOfRange {
        domain: RealmNormalCommitWriteDomain,
    },
    CutoverPreparedIdentityMismatch,
    UnexpectedCutoverPreparedIdentity {
        domain: RealmNormalCommitWriteDomain,
    },
    Coverage(RealmFullCommitCoverageError),
}

impl From<RealmFullCommitCoverageError> for RealmFullCommitPhysicalPlanError {
    fn from(value: RealmFullCommitCoverageError) -> Self {
        Self::Coverage(value)
    }
}

impl fmt::Display for RealmFullCommitPhysicalPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full physical commit plan: {self:?}")
    }
}

impl Error for RealmFullCommitPhysicalPlanError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash,
        crypto::hash::tag_tree::TagTreeMerkleProof,
    };
    use psy_data::{
        prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash,
            CheckpointId as ChainCheckpointId, CheckpointRef, NetworkId,
        },
    };
    use psy_node_core::store::{
        branch_pending_mapping::BranchPendingMapping,
        timestamp::{DeleteFenceTimestampUs, NewBranchWriteTimestampUs},
        typed::{
            CheckpointId, CheckpointRootKey, CheckpointedObjectKey,
            LatestInfoSlot, LogicalMutation, MerkleNode, MutationValue,
            NodeIndex, ProcCheckpointUniqueId, TypedTableKey,
            U64SingletonSlot, UniquePendingId,
        },
    };

    use super::*;
    use crate::rollback::{
        BranchExactCutoverPhase, BranchExactWriterCutoverFence,
        MutationBuildError, RegistryBlocker, RegistryReadinessError,
        TimestampedMutationError, seal_commit_put, seal_commit_put_batch,
        seal_new_branch_put,
    };

    type Hash = PHash;

    fn chain(height: u64, seed: u64) -> CanonicalChainRef<Hash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(0),
            CheckpointRef::new(
                ChainCheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    seed,
                    seed + 1,
                    seed + 2,
                    seed + 3,
                )),
            ),
        )
    }

    fn narrow() -> BranchExactDualWriteIntent<Hash> {
        BranchExactDualWriteIntent::try_realm(
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            BranchPendingMapping::new(
                chain(10, 10),
                UniquePendingId::try_new(100).unwrap(),
            ),
            BranchPendingMapping::new(
                chain(12, 12),
                UniquePendingId::try_new(101).unwrap(),
            ),
            ProcCheckpointUniqueId::from_u128(9001),
            &TagTreeMerkleProof::<Hash>::new_empty(),
        )
        .unwrap()
    }

    fn prepared(timestamp: CommitWriteTimestampUs) -> BranchExactWriterPrepared<Hash> {
        let mut fence = [0u8; 81];
        fence[..8].copy_from_slice(&9_u64.to_be_bytes());
        fence[8..16].copy_from_slice(&3_u64.to_be_bytes());
        fence[16..48].fill(0x44);
        fence[48..80].fill(0x55);
        fence[80] = BranchExactCutoverPhase::TargetPrimaryDualWrite as u8;
        BranchExactWriterPrepared::test_fixture(
            narrow(),
            timestamp,
            BranchExactWriterCutoverFence::decode_canonical(&fence).unwrap(),
        )
    }

    fn no_state_plan() -> RealmNormalCommitCoveragePlan {
        RealmNormalCommitCoveragePlan::from_prepared(
            &PsyPreparedRealmBlockStateUpdates::<Hash> {
                realm_id: 7,
                realm_sub_id: 2,
                unique_pending_id: 101,
                proc_checkpoint_unique_id:
                    parth_core::QCoreProcCheckpointUniqueId::from(9001_u128),
                old_realm_root: PHash::from_owned_32bytes([1; 32]),
                new_realm_root: PHash::from_owned_32bytes([2; 32]),
                update_global_user_tree_nodes_ffs: Vec::new(),
                update_user_contract_tree_nodes_ffs: Vec::new(),
                update_contract_state_tree_nodes_ffs: Vec::new(),
                update_user_leaves_ffs: Vec::new(),
                update_contract_state_imt_leaves_ffs: Vec::new(),
            },
        )
    }

    fn put(
        domain: RealmNormalCommitWriteDomain,
        key: TypedTableKey,
        value: MutationValue,
        timestamp: CommitWriteTimestampUs,
    ) -> RealmCommitPhysicalDomainBatch {
        RealmCommitPhysicalDomainBatch::new(
            domain,
            vec![seal_commit_put(LogicalMutation::Put { key, value }, timestamp)
                .unwrap()],
        )
    }

    fn remaining(
        prepared: &BranchExactWriterPrepared<Hash>,
    ) -> Vec<RealmCommitPhysicalDomainBatch> {
        use RealmNormalCommitWriteDomain as D;
        let timestamp = prepared.timestamp();
        let checkpoint = CheckpointId::try_new(12).unwrap();
        let root = CheckpointRootKey::new(vec![0x44; 32]);
        let root_pair = seal_commit_put_batch(
            LogicalMutation::CheckpointRootMapping {
                root,
                checkpoint,
            },
            timestamp,
        )
        .unwrap();
        let by_hash = root_pair
            .members()
            .iter()
            .find(|put| put.resolved().mutation().key_domain() == key_domain_for(D::CheckpointRootByHash))
            .unwrap()
            .clone();
        let by_checkpoint = root_pair
            .members()
            .iter()
            .find(|put| put.resolved().mutation().key_domain() == key_domain_for(D::CheckpointRootByCheckpoint))
            .unwrap()
            .clone();
        vec![
            RealmCommitPhysicalDomainBatch::global_user_proof_after_cutover(
                    prepared,
                    TypedTableKey::CheckpointedObject(
                        CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint),
                    ),
                    MutationValue::PsyCanonicalBytes(vec![1]),
                )
                .unwrap(),
            put(
                D::CheckpointStateRoots,
                TypedTableKey::CheckpointStateRoots(checkpoint),
                MutationValue::PsyCanonicalBytes(vec![2]),
                timestamp,
            ),
            put(
                D::CheckpointLeaf,
                TypedTableKey::CheckpointLeaf(checkpoint),
                MutationValue::PsyCanonicalBytes(vec![3]),
                timestamp,
            ),
            put(
                D::GlobalCheckpointMerkle,
                TypedTableKey::GlobalCheckpointMerkle {
                    node: MerkleNode::new(1, NodeIndex::new(4)),
                    checkpoint,
                },
                MutationValue::PsyCanonicalBytes(vec![4]),
                timestamp,
            ),
            RealmCommitPhysicalDomainBatch::new(D::CheckpointRootByHash, vec![by_hash]),
            RealmCommitPhysicalDomainBatch::new(
                D::CheckpointRootByCheckpoint,
                vec![by_checkpoint],
            ),
            put(
                D::L2BlockState,
                TypedTableKey::L2BlockState(checkpoint),
                MutationValue::PsyCanonicalBytes(vec![5]),
                timestamp,
            ),
            put(
                D::LatestCheckpoint,
                TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
                MutationValue::CqlU64(checkpoint.get()),
                timestamp,
            ),
            put(
                D::LatestL2BlockState,
                TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
                MutationValue::PsyCanonicalBytes(vec![6]),
                timestamp,
            ),
            put(
                D::RealmAuthorityObservation,
                TypedTableKey::LatestInfo(LatestInfoSlot::RealmAuthorityObservation),
                MutationValue::PsyCanonicalBytes(vec![7]),
                timestamp,
            ),
        ]
    }

    fn assemble_test(
        prepared: &BranchExactWriterPrepared<Hash>,
        remaining: Vec<RealmCommitPhysicalDomainBatch>,
    ) -> Result<RealmFullCommitPhysicalPlan, RealmFullCommitPhysicalPlanError> {
        RealmFullCommitPhysicalPlan::try_assemble(
            no_state_plan(),
            prepared,
            remaining,
        )
    }

    #[test]
    fn real_registry_puts_and_narrow_intent_form_exact_no_state_plan() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_000).unwrap();
        let narrow_prepared = prepared(timestamp);
        let checkpoint = CheckpointId::try_new(12).unwrap();
        assert_eq!(
            seal_commit_put(
                LogicalMutation::Put {
                    key: TypedTableKey::CheckpointedObject(
                        CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint),
                    ),
                    value: MutationValue::PsyCanonicalBytes(vec![1]),
                },
                timestamp,
            ),
            Err(TimestampedMutationError::MutationBuild(
                MutationBuildError::Readiness(RegistryReadinessError::Blocked(
                    RegistryBlocker::MixedCheckpointPendingAxis,
                )),
            ))
        );
        let plan = assemble_test(&narrow_prepared, remaining(&narrow_prepared)).unwrap();
        assert_eq!(plan.coverage().domains().len(), 15);
        assert_eq!(plan.coverage().total_mutation_count(), 18);
        assert_eq!(plan.remaining().len(), 10);
        assert_eq!(plan.narrow_prepared_digest(), narrow_prepared.digest());
        assert_eq!(
            plan.narrow_intent_digest(),
            narrow().intent_digest().as_bytes()
        );

        let counts = plan
            .coverage()
            .domains()
            .iter()
            .map(|domain| (domain.domain(), domain.mutation_count()))
            .collect::<Vec<_>>();
        assert!(counts.contains(&(RealmNormalCommitWriteDomain::PendingToCheckpoint, 2)));
        assert!(counts.contains(&(RealmNormalCommitWriteDomain::CheckpointToPending, 2)));
        assert!(counts.contains(&(RealmNormalCommitWriteDomain::RewardsTopProofAtPending, 2)));
    }

    #[test]
    fn batch_order_does_not_change_coverage_identity() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_001).unwrap();
        let narrow_prepared = prepared(timestamp);
        let first = assemble_test(&narrow_prepared, remaining(&narrow_prepared)).unwrap();
        let mut reversed = remaining(&narrow_prepared);
        reversed.reverse();
        let second = assemble_test(&narrow_prepared, reversed).unwrap();
        assert_eq!(first.coverage(), second.coverage());
        assert_eq!(first.remaining(), second.remaining());
    }

    #[test]
    fn wrong_domain_timestamp_and_duplicate_locator_fail_closed() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_002).unwrap();
        let narrow_prepared = prepared(timestamp);
        let mut wrong_domain = remaining(&narrow_prepared);
        wrong_domain[1].domain = RealmNormalCommitWriteDomain::CheckpointLeaf;
        assert!(matches!(
            assemble_test(&narrow_prepared, wrong_domain),
            Err(RealmFullCommitPhysicalPlanError::PhysicalDomainMismatch { .. })
        ));

        let other_timestamp = CommitWriteTimestampUs::try_from_i128(10_003).unwrap();
        let other_prepared = prepared(other_timestamp);
        let mut mixed = remaining(&narrow_prepared);
        mixed[1] = remaining(&other_prepared).remove(1);
        assert!(matches!(
            assemble_test(&narrow_prepared, mixed),
            Err(RealmFullCommitPhysicalPlanError::MixedWriteTimestamp { .. })
        ));

        let old = CommitWriteTimestampUs::try_from_i128(10_000).unwrap();
        let fence = DeleteFenceTimestampUs::try_after(old, 10_001).unwrap();
        let new_branch = NewBranchWriteTimestampUs::try_after(fence, 10_002).unwrap();
        let mut wrong_write_kind = remaining(&narrow_prepared);
        wrong_write_kind[1].puts = vec![seal_new_branch_put(
            LogicalMutation::Put {
                key: TypedTableKey::CheckpointStateRoots(
                    CheckpointId::try_new(12).unwrap(),
                ),
                value: MutationValue::PsyCanonicalBytes(vec![2]),
            },
            new_branch,
        )
        .unwrap()];
        assert_eq!(
            assemble_test(&narrow_prepared, wrong_write_kind),
            Err(RealmFullCommitPhysicalPlanError::WrongWriteKind {
                domain: RealmNormalCommitWriteDomain::CheckpointStateRoots,
                actual: TimestampedWriteKind::NewBranchAfterFence,
            })
        );

        let mut duplicate = remaining(&narrow_prepared);
        let repeated = duplicate[0].puts[0].clone();
        duplicate[0].puts.push(repeated);
        assert_eq!(
            assemble_test(&narrow_prepared, duplicate),
            Err(RealmFullCommitPhysicalPlanError::DuplicatePhysicalLocator {
                domain: RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint,
            })
        );

        let mut foreign_cutover = remaining(&narrow_prepared);
        foreign_cutover[0].cutover_prepared_digest = Some([0x77; 32]);
        assert_eq!(
            assemble_test(&narrow_prepared, foreign_cutover),
            Err(RealmFullCommitPhysicalPlanError::CutoverPreparedIdentityMismatch)
        );
    }

    #[test]
    fn missing_hidden_and_narrow_substitution_are_rejected() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_004).unwrap();
        let narrow_prepared = prepared(timestamp);
        let mut missing = remaining(&narrow_prepared);
        missing.pop();
        assert!(matches!(
            assemble_test(&narrow_prepared, missing),
            Err(RealmFullCommitPhysicalPlanError::Coverage(
                RealmFullCommitCoverageError::MissingDomain { .. }
            ))
        ));

        let mut narrow_substitution = remaining(&narrow_prepared);
        narrow_substitution[0].domain = RealmNormalCommitWriteDomain::PendingToCheckpoint;
        assert_eq!(
            assemble_test(&narrow_prepared, narrow_substitution),
            Err(RealmFullCommitPhysicalPlanError::NarrowDomainSuppliedAsTypedBatch {
                domain: RealmNormalCommitWriteDomain::PendingToCheckpoint,
            })
        );

        let prepared = PsyPreparedRealmBlockStateUpdates::<Hash> {
            realm_id: 7,
            realm_sub_id: 2,
            unique_pending_id: 101,
            proc_checkpoint_unique_id:
                parth_core::QCoreProcCheckpointUniqueId::from(9001_u128),
            old_realm_root: PHash::from_owned_32bytes([1; 32]),
            new_realm_root: PHash::from_owned_32bytes([2; 32]),
            update_global_user_tree_nodes_ffs: vec![1],
            update_user_contract_tree_nodes_ffs: Vec::new(),
            update_contract_state_tree_nodes_ffs: Vec::new(),
            update_user_leaves_ffs: Vec::new(),
            update_contract_state_imt_leaves_ffs: Vec::new(),
        };
        let hidden = RealmNormalCommitCoveragePlan::from_prepared(&prepared);
        assert_eq!(
            RealmFullCommitPhysicalPlan::try_assemble(
                hidden,
                &narrow_prepared,
                remaining(&narrow_prepared),
            ),
            Err(RealmFullCommitPhysicalPlanError::Coverage(
                RealmFullCommitCoverageError::IgnoredPreparedPayload
            ))
        );
    }
}
