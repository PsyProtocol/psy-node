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
    realm_full_commit_write_set::{
        RealmCommitLogicalDomainBatch, RealmFullCommitWriteSet,
    },
    realm_normal_commit_coverage::{
        H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE, RealmNormalCommitCoveragePlan,
        RealmNormalCommitWriteDomain,
        realm_normal_commit_domain_for_branch_exact_mutation,
    },
    realm_imt_mutation_graph::RealmImtMutationGraphDigest,
    realm_prepared_payload::RealmPreparedPayloadCommitment,
    timestamp::CommitWriteTimestampUs,
    typed::LogicalMutation,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, ScyllaKeyDomain, ScyllaPhysicalTableId,
    SealedTimestampedPut, TimestampedMutationError, TimestampedWriteKind,
    expected_physical_table, key_domain_for,
    realm_prepared_state_physical_plan::RealmPreparedStatePhysicalBatches,
    seal_commit_put_batch,
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
    prepared_payload_commitment: Option<RealmPreparedPayloadCommitment>,
    mutation_graph_digest: Option<RealmImtMutationGraphDigest>,
    remaining: Vec<RealmCommitPhysicalDomainBatch>,
}

impl RealmFullCommitPhysicalPlan {
    /// Resolve the complete driver-independent Processor write set under the
    /// exact timestamp and cutover identity owned by the durable narrow writer.
    pub(crate) fn try_assemble_from_write_set<Hash: Q256BitHash>(
        narrow: &BranchExactWriterPrepared<Hash>,
        logical: &RealmFullCommitWriteSet,
    ) -> Result<Self, RealmFullCommitPhysicalPlanError> {
        let remaining = logical
            .remaining()
            .iter()
            .map(|batch| seal_logical_batch(narrow, batch))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(state) = logical.prepared_state() {
            let state = RealmPreparedStatePhysicalBatches::try_from_write_set(
                state,
                narrow.timestamp(),
            )
            .map_err(|_| RealmFullCommitPhysicalPlanError::PreparedStateExpansion)?;
            Self::try_assemble_with_prepared_state(narrow, remaining, state)
        } else {
            Self::try_assemble(logical.coverage_plan(), narrow, remaining)
        }
    }

    pub(crate) fn try_assemble<Hash: Q256BitHash>(
        coverage_plan: RealmNormalCommitCoveragePlan,
        narrow: &BranchExactWriterPrepared<Hash>,
        remaining: Vec<RealmCommitPhysicalDomainBatch>,
    ) -> Result<Self, RealmFullCommitPhysicalPlanError> {
        if coverage_plan.invokes_state_update_branch() {
            return Err(
                RealmFullCommitPhysicalPlanError::PreparedStateBatchesRequired,
            );
        }
        assemble(
            coverage_plan,
            narrow.intent(),
            narrow.timestamp(),
            *narrow.digest(),
            remaining,
            None,
            None,
        )
    }

    /// Assemble the complete state-changing path only from batches that were
    /// derived from an exact sealed mutation graph and its prepared payload.
    pub(crate) fn try_assemble_with_prepared_state<Hash: Q256BitHash>(
        narrow: &BranchExactWriterPrepared<Hash>,
        mut remaining: Vec<RealmCommitPhysicalDomainBatch>,
        state: RealmPreparedStatePhysicalBatches,
    ) -> Result<Self, RealmFullCommitPhysicalPlanError> {
        if state.authority() != narrow.intent().authority() {
            return Err(
                RealmFullCommitPhysicalPlanError::PreparedStateAuthorityMismatch,
            );
        }
        if state.timestamp() != narrow.timestamp() {
            return Err(
                RealmFullCommitPhysicalPlanError::PreparedStateTimestampMismatch {
                    expected: narrow.timestamp(),
                    actual: state.timestamp(),
                },
            );
        }
        let coverage_plan = state.coverage_plan();
        let prepared_payload_commitment = state.prepared_payload_commitment();
        let mutation_graph_digest = state.mutation_graph_digest();
        remaining.extend(state.into_batches());
        assemble(
            coverage_plan,
            narrow.intent(),
            narrow.timestamp(),
            *narrow.digest(),
            remaining,
            Some(prepared_payload_commitment),
            Some(mutation_graph_digest),
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

    pub(crate) const fn prepared_payload_commitment(
        &self,
    ) -> Option<RealmPreparedPayloadCommitment> {
        self.prepared_payload_commitment
    }

    pub(crate) const fn mutation_graph_digest(
        &self,
    ) -> Option<RealmImtMutationGraphDigest> {
        self.mutation_graph_digest
    }

    pub(crate) fn remaining(&self) -> &[RealmCommitPhysicalDomainBatch] {
        &self.remaining
    }
}

fn seal_logical_batch<Hash: Q256BitHash>(
    narrow: &BranchExactWriterPrepared<Hash>,
    batch: &RealmCommitLogicalDomainBatch,
) -> Result<RealmCommitPhysicalDomainBatch, RealmFullCommitPhysicalPlanError> {
    if batch.domain()
        == RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint
    {
        let [LogicalMutation::Put { key, value }] = batch.mutations() else {
            return Err(
                RealmFullCommitPhysicalPlanError::LogicalMutationPhysicalCardinality {
                    domain: batch.domain(),
                    actual: batch.mutations().len(),
                },
            );
        };
        return RealmCommitPhysicalDomainBatch::global_user_proof_after_cutover(
            narrow,
            key.clone(),
            value.clone(),
        )
        .map_err(Into::into);
    }

    let expected_key_domain = key_domain_for(batch.domain());
    let expected_table = expected_physical_table(batch.domain());
    let mut puts = Vec::with_capacity(batch.mutations().len());
    for mutation in batch.mutations() {
        let sealed = seal_commit_put_batch(mutation.clone(), narrow.timestamp())?;
        let selected = sealed
            .members()
            .iter()
            .filter(|put| {
                let mutation = put.resolved().mutation();
                mutation.key_domain() == expected_key_domain
                    && mutation.physical_table() == expected_table
            })
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            return Err(
                RealmFullCommitPhysicalPlanError::LogicalMutationPhysicalCardinality {
                    domain: batch.domain(),
                    actual: selected.len(),
                },
            );
        }
        puts.push(selected[0].clone());
    }
    Ok(RealmCommitPhysicalDomainBatch::new(batch.domain(), puts))
}

fn assemble<Hash: Q256BitHash>(
    coverage_plan: RealmNormalCommitCoveragePlan,
    narrow: &BranchExactDualWriteIntent<Hash>,
    timestamp: CommitWriteTimestampUs,
    narrow_prepared_digest: [u8; 32],
    mut remaining: Vec<RealmCommitPhysicalDomainBatch>,
    prepared_payload_commitment: Option<RealmPreparedPayloadCommitment>,
    mutation_graph_digest: Option<RealmImtMutationGraphDigest>,
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
        prepared_payload_commitment,
        mutation_graph_digest,
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
    PreparedStateBatchesRequired,
    PreparedStateExpansion,
    PreparedStateAuthorityMismatch,
    PreparedStateTimestampMismatch {
        expected: CommitWriteTimestampUs,
        actual: CommitWriteTimestampUs,
    },
    LogicalMutationPhysicalCardinality {
        domain: RealmNormalCommitWriteDomain,
        actual: usize,
    },
    Timestamped(TimestampedMutationError),
    Coverage(RealmFullCommitCoverageError),
}

impl From<TimestampedMutationError> for RealmFullCommitPhysicalPlanError {
    fn from(value: TimestampedMutationError) -> Self {
        Self::Timestamped(value)
    }
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
pub(crate) mod tests {
    use parth_core::{
        crypto::hash::tag_tree::TagTreeMerkleProof,
        pgoldilocks::PoseidonHasher,
        PHash, PF,
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
        realm_full_commit_write_set::{
            RealmCommitLogicalDomainBatch, RealmFullCommitWriteSet,
            RealmImtCursorBeforeImage, RealmPreparedStateWriteSet,
        },
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

    fn narrow_for(authority: AuthorityScope) -> BranchExactDualWriteIntent<Hash> {
        BranchExactDualWriteIntent::try_realm(
            authority,
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

    fn narrow() -> BranchExactDualWriteIntent<Hash> {
        narrow_for(AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        })
    }

    fn latest_l2_state_bytes(checkpoint: CheckpointId) -> Vec<u8> {
        let mut bytes = vec![0_u8; 60];
        bytes[..8].copy_from_slice(&checkpoint.get().to_le_bytes());
        bytes
    }

    fn realm_observation_bytes(checkpoint: CheckpointId) -> Vec<u8> {
        let mut bytes = vec![0_u8; 122];
        bytes[0..8].copy_from_slice(b"PSYAUTHO");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..18].copy_from_slice(b"PSYCCREF");
        bytes[18..20].copy_from_slice(&1_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&checkpoint.get().to_le_bytes());
        bytes[40] = 1;
        bytes[41..43].copy_from_slice(&32_u16.to_le_bytes());
        bytes[75] = 2;
        bytes[82..90].copy_from_slice(&checkpoint.get().to_le_bytes());
        bytes
    }

    fn prepared_from_intent(
        timestamp: CommitWriteTimestampUs,
        intent: BranchExactDualWriteIntent<Hash>,
    ) -> BranchExactWriterPrepared<Hash> {
        let mut fence = [0u8; 81];
        fence[..8].copy_from_slice(&9_u64.to_be_bytes());
        fence[8..16].copy_from_slice(&3_u64.to_be_bytes());
        fence[16..48].fill(0x44);
        fence[48..80].fill(0x55);
        fence[80] = BranchExactCutoverPhase::TargetPrimaryDualWrite as u8;
        BranchExactWriterPrepared::test_fixture(
            intent,
            timestamp,
            BranchExactWriterCutoverFence::decode_canonical(&fence).unwrap(),
        )
    }

    fn prepared(timestamp: CommitWriteTimestampUs) -> BranchExactWriterPrepared<Hash> {
        prepared_from_intent(timestamp, narrow())
    }

    fn no_state_prepared_for(
        prepared: &BranchExactWriterPrepared<Hash>,
    ) -> PsyPreparedRealmBlockStateUpdates<Hash> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = prepared.intent().authority()
        else {
            panic!("qualification full plan requires Realm authority")
        };
        PsyPreparedRealmBlockStateUpdates::<Hash> {
            realm_id: u64::from(realm_id),
            realm_sub_id: u64::from(realm_sub_id),
            unique_pending_id: prepared.intent().candidate().pending_id().get(),
            proc_checkpoint_unique_id: parth_core::QCoreProcCheckpointUniqueId::from(
                prepared.intent().proc_checkpoint_id().as_u128(),
            ),
            old_realm_root: PHash::from_owned_32bytes([1; 32]),
            new_realm_root: PHash::from_owned_32bytes([1; 32]),
            update_global_user_tree_nodes_ffs: Vec::new(),
            update_user_contract_tree_nodes_ffs: Vec::new(),
            update_contract_state_tree_nodes_ffs: Vec::new(),
            update_user_leaves_ffs: Vec::new(),
            update_contract_state_imt_leaves_ffs: Vec::new(),
        }
    }

    fn no_state_plan_for(
        prepared: &BranchExactWriterPrepared<Hash>,
    ) -> RealmNormalCommitCoveragePlan {
        RealmNormalCommitCoveragePlan::from_prepared(&no_state_prepared_for(prepared))
    }

    fn no_state_plan() -> RealmNormalCommitCoveragePlan {
        no_state_plan_for(&prepared(
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
        ))
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
                MutationValue::PsyCanonicalBytes(vec![4; 32]),
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
                MutationValue::PsyCanonicalBytes(latest_l2_state_bytes(checkpoint)),
                timestamp,
            ),
            put(
                D::RealmAuthorityObservation,
                TypedTableKey::LatestInfo(LatestInfoSlot::RealmAuthorityObservation),
                MutationValue::PsyCanonicalBytes(realm_observation_bytes(checkpoint)),
                timestamp,
            ),
        ]
    }

    fn logical_remaining() -> Vec<RealmCommitLogicalDomainBatch> {
        use RealmNormalCommitWriteDomain as D;
        let checkpoint = CheckpointId::try_new(12).unwrap();
        let root = CheckpointRootKey::new(vec![0x44; 32]);
        vec![
            RealmCommitLogicalDomainBatch::new(
                D::GlobalUserTopProofAtCheckpoint,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::CheckpointedObject(
                        CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint),
                    ),
                    value: MutationValue::PsyCanonicalBytes(vec![1]),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::CheckpointStateRoots,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::CheckpointStateRoots(checkpoint),
                    value: MutationValue::PsyCanonicalBytes(vec![2]),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::CheckpointLeaf,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::CheckpointLeaf(checkpoint),
                    value: MutationValue::PsyCanonicalBytes(vec![3]),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::GlobalCheckpointMerkle,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::GlobalCheckpointMerkle {
                        node: MerkleNode::new(1, NodeIndex::new(4)),
                        checkpoint,
                    },
                    value: MutationValue::PsyCanonicalBytes(vec![4; 32]),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::CheckpointRootByHash,
                vec![LogicalMutation::CheckpointRootMapping {
                    root: root.clone(),
                    checkpoint,
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::CheckpointRootByCheckpoint,
                vec![LogicalMutation::CheckpointRootMapping {
                    root,
                    checkpoint,
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::L2BlockState,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::L2BlockState(checkpoint),
                    value: MutationValue::PsyCanonicalBytes(vec![5]),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::LatestCheckpoint,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
                    value: MutationValue::CqlU64(checkpoint.get()),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::LatestL2BlockState,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
                    value: MutationValue::PsyCanonicalBytes(
                        latest_l2_state_bytes(checkpoint),
                    ),
                }],
            ),
            RealmCommitLogicalDomainBatch::new(
                D::RealmAuthorityObservation,
                vec![LogicalMutation::Put {
                    key: TypedTableKey::LatestInfo(
                        LatestInfoSlot::RealmAuthorityObservation,
                    ),
                    value: MutationValue::PsyCanonicalBytes(
                        realm_observation_bytes(checkpoint),
                    ),
                }],
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

    fn full_state_plan(
        timestamp: CommitWriteTimestampUs,
    ) -> (BranchExactWriterPrepared<Hash>, RealmFullCommitPhysicalPlan) {
        let (prepared_state, graph, cursor_before) =
            crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture()
                .unwrap();
        let state = RealmPreparedStatePhysicalBatches::try_new::<
            PF,
            PHash,
            PoseidonHasher,
        >(&prepared_state, &graph, timestamp, &[cursor_before])
        .unwrap();
        let narrow_prepared = prepared_from_intent(
            timestamp,
            narrow_for(AuthorityScope::Realm {
                realm_id: 1,
                realm_sub_id: 2,
            }),
        );
        let plan = RealmFullCommitPhysicalPlan::try_assemble_with_prepared_state(
            &narrow_prepared,
            remaining(&narrow_prepared),
            state,
        )
        .unwrap();
        (narrow_prepared, plan)
    }

    pub(crate) fn qualification_full_schedule(
        timestamp: CommitWriteTimestampUs,
    ) -> crate::rollback::realm_full_commit_execution::RealmFullCommitExecutionSchedule
    {
        let (narrow, full) = full_state_plan(timestamp);
        crate::rollback::realm_full_commit_execution::RealmFullCommitExecutionSchedule::try_from_plan(
            &full,
            &narrow,
        )
        .expect("qualification full schedule must remain valid")
    }

    /// RF=3 qualification input derived from the exact durable h22 prepared
    /// writer selected by the production lifecycle. This keeps the test from
    /// manufacturing a second writer identity while still exercising the
    /// complete manifest path with the domains that are non-empty for this
    /// checkpoint.
    pub(crate) fn qualification_no_state_full_plan(
        prepared: &BranchExactWriterPrepared<Hash>,
    ) -> RealmFullCommitPhysicalPlan {
        RealmFullCommitPhysicalPlan::try_assemble(
            no_state_plan_for(prepared),
            prepared,
            remaining(prepared),
        )
        .expect("qualification no-state full plan must remain valid")
    }

    pub(crate) fn qualification_prepared(
        timestamp: CommitWriteTimestampUs,
    ) -> BranchExactWriterPrepared<Hash> {
        prepared(timestamp)
    }

    fn state_without_imt_plan(
        timestamp: CommitWriteTimestampUs,
    ) -> (BranchExactWriterPrepared<Hash>, RealmFullCommitPhysicalPlan) {
        let (prepared_state, graph) = crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture_without_imt().unwrap();
        let state = RealmPreparedStatePhysicalBatches::try_new::<
            PF,
            PHash,
            PoseidonHasher,
        >(&prepared_state, &graph, timestamp, &[])
        .unwrap();
        let narrow_prepared = prepared_from_intent(
            timestamp,
            narrow_for(AuthorityScope::Realm {
                realm_id: 1,
                realm_sub_id: 2,
            }),
        );
        let plan = RealmFullCommitPhysicalPlan::try_assemble_with_prepared_state(
            &narrow_prepared,
            remaining(&narrow_prepared),
            state,
        )
        .unwrap();
        (narrow_prepared, plan)
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
    fn processor_logical_write_set_resolves_to_the_same_complete_plan() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_008).unwrap();
        let narrow_prepared = prepared(timestamp);
        let prepared_state = no_state_prepared_for(&narrow_prepared);
        let logical = RealmFullCommitWriteSet::try_new(
            &prepared_state,
            logical_remaining(),
            None,
        )
        .unwrap();
        let resolved = RealmFullCommitPhysicalPlan::try_assemble_from_write_set(
            &narrow_prepared,
            &logical,
        )
        .unwrap();
        let direct = assemble_test(&narrow_prepared, remaining(&narrow_prepared)).unwrap();
        assert_eq!(resolved, direct);

        let wrong_domain = logical_remaining()
            .into_iter()
            .map(|batch| {
                if batch.domain() == RealmNormalCommitWriteDomain::CheckpointLeaf {
                    RealmCommitLogicalDomainBatch::new(
                        batch.domain(),
                        vec![LogicalMutation::Put {
                            key: TypedTableKey::L2BlockState(
                                CheckpointId::try_new(12).unwrap(),
                            ),
                            value: MutationValue::PsyCanonicalBytes(vec![3]),
                        }],
                    )
                } else {
                    batch
                }
            })
            .collect();
        let wrong_domain = RealmFullCommitWriteSet::try_new(
            &prepared_state,
            wrong_domain,
            None,
        )
        .unwrap();
        assert_eq!(
            RealmFullCommitPhysicalPlan::try_assemble_from_write_set(
                &narrow_prepared,
                &wrong_domain,
            ),
            Err(
                RealmFullCommitPhysicalPlanError::LogicalMutationPhysicalCardinality {
                    domain: RealmNormalCommitWriteDomain::CheckpointLeaf,
                    actual: 0,
                },
            ),
        );

        let (prepared_state, graph, cursor_before) =
            crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture()
                .unwrap();
        let state = RealmPreparedStateWriteSet::try_from_verified::<
            PF,
            PHash,
            PoseidonHasher,
        >(
            &prepared_state,
            &graph,
            vec![RealmImtCursorBeforeImage::new(
                cursor_before.tree(),
                cursor_before.tree_sub(),
                cursor_before.next_append_index(),
            )],
        )
        .unwrap();
        let narrow_prepared = prepared_from_intent(
            timestamp,
            narrow_for(AuthorityScope::Realm {
                realm_id: 1,
                realm_sub_id: 2,
            }),
        );
        let logical = RealmFullCommitWriteSet::try_new(
            &prepared_state,
            logical_remaining(),
            Some(state),
        )
        .unwrap();
        let resolved = RealmFullCommitPhysicalPlan::try_assemble_from_write_set(
            &narrow_prepared,
            &logical,
        )
        .unwrap();
        assert_eq!(resolved.coverage().domains().len(), 22);
        assert_eq!(
            resolved.prepared_payload_commitment(),
            Some(graph.prepared_payload_commitment()),
        );
        assert_eq!(resolved.mutation_graph_digest(), Some(graph.digest()));
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
    fn sealed_prepared_state_completes_all_twenty_two_domains() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_005).unwrap();
        let (prepared_state, graph, cursor_before) =
            crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture()
                .unwrap();
        let state = RealmPreparedStatePhysicalBatches::try_new::<
            PF,
            PHash,
            PoseidonHasher,
        >(&prepared_state, &graph, timestamp, &[cursor_before])
        .unwrap();
        assert_eq!(state.batches().len(), 7);

        let authority = AuthorityScope::Realm {
            realm_id: 1,
            realm_sub_id: 2,
        };
        let narrow_prepared =
            prepared_from_intent(timestamp, narrow_for(authority));
        let plan = RealmFullCommitPhysicalPlan::try_assemble_with_prepared_state(
            &narrow_prepared,
            remaining(&narrow_prepared),
            state,
        )
        .unwrap();

        assert_eq!(plan.coverage().domains().len(), 22);
        assert_eq!(plan.coverage().total_mutation_count(), 33);
        assert_eq!(plan.remaining().len(), 17);
        assert_eq!(
            plan.prepared_payload_commitment(),
            Some(graph.prepared_payload_commitment()),
        );
        assert_eq!(plan.mutation_graph_digest(), Some(graph.digest()));
    }

    #[test]
    fn prepared_state_cannot_cross_authority_or_use_generic_assembly() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_006).unwrap();
        let (prepared_state, graph, cursor_before) =
            crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture()
                .unwrap();
        let state = RealmPreparedStatePhysicalBatches::try_new::<
            PF,
            PHash,
            PoseidonHasher,
        >(&prepared_state, &graph, timestamp, &[cursor_before])
        .unwrap();
        let foreign = prepared(timestamp);
        assert_eq!(
            RealmFullCommitPhysicalPlan::try_assemble_with_prepared_state(
                &foreign,
                remaining(&foreign),
                state,
            ),
            Err(RealmFullCommitPhysicalPlanError::PreparedStateAuthorityMismatch),
        );
        assert_eq!(
            RealmFullCommitPhysicalPlan::try_assemble(
                RealmNormalCommitCoveragePlan::from_prepared(&prepared_state),
                &foreign,
                remaining(&foreign),
            ),
            Err(RealmFullCommitPhysicalPlanError::PreparedStateBatchesRequired),
        );
    }

    #[test]
    fn sealed_state_without_imt_completes_nineteen_domains() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_007).unwrap();
        let (prepared_state, graph) = crate::rollback::realm_imt_predecessor_rf3_gate::qualification_state_fixture_without_imt().unwrap();
        let state = RealmPreparedStatePhysicalBatches::try_new::<
            PF,
            PHash,
            PoseidonHasher,
        >(&prepared_state, &graph, timestamp, &[])
        .unwrap();
        assert_eq!(state.batches().len(), 4);

        let narrow_prepared = prepared_from_intent(
            timestamp,
            narrow_for(AuthorityScope::Realm {
                realm_id: 1,
                realm_sub_id: 2,
            }),
        );
        let plan = RealmFullCommitPhysicalPlan::try_assemble_with_prepared_state(
            &narrow_prepared,
            remaining(&narrow_prepared),
            state,
        )
        .unwrap();
        assert_eq!(plan.coverage().domains().len(), 19);
        assert_eq!(plan.coverage().total_mutation_count(), 30);
        assert_eq!(plan.remaining().len(), 14);
    }

    fn exact_observations(
        schedule: &crate::rollback::realm_full_commit_execution::RealmFullCommitExecutionSchedule,
    ) -> Vec<Option<crate::rollback::realm_full_commit_execution::RealmFullCommitObservedRow>> {
        schedule
            .rows()
            .iter()
            .map(|row| {
                Some(
                    crate::rollback::realm_full_commit_execution::RealmFullCommitObservedRow::new(
                        row.physical_table(),
                        row.locator().to_vec(),
                        row.expected_value().to_vec(),
                        row.timestamp().as_i64(),
                    ),
                )
            })
            .collect()
    }

    #[test]
    fn full_plan_has_deterministic_exact_readback_schedule() {
        use crate::rollback::realm_full_commit_execution::RealmFullCommitExecutionSchedule;

        let timestamp = CommitWriteTimestampUs::try_from_i128(10_008).unwrap();
        let (narrow, full) = full_state_plan(timestamp);
        let schedule = RealmFullCommitExecutionSchedule::try_from_plan(&full, &narrow)
            .unwrap();
        assert_eq!(schedule.rows().len(), 25);
        assert_eq!(
            crate::rollback::realm_full_commit_scylla::validate_schedule_bindings(
                &schedule,
            )
            .unwrap(),
            25,
        );
        assert!(schedule.rows().windows(2).all(|pair| {
            (pair[0].domain(), pair[0].physical_table(), pair[0].locator())
                <= (pair[1].domain(), pair[1].physical_table(), pair[1].locator())
        }));

        let missing = vec![None; schedule.rows().len()];
        assert_eq!(
            schedule.preflight(&missing).unwrap().write_indices(),
            (0..25).collect::<Vec<_>>(),
        );
        assert_eq!(
            crate::rollback::realm_full_commit_scylla::validate_schedule_write_plan(
                &schedule,
                &missing,
            )
            .unwrap(),
            24,
        );
        let exact = exact_observations(&schedule);
        let root_by_hash = schedule
            .rows()
            .iter()
            .position(|row| {
                row.domain() == RealmNormalCommitWriteDomain::CheckpointRootByHash
            })
            .unwrap();
        let root_by_checkpoint = schedule
            .rows()
            .iter()
            .position(|row| {
                row.domain()
                    == RealmNormalCommitWriteDomain::CheckpointRootByCheckpoint
            })
            .unwrap();
        let mut partial_root_pair = missing.clone();
        partial_root_pair[root_by_hash] = exact[root_by_hash].clone();
        assert_eq!(
            crate::rollback::realm_full_commit_scylla::validate_schedule_write_plan(
                &schedule,
                &partial_root_pair,
            )
            .unwrap(),
            24,
        );
        partial_root_pair[root_by_checkpoint] =
            exact[root_by_checkpoint].clone();
        assert_eq!(
            crate::rollback::realm_full_commit_scylla::validate_schedule_write_plan(
                &schedule,
                &partial_root_pair,
            )
            .unwrap(),
            23,
        );
        assert!(schedule.preflight(&exact).unwrap().write_indices().is_empty());
        assert_eq!(
            crate::rollback::realm_full_commit_scylla::validate_schedule_write_plan(
                &schedule,
                &exact,
            )
            .unwrap(),
            0,
        );
        let verified = schedule.verify_after_write(&exact).unwrap();
        assert_eq!(verified.row_count(), 25);
        assert_eq!(verified.coverage_digest(), full.coverage().digest());
        assert_eq!(verified.narrow_prepared_digest(), narrow.digest());
        assert_ne!(verified.digest(), &[0; 32]);

        let (narrow, no_imt) = state_without_imt_plan(timestamp);
        assert_eq!(
            RealmFullCommitExecutionSchedule::try_from_plan(&no_imt, &narrow)
                .unwrap()
                .rows()
                .len(),
            22,
        );
        let narrow = prepared(timestamp);
        let no_state = assemble_test(&narrow, remaining(&narrow)).unwrap();
        assert_eq!(
            RealmFullCommitExecutionSchedule::try_from_plan(&no_state, &narrow)
                .unwrap()
                .rows()
                .len(),
            10,
        );
    }

    #[test]
    fn h22_and_typed_observations_form_one_canonical_composite_manifest() {
        use crate::rollback::{
            realm_full_commit_execution::RealmFullCommitExecutionSchedule,
            realm_full_commit_manifest::{
                RealmFullCommitCompositeManifest,
                RealmFullCommitManifestError,
                RealmNarrowWritesVerifiedEvidence,
            },
        };

        let timestamp = CommitWriteTimestampUs::try_from_i128(10_011).unwrap();
        let (narrow, full) = full_state_plan(timestamp);
        let schedule =
            RealmFullCommitExecutionSchedule::try_from_plan(&full, &narrow).unwrap();
        let typed = schedule
            .verify_after_write(&exact_observations(&schedule))
            .unwrap();
        let h22 = RealmNarrowWritesVerifiedEvidence::test_fixture(&narrow);
        let manifest =
            RealmFullCommitCompositeManifest::try_new(&full, &h22, &typed).unwrap();

        assert_eq!(manifest.typed_row_count(), 25);
        assert_eq!(manifest.total_mutation_count(), 33);
        assert_eq!(manifest.canonical_payload().len(), 512);
        assert_ne!(manifest.slot().as_bytes(), &[0; 32]);
        assert_ne!(manifest.digest(), &[0; 32]);
        let retry =
            RealmFullCommitCompositeManifest::try_new(&full, &h22, &typed)
                .unwrap();
        assert_eq!(retry, manifest);
        let decoded = RealmFullCommitCompositeManifest::<Hash>::decode_persisted(
            manifest.slot().as_bytes(),
            manifest.revision() as i64,
            manifest.canonical_payload(),
        )
        .unwrap();
        assert_eq!(decoded, manifest);
        manifest.revalidate_sources(&full, &h22, &typed).unwrap();

        let mut tampered = manifest.canonical_payload().to_vec();
        tampered[40] ^= 1;
        assert_eq!(
            RealmFullCommitCompositeManifest::<Hash>::decode_persisted(
                manifest.slot().as_bytes(),
                manifest.revision() as i64,
                &tampered,
            ),
            Err(RealmFullCommitManifestError::ManifestDigestMismatch),
        );

        let (foreign_narrow, foreign_full) = full_state_plan(
            CommitWriteTimestampUs::try_from_i128(10_012).unwrap(),
        );
        let foreign_schedule = RealmFullCommitExecutionSchedule::try_from_plan(
            &foreign_full,
            &foreign_narrow,
        )
        .unwrap();
        let foreign_typed = foreign_schedule
            .verify_after_write(&exact_observations(&foreign_schedule))
            .unwrap();
        assert_eq!(
            RealmFullCommitCompositeManifest::try_new(
                &full,
                &h22,
                &foreign_typed,
            ),
            Err(RealmFullCommitManifestError::NarrowIdentityMismatch),
        );
        assert_eq!(
            RealmFullCommitCompositeManifest::<Hash>::decode_persisted(
                &[0x99; 32],
                manifest.revision() as i64,
                manifest.canonical_payload(),
            ),
            Err(RealmFullCommitManifestError::PersistedIdentityMismatch),
        );
        let mut oversized = manifest.canonical_payload().to_vec();
        oversized.push(0);
        assert_eq!(
            RealmFullCommitCompositeManifest::<Hash>::decode_persisted(
                manifest.slot().as_bytes(),
                manifest.revision() as i64,
                &oversized,
            ),
            Err(RealmFullCommitManifestError::PayloadTooLarge {
                actual: oversized.len(),
            }),
        );
    }

    #[test]
    fn exact_reconciliation_separates_retry_from_conflict() {
        use crate::rollback::realm_full_commit_execution::{
            RealmFullCommitExecutionError, RealmFullCommitExecutionSchedule,
            RealmFullCommitObservedRow,
        };

        let timestamp = CommitWriteTimestampUs::try_from_i128(10_009).unwrap();
        let (narrow, full) = full_state_plan(timestamp);
        let schedule = RealmFullCommitExecutionSchedule::try_from_plan(&full, &narrow)
            .unwrap();
        let first = &schedule.rows()[0];
        let mut observed = exact_observations(&schedule);

        observed[0] = Some(RealmFullCommitObservedRow::new(
            first.physical_table(),
            first.locator().to_vec(),
            vec![0xAA],
            timestamp.as_i64() - 1,
        ));
        assert_eq!(schedule.preflight(&observed).unwrap().write_indices(), &[0]);
        assert_eq!(
            schedule.verify_after_write(&observed),
            Err(RealmFullCommitExecutionError::RetryRequired {
                indices: vec![0],
            }),
        );

        observed[0] = Some(RealmFullCommitObservedRow::new(
            first.physical_table(),
            first.locator().to_vec(),
            vec![0xAA],
            timestamp.as_i64(),
        ));
        assert_eq!(
            schedule.verify_after_write(&observed),
            Err(RealmFullCommitExecutionError::PhysicalValueConflict { index: 0 }),
        );

        observed[0] = Some(RealmFullCommitObservedRow::new(
            first.physical_table(),
            first.locator().to_vec(),
            first.expected_value().to_vec(),
            timestamp.as_i64() + 1,
        ));
        assert_eq!(
            schedule.preflight(&observed),
            Err(RealmFullCommitExecutionError::SealedTimestampSuperseded {
                index: 0,
                sealed: timestamp.as_i64(),
                actual: timestamp.as_i64() + 1,
            }),
        );
    }

    #[test]
    fn execution_schedule_rejects_foreign_narrow_and_malformed_observations() {
        use crate::rollback::realm_full_commit_execution::{
            RealmFullCommitExecutionError, RealmFullCommitExecutionSchedule,
            RealmFullCommitObservedRow,
        };

        let timestamp = CommitWriteTimestampUs::try_from_i128(10_010).unwrap();
        let (narrow, full) = full_state_plan(timestamp);
        assert_eq!(
            RealmFullCommitExecutionSchedule::try_from_plan(
                &full,
                &prepared(timestamp),
            ),
            Err(RealmFullCommitExecutionError::NarrowIdentityMismatch),
        );

        let schedule =
            RealmFullCommitExecutionSchedule::try_from_plan(&full, &narrow)
                .unwrap();
        assert_eq!(
            schedule.preflight(&[]),
            Err(RealmFullCommitExecutionError::ObservationCountMismatch {
                expected: schedule.rows().len(),
                actual: 0,
            }),
        );

        let first = &schedule.rows()[0];
        let mut observed = exact_observations(&schedule);
        observed[0] = Some(RealmFullCommitObservedRow::new(
            first.physical_table(),
            vec![0xFF],
            first.expected_value().to_vec(),
            first.timestamp().as_i64(),
        ));
        assert_eq!(
            schedule.verify_after_write(&observed),
            Err(RealmFullCommitExecutionError::ObservationIdentityMismatch {
                index: 0,
            }),
        );
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
