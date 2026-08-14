//! Exact preflight and reconciliation schedule for Coordinator typed writes.
//!
//! This is the driver-independent execution boundary after the durable
//! Coordinator commit source has been expanded into physical mutations.  It
//! fixes one row order, retains each sealed mutation, and classifies fresh
//! point reads before and after a write attempt.  It performs no CQL, does not
//! execute the six mapping mutations owned by the narrow dual writer, and
//! cannot commit the source or publish a canonical head.

use std::{collections::BTreeSet, error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    coordinator_normal_commit_coverage::CoordinatorNormalCommitWriteDomain,
    timestamp::CommitWriteTimestampUs,
    typed::{MutationOperation, MutationValue},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, ScyllaPhysicalTableId, SealedTimestampedPut,
    TimestampedWriteKind,
    coordinator_commit_physical_write_plan::CoordinatorCommitPhysicalWritePlan,
};

const ROW_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-execution-row.v1\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-execution-observation.v1\0";

/// The exact logical result a point-read must observe.
///
/// `KeyOnlyPresent` is intentionally separate: Scylla cannot expose
/// `WRITETIME` for a primary-key-only row.  Such a row is always re-issued by
/// the executor, and post-write success requires both an acknowledged write
/// attempt and an exact presence read.  A response-loss is retried rather than
/// being inferred from presence alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitExpectedValue {
    Value(Vec<u8>),
    KeyOnlyPresent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitExpectedRow {
    domain: CoordinatorNormalCommitWriteDomain,
    physical_table: ScyllaPhysicalTableId,
    locator: Vec<u8>,
    expected: CoordinatorCommitExpectedValue,
    timestamp: CommitWriteTimestampUs,
    row_digest: [u8; 32],
    sealed: SealedTimestampedPut,
}

impl CoordinatorCommitExpectedRow {
    fn try_new(
        domain: CoordinatorNormalCommitWriteDomain,
        sealed: &SealedTimestampedPut,
    ) -> Result<Self, CoordinatorCommitPhysicalExecutionError> {
        let mutation = sealed.resolved().mutation();
        let expected = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => {
                CoordinatorCommitExpectedValue::Value(value.clone())
            }
            MutationOperation::Put(MutationValue::CqlU64(value)) => {
                CoordinatorCommitExpectedValue::Value(value.to_be_bytes().to_vec())
            }
            MutationOperation::Put(MutationValue::KeyOnly) => {
                CoordinatorCommitExpectedValue::KeyOnlyPresent
            }
            MutationOperation::Put(_) | MutationOperation::Delete => {
                return Err(CoordinatorCommitPhysicalExecutionError::UnsupportedValue {
                    table: mutation.physical_table(),
                });
            }
        };
        let physical_table = mutation.physical_table();
        let locator = sealed.resolved().locator_bytes().to_vec();
        let timestamp = sealed.timestamp();
        let row_digest = row_digest(
            domain,
            physical_table,
            &locator,
            &expected,
            timestamp,
            sealed.mutation_digest().as_bytes(),
        );
        Ok(Self {
            domain,
            physical_table,
            locator,
            expected,
            timestamp,
            row_digest,
            sealed: sealed.clone(),
        })
    }

    pub(crate) const fn domain(&self) -> CoordinatorNormalCommitWriteDomain {
        self.domain
    }

    pub(crate) const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub(crate) fn locator(&self) -> &[u8] {
        &self.locator
    }

    pub(crate) const fn expected(&self) -> &CoordinatorCommitExpectedValue {
        &self.expected
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn row_digest(&self) -> &[u8; 32] {
        &self.row_digest
    }

    pub(crate) const fn sealed(&self) -> &SealedTimestampedPut {
        &self.sealed
    }

    pub(crate) const fn requires_write_acknowledgement(&self) -> bool {
        matches!(self.expected, CoordinatorCommitExpectedValue::KeyOnlyPresent)
    }
}

/// Deterministic schedule for all 19 typed Coordinator semantic domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalExecutionSchedule<Hash> {
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    candidate: psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
    plan_digest: [u8; 32],
    inventory_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    rows: Vec<CoordinatorCommitExpectedRow>,
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalExecutionSchedule<Hash> {
    pub(crate) fn try_from_plan(
        plan: &CoordinatorCommitPhysicalWritePlan<Hash>,
        narrow: &BranchExactWriterPrepared<Hash>,
    ) -> Result<Self, CoordinatorCommitPhysicalExecutionError> {
        if plan.narrow_prepared_digest() != narrow.digest()
            || plan.narrow_intent_digest() != narrow.intent().intent_digest().as_bytes()
        {
            return Err(CoordinatorCommitPhysicalExecutionError::NarrowIdentityMismatch);
        }
        if plan.timestamp() != narrow.timestamp() {
            return Err(CoordinatorCommitPhysicalExecutionError::NarrowTimestampMismatch);
        }

        let mut rows = Vec::with_capacity(plan.typed_row_count());
        for batch in plan.batches() {
            for put in batch.puts() {
                if put.timestamp() != plan.timestamp()
                    || put.write_kind() != plan.write_kind()
                {
                    return Err(CoordinatorCommitPhysicalExecutionError::MixedSealIdentity);
                }
                rows.push(CoordinatorCommitExpectedRow::try_new(batch.domain(), put)?);
            }
        }
        rows.sort_by(|left, right| {
            (left.domain, left.physical_table, left.locator.as_slice()).cmp(&(
                right.domain,
                right.physical_table,
                right.locator.as_slice(),
            ))
        });
        if rows.len() != plan.typed_row_count() {
            return Err(CoordinatorCommitPhysicalExecutionError::MutationCountMismatch);
        }
        if rows.windows(2).any(|pair| {
            pair[0].physical_table == pair[1].physical_table
                && pair[0].locator == pair[1].locator
        }) {
            return Err(CoordinatorCommitPhysicalExecutionError::DuplicatePhysicalRow);
        }

        Ok(Self {
            source_slot: *plan.source_slot(),
            source_digest: *plan.source_digest(),
            candidate: *plan.candidate(),
            plan_digest: *plan.digest(),
            inventory_digest: *plan.inventory_digest(),
            narrow_prepared_digest: *plan.narrow_prepared_digest(),
            narrow_intent_digest: *plan.narrow_intent_digest(),
            timestamp: plan.timestamp(),
            write_kind: plan.write_kind(),
            rows,
        })
    }

    pub(crate) fn rows(&self) -> &[CoordinatorCommitExpectedRow] {
        &self.rows
    }

    pub(crate) const fn candidate(
        &self,
    ) -> &psy_data::protocol::canonical_chain::CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub(crate) const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn narrow_intent_digest(&self) -> &[u8; 32] {
        &self.narrow_intent_digest
    }

    /// Missing/stale value rows are retryable. Key-only rows are always
    /// selected so a fresh acknowledged timestamped INSERT precedes success.
    pub(crate) fn preflight(
        &self,
        observed: &[Option<CoordinatorCommitObservedRow>],
    ) -> Result<CoordinatorCommitPhysicalPreflight, CoordinatorCommitPhysicalExecutionError>
    {
        self.require_observation_count(observed)?;
        let mut write_indices = Vec::new();
        for (index, (expected, actual)) in self.rows.iter().zip(observed).enumerate() {
            match (&expected.expected, actual) {
                (CoordinatorCommitExpectedValue::KeyOnlyPresent, None) => {
                    write_indices.push(index)
                }
                (
                    CoordinatorCommitExpectedValue::KeyOnlyPresent,
                    Some(CoordinatorCommitObservedRow::KeyOnlyPresent {
                        physical_table,
                        locator,
                    }),
                ) => {
                    require_identity(index, expected, *physical_table, locator)?;
                    write_indices.push(index);
                }
                (CoordinatorCommitExpectedValue::KeyOnlyPresent, Some(_)) => {
                    return Err(CoordinatorCommitPhysicalExecutionError::ObservationKindMismatch {
                        index,
                    });
                }
                (CoordinatorCommitExpectedValue::Value(_), None) => write_indices.push(index),
                (
                    CoordinatorCommitExpectedValue::Value(expected_value),
                    Some(CoordinatorCommitObservedRow::Value {
                        physical_table,
                        locator,
                        value,
                        writetime_us,
                    }),
                ) => {
                    require_identity(index, expected, *physical_table, locator)?;
                    if *writetime_us > expected.timestamp.as_i64() {
                        return Err(CoordinatorCommitPhysicalExecutionError::SealedTimestampSuperseded {
                            index,
                            sealed: expected.timestamp.as_i64(),
                            actual: *writetime_us,
                        });
                    }
                    if *writetime_us == expected.timestamp.as_i64() {
                        if value != expected_value {
                            return Err(CoordinatorCommitPhysicalExecutionError::PhysicalValueConflict { index });
                        }
                    } else {
                        write_indices.push(index);
                    }
                }
                (CoordinatorCommitExpectedValue::Value(_), Some(_)) => {
                    return Err(CoordinatorCommitPhysicalExecutionError::ObservationKindMismatch {
                        index,
                    });
                }
            }
        }
        Ok(CoordinatorCommitPhysicalPreflight { write_indices })
    }

    /// Exact post-write proof. `acknowledged_indices` is relevant only to
    /// key-only rows; it prevents an older indistinguishable presence row from
    /// being accepted after a lost/failed write attempt.
    pub(crate) fn verify_after_write(
        &self,
        observed: &[Option<CoordinatorCommitObservedRow>],
        acknowledged_indices: &BTreeSet<usize>,
    ) -> Result<CoordinatorTypedRowsExactObservation<Hash>, CoordinatorCommitPhysicalExecutionError>
    {
        self.require_observation_count(observed)?;
        let mut retry_indices = Vec::new();
        for (index, (expected, actual)) in self.rows.iter().zip(observed).enumerate() {
            match (&expected.expected, actual) {
                (
                    CoordinatorCommitExpectedValue::KeyOnlyPresent,
                    Some(CoordinatorCommitObservedRow::KeyOnlyPresent {
                        physical_table,
                        locator,
                    }),
                ) => {
                    require_identity(index, expected, *physical_table, locator)?;
                    if !acknowledged_indices.contains(&index) {
                        retry_indices.push(index);
                    }
                }
                (CoordinatorCommitExpectedValue::KeyOnlyPresent, None) => {
                    retry_indices.push(index)
                }
                (CoordinatorCommitExpectedValue::KeyOnlyPresent, Some(_)) => {
                    return Err(CoordinatorCommitPhysicalExecutionError::ObservationKindMismatch {
                        index,
                    });
                }
                (
                    CoordinatorCommitExpectedValue::Value(expected_value),
                    Some(CoordinatorCommitObservedRow::Value {
                        physical_table,
                        locator,
                        value,
                        writetime_us,
                    }),
                ) => {
                    require_identity(index, expected, *physical_table, locator)?;
                    if *writetime_us > expected.timestamp.as_i64() {
                        return Err(CoordinatorCommitPhysicalExecutionError::SealedTimestampSuperseded {
                            index,
                            sealed: expected.timestamp.as_i64(),
                            actual: *writetime_us,
                        });
                    }
                    if *writetime_us < expected.timestamp.as_i64() {
                        retry_indices.push(index);
                    } else if value != expected_value {
                        return Err(CoordinatorCommitPhysicalExecutionError::PhysicalValueConflict { index });
                    }
                }
                (CoordinatorCommitExpectedValue::Value(_), None) => retry_indices.push(index),
                (CoordinatorCommitExpectedValue::Value(_), Some(_)) => {
                    return Err(CoordinatorCommitPhysicalExecutionError::ObservationKindMismatch {
                        index,
                    });
                }
            }
        }
        if !retry_indices.is_empty() {
            return Err(CoordinatorCommitPhysicalExecutionError::RetryRequired {
                indices: retry_indices,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(OBSERVATION_DIGEST_DOMAIN);
        hasher.update(self.source_slot);
        hasher.update(self.source_digest);
        hasher.update(self.plan_digest);
        hasher.update(self.inventory_digest);
        hasher.update(self.narrow_prepared_digest);
        hasher.update(self.narrow_intent_digest);
        hasher.update((self.rows.len() as u64).to_be_bytes());
        for row in &self.rows {
            hasher.update(row.row_digest);
        }
        Ok(CoordinatorTypedRowsExactObservation {
            candidate: self.candidate,
            plan_digest: self.plan_digest,
            inventory_digest: self.inventory_digest,
            narrow_prepared_digest: self.narrow_prepared_digest,
            row_count: self.rows.len(),
            digest: hasher.finalize().into(),
        })
    }

    fn require_observation_count(
        &self,
        observed: &[Option<CoordinatorCommitObservedRow>],
    ) -> Result<(), CoordinatorCommitPhysicalExecutionError> {
        if observed.len() != self.rows.len() {
            return Err(CoordinatorCommitPhysicalExecutionError::ObservationCountMismatch {
                expected: self.rows.len(),
                actual: observed.len(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitObservedRow {
    Value {
        physical_table: ScyllaPhysicalTableId,
        locator: Vec<u8>,
        value: Vec<u8>,
        writetime_us: i64,
    },
    KeyOnlyPresent {
        physical_table: ScyllaPhysicalTableId,
        locator: Vec<u8>,
    },
}

impl CoordinatorCommitObservedRow {
    pub(crate) fn value(
        physical_table: ScyllaPhysicalTableId,
        locator: Vec<u8>,
        value: Vec<u8>,
        writetime_us: i64,
    ) -> Self {
        Self::Value { physical_table, locator, value, writetime_us }
    }

    pub(crate) fn key_only(
        physical_table: ScyllaPhysicalTableId,
        locator: Vec<u8>,
    ) -> Self {
        Self::KeyOnlyPresent { physical_table, locator }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalPreflight {
    write_indices: Vec<usize>,
}

impl CoordinatorCommitPhysicalPreflight {
    pub(crate) fn write_indices(&self) -> &[usize] {
        &self.write_indices
    }
}

/// Exact typed-row observation. It is not the six-row mapping receipt, source
/// commit receipt, manifest, backup, or head-publish authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorTypedRowsExactObservation<Hash> {
    candidate: psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
    plan_digest: [u8; 32],
    inventory_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    row_count: usize,
    digest: [u8; 32],
}

impl<Hash> CoordinatorTypedRowsExactObservation<Hash> {
    pub(crate) const fn candidate(
        &self,
    ) -> &psy_data::protocol::canonical_chain::CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub(crate) const fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn require_identity(
    index: usize,
    expected: &CoordinatorCommitExpectedRow,
    physical_table: ScyllaPhysicalTableId,
    locator: &[u8],
) -> Result<(), CoordinatorCommitPhysicalExecutionError> {
    if physical_table != expected.physical_table || locator != expected.locator {
        return Err(CoordinatorCommitPhysicalExecutionError::ObservationIdentityMismatch {
            index,
        });
    }
    Ok(())
}

fn row_digest(
    domain: CoordinatorNormalCommitWriteDomain,
    physical_table: ScyllaPhysicalTableId,
    locator: &[u8],
    expected: &CoordinatorCommitExpectedValue,
    timestamp: CommitWriteTimestampUs,
    mutation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_DIGEST_DOMAIN);
    hasher.update([domain_id(domain)]);
    hasher.update(physical_table.stable_id().to_be_bytes());
    hasher.update((locator.len() as u32).to_be_bytes());
    hasher.update(locator);
    match expected {
        CoordinatorCommitExpectedValue::Value(value) => {
            hasher.update([1]);
            hasher.update((value.len() as u32).to_be_bytes());
            hasher.update(value);
        }
        CoordinatorCommitExpectedValue::KeyOnlyPresent => hasher.update([2]),
    }
    hasher.update(timestamp.as_i64().to_be_bytes());
    hasher.update(mutation_digest);
    hasher.finalize().into()
}

const fn domain_id(domain: CoordinatorNormalCommitWriteDomain) -> u8 {
    match domain {
        CoordinatorNormalCommitWriteDomain::CheckpointZkProof => 1,
        CoordinatorNormalCommitWriteDomain::PendingToCheckpoint => 2,
        CoordinatorNormalCommitWriteDomain::CheckpointToPending => 3,
        CoordinatorNormalCommitWriteDomain::PendingToProc => 4,
        CoordinatorNormalCommitWriteDomain::ProcToPending => 5,
        CoordinatorNormalCommitWriteDomain::ContractLeaf => 6,
        CoordinatorNormalCommitWriteDomain::ContractCodeDefinition => 7,
        CoordinatorNormalCommitWriteDomain::ContractStateTreeHeight => 8,
        CoordinatorNormalCommitWriteDomain::ContractFunctionMerkle => 9,
        CoordinatorNormalCommitWriteDomain::GlobalContractMerkle => 10,
        CoordinatorNormalCommitWriteDomain::UserPublicKey => 11,
        CoordinatorNormalCommitWriteDomain::PublicKeyToUser => 12,
        CoordinatorNormalCommitWriteDomain::UserRegistrationMerkle => 13,
        CoordinatorNormalCommitWriteDomain::GlobalUserMerkle => 14,
        CoordinatorNormalCommitWriteDomain::RealmRewardNode => 15,
        CoordinatorNormalCommitWriteDomain::CheckpointStateRoots => 16,
        CoordinatorNormalCommitWriteDomain::L2BlockState => 17,
        CoordinatorNormalCommitWriteDomain::LatestL2BlockState => 18,
        CoordinatorNormalCommitWriteDomain::CheckpointLeaf => 19,
        CoordinatorNormalCommitWriteDomain::GlobalCheckpointMerkle => 20,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByHash => 21,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByCheckpoint => 22,
        CoordinatorNormalCommitWriteDomain::LatestCheckpoint => 23,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitPhysicalExecutionError {
    NarrowIdentityMismatch,
    NarrowTimestampMismatch,
    MixedSealIdentity,
    UnsupportedValue { table: ScyllaPhysicalTableId },
    MutationCountMismatch,
    DuplicatePhysicalRow,
    ObservationCountMismatch { expected: usize, actual: usize },
    ObservationIdentityMismatch { index: usize },
    ObservationKindMismatch { index: usize },
    SealedTimestampSuperseded { index: usize, sealed: i64, actual: i64 },
    PhysicalValueConflict { index: usize },
    RetryRequired { indices: Vec<usize> },
}

impl fmt::Display for CoordinatorCommitPhysicalExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator physical execution: {self:?}")
    }
}

impl Error for CoordinatorCommitPhysicalExecutionError {}

#[cfg(test)]
mod tests {
    use psy_node_core::store::{
        coordinator_normal_commit_coverage::CoordinatorNormalCommitWriteDomain,
        timestamp::CommitWriteTimestampUs,
        typed::{LogicalMutation, MutationValue, PublicKeyHash, TypedTableKey, UserId},
    };

    use super::*;
    use crate::rollback::seal_commit_put;

    #[test]
    fn value_rows_classify_missing_stale_exact_conflict_and_newer() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(100).unwrap();
        let sealed = seal_commit_put(
            LogicalMutation::Put {
                key: TypedTableKey::CheckpointLeaf(psy_node_core::store::typed::CheckpointId::try_new(7).unwrap()),
                value: MutationValue::PsyCanonicalBytes(vec![9; 32]),
            },
            timestamp,
        ).unwrap();
        let row = CoordinatorCommitExpectedRow::try_new(
            CoordinatorNormalCommitWriteDomain::CheckpointLeaf,
            &sealed,
        ).unwrap();
        let schedule = fixture_schedule(row);

        assert_eq!(schedule.preflight(&[None]).unwrap().write_indices(), &[0]);
        let stale = CoordinatorCommitObservedRow::value(
            schedule.rows()[0].physical_table(),
            schedule.rows()[0].locator().to_vec(),
            vec![1; 32],
            99,
        );
        assert_eq!(schedule.preflight(&[Some(stale)]).unwrap().write_indices(), &[0]);
        let exact = CoordinatorCommitObservedRow::value(
            schedule.rows()[0].physical_table(),
            schedule.rows()[0].locator().to_vec(),
            vec![9; 32],
            100,
        );
        assert!(schedule.preflight(&[Some(exact.clone())]).unwrap().write_indices().is_empty());
        assert!(schedule.verify_after_write(&[Some(exact)], &BTreeSet::new()).is_ok());
        let conflict = CoordinatorCommitObservedRow::value(
            schedule.rows()[0].physical_table(),
            schedule.rows()[0].locator().to_vec(),
            vec![8; 32],
            100,
        );
        assert!(matches!(
            schedule.preflight(&[Some(conflict)]),
            Err(CoordinatorCommitPhysicalExecutionError::PhysicalValueConflict { .. })
        ));
        let newer = CoordinatorCommitObservedRow::value(
            schedule.rows()[0].physical_table(),
            schedule.rows()[0].locator().to_vec(),
            vec![9; 32],
            101,
        );
        assert!(matches!(
            schedule.preflight(&[Some(newer)]),
            Err(CoordinatorCommitPhysicalExecutionError::SealedTimestampSuperseded { .. })
        ));
    }

    #[test]
    fn key_only_presence_never_substitutes_for_an_acknowledged_retry() {
        let timestamp = CommitWriteTimestampUs::try_from_i128(100).unwrap();
        let sealed = seal_commit_put(
            LogicalMutation::Put {
                key: TypedTableKey::PublicKeyToUser {
                    public_key_hash: PublicKeyHash::new(vec![7; 32]),
                    user: UserId::new(4),
                },
                value: MutationValue::KeyOnly,
            },
            timestamp,
        ).unwrap();
        let row = CoordinatorCommitExpectedRow::try_new(
            CoordinatorNormalCommitWriteDomain::PublicKeyToUser,
            &sealed,
        ).unwrap();
        let schedule = fixture_schedule(row);
        let present = CoordinatorCommitObservedRow::key_only(
            schedule.rows()[0].physical_table(),
            schedule.rows()[0].locator().to_vec(),
        );
        assert_eq!(schedule.preflight(&[Some(present.clone())]).unwrap().write_indices(), &[0]);
        assert!(matches!(
            schedule.verify_after_write(&[Some(present.clone())], &BTreeSet::new()),
            Err(CoordinatorCommitPhysicalExecutionError::RetryRequired { .. })
        ));
        assert!(schedule.verify_after_write(&[Some(present)], &BTreeSet::from([0])).is_ok());
    }

    fn fixture_schedule(
        row: CoordinatorCommitExpectedRow,
    ) -> CoordinatorCommitPhysicalExecutionSchedule<parth_core::PHash> {
        use psy_data::protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointRef,
            NetworkId,
        };
        let candidate = CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1).unwrap(),
            ChainEpoch::new(1),
            CheckpointRef::new(
                psy_data::protocol::canonical_chain::CheckpointId::new(7),
                CheckpointHash::from_last_chain_hash(parth_core::PHash::default()),
            ),
        );
        CoordinatorCommitPhysicalExecutionSchedule {
            source_slot: [1; 32],
            source_digest: [2; 32],
            candidate,
            plan_digest: [3; 32],
            inventory_digest: [4; 32],
            narrow_prepared_digest: [5; 32],
            narrow_intent_digest: [6; 32],
            timestamp: row.timestamp(),
            write_kind: row.sealed().write_kind(),
            rows: vec![row],
        }
    }
}
