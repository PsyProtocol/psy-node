//! Exact-row execution schedule and reconciliation for a full Realm commit.
//!
//! This is the storage-private bridge between the exhaustive c4e2 physical
//! plan and the family-specific Scylla adapters.  It fixes one deterministic
//! row order, derives the canonical value that an exact point read must
//! return, and classifies preflight/post-write observations without treating
//! a driver response as proof of durability.  It deliberately performs no
//! CQL and does not mint a manifest, publish, or authority capability.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    realm_normal_commit_coverage::RealmNormalCommitWriteDomain,
    timestamp::CommitWriteTimestampUs,
    typed::{
        ImtCursorTransition, MutationOperation, MutationValue,
        StructuredValueSchema,
    },
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, ImtLeafPutBinding, ImtPlanError,
    ScyllaPhysicalTableId,
    realm_full_commit_plan::RealmFullCommitPhysicalPlan,
};

const ROW_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-execution-row.v1\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-typed-readback.v1\0";

/// One exact physical row expected from the non-h22 portion of the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitExpectedRow {
    domain: RealmNormalCommitWriteDomain,
    physical_table: ScyllaPhysicalTableId,
    locator: Vec<u8>,
    expected_value: Vec<u8>,
    timestamp: CommitWriteTimestampUs,
    row_digest: [u8; 32],
    sealed: super::SealedTimestampedPut,
}

impl RealmFullCommitExpectedRow {
    pub(crate) const fn domain(&self) -> RealmNormalCommitWriteDomain {
        self.domain
    }

    pub(crate) const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub(crate) fn locator(&self) -> &[u8] { &self.locator }

    pub(crate) fn expected_value(&self) -> &[u8] { &self.expected_value }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn row_digest(&self) -> &[u8; 32] { &self.row_digest }

    /// The immutable mutation retained from the validated full plan. Family
    /// adapters must consume this value rather than reconstructing a typed key
    /// or physical payload from the public observation fields.
    pub(crate) const fn sealed(&self) -> &super::SealedTimestampedPut {
        &self.sealed
    }
}

/// Canonical schedule for every typed row not owned by the h22 dual writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitExecutionSchedule {
    coverage_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    rows: Vec<RealmFullCommitExpectedRow>,
}

impl RealmFullCommitExecutionSchedule {
    pub(crate) fn try_from_plan<Hash: Q256BitHash>(
        plan: &RealmFullCommitPhysicalPlan,
        narrow: &BranchExactWriterPrepared<Hash>,
    ) -> Result<Self, RealmFullCommitExecutionError> {
        if plan.narrow_prepared_digest() != narrow.digest()
            || plan.narrow_intent_digest()
                != narrow.intent().intent_digest().as_bytes()
        {
            return Err(RealmFullCommitExecutionError::NarrowIdentityMismatch);
        }
        if plan.coverage().write_timestamp() != narrow.timestamp() {
            return Err(RealmFullCommitExecutionError::NarrowTimestampMismatch);
        }

        let mut rows = Vec::new();
        for batch in plan.remaining() {
            for put in batch.puts() {
                let mutation = put.resolved().mutation();
                let expected_value = expected_readback_value(put)?;
                let physical_table = mutation.physical_table();
                let locator = put.resolved().locator_bytes().to_vec();
                let timestamp = put.timestamp();
                let row_digest = row_digest(
                    batch.domain(),
                    physical_table,
                    &locator,
                    &expected_value,
                    timestamp,
                    put.mutation_digest().as_bytes(),
                );
                rows.push(RealmFullCommitExpectedRow {
                    domain: batch.domain(),
                    physical_table,
                    locator,
                    expected_value,
                    timestamp,
                    row_digest,
                    sealed: put.clone(),
                });
            }
        }
        rows.sort_by(|left, right| {
            (left.domain, left.physical_table, left.locator.as_slice()).cmp(&(
                right.domain,
                right.physical_table,
                right.locator.as_slice(),
            ))
        });

        let narrow_count = u64::try_from(narrow.intent().mutations().len())
            .map_err(|_| RealmFullCommitExecutionError::MutationCountOutOfRange)?;
        let expected = plan
            .coverage()
            .total_mutation_count()
            .checked_sub(narrow_count)
            .ok_or(RealmFullCommitExecutionError::MutationCountMismatch)?;
        if u64::try_from(rows.len())
            .map_err(|_| RealmFullCommitExecutionError::MutationCountOutOfRange)?
            != expected
        {
            return Err(RealmFullCommitExecutionError::MutationCountMismatch);
        }

        Ok(Self {
            coverage_digest: *plan.coverage().digest(),
            narrow_prepared_digest: *narrow.digest(),
            rows,
        })
    }

    pub(crate) fn rows(&self) -> &[RealmFullCommitExpectedRow] { &self.rows }

    pub(crate) const fn coverage_digest(&self) -> &[u8; 32] {
        &self.coverage_digest
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    /// Classify exact point reads before sending any mutation. Missing rows
    /// and rows below the sealed timestamp are safe to retry; a row at the
    /// same timestamp with different content, or any newer row, is a conflict.
    pub(crate) fn preflight(
        &self,
        observed: &[Option<RealmFullCommitObservedRow>],
    ) -> Result<RealmFullCommitPreflight, RealmFullCommitExecutionError> {
        self.require_observation_count(observed)?;
        let mut write_indices = Vec::new();
        for (index, (expected, actual)) in
            self.rows.iter().zip(observed).enumerate()
        {
            let Some(actual) = actual else {
                write_indices.push(index);
                continue;
            };
            require_identity(index, expected, actual)?;
            if actual.writetime_us > expected.timestamp.as_i64() {
                return Err(RealmFullCommitExecutionError::SealedTimestampSuperseded {
                    index,
                    sealed: expected.timestamp.as_i64(),
                    actual: actual.writetime_us,
                });
            }
            if actual.writetime_us == expected.timestamp.as_i64() {
                if actual.value != expected.expected_value {
                    return Err(RealmFullCommitExecutionError::PhysicalValueConflict {
                        index,
                    });
                }
            } else {
                write_indices.push(index);
            }
        }
        Ok(RealmFullCommitPreflight { write_indices })
    }

    /// Exact post-write verification. A driver success is irrelevant: every
    /// row must be present with the expected canonical value and exact sealed
    /// writetime. Missing/stale rows remain retryable; conflicts fail closed.
    pub(crate) fn verify_after_write(
        &self,
        observed: &[Option<RealmFullCommitObservedRow>],
    ) -> Result<RealmTypedRowsExactObservation, RealmFullCommitExecutionError> {
        self.require_observation_count(observed)?;
        let mut retry_indices = Vec::new();
        for (index, (expected, actual)) in
            self.rows.iter().zip(observed).enumerate()
        {
            let Some(actual) = actual else {
                retry_indices.push(index);
                continue;
            };
            require_identity(index, expected, actual)?;
            if actual.writetime_us > expected.timestamp.as_i64() {
                return Err(RealmFullCommitExecutionError::SealedTimestampSuperseded {
                    index,
                    sealed: expected.timestamp.as_i64(),
                    actual: actual.writetime_us,
                });
            }
            if actual.writetime_us < expected.timestamp.as_i64() {
                retry_indices.push(index);
                continue;
            }
            if actual.value != expected.expected_value {
                return Err(RealmFullCommitExecutionError::PhysicalValueConflict {
                    index,
                });
            }
        }
        if !retry_indices.is_empty() {
            return Err(RealmFullCommitExecutionError::RetryRequired {
                indices: retry_indices,
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(OBSERVATION_DIGEST_DOMAIN);
        hasher.update(self.coverage_digest);
        hasher.update(self.narrow_prepared_digest);
        hasher.update((self.rows.len() as u64).to_be_bytes());
        for row in &self.rows { hasher.update(row.row_digest); }
        Ok(RealmTypedRowsExactObservation {
            coverage_digest: self.coverage_digest,
            narrow_prepared_digest: self.narrow_prepared_digest,
            row_count: self.rows.len(),
            digest: hasher.finalize().into(),
        })
    }

    fn require_observation_count(
        &self,
        observed: &[Option<RealmFullCommitObservedRow>],
    ) -> Result<(), RealmFullCommitExecutionError> {
        if observed.len() != self.rows.len() {
            return Err(RealmFullCommitExecutionError::ObservationCountMismatch {
                expected: self.rows.len(),
                actual: observed.len(),
            });
        }
        Ok(())
    }
}

/// Checked result of an exact physical point read. Its constructor is kept
/// storage-private; this value alone is not a mutation or publish capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitObservedRow {
    physical_table: ScyllaPhysicalTableId,
    locator: Vec<u8>,
    value: Vec<u8>,
    writetime_us: i64,
}

impl RealmFullCommitObservedRow {
    pub(crate) fn new(
        physical_table: ScyllaPhysicalTableId,
        locator: Vec<u8>,
        value: Vec<u8>,
        writetime_us: i64,
    ) -> Self {
        Self { physical_table, locator, value, writetime_us }
    }

    pub(crate) fn value(&self) -> &[u8] { &self.value }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitPreflight { write_indices: Vec<usize> }

impl RealmFullCommitPreflight {
    pub(crate) fn write_indices(&self) -> &[usize] { &self.write_indices }
}

/// Exact typed-row observation. It intentionally excludes the h22 lifecycle
/// observation and therefore cannot be used as a full-writer or manifest
/// receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmTypedRowsExactObservation {
    coverage_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    row_count: usize,
    digest: [u8; 32],
}

impl RealmTypedRowsExactObservation {
    pub(crate) const fn coverage_digest(&self) -> &[u8; 32] {
        &self.coverage_digest
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn row_count(&self) -> usize { self.row_count }

    pub(crate) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

fn expected_readback_value(
    put: &super::SealedTimestampedPut,
) -> Result<Vec<u8>, RealmFullCommitExecutionError> {
    match put.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => {
            Ok(value.clone())
        }
        MutationOperation::Put(MutationValue::CqlU64(value)) => {
            Ok(value.to_be_bytes().to_vec())
        }
        MutationOperation::Put(MutationValue::Structured {
            schema,
            canonical_bytes,
        }) => match (put.resolved().mutation().physical_table(), schema) {
            (ScyllaPhysicalTableId::ImtLeaf, StructuredValueSchema::ImtLeafRowV1) => {
                Ok(ImtLeafPutBinding::try_from_sealed(put)?.expected_physical_value())
            }
            (
                ScyllaPhysicalTableId::ImtKeyIndex,
                StructuredValueSchema::ImtKeyIndexRowV2,
            ) => Ok(canonical_bytes.clone()),
            (
                ScyllaPhysicalTableId::ImtNextAppendIndex,
                StructuredValueSchema::ImtCursorTransitionV1,
            ) => Ok(ImtCursorTransition::decode_canonical(canonical_bytes)
                .map_err(|_| RealmFullCommitExecutionError::InvalidStructuredValue {
                    table: ScyllaPhysicalTableId::ImtNextAppendIndex,
                })?
                .after()
                .to_be_bytes()
                .to_vec()),
            (table, _) => Err(RealmFullCommitExecutionError::UnsupportedValue {
                table,
            }),
        },
        MutationOperation::Put(_) | MutationOperation::Delete => {
            Err(RealmFullCommitExecutionError::UnsupportedValue {
                table: put.resolved().mutation().physical_table(),
            })
        }
    }
}

fn row_digest(
    domain: RealmNormalCommitWriteDomain,
    table: ScyllaPhysicalTableId,
    locator: &[u8],
    value: &[u8],
    timestamp: CommitWriteTimestampUs,
    mutation_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_DIGEST_DOMAIN);
    hasher.update([psy_node_core::store::realm_full_commit_coverage::domain_id(domain)]);
    hasher.update(table.stable_id().to_be_bytes());
    hasher.update((locator.len() as u32).to_be_bytes());
    hasher.update(locator);
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
    hasher.update(timestamp.as_i64().to_be_bytes());
    hasher.update(mutation_digest);
    hasher.finalize().into()
}

fn require_identity(
    index: usize,
    expected: &RealmFullCommitExpectedRow,
    actual: &RealmFullCommitObservedRow,
) -> Result<(), RealmFullCommitExecutionError> {
    if actual.physical_table != expected.physical_table
        || actual.locator != expected.locator
    {
        return Err(RealmFullCommitExecutionError::ObservationIdentityMismatch {
            index,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmFullCommitExecutionError {
    NarrowIdentityMismatch,
    NarrowTimestampMismatch,
    MutationCountOutOfRange,
    MutationCountMismatch,
    UnsupportedValue { table: ScyllaPhysicalTableId },
    InvalidStructuredValue { table: ScyllaPhysicalTableId },
    Imt(ImtPlanError),
    ObservationCountMismatch { expected: usize, actual: usize },
    ObservationIdentityMismatch { index: usize },
    SealedTimestampSuperseded { index: usize, sealed: i64, actual: i64 },
    PhysicalValueConflict { index: usize },
    RetryRequired { indices: Vec<usize> },
}

impl From<ImtPlanError> for RealmFullCommitExecutionError {
    fn from(value: ImtPlanError) -> Self { Self::Imt(value) }
}

impl fmt::Display for RealmFullCommitExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full commit execution: {self:?}")
    }
}

impl Error for RealmFullCommitExecutionError {}
