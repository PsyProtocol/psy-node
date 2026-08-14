//! Composite exact-write boundary for one normal Coordinator commit.
//!
//! The narrow writer durably proves the six compatibility mapping mutations;
//! the typed executor independently proves every remaining physical row. This
//! module joins those two observations with the immutable commit source and
//! the physical plan. It still cannot mark the source committed, publish a
//! canonical head, rebuild a backup, or authorize rollback.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use psy_node_core::store::{
    branch_exact_dual_write::BranchExactDualWriteMutationKind,
    branch_exact_schema::AuthorityScope,
    coordinator_commit_source::CoordinatorCommitSource,
    coordinator_normal_commit_coverage::CoordinatorNormalCommitWriteDomain,
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterVerified, TimestampedWriteKind,
    coordinator_commit_physical_execution::{
        CoordinatorCommitPhysicalExecutionSchedule,
        CoordinatorTypedRowsExactObservation,
    },
};

#[cfg(test)]
use super::BranchExactWriterPrepared;

const OBSERVATION_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-full-write-observation.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorNarrowExactEvidence {
    prepared_digest: [u8; 32],
    intent_digest: [u8; 32],
    observation_digest: [u8; 32],
    verified_digest: [u8; 32],
    timestamp: CommitWriteTimestampUs,
    mutation_count: usize,
}

impl CoordinatorNarrowExactEvidence {
    fn try_from_verified<Hash: Q256BitHash>(
        verified: &BranchExactWriterVerified<Hash>,
    ) -> Result<Self, CoordinatorCommitFullWriteError> {
        let prepared = verified.prepared();
        if prepared.intent().authority() != AuthorityScope::Coordinator {
            return Err(CoordinatorCommitFullWriteError::CoordinatorAuthorityRequired);
        }
        Ok(Self {
            prepared_digest: *prepared.digest(),
            intent_digest: *prepared.intent().intent_digest().as_bytes(),
            observation_digest: *verified.observation().as_bytes(),
            verified_digest: *verified.digest(),
            timestamp: prepared.timestamp(),
            mutation_count: prepared.intent().mutations().len(),
        })
    }

    #[cfg(test)]
    fn from_prepared<Hash: Q256BitHash>(prepared: &BranchExactWriterPrepared<Hash>) -> Self {
        Self {
            prepared_digest: *prepared.digest(),
            intent_digest: *prepared.intent().intent_digest().as_bytes(),
            observation_digest: [0x71; 32],
            verified_digest: [0x72; 32],
            timestamp: prepared.timestamp(),
            mutation_count: prepared.intent().mutations().len(),
        }
    }
}

/// Complete in-memory proof that all 23 Coordinator semantic domains reached
/// their exact physical rows at the one sealed timestamp.
///
/// This type is deliberately non-`Clone`. It is input to the next manifest /
/// committed-source stage, not a durable publication capability by itself.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitFullWriteObservation<Hash> {
    candidate: CanonicalChainRef<Hash>,
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    plan_digest: [u8; 32],
    inventory_digest: [u8; 32],
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    narrow_observation_digest: [u8; 32],
    narrow_verified_digest: [u8; 32],
    typed_observation_digest: [u8; 32],
    semantic_domain_count: usize,
    typed_row_count: usize,
    total_physical_row_count: usize,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCommitFullWriteObservation<Hash> {
    pub(crate) fn try_from_storage(
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        narrow: &BranchExactWriterVerified<Hash>,
        typed: CoordinatorTypedRowsExactObservation<Hash>,
    ) -> Result<Self, CoordinatorCommitFullWriteError> {
        Self::try_from_evidence(
            source,
            schedule,
            CoordinatorNarrowExactEvidence::try_from_verified(narrow)?,
            typed,
        )
    }

    #[cfg(test)]
    pub(super) fn test_fixture(
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        narrow: &BranchExactWriterPrepared<Hash>,
        typed: CoordinatorTypedRowsExactObservation<Hash>,
    ) -> Result<Self, CoordinatorCommitFullWriteError> {
        Self::try_from_evidence(
            source,
            schedule,
            CoordinatorNarrowExactEvidence::from_prepared(narrow),
            typed,
        )
    }

    fn try_from_evidence(
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        narrow: CoordinatorNarrowExactEvidence,
        typed: CoordinatorTypedRowsExactObservation<Hash>,
    ) -> Result<Self, CoordinatorCommitFullWriteError> {
        let source_slot = source.slot().as_bytes();
        let source_digest = source.digest().as_bytes();
        if source.candidate() != schedule.candidate()
            || source_slot != *schedule.source_slot()
            || source_digest != *schedule.source_digest()
        {
            return Err(CoordinatorCommitFullWriteError::SourceIdentityMismatch);
        }
        if narrow.prepared_digest != *schedule.narrow_prepared_digest()
            || narrow.intent_digest != *schedule.narrow_intent_digest()
            || narrow.timestamp != schedule.timestamp()
        {
            return Err(CoordinatorCommitFullWriteError::NarrowIdentityMismatch);
        }
        let expected_narrow_count = BranchExactDualWriteMutationKind::COORDINATOR.len();
        if narrow.mutation_count != expected_narrow_count {
            return Err(CoordinatorCommitFullWriteError::NarrowMutationCountMismatch {
                expected: expected_narrow_count,
                actual: narrow.mutation_count,
            });
        }
        if typed.candidate() != schedule.candidate()
            || typed.plan_digest() != schedule.plan_digest()
            || typed.inventory_digest() != schedule.inventory_digest()
            || typed.narrow_prepared_digest() != schedule.narrow_prepared_digest()
            || typed.row_count() != schedule.rows().len()
        {
            return Err(CoordinatorCommitFullWriteError::TypedObservationMismatch);
        }
        let expected_domains: usize = CoordinatorNormalCommitWriteDomain::ALL.len();
        if schedule.semantic_domain_count() != expected_domains {
            return Err(CoordinatorCommitFullWriteError::SemanticDomainCountMismatch {
                expected: expected_domains,
                actual: schedule.semantic_domain_count(),
            });
        }
        let expected_physical = schedule
            .rows()
            .len()
            .checked_add(expected_narrow_count)
            .ok_or(CoordinatorCommitFullWriteError::PhysicalRowCountOverflow)?;
        if schedule.total_physical_row_count() != expected_physical {
            return Err(CoordinatorCommitFullWriteError::PhysicalRowCountMismatch {
                expected: expected_physical,
                actual: schedule.total_physical_row_count(),
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(OBSERVATION_DOMAIN);
        hasher.update(source_slot);
        hasher.update(source_digest);
        hasher.update(schedule.candidate().to_canonical_bytes());
        hasher.update(schedule.plan_digest());
        hasher.update(schedule.inventory_digest());
        hasher.update(schedule.timestamp().as_i64().to_be_bytes());
        hasher.update([schedule.write_kind() as u8]);
        hasher.update(narrow.prepared_digest);
        hasher.update(narrow.intent_digest);
        hasher.update(narrow.observation_digest);
        hasher.update(narrow.verified_digest);
        hasher.update(typed.digest());
        hasher.update((expected_domains as u64).to_be_bytes());
        hasher.update((typed.row_count() as u64).to_be_bytes());
        hasher.update((expected_physical as u64).to_be_bytes());
        Ok(Self {
            candidate: *schedule.candidate(),
            source_slot,
            source_digest,
            plan_digest: *schedule.plan_digest(),
            inventory_digest: *schedule.inventory_digest(),
            timestamp: schedule.timestamp(),
            write_kind: schedule.write_kind(),
            narrow_prepared_digest: narrow.prepared_digest,
            narrow_intent_digest: narrow.intent_digest,
            narrow_observation_digest: narrow.observation_digest,
            narrow_verified_digest: narrow.verified_digest,
            typed_observation_digest: *typed.digest(),
            semantic_domain_count: expected_domains,
            typed_row_count: typed.row_count(),
            total_physical_row_count: expected_physical,
            digest: hasher.finalize().into(),
        })
    }

    pub(crate) const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub(crate) const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub(crate) const fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn narrow_intent_digest(&self) -> &[u8; 32] {
        &self.narrow_intent_digest
    }

    pub(crate) const fn narrow_observation_digest(&self) -> &[u8; 32] {
        &self.narrow_observation_digest
    }

    pub(crate) const fn narrow_verified_digest(&self) -> &[u8; 32] {
        &self.narrow_verified_digest
    }

    pub(crate) const fn typed_observation_digest(&self) -> &[u8; 32] {
        &self.typed_observation_digest
    }

    pub(crate) const fn semantic_domain_count(&self) -> usize {
        self.semantic_domain_count
    }

    pub(crate) const fn typed_row_count(&self) -> usize {
        self.typed_row_count
    }

    pub(crate) const fn total_physical_row_count(&self) -> usize {
        self.total_physical_row_count
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitFullWriteError {
    CoordinatorAuthorityRequired,
    SourceIdentityMismatch,
    NarrowIdentityMismatch,
    NarrowMutationCountMismatch { expected: usize, actual: usize },
    TypedObservationMismatch,
    SemanticDomainCountMismatch { expected: usize, actual: usize },
    PhysicalRowCountOverflow,
    PhysicalRowCountMismatch { expected: usize, actual: usize },
}

impl fmt::Display for CoordinatorCommitFullWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator full-write evidence: {self:?}")
    }
}

impl Error for CoordinatorCommitFullWriteError {}

#[cfg(test)]
mod tests {
    #[test]
    fn observation_is_non_clone_and_has_no_publication_or_commit_api() {
        let source = include_str!("coordinator_commit_full_write.rs");
        let declaration = source
            .split("pub(crate) struct CoordinatorCommitFullWriteObservation")
            .next()
            .expect("observation declaration prefix");
        assert!(declaration.ends_with("#[derive(Debug, Eq, PartialEq)]\n"));
        assert!(!source.contains(&["mark_committed", "_and_readback"].concat()));
        assert!(!source.contains(&["compare", "_and_set"].concat()));
        assert!(!source.contains(&["publish", "_head"].concat()));
    }
}
