//! Stable logical identities reserved for the branch-exact schema migration.
//!
//! The current production setup remains the original 32 logical tables. These
//! identities reserve the next routing keys now, before schema materialization
//! and writer cutover, so future locators/manifests cannot assign them
//! differently.

/// Logical table identities reserved immediately after the original
/// [`super::typed::PsyLogicalTableId`] range `1..=32`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum BranchExactLogicalTableId {
    CanonicalChainRefToPendingId = 33,
    PendingIdToCanonicalChainRef = 34,
    PendingRewardTopProof = 35,
}

impl BranchExactLogicalTableId {
    pub const ALL: [Self; 3] = [
        Self::CanonicalChainRefToPendingId,
        Self::PendingIdToCanonicalChainRef,
        Self::PendingRewardTopProof,
    ];

    pub const fn stable_id(self) -> u16 {
        self as u16
    }

    pub const fn routing_key(self) -> u64 {
        self.stable_id() as u64
    }

    pub const fn table_name(self) -> &'static str {
        match self {
            Self::CanonicalChainRefToPendingId => {
                "canonical_chain_ref_to_pending_id_table"
            }
            Self::PendingIdToCanonicalChainRef => {
                "pending_id_to_canonical_chain_ref_table"
            }
            Self::PendingRewardTopProof => "pending_reward_top_proof_table",
        }
    }
}

/// Counts are kept explicit so planning and release tooling cannot confuse the
/// active production catalog with the post-migration target catalog.
pub const ACTIVE_LOGICAL_TABLE_COUNT: usize = 32;
pub const BRANCH_EXACT_LOGICAL_EXTENSION_COUNT: usize = 3;
pub const BRANCH_EXACT_TARGET_LOGICAL_TABLE_COUNT: usize =
    ACTIVE_LOGICAL_TABLE_COUNT + BRANCH_EXACT_LOGICAL_EXTENSION_COUNT;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use strum::IntoEnumIterator;

    use super::*;
    use crate::store::typed::PsyLogicalTableId;

    #[test]
    fn extension_is_contiguous_after_the_active_catalog() {
        assert_eq!(PsyLogicalTableId::iter().count(), ACTIVE_LOGICAL_TABLE_COUNT);
        assert_eq!(
            PsyLogicalTableId::iter()
                .map(PsyLogicalTableId::routing_key)
                .collect::<Vec<_>>(),
            (1_u64..=32).collect::<Vec<_>>()
        );
        assert_eq!(
            BranchExactLogicalTableId::ALL.map(BranchExactLogicalTableId::stable_id),
            [33, 34, 35]
        );
        assert_eq!(
            BRANCH_EXACT_TARGET_LOGICAL_TABLE_COUNT,
            ACTIVE_LOGICAL_TABLE_COUNT + BranchExactLogicalTableId::ALL.len()
        );
    }

    #[test]
    fn names_and_routing_keys_are_stable_and_unique() {
        let names = BranchExactLogicalTableId::ALL
            .map(BranchExactLogicalTableId::table_name)
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 3);
        assert_eq!(
            BranchExactLogicalTableId::ALL.map(BranchExactLogicalTableId::routing_key),
            [33, 34, 35]
        );
        assert!(names.iter().all(|name| !name.starts_with("d04")));
    }
}
