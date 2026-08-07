//! Stable logical identities reserved for the branch-exact schema migration.
//!
//! The current production setup remains the original 32 logical tables. These
//! identities reserve the next routing keys now, before schema materialization
//! and writer cutover, so future locators/manifests cannot assign them
//! differently.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CANONICAL_CHAIN_REF_V1_LEN;
pub use psy_data::protocol::chain_context::AuthorityScope;
use sha2::{Digest, Sha256};

use super::{
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    },
    manifest_record::AuthorityManifestDigest,
};

const BRANCH_EXACT_MATERIALIZATION_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-schema-materialization/v1";
pub const BRANCH_EXACT_SCHEMA_VERSION: u16 = 1;

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BaselineSnapshotArtifactDigest([u8; 32]);

impl BaselineSnapshotArtifactDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, BranchExactMaterializationError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(BranchExactMaterializationError::ZeroSnapshotDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactPostGenesisFloorEvidence {
    authority: AuthorityScope,
    snapshot_digest: BaselineSnapshotArtifactDigest,
    manifest_digest: AuthorityManifestDigest,
}

impl BranchExactPostGenesisFloorEvidence {
    pub const fn new(
        authority: AuthorityScope,
        snapshot_digest: BaselineSnapshotArtifactDigest,
        manifest_digest: AuthorityManifestDigest,
    ) -> Self {
        Self {
            authority,
            snapshot_digest,
            manifest_digest,
        }
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn snapshot_digest(&self) -> BaselineSnapshotArtifactDigest {
        self.snapshot_digest
    }

    pub const fn manifest_digest(&self) -> AuthorityManifestDigest {
        self.manifest_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactMaterializationPlanDigest([u8; 32]);

impl BranchExactMaterializationPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Sealed release-time authorization for creating the reserved schema.
///
/// A genesis deployment must not carry floor evidence. A post-genesis
/// deployment must bind both a selected snapshot artifact and its baseline
/// manifest. Upstream deployment policy remains responsible for proving that
/// the snapshot is VERIFIED. The plan only authorizes schema materialization; it never
/// authorizes reader/writer cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaMaterializationPlan {
    schema_version: u16,
    profile: CanonicalHeadBootstrapProfile,
    authority: AuthorityScope,
    anchor_payload: [u8; CANONICAL_CHAIN_REF_V1_LEN],
    floor_evidence: Option<BranchExactPostGenesisFloorEvidence>,
    digest: BranchExactMaterializationPlanDigest,
}

impl BranchExactSchemaMaterializationPlan {
    pub fn try_new<Hash: Q256BitHash>(
        bootstrap: &CanonicalHeadBootstrap<Hash>,
        authority: AuthorityScope,
        floor_evidence: Option<BranchExactPostGenesisFloorEvidence>,
    ) -> Result<Self, BranchExactMaterializationError> {
        match (bootstrap.profile(), floor_evidence) {
            (CanonicalHeadBootstrapProfile::GenesisNative, Some(_)) => {
                return Err(BranchExactMaterializationError::UnexpectedFloorEvidence);
            }
            (CanonicalHeadBootstrapProfile::PostGenesisFloor, None) => {
                return Err(BranchExactMaterializationError::MissingFloorEvidence);
            }
            (CanonicalHeadBootstrapProfile::GenesisNative, None)
            | (CanonicalHeadBootstrapProfile::PostGenesisFloor, Some(_)) => {}
        }
        if let Some(evidence) = floor_evidence {
            if evidence.authority() != authority {
                return Err(BranchExactMaterializationError::FloorAuthorityMismatch);
            }
        }
        let anchor_payload = *bootstrap.candidate_payload();
        let digest = calculate_materialization_digest(
            bootstrap.profile(),
            authority,
            &anchor_payload,
            floor_evidence,
        );
        Ok(Self {
            schema_version: BRANCH_EXACT_SCHEMA_VERSION,
            profile: bootstrap.profile(),
            authority,
            anchor_payload,
            floor_evidence,
            digest,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn profile(&self) -> CanonicalHeadBootstrapProfile {
        self.profile
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn anchor_payload(&self) -> &[u8; CANONICAL_CHAIN_REF_V1_LEN] {
        &self.anchor_payload
    }

    pub const fn floor_evidence(&self) -> Option<BranchExactPostGenesisFloorEvidence> {
        self.floor_evidence
    }

    pub const fn digest(&self) -> BranchExactMaterializationPlanDigest {
        self.digest
    }
}

fn calculate_materialization_digest(
    profile: CanonicalHeadBootstrapProfile,
    authority: AuthorityScope,
    anchor_payload: &[u8; CANONICAL_CHAIN_REF_V1_LEN],
    floor_evidence: Option<BranchExactPostGenesisFloorEvidence>,
) -> BranchExactMaterializationPlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(BRANCH_EXACT_MATERIALIZATION_DIGEST_DOMAIN);
    hasher.update(BRANCH_EXACT_SCHEMA_VERSION.to_be_bytes());
    hasher.update([match profile {
        CanonicalHeadBootstrapProfile::GenesisNative => 1,
        CanonicalHeadBootstrapProfile::PostGenesisFloor => 2,
    }]);
    match authority {
        AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
    hasher.update(anchor_payload);
    match floor_evidence {
        None => hasher.update([0]),
        Some(evidence) => {
            hasher.update([1]);
            hasher.update(evidence.snapshot_digest().as_bytes());
            hasher.update(evidence.manifest_digest().as_bytes());
        }
    }
    BranchExactMaterializationPlanDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactMaterializationError {
    ZeroSnapshotDigest,
    MissingFloorEvidence,
    UnexpectedFloorEvidence,
    FloorAuthorityMismatch,
}

impl fmt::Display for BranchExactMaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactMaterializationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use strum::IntoEnumIterator;

    use super::*;
    use crate::store::typed::PsyLogicalTableId;

    fn bootstrap(
        profile: CanonicalHeadBootstrapProfile,
        checkpoint_id: u64,
    ) -> CanonicalHeadBootstrap<PHash> {
        CanonicalHeadBootstrap::try_new(
            profile,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint_id),
                    CheckpointHash::from_last_chain_hash(PHash::ZERO),
                ),
            ),
        )
        .unwrap()
    }

    fn floor_evidence(byte: u8) -> BranchExactPostGenesisFloorEvidence {
        BranchExactPostGenesisFloorEvidence::new(
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            BaselineSnapshotArtifactDigest::try_new([byte; 32]).unwrap(),
            AuthorityManifestDigest::from_persisted([byte.wrapping_add(1); 32]),
        )
    }

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

    #[test]
    fn materialization_profile_and_floor_evidence_are_fail_closed() {
        let genesis = bootstrap(CanonicalHeadBootstrapProfile::GenesisNative, 0);
        assert!(
            BranchExactSchemaMaterializationPlan::try_new(
                &genesis,
                AuthorityScope::Coordinator,
                None,
            )
            .is_ok()
        );
        assert_eq!(
            BranchExactSchemaMaterializationPlan::try_new(
                &genesis,
                AuthorityScope::Coordinator,
                Some(floor_evidence(7)),
            ),
            Err(BranchExactMaterializationError::UnexpectedFloorEvidence)
        );

        let floor = bootstrap(CanonicalHeadBootstrapProfile::PostGenesisFloor, 100);
        assert_eq!(
            BranchExactSchemaMaterializationPlan::try_new(
                &floor,
                AuthorityScope::Coordinator,
                None,
            ),
            Err(BranchExactMaterializationError::MissingFloorEvidence)
        );
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &floor,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            Some(floor_evidence(7)),
        )
        .unwrap();
        assert_eq!(plan.schema_version(), BRANCH_EXACT_SCHEMA_VERSION);
        assert_eq!(plan.profile(), CanonicalHeadBootstrapProfile::PostGenesisFloor);
        assert_eq!(
            plan.authority(),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            }
        );
        assert_eq!(
            BranchExactSchemaMaterializationPlan::try_new(
                &floor,
                AuthorityScope::Coordinator,
                Some(floor_evidence(7)),
            ),
            Err(BranchExactMaterializationError::FloorAuthorityMismatch)
        );
    }

    #[test]
    fn materialization_digest_binds_anchor_and_baseline_artifacts() {
        let floor_100 = bootstrap(CanonicalHeadBootstrapProfile::PostGenesisFloor, 100);
        let floor_101 = bootstrap(CanonicalHeadBootstrapProfile::PostGenesisFloor, 101);
        let first = BranchExactSchemaMaterializationPlan::try_new(
            &floor_100,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            Some(floor_evidence(7)),
        )
        .unwrap();
        let retry = BranchExactSchemaMaterializationPlan::try_new(
            &floor_100,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            Some(floor_evidence(7)),
        )
        .unwrap();
        let different_anchor = BranchExactSchemaMaterializationPlan::try_new(
            &floor_101,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            Some(floor_evidence(7)),
        )
        .unwrap();
        let different_evidence = BranchExactSchemaMaterializationPlan::try_new(
            &floor_100,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            Some(floor_evidence(8)),
        )
        .unwrap();
        assert_eq!(first, retry);
        assert_ne!(first.digest(), different_anchor.digest());
        assert_ne!(first.digest(), different_evidence.digest());
        let genesis = bootstrap(CanonicalHeadBootstrapProfile::GenesisNative, 0);
        let coordinator = BranchExactSchemaMaterializationPlan::try_new(
            &genesis,
            AuthorityScope::Coordinator,
            None,
        )
        .unwrap();
        let realm = BranchExactSchemaMaterializationPlan::try_new(
            &genesis,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
            None,
        )
        .unwrap();
        assert_ne!(coordinator.digest(), realm.digest());
        assert_eq!(
            BaselineSnapshotArtifactDigest::try_new([0; 32]),
            Err(BranchExactMaterializationError::ZeroSnapshotDigest)
        );
    }
}
