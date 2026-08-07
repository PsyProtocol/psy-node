//! Branch-exact identity for the checkpoint/pending operational mapping.
//!
//! The legacy tables map a reusable checkpoint height to a monotonic pending
//! identifier and map the pending identifier back to only that height.  Both
//! directions lose the canonical branch occurrence after rollback.  This
//! contract deliberately uses the complete [`CanonicalChainRef`] as the
//! checkpoint-side identity; height, hash, epoch, and network therefore move
//! together.

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, CanonicalChainRefCodecError,
    CANONICAL_CHAIN_REF_V1_LEN,
};
use sha2::{Digest, Sha256};

use super::typed::UniquePendingId;

const BRANCH_PENDING_MAPPING_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.branch-pending-mapping.v1\0";

/// Content identity of one exact branch-to-pending pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchPendingMappingDigest([u8; 32]);

impl BranchPendingMappingDigest {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One immutable relationship between a canonical checkpoint occurrence and
/// the Realm/Coordinator operational pending namespace used for that commit.
///
/// There is no height-only constructor and no `Default`:
///
/// ```compile_fail
/// use psy_node_core::store::branch_pending_mapping::BranchPendingMapping;
/// let _: BranchPendingMapping<parth_core::PHash> = Default::default();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchPendingMapping<Hash> {
    canonical_chain: CanonicalChainRef<Hash>,
    pending_id: UniquePendingId,
}

impl<Hash> BranchPendingMapping<Hash> {
    pub const fn new(
        canonical_chain: CanonicalChainRef<Hash>,
        pending_id: UniquePendingId,
    ) -> Self {
        Self {
            canonical_chain,
            pending_id,
        }
    }

    pub const fn canonical_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.canonical_chain
    }

    pub const fn pending_id(&self) -> UniquePendingId {
        self.pending_id
    }
}

impl<Hash: Q256BitHash> BranchPendingMapping<Hash> {
    /// The exact 65-byte partition identity used by the migration prototype.
    pub fn canonical_chain_bytes(
        &self,
    ) -> [u8; CANONICAL_CHAIN_REF_V1_LEN] {
        self.canonical_chain.to_canonical_bytes()
    }

    /// Stable retry/reconciliation commitment.  It is not used as the table
    /// key, so readers still retain and validate the full canonical identity.
    pub fn digest(&self) -> BranchPendingMappingDigest {
        let mut hasher = Sha256::new();
        hasher.update(BRANCH_PENDING_MAPPING_DIGEST_DOMAIN);
        hasher.update(self.canonical_chain_bytes());
        hasher.update(self.pending_id.get().to_be_bytes());
        BranchPendingMappingDigest(hasher.finalize().into())
    }

    /// Validate one stored partition identity with the authoritative codec.
    /// Adapters can fail closed without introducing a second decoder.
    pub fn validate_canonical_chain_bytes(
        bytes: &[u8],
    ) -> Result<(), CanonicalChainRefCodecError> {
        CanonicalChainRef::<Hash>::from_canonical_bytes(bytes).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash,
        protocol::core_types::Q256BitHash,
    };
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };

    use super::*;

    fn chain(epoch: u64, height: u64, hash: PHash) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(hash),
            ),
        )
    }

    #[test]
    fn same_mapping_has_stable_bytes_and_digest() {
        let mapping = BranchPendingMapping::new(
            chain(4, 100, PHash::from_owned_32bytes([7; 32])),
            UniquePendingId::try_new(901).unwrap(),
        );
        assert_eq!(mapping.canonical_chain_bytes(), mapping.canonical_chain_bytes());
        assert_eq!(mapping.digest(), mapping.digest());
        assert_eq!(mapping.canonical_chain_bytes().len(), CANONICAL_CHAIN_REF_V1_LEN);
    }

    #[test]
    fn epoch_is_part_of_identity_even_when_height_and_hash_repeat() {
        let hash = PHash::from_owned_32bytes([7; 32]);
        let old = BranchPendingMapping::new(
            chain(4, 100, hash),
            UniquePendingId::try_new(901).unwrap(),
        );
        let reopened = BranchPendingMapping::new(
            chain(5, 100, hash),
            UniquePendingId::try_new(902).unwrap(),
        );
        assert_ne!(old.canonical_chain_bytes(), reopened.canonical_chain_bytes());
        assert_ne!(old.digest(), reopened.digest());
    }

    #[test]
    fn pending_identity_is_not_interchangeable_with_checkpoint_height() {
        let mapping = BranchPendingMapping::new(
            chain(4, 100, PHash::from_owned_32bytes([8; 32])),
            UniquePendingId::try_new(100).unwrap(),
        );
        assert_eq!(mapping.pending_id().get(), 100);
        assert_eq!(mapping.canonical_chain().checkpoint().checkpoint_id().get(), 100);
        assert_ne!(mapping.digest().as_bytes(), [0; 32]);
    }
}
