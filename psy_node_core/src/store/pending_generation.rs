//! Typed pending/proc generation reservation.
//!
//! Reserving a generation advances the monotonic pending counter and chooses
//! its proc-checkpoint namespace, but deliberately does not publish either
//! direction of the legacy pending/proc mapping.  Branch-exact writers use
//! this split so the mapping can be committed later by one timestamp-bound
//! durable intent.

use super::typed::{
    ProcCheckpointUniqueId, UniquePendingId, UniquePendingIdOutOfRange,
};
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcNamespacePrefix(u64);

impl ProcNamespacePrefix {
    pub const fn try_new(value: u64) -> Result<Self, ProcNamespacePrefixError> {
        if value == 0 {
            Err(ProcNamespacePrefixError::Zero)
        } else if value > i64::MAX as u64 {
            Err(ProcNamespacePrefixError::OutOfCqlRange(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Injective prefix for the complete currently supported typed authority
    /// domain. It deliberately does not hash/truncate a raw configuration ID.
    pub const fn for_authority(network: NetworkId, authority: AuthorityScope) -> Self {
        let network = match network.network_type() {
            PsyChainNetworkType::LocalDevnet => 0_u64,
            PsyChainNetworkType::PsyTeamDevnet => 1,
            PsyChainNetworkType::InternalDevnet => 2,
            PsyChainNetworkType::InternalTestnet => 3,
            PsyChainNetworkType::InternalPreProduction => 4,
            PsyChainNetworkType::PsyPublicCanary => 5,
            PsyChainNetworkType::PsyPublicTestnet => 6,
            PsyChainNetworkType::PsyMainnet => 7,
        };
        let authority_bits = match authority {
            AuthorityScope::Coordinator => 0,
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => {
                (1_u64 << 48)
                    | ((realm_id as u64) << 16)
                    | realm_sub_id as u64
            }
        };
        // `[network:3][kind:1][realm:32][sub:16] + 1`; range 1..=2^52.
        Self(((network << 49) | authority_bits) + 1)
    }

    pub const fn derive_proc_id(
        self,
        pending_id: UniquePendingId,
    ) -> ProcCheckpointUniqueId {
        ProcCheckpointUniqueId::from_u128(
            ((self.0 as u128) << 64) | pending_id.get() as u128,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcNamespacePrefixError {
    Zero,
    OutOfCqlRange(u64),
}

impl std::fmt::Display for ProcNamespacePrefixError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProcNamespacePrefixError {}

#[must_use = "an unmapped pending generation must be persisted in a durable intent or deliberately abandoned"]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReservedPendingGeneration {
    pending_id: UniquePendingId,
    proc_checkpoint_id: ProcCheckpointUniqueId,
}

impl ReservedPendingGeneration {
    pub(crate) fn try_new(
        pending_id: u64,
        proc_checkpoint_id: u128,
    ) -> Result<Self, UniquePendingIdOutOfRange> {
        Ok(Self {
            pending_id: UniquePendingId::try_new(pending_id)?,
            proc_checkpoint_id: ProcCheckpointUniqueId::from_u128(
                proc_checkpoint_id,
            ),
        })
    }

    pub(crate) fn try_from_prefix(
        pending_id: u64,
        prefix: ProcNamespacePrefix,
    ) -> Result<Self, UniquePendingIdOutOfRange> {
        let pending_id = UniquePendingId::try_new(pending_id)?;
        Ok(Self {
            pending_id,
            proc_checkpoint_id: prefix.derive_proc_id(pending_id),
        })
    }

    pub const fn pending_id(self) -> UniquePendingId {
        self.pending_id
    }

    pub const fn proc_checkpoint_id(self) -> ProcCheckpointUniqueId {
        self.proc_checkpoint_id
    }

    pub const fn into_legacy_parts(self) -> (u64, u128) {
        (
            self.pending_id.get(),
            self.proc_checkpoint_id.as_u128(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::constants::chain_id::PsyChainNetworkType;

    #[test]
    fn reservation_preserves_semantic_id_domains() {
        let reservation = ReservedPendingGeneration::try_new(17, 29).unwrap();
        assert_eq!(reservation.pending_id().get(), 17);
        assert_eq!(reservation.proc_checkpoint_id().as_u128(), 29);
        assert_eq!(reservation.into_legacy_parts(), (17, 29));
        assert!(ReservedPendingGeneration::try_new(i64::MAX as u64 + 1, 29)
            .is_err());
        let prefix = ProcNamespacePrefix::try_new(0x1234).unwrap();
        let derived = ReservedPendingGeneration::try_from_prefix(17, prefix)
            .unwrap();
        assert_eq!(
            derived.proc_checkpoint_id().as_u128(),
            (0x1234_u128 << 64) | 17
        );
        assert_eq!(ProcNamespacePrefix::try_new(0), Err(ProcNamespacePrefixError::Zero));
    }

    #[test]
    fn authority_prefix_is_injective_across_the_typed_domain_boundaries() {
        let networks = [
            PsyChainNetworkType::LocalDevnet,
            PsyChainNetworkType::PsyTeamDevnet,
            PsyChainNetworkType::InternalDevnet,
            PsyChainNetworkType::InternalTestnet,
            PsyChainNetworkType::InternalPreProduction,
            PsyChainNetworkType::PsyPublicCanary,
            PsyChainNetworkType::PsyPublicTestnet,
            PsyChainNetworkType::PsyMainnet,
        ];
        let authorities = [
            AuthorityScope::Coordinator,
            AuthorityScope::Realm {
                realm_id: 0,
                realm_sub_id: 0,
            },
            AuthorityScope::Realm {
                realm_id: u32::MAX,
                realm_sub_id: u16::MAX,
            },
        ];
        let mut prefixes = std::collections::HashSet::new();
        for network in networks {
            for authority in authorities {
                let prefix = ProcNamespacePrefix::for_authority(
                    NetworkId::from(network),
                    authority,
                );
                assert!(prefix.get() > 0);
                assert!(prefix.get() <= (1_u64 << 52));
                assert!(prefixes.insert(prefix));
            }
        }
    }
}
