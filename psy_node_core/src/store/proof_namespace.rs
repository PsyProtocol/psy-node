//! Exact, epoch-fenced proof-store addressing for C-02b.
//!
//! The address codec is independent of Redis. Backends only receive sealed
//! namespace/address values, so a bare pending ID cannot accidentally select a
//! proof from another canonical branch.

use std::{error::Error, fmt};

use parth_core::{
    protocol::core_types::Q256BitHash, QJobIdBase, QJOB_ID_SERIALIZED_SIZE,
};
use psy_data::protocol::chain_context::{PendingContext, WorkContext};

pub const CANONICAL_PROOF_STORE_PREFIX_V2: &str = "TMPPSV2";

/// One exact pending/proc namespace on one canonical branch.
///
/// The Redis key is opaque to callers and can only be derived from a typed
/// [`PendingContext`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalProofStoreNamespace {
    redis_hash_key: String,
}

impl CanonicalProofStoreNamespace {
    pub fn from_pending_context<Hash: Q256BitHash>(
        root_prefix: &str,
        context: &PendingContext<Hash>,
    ) -> Self {
        Self {
            redis_hash_key: format!(
                "{}:{}:{}",
                CANONICAL_PROOF_STORE_PREFIX_V2,
                hex::encode(root_prefix.as_bytes()),
                hex::encode(context.to_canonical_bytes()),
            ),
        }
    }

    pub fn redis_hash_key(&self) -> &str {
        &self.redis_hash_key
    }
}

/// Exact Redis hash address for one proof.
///
/// ```compile_fail
/// use psy_node_core::store::proof_namespace::CanonicalProofStoreAddress;
/// let _ = CanonicalProofStoreAddress {
///     namespace: unsafe { std::mem::zeroed() },
///     job_field: [0; 24],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalProofStoreAddress {
    namespace: CanonicalProofStoreNamespace,
    job_field: [u8; QJOB_ID_SERIALIZED_SIZE],
}

impl CanonicalProofStoreAddress {
    pub fn try_from_pending_context<Hash: Q256BitHash, JobId: QJobIdBase>(
        root_prefix: &str,
        context: &PendingContext<Hash>,
        job_id: &JobId,
    ) -> Result<Self, CanonicalProofStoreAddressError> {
        if !job_id.is_valid() {
            return Err(CanonicalProofStoreAddressError::InvalidJobId);
        }
        Ok(Self {
            namespace: CanonicalProofStoreNamespace::from_pending_context(
                root_prefix,
                context,
            ),
            job_field: job_id.to_bytes_fixed(),
        })
    }

    pub fn try_from_work_context<Hash: Q256BitHash, JobId: QJobIdBase>(
        root_prefix: &str,
        context: &WorkContext<Hash, JobId>,
    ) -> Result<Self, CanonicalProofStoreAddressError> {
        let pending = PendingContext::new(
            *context.chain(),
            context.authority(),
            context.unique_pending_id(),
            context.proc_checkpoint_unique_id(),
        );
        Self::try_from_pending_context(root_prefix, &pending, context.job_id())
    }

    pub const fn namespace(&self) -> &CanonicalProofStoreNamespace {
        &self.namespace
    }

    pub fn redis_hash_key(&self) -> &str {
        self.namespace.redis_hash_key()
    }

    pub fn job_field(&self) -> &[u8] {
        &self.job_field
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalProofStoreAddressError {
    InvalidJobId,
}

impl fmt::Display for CanonicalProofStoreAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJobId => formatter.write_str("proof-store address contains an invalid job ID"),
        }
    }
}

impl Error for CanonicalProofStoreAddressError {}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;
    use psy_core::{
        constants::chain_id::PsyChainNetworkType,
        job::job_id::{
            ProvingJobCircuitType, ProvingJobDataType, QJobTopic,
            QProvingJobDataID,
        },
    };
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef,
        },
        chain_context::{
            AuthorityScope, WorkProcCheckpointUniqueId, WorkUniquePendingId,
        },
    };

    fn chain_on_network(
        network: PsyChainNetworkType,
        epoch: u64,
        checkpoint: u64,
        hash: u64,
    ) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            network.into(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    hash,
                    hash + 1,
                    hash + 2,
                    hash + 3,
                )),
            ),
        )
    }

    fn chain(epoch: u64, checkpoint: u64, hash: u64) -> CanonicalChainRef<PHash> {
        chain_on_network(PsyChainNetworkType::PsyMainnet, epoch, checkpoint, hash)
    }

    fn pending(
        epoch: u64,
        checkpoint: u64,
        hash: u64,
        authority: AuthorityScope,
        pending_id: u64,
        proc_id: u128,
    ) -> PendingContext<PHash> {
        PendingContext::new(
            chain(epoch, checkpoint, hash),
            authority,
            WorkUniquePendingId::new(pending_id),
            WorkProcCheckpointUniqueId::from_u128(proc_id),
        )
    }

    fn job_id() -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 0x1122_3344_5566_7788,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 0x1122_3344,
            sub_group_id: 0x5566_7788,
            task_index: 0x99aa_bbcc,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 1,
        }
    }

    fn sample_pending() -> PendingContext<PHash> {
        pending(
            42,
            367,
            1,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 3,
            },
            0x0102_0304_0506_0708,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
        )
    }

    #[test]
    fn namespace_and_job_field_match_frozen_golden() {
        let address = CanonicalProofStoreAddress::try_from_pending_context(
            "prod/realm",
            &sample_pending(),
            &job_id(),
        )
        .unwrap();
        assert_eq!(
            address.redis_hash_key(),
            concat!(
                "TMPPSV2:70726f642f7265616c6d:",
                "50535950454e4443010050535943435245460100507379692a00000000000000",
                "6f01000000000000012000010000000000000002000000000000000300000000",
                "0000000400000000000000020700000003000807060504030201001122334455",
                "66778899aabbccddeeff"
            )
        );
        assert_eq!(
            hex::encode(address.job_field()),
            "008877665544332211134433221188776655ccbbaa990001"
        );
    }

    #[test]
    fn every_namespace_identity_dimension_changes_the_redis_key() {
        let base = CanonicalProofStoreNamespace::from_pending_context("prod", &sample_pending());
        let variants = [
            PendingContext::new(
                chain_on_network(PsyChainNetworkType::LocalDevnet, 42, 367, 1),
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                WorkUniquePendingId::new(0x0102_0304_0506_0708),
                WorkProcCheckpointUniqueId::from_u128(
                    0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                ),
            ),
            pending(
                43,
                367,
                1,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0708,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
            pending(
                42,
                368,
                1,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0708,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
            pending(
                42,
                367,
                5,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0708,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
            pending(
                42,
                367,
                1,
                AuthorityScope::Realm {
                    realm_id: 8,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0708,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
            pending(
                42,
                367,
                1,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0709,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
            pending(
                42,
                367,
                1,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                0x0102_0304_0506_0708,
                0x0011_2233_4455_6677_8899_aabb_ccdd_ef00,
            ),
        ];
        for variant in variants {
            assert_ne!(
                CanonicalProofStoreNamespace::from_pending_context("prod", &variant),
                base
            );
        }
        assert_ne!(
            CanonicalProofStoreNamespace::from_pending_context("staging", &sample_pending()),
            base
        );
    }

    #[test]
    fn job_changes_only_the_hash_field_and_invalid_job_fails_closed() {
        let base = CanonicalProofStoreAddress::try_from_pending_context(
            "prod",
            &sample_pending(),
            &job_id(),
        )
        .unwrap();
        let mut other_job = job_id();
        other_job.goal_id += 1;
        let other = CanonicalProofStoreAddress::try_from_pending_context(
            "prod",
            &sample_pending(),
            &other_job,
        )
        .unwrap();
        assert_eq!(base.namespace(), other.namespace());
        assert_ne!(base.job_field(), other.job_field());
        assert_eq!(
            CanonicalProofStoreAddress::try_from_pending_context(
                "prod",
                &sample_pending(),
                &QProvingJobDataID::new_invalid_job_id(),
            ),
            Err(CanonicalProofStoreAddressError::InvalidJobId)
        );
    }

    #[test]
    fn work_context_resolves_to_the_same_exact_address() {
        let pending = sample_pending();
        let work = WorkContext::try_new(
            *pending.chain(),
            pending.authority(),
            pending.unique_pending_id(),
            pending.proc_checkpoint_unique_id(),
            job_id(),
        )
        .unwrap();
        assert_eq!(
            CanonicalProofStoreAddress::try_from_work_context("prod", &work).unwrap(),
            CanonicalProofStoreAddress::try_from_pending_context(
                "prod",
                &pending,
                &job_id()
            )
            .unwrap()
        );
    }

    #[test]
    fn v2_namespace_cannot_alias_the_legacy_pending_only_prefix() {
        let namespace =
            CanonicalProofStoreNamespace::from_pending_context("prod", &sample_pending());
        assert!(namespace.redis_hash_key().starts_with("TMPPSV2:"));
        assert!(!namespace.redis_hash_key().starts_with("TMPPSV1-"));
    }
}
