use parth_core::{
    crypto::hash::{
        tag_tree::hash_tag_tree_node,
        traits::{FieldQHasher, MerkleHasher, QFieldHashable, ZeroableHash},
    },
    felt::{QFelt, QFelt64},
    impl_qpd_serialize_params,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
    utils::QPGenRandom,
};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafCompact, PQEDCheckpointLeafStats};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointLeaf")]
pub struct PsyCheckpointLeafPopulated<F, Hash> {
    pub global_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub stats: PQEDCheckpointLeafStats<F, Hash>,
}

impl<F, Hash: Copy + ZeroableHash> PsyCheckpointLeafPopulated<F, Hash> {
    pub fn modify_with_final_reward_tag<Hasher: MerkleHasher<Hash>>(&mut self, final_worker_reward_tag: &Hash) {
        let old_reward_tree_root = &self.stats.pm_rewards_commitment.register_users_root;
        let new_reward_tree_root = hash_tag_tree_node::<Hash, Hasher>(old_reward_tree_root, &Hash::get_zero_value(), final_worker_reward_tag);
        self.stats.pm_rewards_commitment.register_users_root = new_reward_tree_root;
        self.stats.pm_rewards_commitment.gutas_root = new_reward_tree_root;
        self.stats.pm_rewards_commitment.deploy_contracts_root = new_reward_tree_root;
    }
    pub fn get_rewards_tree_root(&self) -> Hash {
        // HACK: if we change the pm_rewards_commitment structure, we may need to adjust this
        self.stats.pm_rewards_commitment.register_users_root
    }
}
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyCheckpointLeafPopulated<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            global_state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
            stats: PQEDCheckpointLeafStats::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyCheckpointLeafPopulated<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = PQEDCheckpointGlobalStateRoots::<Hash>::FIXED_SIZE + PQEDCheckpointLeafStats::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyCheckpointLeafPopulated<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.global_state_roots.pio_write_to_io(writer)?;
        self.stats.pio_write_to_io(writer)
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let global_state_roots = PQEDCheckpointGlobalStateRoots::pio_read_from_io(reader)?;
        let stats = PQEDCheckpointLeafStats::<F, Hash>::pio_read_from_io(reader)?;

        Ok(Self { global_state_roots, stats })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyCheckpointLeafPopulated,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyCheckpointLeafPopulated<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyCheckpointLeafPopulated,
    { parth_core::PF, parth_core::PHash },
    qed_checkpoint_leaf
);

impl<F: QFelt64, Hash: QFHashBase<F>> PsyCheckpointLeafPopulated<F, Hash> {
    pub fn to_checkpoint_leaf<H: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeaf<F, Hash> {
        PQEDCheckpointLeaf {
            global_chain_root: self.global_state_roots.qfhash::<H>(),
            stats: self.stats,
        }
    }
    pub fn to_compact<H: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeafCompact<Hash> {
        PQEDCheckpointLeafCompact {
            global_chain_root: self.global_state_roots.qfhash::<H>(),
            stats_hash: self.stats.qfhash::<H>(),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PsyCheckpointLeafPopulated<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.to_checkpoint_leaf::<H>().qfhash::<H>()
    }
}
