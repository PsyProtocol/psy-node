use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::guta::{stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition};
#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeader<F, Hash > {
    pub guta_circuit_whitelist: Hash,
    pub checkpoint_tree_root: Hash,
    pub state_transition: SubTreeNodeStateTransition<F, Hash>,
    pub stats: GUTAStats<F>,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeader<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let state_transition_hash = self.state_transition.qfhash::<H>();
        let stats_hash = self.stats.qfhash::<H>();



        let state_transition_and_stats_hash = H::q_two_to_one(
            state_transition_hash,
            stats_hash,
        );

        let state_stats_checkpoint_hash = H::q_two_to_one(
            self.checkpoint_tree_root,
            state_transition_and_stats_hash,
        );

        H::q_two_to_one(
            self.guta_circuit_whitelist,
            state_stats_checkpoint_hash,
        )
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeader<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: Hash::qp_rand_gen(),
            checkpoint_tree_root: Hash::qp_rand_gen(),
            state_transition: SubTreeNodeStateTransition::qp_rand_gen(),
            stats: GUTAStats::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeader<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*2 + SubTreeNodeStateTransition::<F, Hash>::FIXED_SIZE + GUTAStats::<F>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeader<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         32*2 + SubTreeNodeStateTransition::<F, Hash>::FIXED_SIZE + GUTAStats::<F>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.guta_circuit_whitelist.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
            self.state_transition.pio_write_to_io(writer)?;
            self.stats.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_circuit_whitelist = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let state_transition = SubTreeNodeStateTransition::pio_read_from_io(reader)?;
        let stats = GUTAStats::<F>::pio_read_from_io(reader)?;
        Ok(Self {
            guta_circuit_whitelist,
            checkpoint_tree_root,
            state_transition,
            stats,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeader,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeader<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeader,
    { parth_core::PF, parth_core::PHash },
    psy_guta_node_update
);