use std::ops::Add;

use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::QFHashBase, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


#[pderive::serialize_copy_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
#[repr(C)]
pub struct GUTAStats<F> {
    pub fees_collected: F,

    pub user_ops_processed: F,
    pub total_transactions: F,

    pub slots_modified: F,
}
impl<F: Add<Output = F> + Copy> GUTAStats<F> {
    pub fn combine_with(&self, other: &GUTAStats<F>) -> Self {
        Self {
            fees_collected: self.fees_collected + other.fees_collected,
            user_ops_processed: self.user_ops_processed + other.user_ops_processed,
            total_transactions: self.total_transactions + other.total_transactions,
            slots_modified: self.slots_modified + other.slots_modified,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GUTAStats<F> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        Hash::from_4_felts([self.fees_collected, self.user_ops_processed, self.total_transactions, self.slots_modified])
    }
}

impl<F: QPGenRandom> QPGenRandom for GUTAStats<F> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            fees_collected: F::qp_rand_gen(),
            user_ops_processed: F::qp_rand_gen(),
            total_transactions: F::qp_rand_gen(),
            slots_modified: F::qp_rand_gen(),
        }
    }
}




impl<F: QFelt64> PsyCanonicalSerializeMetadata for GUTAStats<F> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32; // 4 * 8 bytes for F = QFelt64
}
impl<F: QFelt64> FallbackPsySerializeCanonical for GUTAStats<F> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.fees_collected.to_u64_value())?;
        writer.psy_write_u64(self.user_ops_processed.to_u64_value())?;
        writer.psy_write_u64(self.total_transactions.to_u64_value())?;
        writer.psy_write_u64(self.slots_modified.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        
        let fees_collected = F::from_u64_value(reader.psy_read_u64()?);
        let user_ops_processed = F::from_u64_value(reader.psy_read_u64()?);
        let total_transactions = F::from_u64_value(reader.psy_read_u64()?);
        let slots_modified = F::from_u64_value(reader.psy_read_u64()?);

        Ok(Self {
            fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAStats,
    { F: QFelt64 } => { F }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTAStats<F> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GUTAStats,
    { parth_core::PF },
    guta_stats_tests
);