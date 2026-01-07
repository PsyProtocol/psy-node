use std::ops::Add;

use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::{QFelt64, ZeroableFelt}, protocol::core_types::QFHashBase, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


#[pderive::serialize_copy_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
#[repr(C)]
pub struct GUTAStats<F> {
    pub guta_fees_collected: F,
    pub da_fees_collected: F,

    pub user_ops_processed: F,
    pub total_transactions: F,

    pub slots_modified: F,
}

impl<F: ZeroableFelt> GUTAStats<F> {
    pub fn get_zero_value() -> Self {
        Self {
            guta_fees_collected: F::ZERO_VALUE,
            da_fees_collected: F::ZERO_VALUE,
            user_ops_processed: F::ZERO_VALUE,
            total_transactions: F::ZERO_VALUE,
            slots_modified: F::ZERO_VALUE,
        }
    }
}
impl<F: Add<Output = F> + Copy> GUTAStats<F> {
    pub fn add_from_mut(&mut self, other: &GUTAStats<F>) {
        self.guta_fees_collected = self.guta_fees_collected + other.guta_fees_collected;
        self.da_fees_collected = self.da_fees_collected + other.da_fees_collected;
        self.user_ops_processed = self.user_ops_processed + other.user_ops_processed;
        self.total_transactions = self.total_transactions + other.total_transactions;
        self.slots_modified = self.slots_modified + other.slots_modified;
    }
    pub fn combine_with(&self, other: &GUTAStats<F>) -> Self {
        Self {
            guta_fees_collected: self.guta_fees_collected + other.guta_fees_collected,
            da_fees_collected: self.da_fees_collected + other.da_fees_collected,
            user_ops_processed: self.user_ops_processed + other.user_ops_processed,
            total_transactions: self.total_transactions + other.total_transactions,
            slots_modified: self.slots_modified + other.slots_modified,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GUTAStats<F> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        H::q_hash_many(&[self.guta_fees_collected, self.da_fees_collected, self.user_ops_processed, self.total_transactions, self.slots_modified])
    }
}

impl<F: QPGenRandom> QPGenRandom for GUTAStats<F> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_fees_collected: F::qp_rand_gen(),
            da_fees_collected: F::qp_rand_gen(),
            user_ops_processed: F::qp_rand_gen(),
            total_transactions: F::qp_rand_gen(),
            slots_modified: F::qp_rand_gen(),
        }
    }
}




impl<F: QFelt64> PsyCanonicalSerializeMetadata for GUTAStats<F> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 40; // 5 * 8 bytes for F = QFelt64
}
impl<F: QFelt64> FallbackPsySerializeCanonical for GUTAStats<F> {
    fn fallback_pio_serialized_size(&self) -> usize {
        40
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.guta_fees_collected.to_u64_value())?;
        writer.psy_write_u64(self.da_fees_collected.to_u64_value())?;
        writer.psy_write_u64(self.user_ops_processed.to_u64_value())?;
        writer.psy_write_u64(self.total_transactions.to_u64_value())?;
        writer.psy_write_u64(self.slots_modified.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        
        let guta_fees_collected = F::from_u64_value(reader.psy_read_u64()?);
        let da_fees_collected = F::from_u64_value(reader.psy_read_u64()?);
        let user_ops_processed = F::from_u64_value(reader.psy_read_u64()?);
        let total_transactions = F::from_u64_value(reader.psy_read_u64()?);
        let slots_modified = F::from_u64_value(reader.psy_read_u64()?);

        Ok(Self {
            guta_fees_collected,
            da_fees_collected,
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