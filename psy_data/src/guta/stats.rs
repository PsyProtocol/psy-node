use std::ops::Add;

use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::QFHashBase};


#[pderive::serialize_copy_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
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
