use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct GUTAStats<F: RichField> {
    pub guta_fees_collected: F,
    pub da_fees_collected: F,

    pub user_ops_processed: F,
    pub total_transactions: F,

    pub slots_modified: F,
}
impl<F: RichField> GUTAStats<F> {
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

impl<F: RichField> QFieldHashable<F> for GUTAStats<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&[
            self.guta_fees_collected,
            self.da_fees_collected,
            self.user_ops_processed,
            self.total_transactions,
            self.slots_modified,
        ])
    }
}
impl<F: RichField> KVQSerializable for GUTAStats<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
