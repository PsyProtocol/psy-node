use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::guta::stats::GUTAStats;
use psy_common_circuit::traits::{AlgebraicHashableTarget, WitnessValueFor};

#[derive(Clone, Debug, Copy)]
pub struct GUTAStatsGadget {
    // start require witness
    pub guta_fees_collected: Target,
    pub da_fees_collected: Target,

    pub user_ops_processed: Target,
    pub total_transactions: Target,

    pub slots_modified: Target,
    // start computed
}
impl GUTAStatsGadget {
    pub fn add_virtual_to_zero<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let guta_fees_collected = builder.zero();
        let da_fees_collected = builder.zero();

        let user_ops_processed = builder.zero();
        let total_transactions = builder.zero();

        let slots_modified = builder.zero();

        Self {
            guta_fees_collected,
            da_fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
        }
    }
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let guta_fees_collected = builder.add_virtual_target();
        let da_fees_collected = builder.add_virtual_target();

        let user_ops_processed = builder.add_virtual_target();
        let total_transactions = builder.add_virtual_target();

        let slots_modified = builder.add_virtual_target();

        Self {
            guta_fees_collected,
            da_fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
        }
    }
    pub fn combine_with<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &GUTAStatsGadget,
    ) -> GUTAStatsGadget {
        let guta_fees_collected = builder.add(self.guta_fees_collected, other.guta_fees_collected);
        let da_fees_collected = builder.add(self.da_fees_collected, other.da_fees_collected);
        let user_ops_processed = builder.add(self.user_ops_processed, other.user_ops_processed);
        let total_transactions = builder.add(self.total_transactions, other.total_transactions);
        let slots_modified = builder.add(self.slots_modified, other.slots_modified);

        Self {
            guta_fees_collected,
            da_fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &GUTAStats<F>) -> anyhow::Result<()> {
        witness.set_target(self.guta_fees_collected, target.guta_fees_collected)?;
        witness.set_target(self.da_fees_collected, target.da_fees_collected)?;
        witness.set_target(self.user_ops_processed, target.user_ops_processed)?;
        witness.set_target(self.total_transactions, target.total_transactions)?;
        witness.set_target(self.slots_modified, target.slots_modified)
    }

    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(
            [
                self.guta_fees_collected,
                self.da_fees_collected,
                self.user_ops_processed,
                self.total_transactions,
                self.slots_modified,
            ]
            .to_vec(),
        )
    }
}
impl AlgebraicHashableTarget for GUTAStatsGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<GUTAStatsGadget, F, true> for GUTAStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &GUTAStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<GUTAStatsGadget, F, false> for GUTAStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &GUTAStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
