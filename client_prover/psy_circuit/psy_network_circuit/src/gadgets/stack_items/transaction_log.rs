use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::dpn::proving_session::DPNProvingSessionCompactMethodCall;
use psy_common_circuit::traits::{AlgebraicHashableTarget, CreatableTarget, WitnessValueFor};

use crate::gadgets::qdata::contract_function_call::DPNProvingSessionCompactMethodCallGadget;

// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionLogStackItemGadget {
    pub call_data: DPNProvingSessionCompactMethodCallGadget,
}

impl TransactionLogStackItemGadget {
    fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let call_data = DPNProvingSessionCompactMethodCallGadget::add_virtual_to(builder);

        Self { call_data }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionCompactMethodCall<F>) -> anyhow::Result<()> {
        self.call_data.set_witness(witness, target)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.call_data.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for TransactionLogStackItemGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<F, D>(builder)
    }
}
impl AlgebraicHashableTarget for TransactionLogStackItemGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<TransactionLogStackItemGadget, F, true> for DPNProvingSessionCompactMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &TransactionLogStackItemGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<TransactionLogStackItemGadget, F, false> for DPNProvingSessionCompactMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &TransactionLogStackItemGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
