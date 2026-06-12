use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use crate::{builder::hash::core::CircuitBuilderHashCore, traits::AlgebraicHashableTarget};

#[derive(Debug, Clone)]
pub struct SimpleHashStackGadget {
    current_tip: HashOutTarget,
}
impl SimpleHashStackGadget {
    pub fn new(tip: HashOutTarget) -> Self {
        Self { current_tip: tip }
    }
    pub fn push_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: HashOutTarget,
    ) {
        let new_tip = builder.hash_two_to_one::<H>(self.current_tip, value);
        self.current_tip = new_tip;
    }
    pub fn pop_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        new_tip: HashOutTarget,
        value: HashOutTarget,
    ) -> HashOutTarget {
        let expected_current_tip = builder.hash_two_to_one::<H>(new_tip, value);
        builder.connect_hashes(expected_current_tip, self.current_tip);
        self.current_tip = new_tip;
        value
    }
    pub fn push_hashable<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize, T: AlgebraicHashableTarget>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        value: T,
    ) {
        let value_hash = value.to_hash_target::<H, F, D>(builder);
        self.push_hash::<H, F, D>(builder, value_hash);
    }
    pub fn pop_hashable<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize, T: AlgebraicHashableTarget>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        new_tip: HashOutTarget,
        value: T,
    ) -> HashOutTarget {
        let value_hash = value.to_hash_target::<H, F, D>(builder);
        self.pop_hash::<H, F, D>(builder, new_tip, value_hash)
    }
    pub fn get_tip(&self) -> HashOutTarget {
        self.current_tip
    }
}
