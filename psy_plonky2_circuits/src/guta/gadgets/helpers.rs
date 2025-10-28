use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};

use super::guta_header::GlobalUserTreeAggregatorHeaderGadget;

pub trait ToGUTAHeader<const D: usize> {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, builder: &mut CircuitBuilder<F, D>, default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget;
}