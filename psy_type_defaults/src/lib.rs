use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

pub type F = GoldilocksField;
pub type Hash = HashOut<F>;