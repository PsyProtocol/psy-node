
mod qhashout;
pub use qhashout::*;
pub type PGoldilocksHash = QHashOut<plonky2::field::goldilocks_field::GoldilocksField>;
pub type PGoldilocksFelt = plonky2::field::goldilocks_field::GoldilocksField;