
mod qhashout;
use plonky2::field::types::Field;
pub use qhashout::*;

use crate::felt::{FromPrimitiveValuesFelt, ZeroableFelt};
pub type PGoldilocksHash = QHashOut<plonky2::field::goldilocks_field::GoldilocksField>;
pub type PGoldilocksFelt = plonky2::field::goldilocks_field::GoldilocksField;

impl ZeroableFelt for PGoldilocksFelt {
    const ZERO_VALUE: Self = plonky2::field::goldilocks_field::GoldilocksField::ZERO;
}

impl FromPrimitiveValuesFelt for PGoldilocksFelt {
    fn from_u8_value(value: u8) -> Self {
        plonky2::field::goldilocks_field::GoldilocksField::from_canonical_u8(value)
    }
    fn from_u16_value(value: u16) -> Self {
        plonky2::field::goldilocks_field::GoldilocksField::from_canonical_u16(value)
    }
    fn from_u32_value(value: u32) -> Self {
        plonky2::field::goldilocks_field::GoldilocksField::from_canonical_u32(value)
    }
    fn from_u64_value(value: u64) -> Self {
        plonky2::field::goldilocks_field::GoldilocksField::from_noncanonical_u64(value)
    }
}