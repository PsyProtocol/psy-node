
use plonky2::{field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64, Sample}}, hash::hash_types::RichField};

use super::qhashout::QHashOut;
use crate::{felt::{FromPrimitiveValuesFelt, QFelt64, SimpleRandFelt, ToU64Value, ZeroableFelt}, generic_traits::QStaticNamedType, utils::{debug_code_string::QToCodeString, QPGenRandom}};
pub type PGoldilocksHash = QHashOut<GoldilocksField>;
pub type PGoldilocksFelt = GoldilocksField;

impl QToCodeString for PGoldilocksHash {
    fn to_debug_code_string(&self) -> String {
        if *self == Self::ZERO {
            return "PHash::ZERO".to_string();
        }
        format!(
            "PHash::from_values({}, {}, {}, {})",
            self.0.elements[0].to_noncanonical_u64(),
            self.0.elements[1].to_noncanonical_u64(),
            self.0.elements[2].to_noncanonical_u64(),
            self.0.elements[3].to_noncanonical_u64(),
        )
    }
}


impl ZeroableFelt for PGoldilocksFelt {
    const ZERO_VALUE: Self = GoldilocksField::ZERO;
}

impl FromPrimitiveValuesFelt for PGoldilocksFelt {
    fn from_u8_value(value: u8) -> Self {
        GoldilocksField::from_canonical_u8(value)
    }
    fn from_u16_value(value: u16) -> Self {
        GoldilocksField::from_canonical_u16(value)
    }
    fn from_u32_value(value: u32) -> Self {
        GoldilocksField::from_canonical_u32(value)
    }
    fn from_u64_value(value: u64) -> Self {
        GoldilocksField::from_noncanonical_u64(value)
    }
}

impl SimpleRandFelt for PGoldilocksFelt {
    fn get_simple_rand() -> Self {
        Self::rand()
    }
}


impl ToU64Value for PGoldilocksFelt {
    fn to_u64_value(&self) -> u64 {
        self.to_canonical_u64()
    }

    #[inline(always)]
    fn into_u64_value_serialize_non_canonical(self) -> u64 {
        self.0
    }
    
    #[inline(always)]
    fn from_owned_u64(value: u64) -> Self {
        Self::from_noncanonical_u64(value)
    }
    
    fn tuv_to_canonical_u64(&self) -> u64 {
        self.to_canonical_u64()
    }
}

impl QPGenRandom for PGoldilocksFelt {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self::rand()
    }
}

impl QStaticNamedType for PGoldilocksFelt {
    fn q_static_type_name() -> &'static str {
        "PGoldilocksFelt"
    }
}





pub trait QRichField: RichField + QFelt64 {}
impl QRichField for GoldilocksField {}
