// src/metadata.rs

pub trait PsyCanonicalSerializeMetadata {
    const IS_FIXED_SIZE: bool;
    const FIXED_SIZE: usize;
    const MAX_VEC_LENGTH: usize = u32::MAX as usize;
}
pub trait PsyIOWithMaxVecLength {
    #[inline(always)]
    fn psy_io_max_vec_length() -> usize {
        // Default to a large but reasonable value to prevent accidental OOM.
        // Can be overridden for specific types.
        1_000_000_000
    }
}
impl<T: PsyCanonicalSerializeMetadata> PsyIOWithMaxVecLength for T {
    #[inline(always)]
    fn psy_io_max_vec_length() -> usize {
        T::MAX_VEC_LENGTH
    }
}



#[macro_export]
macro_rules! impl_max_length_for_type {
    ($ty:ty, $size:expr, $max_vec_len:expr) => {
        impl $crate::PsyCanonicalSerializeMetadata for $ty {
            const IS_FIXED_SIZE: bool = true;
            const FIXED_SIZE: usize = $size as usize;
            const MAX_VEC_LENGTH: usize = $max_vec_len as usize;
        }
    }
}

impl_max_length_for_type!(u8, 1, u32::MAX);
impl_max_length_for_type!(u16, 2, u32::MAX);
impl_max_length_for_type!(u32, 4, u32::MAX);
impl_max_length_for_type!(u64, 8, u32::MAX);
impl_max_length_for_type!(u128, 16, u32::MAX);
impl_max_length_for_type!(i8, 1, u32::MAX);
impl_max_length_for_type!(i16, 2, u32::MAX);
impl_max_length_for_type!(i32, 4, u32::MAX);
impl_max_length_for_type!(i64, 8, u32::MAX);
impl_max_length_for_type!(i128, 16, u32::MAX);
impl_max_length_for_type!(f32, 4, u32::MAX);
impl_max_length_for_type!(f64, 8, u32::MAX);