// src/metadata.rs

pub trait PsyCanonicalSerializeMetadata {
    const IS_FIXED_SIZE: bool;
    const FIXED_SIZE: usize;
}

/// Provides a hint for the maximum number of items allowed in a dynamically-sized vector
/// during serialization and deserialization to prevent excessive memory allocation.
pub trait PsyCanonicalSerializeMaxVecLength {
    /// The maximum number of items allowed in a Vec.
    #[inline(always)]
    fn psy_io_max_vec_length() -> usize {
        u32::MAX as usize
    }
}