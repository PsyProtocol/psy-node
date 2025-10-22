use crate::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata};

pub trait PsyCanonicalDatabaseSerializeBaseMulti: PsyCanonicalDatabaseSerializeBaseSingle {
    #[inline]
    fn psy_ser_serialize_vec_of_self_ref(data: &[Self], write_count: bool) -> Vec<u8> {
        // This is a high-level API; unwrapping is acceptable if serialization to a Vec
        // is not expected to fail (e.g., OOM).
        Self::pio_write_many_to_bytes(data, write_count || !Self::IS_FIXED_SIZE).expect("Failed to serialize vec of self")
    }

    #[inline]
    fn psy_ser_serialize_vec_of_self(data: Vec<Self>, write_count: bool) -> Vec<u8> {
        Self::psy_ser_serialize_vec_of_self_ref(&data, write_count || !Self::IS_FIXED_SIZE)
    }

    fn psy_ser_deserialize_vec_of_self(data: &[u8], include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        if Self::IS_FIXED_SIZE && !include_count_for_fixed {
            // This is a raw slab of fixed-size items with no count prefix.
            // We calculate the count and pass it to the pio layer.
            // This enables the fast path for bytemuck zero-copy deserialization.
            if data.len() % Self::FIXED_SIZE != 0 {
                anyhow::bail!(
                    "Data length {} is not a multiple of fixed size {}",
                    data.len(),
                    Self::FIXED_SIZE
                );
            }
            let count = data.len() / Self::FIXED_SIZE;
            Self::pio_read_many_from_ref_bytes(data, Some(count))
        } else {
            // This is either variable-size items (which always have a count) or
            // fixed-size items that are prefixed with a count.
            // We pass the full slice and let the pio layer read the count.
            Self::pio_read_many_from_ref_bytes(data, None)
        }
    }

    #[inline]
    fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        // The owned version can also benefit from the same logic.
        // The pio_rw_fixed layer will use ffs_deserialize_vec_of_self_owned for potential zero-copy.
        Self::psy_ser_deserialize_vec_of_self(&data, include_count_for_fixed)
    }
}

pub trait PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<const N: usize>: Sized {
    fn fx_tpl_psy_ser_serialize_vec_of_self_ref(data: &[Self], write_count: bool) -> Vec<u8>;
    fn fx_tpl_psy_ser_serialize_vec_of_self(data: Vec<Self>, write_count: bool) -> Vec<u8>;
    fn fx_tpl_psy_ser_deserialize_vec_of_self(data: &[u8], include_count: bool) -> anyhow::Result<Vec<Self>>;
    fn fx_tpl_psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_count: bool) -> anyhow::Result<Vec<Self>>;
}

impl PsyCanonicalDatabaseSerializeBaseMulti for u8 {
    fn psy_ser_serialize_vec_of_self_ref(data: &[Self], write_count: bool) -> Vec<u8> {
        // This is a high-level API; unwrapping is acceptable if serialization to a Vec
        // is not expected to fail (e.g., OOM).
        if write_count {
            let mut result = Vec::with_capacity(4 + data.len());
            let count = data.len() as u32;
            result.extend_from_slice(&count.to_le_bytes());
            result.extend_from_slice(data);
            result
        } else {
            data.to_vec()
        }
    }

    fn psy_ser_serialize_vec_of_self(data: Vec<Self>, write_count: bool) -> Vec<u8> {
        if !write_count {
            data
        } else {
            Self::psy_ser_serialize_vec_of_self_ref(&data, write_count)
        }
    }

    fn psy_ser_deserialize_vec_of_self(data: &[u8], include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        if Self::IS_FIXED_SIZE && !include_count_for_fixed {
            Ok(data.to_vec())
        } else {
            let count = if data.len() < 4 {
                anyhow::bail!("Data length {} is too small to contain count prefix", data.len());
            } else {
                let mut count_bytes = [0u8; 4];
                count_bytes.copy_from_slice(&data[0..4]);
                u32::from_le_bytes(count_bytes) as usize
            };
            let expected_len = 4 + count;
            if data.len() < expected_len {
                anyhow::bail!(
                    "Data length {} is smaller than expected length {} for count {}",
                    data.len(),
                    expected_len,
                    count
                );
            }
            Ok(data[4..expected_len].to_vec())
        }
    }

    fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if include_count_for_fixed {
            return Self::psy_ser_deserialize_vec_of_self(&data, include_count_for_fixed);
        }else{
            Ok(data)
        }
    }
}