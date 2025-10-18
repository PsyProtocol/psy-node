use crate::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable};

pub const CONST_FFS_PRIMITIVES_ENABLED: bool = true;

// --- Macro to implement the trait for primitive numeric types ---

macro_rules! impl_ffs_for_primitive {
    ($ty:ty, $size:expr) => {
        const _: () = {
            const fn assert_pod<T: bytemuck::Pod>() {}
            assert_pod::<$ty>();
        };
        impl AutoDatabaseSerializationUseFastFixedSerialize<$size> for $ty {}

        crate::impl_psy_canonical_serialize_for_fixed_type_crate!(
            $ty,
            $size
        );

        impl FastFixedSerializable<$size> for $ty {
            #[inline(always)]
            fn ffs_from_owned_bytes(data: [u8; $size]) -> Self {
                Self::from_le_bytes(data)
            }
            #[inline]
            fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
                Self::from_le_bytes(data.try_into().unwrap())
            }
            #[inline]
            fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                Ok(Self::from_le_bytes(data.try_into()?))
            }
            #[inline(always)]
            fn ffs_to_bytes(&self) -> [u8; $size] {
                self.to_le_bytes()
            }
            #[inline(always)]
            fn ffs_into_bytes(self) -> [u8; $size] {
                self.to_le_bytes()
            }

            #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
            #[inline]
            fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) {
                bytes.extend_from_slice(bytemuck::cast_slice(data));
            }
            #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
            #[inline]
            fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
                bytemuck::cast_slice(data).to_vec()
            }
            #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
            #[inline]
            fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
                bytemuck::cast_vec(data)
            }
            #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
            #[inline]
            fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
                bytemuck::try_cast_slice(data).map(Vec::from).map_err(|e| anyhow::anyhow!(e))
            }
            #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
            #[inline]
            fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
                bytemuck::try_cast_vec(data).map_err(|e| anyhow::anyhow!("{:?}", e))
            }
        }
    };
}
impl_ffs_for_primitive!(u16, 2);
impl_ffs_for_primitive!(u32, 4);
impl_ffs_for_primitive!(u64, 8);
impl_ffs_for_primitive!(u128, 16);
impl_ffs_for_primitive!(i16, 2);
impl_ffs_for_primitive!(i32, 4);
impl_ffs_for_primitive!(i64, 8);
impl_ffs_for_primitive!(i128, 16);
impl_ffs_for_primitive!(f32, 4);
impl_ffs_for_primitive!(f64, 8);

//==================================================================================
// 4. ROBUST MACRO AND IMPLEMENTATIONS FOR ARRAYS OF PRIMITIVES
//==================================================================================
/* 
macro_rules! impl_ffs_for_array {
    ($inner_ty:ty, $inner_size:expr, $array_len:expr) => {
        paste! {
            mod [<__ffs_impl_for_ $inner_ty _ $array_len>] {
                use super::*;
                const _: () = {
                    assert!(std::mem::size_of::<$inner_ty>() == $inner_size, "Provided inner_size does not match the type's actual size.");
                    const fn assert_pod<T: bytemuck::Pod>() {}
                    assert_pod::<[$inner_ty; $array_len]>();
                };

                const TOTAL_SIZE: usize = $inner_size * $array_len;

                impl FastFixedSerializable<TOTAL_SIZE> for [$inner_ty; $array_len] {
                    fn ffs_from_owned_bytes(data: [u8; TOTAL_SIZE]) -> Self {
                        core::array::from_fn(|i| {
                            let start = i * $inner_size;
                            let chunk: [u8; $inner_size] = data[start..start + $inner_size].try_into().unwrap();
                            <$inner_ty>::ffs_from_owned_bytes(chunk)
                        })
                    }
                    fn ffs_to_bytes(&self) -> [u8; TOTAL_SIZE] {
                        let mut bytes = [0u8; TOTAL_SIZE];
                        for (i, item) in self.iter().enumerate() {
                            bytes[i * $inner_size.. (i + 1) * $inner_size].copy_from_slice(&item.ffs_to_bytes());
                        }
                        bytes
                    }
                    fn ffs_into_bytes(self) -> [u8; TOTAL_SIZE] { self.ffs_to_bytes() }
                    fn ffs_from_slice_or_panic(data: &[u8]) -> Self { Self::ffs_try_from_slice(data).unwrap() }
                    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                        let owned_data: [u8; TOTAL_SIZE] = data.try_into().map_err(|_| anyhow::anyhow!("Invalid slice length"))?;
                        Ok(Self::ffs_from_owned_bytes(owned_data))
                    }

                    #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
                    #[inline] fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) { bytes.extend_from_slice(bytemuck::cast_slice(data)); }
                    #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
                    #[inline] fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> { bytemuck::cast_slice(data).to_vec() }
                    #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
                    #[inline] fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> { bytemuck::cast_vec(data) }
                    #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
                    #[inline] fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> { bytemuck::try_cast_slice(data).map(Vec::from).map_err(|e| anyhow::anyhow!(e)) }
                    #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
                    #[inline] fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> { bytemuck::try_cast_vec(data).map_err(|e| anyhow::anyhow!("{:?}",e)) }
                }
            }
        }
    };
}
*/
impl FastFixedSerializable<1> for u8 {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 1]) -> Self {
        data[0]
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 1 {
            panic!("Data length {} is not equal to expected size 1", data.len());
        }
        data[0]
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 1 {
            anyhow::bail!("Data length {} is not equal to expected size 1", data.len());
        }
        Ok(data[0])
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; 1] {
        [*self]
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; 1] {
        [self]
    }

    #[inline(always)]
    fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(data);
    }

    #[inline(always)]
    fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        data.to_vec()
    }

    #[inline(always)]
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        data
    }

    #[inline(always)]
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        Ok(data.to_vec())
    }

    #[inline(always)]
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        Ok(data)
    }
}

impl<const N: usize> FastFixedSerializable<N> for [u8; N] {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; N]) -> Self {
        data
    }

    #[inline]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != N {
            panic!("Data length {} is not equal to expected size {}", data.len(), N);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&data[0..N]);
        arr
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != N {
            anyhow::bail!("Data length {} is not equal to expected size {}", data.len(), N);
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&data[0..N]);
        Ok(arr)
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; N] {
        *self
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; N] {
        self
    }

    #[inline(always)]
    fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) {
        for item in data {
            bytes.extend_from_slice(item);
        }
    }
    #[inline(always)]
    fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        data.as_flattened().to_vec()
    }

    #[inline(always)]
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        data.into_flattened()
    }

    #[inline]
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % N != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), N);
        }

        // Use chunks_exact to iterate over the byte slice in N-sized chunks.
        // This is highly optimized by the compiler (often using SIMD).
        Ok(data
            .chunks_exact(N)
            .map(|chunk| {
                // For each chunk, call the single-item deserializer.
                // try_into().unwrap() is safe because chunks_exact guarantees length N.
                chunk.try_into().unwrap()
            })
            .collect())
    }

    #[inline]
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        if data.len() == 0 {
            return Ok(Vec::new());
        } else if data.len() % N != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), N);
        }

        // can I bytemuck this?
        let vec_of_arrays: Vec<[u8; N]> = data
            .chunks_exact(N)
            .map(|chunk| {
                // For each chunk, call the single-item deserializer.
                // try_into().unwrap() is safe because chunks_exact guarantees length N.
                chunk.try_into().unwrap()
            })
            .collect();
        Ok(vec_of_arrays)
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_ffs_u32() {
        use crate::FastFixedSerializable;
        let values: Vec<u32> = vec![1, 256, 65536, 4294967295];
        let result_bytes = u32::ffs_serialize_vec_of_self_ref(&values);
        let deserialized_values = u32::ffs_deserialize_vec_of_self(&result_bytes).unwrap();
        assert_eq!(values, deserialized_values);
    }

}