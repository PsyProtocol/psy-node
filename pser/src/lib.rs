
/*use serde::{de::DeserializeOwned, Serialize};

pub type QBytes = std::vec::Vec<u8>;
pub trait QBytesSerialize: Serialize {
    fn to_qbytes(&self) -> anyhow::Result<QBytes>;
    fn to_qbytes_unwrap(&self) -> QBytes;
}
impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        Ok(bincode::serde::encode_to_vec(self, bincode::config::standard())?)
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}
pub trait QBytesDeserialize: DeserializeOwned {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn from_qbytes_unwrap(bytes: &[u8]) -> Self;
}
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::serde::decode_from_slice(bytes, bincode::config::standard())?.0)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap().0
    }
}*/
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub type QBytes = std::vec::Vec<u8>;
pub trait QBytesSerialize {
    fn to_qbytes(&self) -> anyhow::Result<QBytes>;
    fn to_qbytes_unwrap(&self) -> QBytes;
}
pub trait QBytesDeserialize {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> where for<'de> Self: Deserialize<'de>;
    fn from_qbytes_unwrap(bytes: &[u8]) -> Self;
}
pub trait QBytesSerializable: QBytesSerialize + QBytesDeserialize {}
impl<T: QBytesSerialize + QBytesDeserialize> QBytesSerializable for T {}

/* 
impl<T> QBytesDeserialize for T where for<'de> T: Deserialize<'de>,{
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

*/
/* 
// bincode 2.0.1
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::serde::decode_from_slice(bytes, bincode::config::standard())?.0)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap().0
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        Ok(bincode::serde::encode_to_vec(self, bincode::config::standard())?)
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}
*/
/*
// postcard
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        postcard::from_bytes(bytes).unwrap()
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        postcard::to_stdvec(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        postcard::to_stdvec(self).unwrap()
    }
}

*/

impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serialize(self).unwrap()
    }
}

#[inline]
pub fn serialize<T: QBytesSerialize>(value: &T) -> anyhow::Result<QBytes> {
    value.to_qbytes()
}

#[inline]
pub fn deserialize<T: QBytesDeserialize>(bytes: &[u8]) -> anyhow::Result<T> where for<'de> T: Deserialize<'de> {
    T::from_qbytes(bytes)
}


#[macro_export]
macro_rules! impl_bytemuck_pod_and_zeroable {
    // Arm 1: Matcher for a type with one or more generic parameters.
    // Example: MyType, F, Hash
    ($type_name:ident, $( $generic:ident ),+) => {
        #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
        unsafe impl< $( $generic: bytemuck::Pod ),+ > bytemuck::Zeroable for $type_name< $( $generic ),+ > {}

        #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
        unsafe impl< $( $generic: bytemuck::Pod ),+ > bytemuck::Pod for $type_name< $( $generic ),+ > {}
    };

    // Arm 2: Matcher for a simple type with no generics.
    // Example: MyOtherType
    ($type_name:ident) => {
        #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
        unsafe impl bytemuck::Zeroable for $type_name {}

        #[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
        unsafe impl bytemuck::Pod for $type_name {}
    };
}

/// Implements `FastFixedSerializable` for a `#[repr(C)]` struct using `bytemuck`
/// for zero-copy/low-copy serialization and deserialization.
///
/// This macro is designed for structs that are Plain Old Data (`Pod`) and is
/// feature-gated behind `all(target_endian = "little", feature = "serialize_bytemuck")`.
///
/// # Pre-requisites
///
/// The target struct MUST:
/// 1. Be annotated with `#[repr(C)]`.
/// 2. Derive or implement `bytemuck::Pod` and `bytemuck::Zeroable`.
/// 3. Derive or implement `Copy`.
///
/// # Usage
///
/// ```rust,ignore
/// impl_bytemuck_ffs!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. Generic parameters and their required trait bounds for the impl.
///     //    These bounds should typically be the concrete marker traits that
///     //    ensure the struct is `Pod`.
///     { F: MyFieldTrait, H: MyHashTrait },
///     // 3. The compile-time constant size of the struct in bytes.
///     128
/// );
/// ```
#[macro_export]
macro_rules! impl_bytemuck_ffs {
    (
        $struct_name:ident,
        { $($generic_param:ident: $trait_bound:path),* },
        $size:literal
    ) => {
        // --- ZERO-COPY FastFixedSerializable IMPLEMENTATION ---
        // This implementation uses `bytemuck` to perform zero-copy or low-copy
        // serialization and deserialization. This is highly efficient but requires the
        // struct to be `#[repr(C)]` and implement `bytemuck::Pod` (Plain Old Data).
        // This code is only compiled when the appropriate features and target are enabled.
        #[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
        impl<
            $($generic_param: $trait_bound + bytemuck::Pod + Copy),*
        > psy_serialize::FastFixedSerializable<$size> for $struct_name<$($generic_param),*> {
            #[inline(always)]
            fn ffs_try_from_slice(data: &[u8]) -> ::anyhow::Result<Self> {
                bytemuck::try_from_bytes(data)
                    .map(|&s| s)
                    .map_err(|e| ::anyhow::anyhow!("Failed to cast slice to {}: {}", stringify!($struct_name), e))
            }

            #[inline(always)]
            fn ffs_from_owned_bytes(data: [u8; $size]) -> Self {
                bytemuck::cast(data)
            }

            #[inline(always)]
            fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
                *bytemuck::from_bytes(data)
            }

            #[inline(always)]
            fn ffs_to_bytes(&self) -> [u8; $size] {
                bytemuck::cast(*self)
            }

            #[inline(always)]
            fn ffs_into_bytes(self) -> [u8; $size] {
                bytemuck::cast(self)
            }

            // --- OPTIMIZED VECTOR IMPLEMENTATIONS ---

            /// Serializes a slice of `Self` into a `Vec<u8>` using a single, efficient
            /// memory copy.
            #[inline(always)]
            fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
                bytemuck::cast_slice(data).to_vec()
            }

            /// Serializes a `Vec<Self>` into a `Vec<u8>` using a zero-copy memory
            /// reinterpret cast.
            #[inline(always)]
            fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
                // This is a zero-copy operation that reinterprets the `Vec<Self>` as a
                // `Vec<u8>`. It's safe because `Self` is `Pod` and its memory
                // representation is just a sequence of bytes.
                let mut data = ::std::mem::ManuallyDrop::new(data);
                let len = data.len() * $size;
                let capacity = data.capacity() * $size;
                let ptr = data.as_mut_ptr() as *mut u8;
                // SAFETY: The original Vec is not dropped (thanks to ManuallyDrop), so we are
                // taking ownership of its allocation. The new length and capacity are
                // calculated correctly. Since `Self` is `Pod`, it's safe to view its
                // bytes as `u8`.
                unsafe { Vec::from_raw_parts(ptr, len, capacity) }
            }

            /// Deserializes a slice of bytes into a `Vec<Self>`, copying only if memory
            /// alignment is incorrect.
            #[inline(always)]
            fn ffs_deserialize_vec_of_self(data: &[u8]) -> ::anyhow::Result<Vec<Self>> {
                if data.len() % $size != 0 {
                    ::anyhow::bail!(
                        "Data length {} is not a multiple of object size {}",
                        data.len(),
                        $size
                    );
                }
                // `pod_collect_to_vec` is the canonical way to safely convert `&[u8]` to
                // `Vec<Pod>`. It handles potential memory alignment issues by copying
                // the data if and only if the source slice is not already suitably
                // aligned for `Self`.
                Ok(bytemuck::pod_collect_to_vec(data))
            }

            /// Deserializes a `Vec<u8>` into a `Vec<Self>`, performing a zero-copy cast
            /// if memory is aligned, otherwise falling back to a copy.
            #[inline(always)]
            fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> ::anyhow::Result<Vec<Self>> {
                if data.len() % $size != 0 {
                    ::anyhow::bail!(
                        "Data length {} is not a multiple of object size {}",
                        data.len(),
                        $size
                    );
                }

                // Check if the alignment of the `Vec<u8>` buffer is sufficient for `Self`.
                // If it is, we can perform a zero-copy conversion. Otherwise, we must copy.
                if data.as_ptr() as usize % ::std::mem::align_of::<Self>() == 0 {
                    // Alignment is correct, proceed with zero-copy.
                    let mut data = ::std::mem::ManuallyDrop::new(data);
                    let len = data.len() / $size;
                    let capacity = data.capacity() / $size;
                    let ptr = data.as_mut_ptr() as *mut Self;
                    // SAFETY: We checked length and alignment. The original Vec is not dropped.
                    // `Self` is `Pod`, so any correctly-sized byte pattern is valid.
                    Ok(unsafe { Vec::from_raw_parts(ptr, len, capacity) })
                } else {
                    // Alignment is incorrect, fall back to a safe, copying deserialization.
                    Ok(bytemuck::pod_collect_to_vec(&data))
                }
            }
        }
    };
}


/// Generates a comprehensive test suite for a `FastFixedSerializable` implementation
/// that uses `bytemuck`.
///
/// This macro should be called after `impl_bytemuck_ffs` and will verify the
/// correctness of the implementation, including single-item and vector roundtrips,
/// error handling, and behavior with unaligned data.
///
/// # Pre-requisites
///
/// The tested struct MUST implement:
/// 1. `QPGenRandom` to generate test instances.
/// 2. `PartialEq` and `Clone` to compare results.
///
/// # Usage
///
/// ```rust,ignore
/// impl_bytemuck_ffs_tests!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. The concrete types to use when creating an instance for testing.
///     //    These must match the order of the generic parameters.
///     { ConcreteField, ConcreteHash },
///     // 3. The compile-time constant size of the struct in bytes.
///     128
/// );
/// ```
///
/// To use `crate::utils::QPGenRandom` instead of `parth_core::utils::QPGenRandom`,
/// add `, true` at the end:
///
/// ```rust,ignore
/// impl_bytemuck_ffs_tests!(MyStruct, { ConcreteField, ConcreteHash }, 128, true);
/// ```
#[macro_export]
macro_rules! impl_bytemuck_ffs_tests {
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal $(,)?
    ) => {
        $crate::impl_bytemuck_ffs_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $size,
            parth_core::utils::QPGenRandom
        );
    };
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal,
        true
    ) => {
        $crate::impl_bytemuck_ffs_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $size,
            crate::utils::QPGenRandom
        );
    };
    (@gen
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal,
        $qp_gen_path:path
    ) => {
        #[cfg(all(test, target_endian = "little", feature = "serialize_bytemuck"))]
        mod ffs_tests {
            use super::*;
            use psy_serialize::FastFixedSerializable;
            use $qp_gen_path;

            const SIZE_OF_ITEM: usize = $size;
            type ItemForTesting = $struct_name<$($concrete_type),*>;

            fn gen_item_vec(count: usize) -> Vec<ItemForTesting> {
                let mut base = Vec::with_capacity(count);
                for _ in 0..count {
                    base.push(ItemForTesting::qp_rand_gen());
                }
                base
            }
            #[test]
            fn test_ffs_serialization_fuzz_many_v0() {
                let many = gen_item_vec(100_000);
                let original = many.clone();
                let start_time = ::std::time::Instant::now();
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(many);
                let deserialized = ItemForTesting::ffs_deserialize_vec_of_self(&bytes).unwrap();
                let duration = start_time.elapsed();
                println!("Serialized and deserialized 100_000 in {:?}", duration);
                assert_eq!(original.len(), deserialized.len());
                for (o, d) in original.iter().zip(deserialized.iter()) {
                    assert_eq!(o, d);
                }
            }

            fn gen_single_item() -> ItemForTesting {
                ItemForTesting::qp_rand_gen()
            }

            // --- Single Item Serialization Tests ---

            #[test]
            fn test_ffs_to_bytes_and_from_slice() {
                let original = gen_single_item();
                let bytes_arr = original.ffs_to_bytes();
                let deserialized = ItemForTesting::ffs_from_slice_or_panic(&bytes_arr);
                assert_eq!(original, deserialized);
            }

            #[test]
            fn test_ffs_into_bytes_and_from_owned_bytes() {
                let original = gen_single_item();
                let bytes_arr = original.ffs_into_bytes();
                let deserialized = ItemForTesting::ffs_from_owned_bytes(bytes_arr);
                assert_eq!(original, deserialized);
            }

            #[test]
            fn test_ffs_try_from_slice_valid() {
                let original = gen_single_item();
                let bytes = original.ffs_to_bytes();
                let result = ItemForTesting::ffs_try_from_slice(&bytes);
                assert!(result.is_ok());
                assert_eq!(original, result.unwrap());
            }

            // --- Error Condition Tests for Single Items ---

            #[test]
            fn test_ffs_try_from_slice_invalid_length() {
                // Test with a slice that is too short
                let short_data = vec![0u8;  SIZE_OF_ITEM - 1];
                let result = ItemForTesting::ffs_try_from_slice(&short_data);
                assert!(result.is_err(), "Should fail with slice too short");

                // Test with a slice that is too long
                let long_data = vec![0u8;  SIZE_OF_ITEM + 1];
                let result = ItemForTesting::ffs_try_from_slice(&long_data);
                assert!(result.is_err(), "Should fail with slice too long");
            }

            #[test]
            #[should_panic]
            fn test_ffs_from_slice_or_panic_with_invalid_length() {
                let short_data = vec![0u8; 10];
                // This should panic because the length is incorrect
                ItemForTesting::ffs_from_slice_or_panic(&short_data);
            }

            // --- Vector Serialization/Deserialization Tests ---

            #[test]
            fn test_deserialization_of_unaligned_data() {
                const N: usize =  SIZE_OF_ITEM;
                let original_vec: Vec<_> = gen_item_vec(10);

                // Create a perfectly valid byte representation of our vector.
                let valid_bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&original_vec);
                assert_eq!(valid_bytes.len(), 10 * N);

                // Now, create a larger buffer and copy the valid bytes into it at an
                // offset of 1, guaranteeing the sub-slice is unaligned for any type
                // with alignment > 1 (which ItemForTesting likely has).
                let mut unaligned_buffer = vec![0u8; valid_bytes.len() + 1];
                unaligned_buffer[1..].copy_from_slice(&valid_bytes);

                // Create the unaligned slice. Direct casting would fail on this.
                let unaligned_slice = &unaligned_buffer[1..];
                assert_eq!(unaligned_slice.len(), valid_bytes.len());

                // 1. Test ffs_deserialize_vec_of_self with the unaligned slice.
                // This should succeed by using the copying fallback.
                let result_from_slice = ItemForTesting::ffs_deserialize_vec_of_self(unaligned_slice);
                assert!(result_from_slice.is_ok(), "Deserializing from unaligned slice should succeed");
                assert_eq!(original_vec, result_from_slice.unwrap());

                // 2. Test ffs_deserialize_vec_of_self_owned with an unaligned Vec.
                // This simulates passing an owned Vec<u8> with an unaligned buffer.
                let unaligned_owned_vec = unaligned_slice.to_vec();

                let result_from_owned = ItemForTesting::ffs_deserialize_vec_of_self_owned(unaligned_owned_vec);
                assert!(result_from_owned.is_ok(), "Deserializing from unaligned owned vec should succeed");
                assert_eq!(original_vec, result_from_owned.unwrap());
            }

            #[test]
            fn test_vec_serialization_deserialization_roundtrip() {
                let original_vec = gen_item_vec(69);

                // Test `ffs_serialize_vec_of_self` (takes ownership)
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(original_vec.clone());

                // Test `ffs_deserialize_vec_of_self` (takes a slice)
                let deserialized_vec_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes);

                assert!(deserialized_vec_result.is_ok());
                assert_eq!(original_vec, deserialized_vec_result.unwrap());
            }

            #[test]
            fn test_vec_ref_serialization_deserialization_roundtrip() {
                let original_vec = gen_item_vec(1337);

                // Test `ffs_serialize_vec_of_self_ref` (takes a slice)
                let bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&original_vec);

                // Test `ffs_deserialize_vec_of_self_owned` (takes ownership)
                let deserialized_vec_result = ItemForTesting::ffs_deserialize_vec_of_self_owned(bytes);

                assert!(deserialized_vec_result.is_ok());
                assert_eq!(original_vec, deserialized_vec_result.unwrap());
            }

            // --- Error Condition and Edge Case Tests for Vectors ---

            #[test]
            fn test_deserialize_vec_with_invalid_length() {
                let valid_bytes = ItemForTesting::ffs_serialize_vec_of_self(gen_item_vec(2));

                // Create a byte vector with a length that's not a multiple of the object size
                let mut invalid_bytes = valid_bytes;
                invalid_bytes.push(0xAB); // Add an extra byte

                let result = ItemForTesting::ffs_deserialize_vec_of_self(&invalid_bytes);
                assert!(result.is_err(), "Deserialization should fail for data with incorrect length");
            }

            #[test]
            fn test_empty_vec_serialization_roundtrip() {
                let empty_vec: Vec<ItemForTesting> = Vec::new();

                // Serialize empty vector (ref)
                let bytes_ref = ItemForTesting::ffs_serialize_vec_of_self_ref(&empty_vec);
                assert!(bytes_ref.is_empty());

                // Serialize empty vector (owned)
                let bytes_owned = ItemForTesting::ffs_serialize_vec_of_self(empty_vec.clone());
                assert!(bytes_owned.is_empty());

                // Deserialize back from empty byte slice
                let deserialized_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes_ref);
                assert!(deserialized_result.is_ok());
                assert!(deserialized_result.unwrap().is_empty());
            }

            #[test]
            fn test_single_element_vec_serialization_roundtrip() {
                let single_element_vec = gen_item_vec(1);

                let bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&single_element_vec);
                assert_eq!(bytes.len(),  SIZE_OF_ITEM);

                let deserialized_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes);
                assert!(deserialized_result.is_ok());
                assert_eq!(single_element_vec, deserialized_result.unwrap());
            }

            // --- Fuzz and Performance Test ---

            #[test]
            fn test_ffs_serialization_fuzz_many() {
                let many = gen_item_vec(1_000);
                let original = many.clone();

                let start_time = ::std::time::Instant::now();

                // Serialize using the bytemuck-optimized method
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(many);
                // Deserialize using the bytemuck-optimized method
                let deserialized = ItemForTesting::ffs_deserialize_vec_of_self(&bytes).unwrap();

                let duration = start_time.elapsed();
                println!(
                    "Optimized bytemuck S/D of 1,000 {} took: {:?}",
                    stringify!($struct_name),
                    duration
                );

                // Verify correctness
                assert_eq!(original.len(), deserialized.len());
                assert_eq!(original, deserialized, "The deserialized vector must be identical to the original");
            }
        }
    };
}

/// Generates a basic test suite for types implementing `psy-serialize`'s canonical traits.
///
/// This macro creates a nested test module structure: `tests_psy_ser::<module_base_name>`.
/// This approach does not require any external crates like `paste`.
///
/// # Pre-requisites
///
/// The tested struct MUST implement:
/// 1.  `parth_core::utils::QPGenRandom` (or `crate::utils::QPGenRandom`).
/// 2.  `PartialEq` to compare results.
/// 3.  The relevant `psy-serialize` traits.
///
/// # Usage
///
/// ### Basic Usage
///
/// This will generate a module `my_struct` inside a parent module `tests_psy_ser`.
///
/// ```rust,ignore
/// impl_psy_ser_basic_tests!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. The concrete types for testing (e.g., { ConcreteField, ConcreteHash }).
///     //    Use `{}` for non-generic types.
///     { ConcreteField, ConcreteHash },
///     // 3. The base name for the inner test module.
///     my_struct
/// );
/// ```
#[macro_export]
macro_rules! impl_psy_ser_basic_tests_fallback {
    // Arm 1: Default, uses `parth_core::utils::QPGenRandom`.
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident $(,)?
    ) => {
        $crate::impl_psy_ser_basic_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $module_base_name,
            parth_core::utils::QPGenRandom
        );
    };

    // Arm 2: For local testing, uses `crate::utils::QPGenRandom`.
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident,
        true
    ) => {
        $crate::impl_psy_ser_basic_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $module_base_name,
            crate::utils::QPGenRandom
        );
    };

    // Arm 3: The internal generator arm.
    // It creates a nested module structure to achieve the desired naming.
    (@gen
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident,
        $qp_gen_path:path
    ) => {
        #[cfg(test)]
            mod $module_base_name {
                // The struct is now two levels up, so we use `super::super::`.
                use super::$struct_name;
                use $qp_gen_path;
                use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

                type PsySerTestTargetType = $struct_name<$($concrete_type),*>;

                #[test]
                fn test_simple_round_trip() -> anyhow::Result<()> {
                    let value = PsySerTestTargetType::qp_rand_gen();
                    let serialized = value.psy_ser_to_bytes_vec()?;
                    let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
                    let deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(serialized.clone())?;

                    assert!(value == deserialized, "Round trip serialization failed");
                    assert!(value == deserialized_owned, "Round trip owned serialization failed");

                    let serialized_owned = value.psy_ser_into_bytes_vec()?;
                    assert_eq!(serialized, serialized_owned, "Owned and non-owned serialization differ");

                    let fallback_serialized = value.fallback_psy_ser_to_bytes_vec()?;
                    assert_eq!(serialized, fallback_serialized, "Fallback and non-fallback serialization differ");

                    let fallback_deserialized = PsySerTestTargetType::fallback_psy_ser_from_slice(&fallback_serialized)?;
                    assert!(value == fallback_deserialized, "Fallback round trip serialization failed");

                    let fallback_deserialized_owned = PsySerTestTargetType::fallback_psy_ser_from_owned_bytes_vec(fallback_serialized.clone())?;
                    assert!(value == fallback_deserialized_owned, "Fallback round trip owned serialization failed");

                    Ok(())
                }

                #[test]
                fn fuzz_10000_round_trips() -> anyhow::Result<()> {
                    for _ in 0..10_000 {
                        let value = PsySerTestTargetType::qp_rand_gen();
                        let serialized = value.psy_ser_to_bytes_vec()?;
                        let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
                        assert!(value == deserialized, "Round trip serialization failed on fuzz test");
                    }
                    Ok(())
                }

                #[test]
                fn test_simple_vec_round_trip() -> anyhow::Result<()> {
                    let values = PsySerTestTargetType::qp_rand_gen_vec(10);
                    let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                    let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                    assert!(values == deserialized, "Vector round trip serialization failed");
                    Ok(())
                }

                #[test]
                fn fuzz_1000_non_empty_vec_round_trips() -> anyhow::Result<()> {
                    for _ in 0..1_000 {
                        let count = (rand::random::<usize>() % 255) + 1;
                        let values = PsySerTestTargetType::qp_rand_gen_vec(count);
                        let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                        let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                        assert!(values == deserialized, "Fuzz vector round trip serialization failed");
                    }
                    Ok(())
                }

                #[test]
                fn test_empty_vec_round_trip() -> anyhow::Result<()> {
                    let values: Vec<PsySerTestTargetType> = vec![];
                    let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                    let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                    assert!(values == deserialized, "Empty vector round trip serialization failed");
                    Ok(())
                }
            }
    };
}


/// Generates a basic test suite for types implementing `psy-serialize`'s canonical traits.
///
/// This macro creates a nested test module structure: `tests_psy_ser::<module_base_name>`.
/// This approach does not require any external crates like `paste`.
///
/// # Pre-requisites
///
/// The tested struct MUST implement:
/// 1.  `parth_core::utils::QPGenRandom` (or `crate::utils::QPGenRandom`).
/// 2.  `PartialEq` to compare results.
/// 3.  The relevant `psy-serialize` traits.
///
/// # Usage
///
/// ### Basic Usage
///
/// This will generate a module `my_struct` inside a parent module `tests_psy_ser`.
///
/// ```rust,ignore
/// impl_psy_ser_basic_tests!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. The concrete types for testing (e.g., { ConcreteField, ConcreteHash }).
///     //    Use `{}` for non-generic types.
///     { ConcreteField, ConcreteHash },
///     // 3. The base name for the inner test module.
///     my_struct
/// );
/// ```
#[macro_export]
macro_rules! impl_psy_ser_basic_tests {
    // Arm 1: Default, uses `parth_core::utils::QPGenRandom`.
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident $(,)?
    ) => {
        $crate::impl_psy_ser_basic_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $module_base_name,
            parth_core::utils::QPGenRandom
        );
    };

    // Arm 2: For local testing, uses `crate::utils::QPGenRandom`.
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident,
        true
    ) => {
        $crate::impl_psy_ser_basic_tests!(@gen
            $struct_name,
            { $($concrete_type),* },
            $module_base_name,
            crate::utils::QPGenRandom
        );
    };

    // Arm 3: The internal generator arm.
    // It creates a nested module structure to achieve the desired naming.
    (@gen
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $module_base_name:ident,
        $qp_gen_path:path
    ) => {
        #[cfg(test)]
            mod $module_base_name {
                // The struct is now two levels up, so we use `super::super::`.
                use super::$struct_name;
                use $qp_gen_path;
                use psy_serialize::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};

                type PsySerTestTargetType = $struct_name<$($concrete_type),*>;

                #[test]
                fn test_simple_round_trip() -> anyhow::Result<()> {
                    let value = PsySerTestTargetType::qp_rand_gen();
                    let serialized = value.psy_ser_to_bytes_vec()?;
                    let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
                    let deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(serialized.clone())?;

                    assert!(value == deserialized, "Round trip serialization failed");
                    assert!(value == deserialized_owned, "Round trip owned serialization failed");

                    let serialized_owned = value.psy_ser_into_bytes_vec()?;
                    assert_eq!(serialized, serialized_owned, "Owned and non-owned serialization differ");


                    Ok(())
                }

                #[test]
                fn fuzz_10000_round_trips() -> anyhow::Result<()> {
                    for _ in 0..10_000 {
                        let value = PsySerTestTargetType::qp_rand_gen();
                        let serialized = value.psy_ser_to_bytes_vec()?;
                        let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
                        assert!(value == deserialized, "Round trip serialization failed on fuzz test");
                    }
                    Ok(())
                }

                #[test]
                fn test_simple_vec_round_trip() -> anyhow::Result<()> {
                    let values = PsySerTestTargetType::qp_rand_gen_vec(10);
                    let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                    let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                    assert!(values == deserialized, "Vector round trip serialization failed");
                    Ok(())
                }

                #[test]
                fn fuzz_100_non_empty_vec_round_trips() -> anyhow::Result<()> {
                    for _ in 0..100 {
                        let count = (rand::random::<usize>() % 255) + 1;
                        let values = PsySerTestTargetType::qp_rand_gen_vec(count);
                        let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                        let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                        assert!(values == deserialized, "Fuzz vector round trip serialization failed");
                    }
                    Ok(())
                }

                #[test]
                fn test_empty_vec_round_trip() -> anyhow::Result<()> {
                    let values: Vec<PsySerTestTargetType> = vec![];
                    let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
                    let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;

                    assert!(values == deserialized, "Empty vector round trip serialization failed");
                    Ok(())
                }
            }
    };
}

/// Generates a test suite for types implementing `FastFixedSerializable`.
///
/// This macro creates a unique test module name for each invocation by appending
/// the snake_cased struct name, e.g., `ffs_tests_my_struct_name`.
///
/// # Pre-requisites
///
/// This macro requires the `paste` crate in `dev-dependencies`.

/// Generates a comprehensive test suite for a `FastFixedSerializable` implementation
/// that uses `bytemuck`.
///
/// This macro should be called after `impl_bytemuck_ffs` and will verify the
/// correctness of the implementation, including single-item and vector roundtrips,
/// error handling, and behavior with unaligned data.
///
/// # Pre-requisites
///
/// The tested struct MUST implement:
/// 1. `QPGenRandom` to generate test instances.
/// 2. `PartialEq` and `Clone` to compare results.
///
/// # Usage
///
/// ```rust,ignore
/// impl_bytemuck_ffs_tests!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. The concrete types to use when creating an instance for testing.
///     //    These must match the order of the generic parameters.
///     { ConcreteField, ConcreteHash },
///     // 3. The compile-time constant size of the struct in bytes.
///     128
/// );
/// ```
///
/// To use `crate::utils::QPGenRandom` instead of `parth_core::utils::QPGenRandom`,
/// add `, true` at the end:
///
/// ```rust,ignore
/// impl_bytemuck_ffs_tests!(MyStruct, { ConcreteField, ConcreteHash }, 128, true);
/// ```
#[macro_export]
macro_rules! impl_bytemuck_ffs_tests_rn {
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal $(,)?
    ) => {
        $crate::impl_bytemuck_ffs_tests_rn!(@gen
            $struct_name,
            { $($concrete_type),* },
            $size,
            parth_core::utils::QPGenRandom
        );
    };
    (
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal,
        true
    ) => {
        $crate::impl_bytemuck_ffs_tests_rn!(@gen
            $struct_name,
            { $($concrete_type),* },
            $size,
            crate::utils::QPGenRandom
        );
    };
    (@gen
        $struct_name:ident,
        { $($concrete_type:ty),* },
        $size:literal,
        $qp_gen_path:path
    ) => {
        #[cfg(all(test, target_endian = "little", feature = "serialize_bytemuck"))]
        // Use the `paste` crate to create a unique module name.
        // e.g., for `TagTreeStorageNode`, this generates `mod ffs_tests_tag_tree_storage_node { ... }`
        paste::paste! {
            #[cfg(test)]
            mod [<ffs_tests_ $struct_name:snake>] {

            use super::*;
            use psy_serialize::FastFixedSerializable;
            use $qp_gen_path;

            const SIZE_OF_ITEM: usize = $size;
            type ItemForTesting = $struct_name<$($concrete_type),*>;

            fn gen_item_vec(count: usize) -> Vec<ItemForTesting> {
                let mut base = Vec::with_capacity(count);
                for _ in 0..count {
                    base.push(ItemForTesting::qp_rand_gen());
                }
                base
            }
            #[test]
            fn test_ffs_serialization_fuzz_many_v0() {
                let many = gen_item_vec(100_000);
                let original = many.clone();
                let start_time = ::std::time::Instant::now();
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(many);
                let deserialized = ItemForTesting::ffs_deserialize_vec_of_self(&bytes).unwrap();
                let duration = start_time.elapsed();
                println!("Serialized and deserialized 100_000 in {:?}", duration);
                assert_eq!(original.len(), deserialized.len());
                for (o, d) in original.iter().zip(deserialized.iter()) {
                    assert_eq!(o, d);
                }
            }

            fn gen_single_item() -> ItemForTesting {
                ItemForTesting::qp_rand_gen()
            }

            // --- Single Item Serialization Tests ---

            #[test]
            fn test_ffs_to_bytes_and_from_slice() {
                let original = gen_single_item();
                let bytes_arr = original.ffs_to_bytes();
                let deserialized = ItemForTesting::ffs_from_slice_or_panic(&bytes_arr);
                assert_eq!(original, deserialized);
            }

            #[test]
            fn test_ffs_into_bytes_and_from_owned_bytes() {
                let original = gen_single_item();
                let bytes_arr = original.ffs_into_bytes();
                let deserialized = ItemForTesting::ffs_from_owned_bytes(bytes_arr);
                assert_eq!(original, deserialized);
            }

            #[test]
            fn test_ffs_try_from_slice_valid() {
                let original = gen_single_item();
                let bytes = original.ffs_to_bytes();
                let result = ItemForTesting::ffs_try_from_slice(&bytes);
                assert!(result.is_ok());
                assert_eq!(original, result.unwrap());
            }

            // --- Error Condition Tests for Single Items ---

            #[test]
            fn test_ffs_try_from_slice_invalid_length() {
                // Test with a slice that is too short
                let short_data = vec![0u8;  SIZE_OF_ITEM - 1];
                let result = ItemForTesting::ffs_try_from_slice(&short_data);
                assert!(result.is_err(), "Should fail with slice too short");

                // Test with a slice that is too long
                let long_data = vec![0u8;  SIZE_OF_ITEM + 1];
                let result = ItemForTesting::ffs_try_from_slice(&long_data);
                assert!(result.is_err(), "Should fail with slice too long");
            }

            #[test]
            #[should_panic]
            fn test_ffs_from_slice_or_panic_with_invalid_length() {
                let short_data = vec![0u8; 10];
                // This should panic because the length is incorrect
                ItemForTesting::ffs_from_slice_or_panic(&short_data);
            }

            // --- Vector Serialization/Deserialization Tests ---

            #[test]
            fn test_deserialization_of_unaligned_data() {
                const N: usize =  SIZE_OF_ITEM;
                let original_vec: Vec<_> = gen_item_vec(10);

                // Create a perfectly valid byte representation of our vector.
                let valid_bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&original_vec);
                assert_eq!(valid_bytes.len(), 10 * N);

                // Now, create a larger buffer and copy the valid bytes into it at an
                // offset of 1, guaranteeing the sub-slice is unaligned for any type
                // with alignment > 1 (which ItemForTesting likely has).
                let mut unaligned_buffer = vec![0u8; valid_bytes.len() + 1];
                unaligned_buffer[1..].copy_from_slice(&valid_bytes);

                // Create the unaligned slice. Direct casting would fail on this.
                let unaligned_slice = &unaligned_buffer[1..];
                assert_eq!(unaligned_slice.len(), valid_bytes.len());

                // 1. Test ffs_deserialize_vec_of_self with the unaligned slice.
                // This should succeed by using the copying fallback.
                let result_from_slice = ItemForTesting::ffs_deserialize_vec_of_self(unaligned_slice);
                assert!(result_from_slice.is_ok(), "Deserializing from unaligned slice should succeed");
                assert_eq!(original_vec, result_from_slice.unwrap());

                // 2. Test ffs_deserialize_vec_of_self_owned with an unaligned Vec.
                // This simulates passing an owned Vec<u8> with an unaligned buffer.
                let unaligned_owned_vec = unaligned_slice.to_vec();

                let result_from_owned = ItemForTesting::ffs_deserialize_vec_of_self_owned(unaligned_owned_vec);
                assert!(result_from_owned.is_ok(), "Deserializing from unaligned owned vec should succeed");
                assert_eq!(original_vec, result_from_owned.unwrap());
            }

            #[test]
            fn test_vec_serialization_deserialization_roundtrip() {
                let original_vec = gen_item_vec(69);

                // Test `ffs_serialize_vec_of_self` (takes ownership)
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(original_vec.clone());

                // Test `ffs_deserialize_vec_of_self` (takes a slice)
                let deserialized_vec_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes);

                assert!(deserialized_vec_result.is_ok());
                assert_eq!(original_vec, deserialized_vec_result.unwrap());
            }

            #[test]
            fn test_vec_ref_serialization_deserialization_roundtrip() {
                let original_vec = gen_item_vec(1337);

                // Test `ffs_serialize_vec_of_self_ref` (takes a slice)
                let bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&original_vec);

                // Test `ffs_deserialize_vec_of_self_owned` (takes ownership)
                let deserialized_vec_result = ItemForTesting::ffs_deserialize_vec_of_self_owned(bytes);

                assert!(deserialized_vec_result.is_ok());
                assert_eq!(original_vec, deserialized_vec_result.unwrap());
            }

            // --- Error Condition and Edge Case Tests for Vectors ---

            #[test]
            fn test_deserialize_vec_with_invalid_length() {
                let valid_bytes = ItemForTesting::ffs_serialize_vec_of_self(gen_item_vec(2));

                // Create a byte vector with a length that's not a multiple of the object size
                let mut invalid_bytes = valid_bytes;
                invalid_bytes.push(0xAB); // Add an extra byte

                let result = ItemForTesting::ffs_deserialize_vec_of_self(&invalid_bytes);
                assert!(result.is_err(), "Deserialization should fail for data with incorrect length");
            }

            #[test]
            fn test_empty_vec_serialization_roundtrip() {
                let empty_vec: Vec<ItemForTesting> = Vec::new();

                // Serialize empty vector (ref)
                let bytes_ref = ItemForTesting::ffs_serialize_vec_of_self_ref(&empty_vec);
                assert!(bytes_ref.is_empty());

                // Serialize empty vector (owned)
                let bytes_owned = ItemForTesting::ffs_serialize_vec_of_self(empty_vec.clone());
                assert!(bytes_owned.is_empty());

                // Deserialize back from empty byte slice
                let deserialized_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes_ref);
                assert!(deserialized_result.is_ok());
                assert!(deserialized_result.unwrap().is_empty());
            }

            #[test]
            fn test_single_element_vec_serialization_roundtrip() {
                let single_element_vec = gen_item_vec(1);

                let bytes = ItemForTesting::ffs_serialize_vec_of_self_ref(&single_element_vec);
                assert_eq!(bytes.len(),  SIZE_OF_ITEM);

                let deserialized_result = ItemForTesting::ffs_deserialize_vec_of_self(&bytes);
                assert!(deserialized_result.is_ok());
                assert_eq!(single_element_vec, deserialized_result.unwrap());
            }

            // --- Fuzz and Performance Test ---

            #[test]
            fn test_ffs_serialization_fuzz_many() {
                let many = gen_item_vec(1_000);
                let original = many.clone();

                let start_time = ::std::time::Instant::now();

                // Serialize using the bytemuck-optimized method
                let bytes = ItemForTesting::ffs_serialize_vec_of_self(many);
                // Deserialize using the bytemuck-optimized method
                let deserialized = ItemForTesting::ffs_deserialize_vec_of_self(&bytes).unwrap();

                let duration = start_time.elapsed();
                println!(
                    "Optimized bytemuck S/D of 1,000 {} took: {:?}",
                    stringify!($struct_name),
                    duration
                );

                // Verify correctness
                assert_eq!(original.len(), deserialized.len());
                assert_eq!(original, deserialized, "The deserialized vector must be identical to the original");
            }
                    
            }
        }
    };
}

/// A comprehensive macro to implement fast, fixed-size, zero-copy serialization
/// for a `#[repr(C)]` struct.
///
/// This macro is a convenient bundle that generates:
/// 1. `bytemuck::Pod` and `bytemuck::Zeroable` trait implementations.
/// 2. The `psy_serialize::FastFixedSerializable` implementation using `bytemuck`.
/// 3. A test suite for the `FastFixedSerializable` implementation.
/// 4. `PsyCanonicalSerializeMetadata` to declare the type as fixed-size.
/// 5. `AutoDatabaseSerializationUseFastFixedSerialize` to enable optimizations.
/// 6. Implementations for the canonical `psy-serialize` traits that delegate to the
///    high-performance `ffs_` methods.
/// 7. A compile-time check to ensure the provided size constant matches the
///    actual implementation size.
///
/// # Usage
///
/// ```rust,ignore
/// impl_ffs_psy_serialize_fixed_size!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. Generics definition: { Bounds } => { Names }.
///     { F: Trait1, H: Trait2 } => { F, H },
///     // 3. The compile-time constant size of the struct in bytes.
///     128,
///     // 4. Concrete types for use in tests and compile-time checks.
///     { ConcreteF, ConcreteH },
///     // 5. The name of an existing `const` variable that holds the expected size.
///     //    This is used for a compile-time assertion.
///     MY_STRUCT_EXPECTED_SIZE
/// );
/// ```
#[macro_export]
macro_rules! impl_ffs_psy_serialize_fixed_size {
    (
        $struct_name:ident,
        { $( $generic_param:ident: $trait_bound:path ),* } => { $( $generic_name:ident ),* },
        $size:literal,
        { $( $concrete_type:ty ),* },
        $size_check_const:ident
    ) => {
        // Step 1: Implement Pod and Zeroable, which are prerequisites for bytemuck.
        // Assumes the crate alias `pser` exists or these macros are in the current crate.
        pser::impl_bytemuck_pod_and_zeroable!($struct_name, $( $generic_name ),*);

        // Step 2: Implement the high-performance FastFixedSerializable trait.
        pser::impl_bytemuck_ffs!(
            $struct_name,
            { $( $generic_param: $trait_bound ),* },
            $size
        );

        // Step 3: Generate a test suite for the FFS implementation.
        pser::impl_bytemuck_ffs_tests!(
            $struct_name,
            { $( $concrete_type ),* },
            $size
        );

        // Step 4: Implement metadata traits to inform the serialization system
        // that this type is fixed-size and can use the fast path.
        impl<$( $generic_param: $trait_bound ),*> psy_serialize::PsyCanonicalSerializeMetadata for $struct_name<$($generic_name),*> {
            const IS_FIXED_SIZE: bool = true;
            const FIXED_SIZE: usize = $size;
        }
        impl<$( $generic_param: $trait_bound + Copy),*> psy_serialize::AutoDatabaseSerializationUseFastFixedSerialize<$size> for $struct_name<$($generic_name),*> {}

        // Step 5: Implement the canonical serialization traits by delegating to the
        // fast fixed-size (`ffs_`) methods.
        psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
            $struct_name,
            { $( $generic_param: $trait_bound ),* } => { $( $generic_name ),* },
            $size
        );

        // Step 6: A compile-time check function. This function is never called,
        // but its body enforces that the type of `ffs_into_bytes()` (which is
        // `[u8; $size]`) matches the type `[u8; $size_check_const]`.
        // If `$size` and `$size_check_const` are not equal, this will fail to compile.
        #[allow(unused)]
        #[allow(non_snake_case)]
        fn _ensure_compile_time_size_match() {
            // This function uses a type annotation to enforce a compile-time size match.
            // `ffs_into_bytes()` returns `[u8; $size]`.
            // The variable is explicitly typed as `[u8; $size_check_const]`.
            // If the two constants differ, the Rust compiler will error due to a type mismatch.
            let _bytes_check: [u8; $size_check_const] =
                $struct_name::<$($concrete_type),*>::qp_rand_gen().ffs_into_bytes();
        }
    };
}


/// A comprehensive macro to implement fast, fixed-size, zero-copy serialization
/// for a `#[repr(C)]` struct.
///
/// This macro is a convenient bundle that generates:
/// 1. `bytemuck::Pod` and `bytemuck::Zeroable` trait implementations.
/// 2. The `psy_serialize::FastFixedSerializable` implementation using `bytemuck`.
/// 3. A test suite for the `FastFixedSerializable` implementation.
/// 4. `PsyCanonicalSerializeMetadata` to declare the type as fixed-size.
/// 5. `AutoDatabaseSerializationUseFastFixedSerialize` to enable optimizations.
/// 6. Implementations for the canonical `psy-serialize` traits that delegate to the
///    high-performance `ffs_` methods.
/// 7. A compile-time check to ensure the provided size constant matches the
///    actual implementation size.
///
/// # Usage
///
/// ```rust,ignore
/// impl_ffs_psy_serialize_fixed_size!(
///     // 1. The name of the struct.
///     MyStruct,
///     // 2. Generics definition: { Bounds } => { Names }.
///     { F: Trait1, H: Trait2 } => { F, H },
///     // 3. The compile-time constant size of the struct in bytes.
///     128,
///     // 4. Concrete types for use in tests and compile-time checks.
///     { ConcreteF, ConcreteH },
///     // 5. The name of an existing `const` variable that holds the expected size.
///     //    This is used for a compile-time assertion.
///     MY_STRUCT_EXPECTED_SIZE
/// );
/// ```
#[macro_export]
macro_rules! impl_ffs_psy_serialize_fixed_size_pc {
    (
        $struct_name:ident,
        { $( $generic_param:ident: $trait_bound:path ),* } => { $( $generic_name:ident ),* },
        $size:literal,
        { $( $concrete_type:ty ),* },
        $size_check_const:ident
    ) => {
        // Step 1: Implement Pod and Zeroable, which are prerequisites for bytemuck.
        // Assumes the crate alias `pser` exists or these macros are in the current crate.
        pser::impl_bytemuck_pod_and_zeroable!($struct_name, $( $generic_name ),*);

        // Step 2: Implement the high-performance FastFixedSerializable trait.
        pser::impl_bytemuck_ffs!(
            $struct_name,
            { $( $generic_param: $trait_bound ),* },
            $size
        );

        // Step 3: Generate a test suite for the FFS implementation.
        pser::impl_bytemuck_ffs_tests_rn!(
            $struct_name,
            { $( $concrete_type ),* },
            $size,
            true
        );

        // Step 4: Implement metadata traits to inform the serialization system
        // that this type is fixed-size and can use the fast path.
        impl<$( $generic_param: $trait_bound ),*> psy_serialize::PsyCanonicalSerializeMetadata for $struct_name<$($generic_name),*> {
            const IS_FIXED_SIZE: bool = true;
            const FIXED_SIZE: usize = $size;
        }
        impl<$( $generic_param: $trait_bound + Copy),*> psy_serialize::AutoDatabaseSerializationUseFastFixedSerialize<$size> for $struct_name<$($generic_name),*> {}

        // Step 5: Implement the canonical serialization traits by delegating to the
        // fast fixed-size (`ffs_`) methods.
        psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
            $struct_name,
            { $( $generic_param: $trait_bound ),* } => { $( $generic_name ),* },
            $size
        );

        // Step 6: A compile-time check function. This function is never called,
        // but its body enforces that the type of `ffs_into_bytes()` (which is
        // `[u8; $size]`) matches the type `[u8; $size_check_const]`.
        // If `$size` and `$size_check_const` are not equal, this will fail to compile.
        /*#[allow(unused)]
        #[allow(non_snake_case)]
        fn _ensure_compile_time_size_match() {
            use psy_serialize::FastFixedSerializable;
            // This function uses a type annotation to enforce a compile-time size match.
            // `ffs_into_bytes()` returns `[u8; $size]`.
            // The variable is explicitly typed as `[u8; $size_check_const]`.
            // If the two constants differ, the Rust compiler will error due to a type mismatch.
            let _bytes_check: [u8; $size_check_const] =
                $struct_name::<$($concrete_type),*>::qp_rand_gen().ffs_into_bytes();
        }*/
    };
}


