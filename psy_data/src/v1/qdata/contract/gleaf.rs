#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use core::fmt;
#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use std::fmt::Debug;

use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::serializable::{FastFixedSerializable, QPDSerializable},
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
    impl_psyser_for_ffs_with_params, impl_qpd_serialize_params,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
    utils::QPGenRandom,
};
use pser::{QBytesDeserialize, QBytesSerialize};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;

//#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDContractLeaf")]
#[repr(C)]
pub struct PQEDContractLeaf<F, Hash> {
    pub deployer: Hash,
    pub function_tree_root: Hash,
    pub state_tree_height: F,
}

pser::impl_bytemuck_pod_and_zeroable!(PQEDContractLeaf, F, Hash);

impl_qpd_serialize_params!(
    PQEDContractLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDContractLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        9
    }

    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDContractLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let deployer = self.deployer.to_4_felts();
        let function_tree_root = self.function_tree_root.to_4_felts();

        vec![
            deployer[0],
            deployer[1],
            deployer[2],
            deployer[3],
            function_tree_root[0],
            function_tree_root[1],
            function_tree_root[2],
            function_tree_root[3],
            self.state_tree_height,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 9 {
            panic!("Invalid number of elements for QEDContractLeaf");
        }
        let deployer = Hash::from_4_felts_slice(&felts[0..4]);
        let function_tree_root = Hash::from_4_felts_slice(&felts[4..8]);
        let state_tree_height = felts[8];
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PQEDContractLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let deployer = self.deployer.to_4_felts();
        let function_tree_root = self.function_tree_root.to_4_felts();

        H::q_hash_many(&[
            deployer[0],
            deployer[1],
            deployer[2],
            deployer[3],
            function_tree_root[0],
            function_tree_root[1],
            function_tree_root[2],
            function_tree_root[3],
            self.state_tree_height,
        ])
    }
}

// --- ZERO-COPY FastFixedSerializable IMPLEMENTATION ---
// We replace the entire intermediate-struct-and-copy mechanism with direct
// casts. This is safe because of #[repr(C)] and the unsafe `Pod` impl above.
#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        bytemuck::try_from_bytes(data)
            .map(|&s| s)
            .map_err(|e| anyhow::anyhow!("Failed to cast slice to PQEDContractLeaf: {}", e))
    }

    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        bytemuck::cast(data)
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        *bytemuck::from_bytes(data)
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        bytemuck::cast(*self)
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
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
        let mut data = std::mem::ManuallyDrop::new(data);
        let len = data.len() * PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;
        let capacity = data.capacity() * PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;
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
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF != 0 {
            anyhow::bail!(
                "Data length {} is not a multiple of object size {}",
                data.len(),
                PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF
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
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        if data.len() % PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF != 0 {
            anyhow::bail!(
                "Data length {} is not a multiple of object size {}",
                data.len(),
                PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF
            );
        }

        // Check if the alignment of the `Vec<u8>` buffer is sufficient for `Self`.
        // If it is, we can perform a zero-copy conversion. Otherwise, we must copy.
        if data.as_ptr() as usize % std::mem::align_of::<Self>() == 0 {
            // Alignment is correct, proceed with zero-copy.
            let mut data = std::mem::ManuallyDrop::new(data);
            let len = data.len() / PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;
            let capacity = data.capacity() / PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;
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

impl_psyser_for_ffs_with_params!(
    PQEDContractLeaf,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash },
    72
);

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDContractLeaf<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PQEDContractLeaf {
            deployer: Hash::qp_rand_gen(),
            function_tree_root: Hash::qp_rand_gen(),
            state_tree_height: F::qp_rand_gen(),
        }
    }
}

// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            panic!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            anyhow::bail!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        Ok(PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{PHash, PF};

    use super::*;

    const SIZE_OF_ITEM: usize = 72;
    type ItemForTesting = PQEDContractLeaf<PF, PHash>;
    
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
        let start_time = std::time::Instant::now();
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
        // with alignment > 1 (which ItemForTesting has).
        let mut unaligned_buffer = vec![0u8; valid_bytes.len() + 1];
        unaligned_buffer[1..].copy_from_slice(&valid_bytes);

        // Create the unaligned slice. Direct casting would fail on this.
        let unaligned_slice = &unaligned_buffer[1..];
        assert_eq!(unaligned_slice.len(), valid_bytes.len());

        // 1. Test ffs_deserialize_vec_of_self with the unaligned slice.
        // This should now succeed by using the copying fallback.
        let result_from_slice = ItemForTesting::ffs_deserialize_vec_of_self(unaligned_slice);
        assert!(result_from_slice.is_ok(), "Deserializing from unaligned slice should succeed");
        assert_eq!(original_vec, result_from_slice.unwrap());

        // 2. Test ffs_deserialize_vec_of_self_owned with an unaligned Vec.
        // Note: Creating an owned Vec<u8> with a guaranteed unaligned buffer is tricky,
        // as the allocator might re-align it. Slicing is the most reliable way to test
        // this. However, we can simulate the scenario by passing an unaligned
        // slice's owned data.
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

    // --- Fuzz and Performance Test (Adapted from original) ---

    #[test]
    fn test_ffs_serialization_fuzz_many() {
        let many = gen_item_vec(1_000);
        let original = many.clone();

        let start_time = std::time::Instant::now();

        // Serialize using the bytemuck-optimized method
        let bytes = ItemForTesting::ffs_serialize_vec_of_self(many);
        // Deserialize using the bytemuck-optimized method
        let deserialized = ItemForTesting::ffs_deserialize_vec_of_self(&bytes).unwrap();

        let duration = start_time.elapsed();
        println!(
            "Optimized bytemuck serialization and deserialization of 1,000 ItemForTesting took: {:?}",
            duration
        );

        // Verify correctness
        assert_eq!(original.len(), deserialized.len());
        assert_eq!(original, deserialized, "The deserialized vector must be identical to the original");
    }
}
