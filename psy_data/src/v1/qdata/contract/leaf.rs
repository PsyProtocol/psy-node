#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use core::fmt;
#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use std::fmt::Debug;

use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, data::serializable::{FastFixedSerializable, QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized, ToQFelts}, impl_psyser_for_ffs_with_params, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}, utils::QPGenRandom};
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


// --- Unsafe `bytemuck` implementations to enable zero-copy casting ---
// This tells the compiler that PQEDContractLeaf is "Plain Old Data" and can be
// safely cast from/to bytes, provided its generic fields (F and Hash) are also Pod.
#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F, Hash> bytemuck::Zeroable for PQEDContractLeaf<F, Hash>
where
    F: bytemuck::Zeroable,
    Hash: bytemuck::Zeroable,
{
}

#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F, Hash> bytemuck::Pod for PQEDContractLeaf<F, Hash>
where
    F: bytemuck::Pod,
    Hash: bytemuck::Pod,
{
}


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
/*
impl<F: QFelt64, Hash: Q256BitHash>  FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
*/


// --- ZERO-COPY FastFixedSerializable IMPLEMENTATION ---
// We replace the entire intermediate-struct-and-copy mechanism with direct casts.
// This is safe because of #[repr(C)] and the unsafe `Pod` impl above.
//#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]

#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        bytemuck::cast(data)
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        *bytemuck::from_bytes(data)
    }


    #[inline(always)]
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        //bytemuck::cast_vec(data)
        let byte_slice: &[u8] = bytemuck::cast_slice::<Self, u8>(&data);
        byte_slice.to_vec()

    }
    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        // bytemuck checks both length and alignment
        bytemuck::try_from_bytes(data)
            .map(|&s| s)
            .map_err(|e| anyhow::anyhow!("Failed to cast slice to PQEDContractLeaf: {}", e))
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        bytemuck::cast(*self)
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        bytemuck::cast(self)
    }
}


impl_psyser_for_ffs_with_params!(
    PQEDContractLeaf, 
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash },
    72
);

impl<F: QFelt64 + QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDContractLeaf<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        PQEDContractLeaf {
            deployer: Hash::qp_rand_gen(),
            function_tree_root: Hash::qp_rand_gen(),
            state_tree_height: F::qp_rand_gen(),
        }
    }
}



// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<F: QFelt64, Hash: Q256BitHash>  FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
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
    use super::*;
    use parth_core::{PF, PHash};

    fn gen_contract_leaves(count: usize) -> Vec<PQEDContractLeaf<PF, PHash>> {
        let mut base = Vec::with_capacity(count);
        for _ in 0..count {
            base.push(PQEDContractLeaf {
                deployer: PHash::qp_rand_gen(),
                function_tree_root: PHash::qp_rand_gen(),
                state_tree_height: PF::qp_rand_gen(),
            });
        }
        base
    }
    #[test]
    fn test_ffs_serialization() {
        let original = PQEDContractLeaf::<PF, PHash> {
            deployer: PHash::qp_rand_gen(),
            function_tree_root: PHash::qp_rand_gen(),
            state_tree_height: PF::qp_rand_gen(),
        };

        let bytes = original.ffs_into_bytes();
        let deserialized = PQEDContractLeaf::<PF, PHash>::ffs_from_owned_bytes(bytes);

        assert_eq!(original.deployer, deserialized.deployer);
        assert_eq!(original.function_tree_root, deserialized.function_tree_root);
        assert_eq!(original.state_tree_height, deserialized.state_tree_height);
    }


    #[test]
    fn test_ffs_serialization_fuzz_many() {

        let many = gen_contract_leaves(1_000_000);
        let original = many.clone();
        let start_time = std::time::Instant::now();
        let bytes = PQEDContractLeaf::ffs_serialize_vec_of_self(many);
        let deserialized = PQEDContractLeaf::<PF, PHash>::ffs_deserialize_vec_of_self(&bytes).unwrap();
        let duration = start_time.elapsed();
        println!("Serialized and deserialized 1_000_000 PQEDContractLeaf in {:?}", duration);
        assert_eq!(original.len(), deserialized.len());
        for (o, d) in original.iter().zip(deserialized.iter()) {
            assert_eq!(o.deployer, d.deployer);
            assert_eq!(o.function_tree_root, d.function_tree_root);
            assert_eq!(o.state_tree_height, d.state_tree_height);
        }
    }
}