#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use std::fmt::Debug;

use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::serializable::{QPDSerializable},
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
     impl_qpd_serialize_params,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
    utils::QPGenRandom,
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

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
impl<F: Default, Hash: Default> Default for PQEDContractLeaf<F, Hash> {
    fn default() -> Self {
        PQEDContractLeaf {
            deployer: Hash::default(),
            function_tree_root: Hash::default(),
            state_tree_height: F::default(),
        }
    }
}

impl_qpd_serialize_params!(
    PQEDContractLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
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

pser::impl_bytemuck_ffs!(
    PQEDContractLeaf,
    { F: QFelt64, Hash: Q256BitHash },
    72
);

pser::impl_bytemuck_ffs_tests!(
    PQEDContractLeaf,
    // Note the use of concrete types here
    { parth_core::PF, parth_core::PHash },
    72
);


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDContractLeaf<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 72;
}
impl<F: QFelt64, Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<72> for PQEDContractLeaf<F, Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    PQEDContractLeaf, 
    {F: QFelt64, Hash: Q256BitHash} => {F, Hash}, 
    72
);


// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] = PQEDContractLeaf::<u64, parth_core::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] = PQEDContractLeaf::<parth_core::PF, parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
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

pser::impl_psy_ser_basic_tests!(
    PQEDContractLeaf,
    // Note the use of concrete types here
    { parth_core::PF, parth_core::PHash },
    qed_contract_leaf_tests
);