use parth_core::{protocol::core_types::Q256BitHash, utils::QPGenRandom, QJobIdSerialized};
use psy_data::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA;
use parth_core::QJOB_ID_SERIALIZED_SIZE;
use psy_serialize::FastFixedSerializable;



#[pderive::serialize_copy]
#[repr(C)]
pub struct PsyNodeUserUpdateMetaData<Hash> {
    pub job_id: QJobIdSerialized,
    pub user_id: u64,
    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub checkpoint_tree_root_hash: Hash,
    pub checkpoint_tree_root_checkpoint_id: u64,
}
impl<Hash> PsyNodeUserUpdateMetaData<Hash> {
    pub fn new(
        job_id: QJobIdSerialized,
        user_id: u64,
        start_user_leaf_hash: Hash,
        end_user_leaf_hash: Hash,
        checkpoint_tree_root_hash: Hash,
        checkpoint_tree_root_checkpoint_id: u64,
    ) -> Self {
        Self {
            job_id,
            user_id,
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            checkpoint_tree_root_checkpoint_id,
        }
    }
    pub fn read_user_id_from_fixed_bytes(data: &[u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA]) -> u64 {
        u64::from_le_bytes(data[24..32].try_into().unwrap())
    }
    pub fn read_user_id_from_bytes_ref(bytes: &[u8]) -> anyhow::Result<u64> {
        if bytes.len() != PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA {
            anyhow::bail!("Invalid number of bytes for PsyNodeUserUpdateMetaData");
        }
        Ok(u64::from_le_bytes(bytes[24..32].try_into().unwrap()))
    }
}
impl<Hash: QPGenRandom> QPGenRandom for PsyNodeUserUpdateMetaData<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            job_id: QJobIdSerialized::qp_rand_gen(),
            user_id: u64::qp_rand_gen(),
            start_user_leaf_hash: Hash::qp_rand_gen(),
            end_user_leaf_hash: Hash::qp_rand_gen(),
            checkpoint_tree_root_hash: Hash::qp_rand_gen(),
            checkpoint_tree_root_checkpoint_id: u64::qp_rand_gen(),
        }
    }
}


// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA matches the FFS implementation
fn _ensure_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA] = PsyNodeUserUpdateMetaData::<parth_core::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA] = PsyNodeUserUpdateMetaData::<parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
    let _job_id_dummy: [u8; QJOB_ID_SERIALIZED_SIZE] = [0u8; 24];
}

pser::impl_bytemuck_ffs_tests!(
    PsyNodeUserUpdateMetaData,
    // Note the use of concrete types here
    { parth_core::PHash },
    136
);


pser::impl_bytemuck_pod_and_zeroable!(PsyNodeUserUpdateMetaData, Hash);

pser::impl_bytemuck_ffs!(
    PsyNodeUserUpdateMetaData,
    { Hash: Q256BitHash },
    136
);

// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<Hash: Q256BitHash> FastFixedSerializable<136> for PsyNodeUserUpdateMetaData<Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA]) -> Self {
/*

    pub job_id: QJobIdSerialized,
    pub user_id: u64,
    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub checkpoint_tree_root_hash: Hash,
    pub checkpoint_tree_root_checkpoint_id: u64,
     */
        let job_id: [u8; 24] = data[0..QJOB_ID_SERIALIZED_SIZE].try_into().unwrap();
        let user_id = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[96..128].try_into().unwrap());
        let checkpoint_tree_root_checkpoint_id = u64::from_le_bytes(data[128..136].try_into().unwrap());
        
        Self {
            job_id,
            user_id,
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            checkpoint_tree_root_checkpoint_id,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA {
            panic!("Invalid number of bytes for PQEDContractLeaf");
        }
        let job_id: [u8; 24] = data[0..QJOB_ID_SERIALIZED_SIZE].try_into().unwrap();
        let user_id = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[96..128].try_into().unwrap());
        let checkpoint_tree_root_checkpoint_id = u64::from_le_bytes(data[128..136].try_into().unwrap());
        
        Self {
            job_id,
            user_id,
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            checkpoint_tree_root_checkpoint_id,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA {
            anyhow::bail!("Invalid number of bytes for PUPSEndCapResultCompact");
        }

        let job_id: [u8; 24] = data[0..QJOB_ID_SERIALIZED_SIZE].try_into().unwrap();
        let user_id = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let start_user_leaf_hash = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let end_user_leaf_hash = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let checkpoint_tree_root_hash = Hash::from_ref_32bytes(&data[96..128].try_into().unwrap());
        let checkpoint_tree_root_checkpoint_id = u64::from_le_bytes(data[128..136].try_into().unwrap());
        
        Ok(Self {
            job_id,
            user_id,
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            checkpoint_tree_root_checkpoint_id,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA];
        bytes[0..QJOB_ID_SERIALIZED_SIZE].copy_from_slice(&self.job_id);
        bytes[24..32].copy_from_slice(&self.user_id.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.start_user_leaf_hash.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.end_user_leaf_hash.into_owned_32bytes());
        bytes[96..128].copy_from_slice(&self.checkpoint_tree_root_hash.into_owned_32bytes());
        bytes[128..136].copy_from_slice(&self.checkpoint_tree_root_checkpoint_id.to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA];
        bytes[0..QJOB_ID_SERIALIZED_SIZE].copy_from_slice(&self.job_id);
        bytes[24..32].copy_from_slice(&self.user_id.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.start_user_leaf_hash.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.end_user_leaf_hash.into_owned_32bytes());
        bytes[96..128].copy_from_slice(&self.checkpoint_tree_root_hash.into_owned_32bytes());
        bytes[128..136].copy_from_slice(&self.checkpoint_tree_root_checkpoint_id.to_le_bytes());
        bytes
    }
}
