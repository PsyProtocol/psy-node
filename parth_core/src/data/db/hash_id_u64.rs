use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

use crate::{data::hash::hash256::Hash256, protocol::core_types::Q256BitHash, utils::QPGenRandom};

pub const PSY_OBJECT_FFS_SIZE_HASH_256_AND_U64: usize = 40;

#[pderive::serialize_copy]
#[repr(C)]
pub struct QHash256AndU64<Hash> {
    pub hash: Hash,
    pub value_u64: u64,
}
impl<Hash :QPGenRandom> QPGenRandom for QHash256AndU64<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            hash: Hash::qp_rand_gen(),
            value_u64: u64::qp_rand_gen(),
        }
    }
}


impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QHash256AndU64<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 40;
}

//impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<40> for QHash256AndU64<Hash> {}

pser::impl_bytemuck_pod_and_zeroable!(QHash256AndU64, Hash);

impl<Hash: Q256BitHash> FastFixedSerializable<40> for QHash256AndU64<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 40]) -> Self {
        Self {
            hash: Hash::from_owned_32bytes(data[0..32].try_into().unwrap()),
            value_u64: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 40 {
            panic!("expected 40 bytes for QHash256AndU64, got {} bytes", data.len());
        }
        Self {
            hash: Hash::from_slice_32bytes(&data[0..32]).expect("data should be 40 bytes long!"),
            value_u64: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 40 {
            anyhow::bail!("invalid length for QHash256AndU64, expected 40 bytes, got {}",data.len());
        }
        Ok(Self {
            hash: Hash::from_slice_32bytes(&data[0..32])?,
            value_u64: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 40] {
        let mut data: [u8; 40] = [0u8; 40];
        data[0..32].copy_from_slice(&self.hash.into_owned_32bytes());
        data[32..40].copy_from_slice(&self.value_u64.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 40] {
        let mut data: [u8; 40] = [0u8; 40];
        data[0..32].copy_from_slice(&self.hash.into_owned_32bytes());
        data[32..40].copy_from_slice(&self.value_u64.to_le_bytes());
        data
    }
}
pser::impl_bytemuck_ffs_tests!(QHash256AndU64, { crate::PHash }, 40, true);

impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<40> for QHash256AndU64<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    QHash256AndU64,
    {Hash: Q256BitHash} => {Hash},
    40
);


// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match_key() {
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_HASH_256_AND_U64] = QHash256AndU64::<crate::PHash>::qp_rand_gen().ffs_into_bytes();
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_HASH_256_AND_U64] = QHash256AndU64::<Hash256>::qp_rand_gen().ffs_into_bytes();
}

pub fn get_data_buffer_for_hash256_and_u64s<Hash: Q256BitHash>(items: &[QHash256AndU64<Hash>]) -> Vec<u8> {
    let mut result = Vec::with_capacity(items.len()*40);
    for item in items {
        result.extend_from_slice(&item.hash.into_owned_32bytes());
        result.extend_from_slice(&item.value_u64.to_le_bytes());
    }
    result

}
pub fn read_hash256_ref_and_i64_from_buffer(buffer: &[u8]) -> anyhow::Result<(&[u8], i64)>{
    if buffer.len() < 40 {
        anyhow::bail!("expected 40 bytes for a QHash256AndU64, got {}",buffer.len());
    }
    Ok((&buffer[0..32], i64::from_le_bytes(buffer[32..40].try_into().unwrap(),)))
}



pub fn read_hash256_refs_and_i64s_from_buffer(buffer: &[u8]) -> anyhow::Result<Vec<(&[u8], i64)>>{
    
    if buffer.len() % 40 != 0 {
        anyhow::bail!("expected 40 bytes for a QHash256AndU64, got {}",buffer.len());
    }
    let count = buffer.len() / 40;
    let mut results = Vec::with_capacity(count);
    for i in 0..count {
        results.push((&buffer[i*40..i*40+32], i64::from_le_bytes(buffer[i*40+32..i*40+40].try_into().unwrap())));
    }
    
    Ok(results)
}