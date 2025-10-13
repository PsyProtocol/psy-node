use rkyv::validation::archive;

use crate::{data::serializable::{QPDSerializable, QPDSerializableFixed}, utils::QPGenRandom};



#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdKey {
    pub tree_id: u64, // 8
    pub level: u8, // 9
    pub index: u64, // 17
}
impl QPDSerializable for QMerkleStoreSingleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            level: bytes[8],
            index: u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreSingleIdKey {
    fn get_fixed_size() -> usize {
        17
    }
}

impl QPGenRandom for QMerkleStoreSingleIdKey {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdNode<Hash> {
    pub key: QMerkleStoreSingleIdKey,
    pub hash: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreSingleIdNode<Hash> {
    
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            key: QMerkleStoreSingleIdKey::qp_rand_gen(),
            hash: QPGenRandom::qp_rand_gen(),
        }
    }
}



#[pderive::serialize_copy_default]
pub struct QMerkleDoubleIdStoreKey {
    pub tree_id: u64, // 8
    pub tree_sub_id: u64, // 16
    pub level: u8, // 17
    pub index: u64, // 25
}
impl QPDSerializable for QMerkleDoubleIdStoreKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 25 {
            anyhow::bail!("invalid length for QMerkleDoubleIdStoreKey, expected 25 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            level: bytes[16],
            index: u64::from_le_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleDoubleIdStoreKey {
    fn get_fixed_size() -> usize {
        25
    }
}





#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdNode<Hash> {
    pub key: QMerkleDoubleIdStoreKey,
    pub hash: Hash,
}

