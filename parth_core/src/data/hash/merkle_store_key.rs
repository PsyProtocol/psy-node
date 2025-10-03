use serde::{Deserialize, Serialize};

use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};



#[pderive::serialize_copy_default]
pub struct QMerkleStoreKey {
    pub tree_type: u16, // 2
    pub tree_id: u64, // 10
    pub level: u8, // 11
    pub index: u64, // 19
    pub checkpoint_id: u64, // 27
}
impl QPDSerializable for QMerkleStoreKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 27] = [0u8; 27];
        data[0..2].copy_from_slice(&self.tree_type.to_le_bytes());
        data[2..10].copy_from_slice(&self.tree_id.to_le_bytes());
        data[10] = self.level;

        data[11..19].copy_from_slice(&self.index.to_be_bytes());
        data[19..27].copy_from_slice(&self.checkpoint_id.to_be_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 27 {
            anyhow::bail!("invalid length for QMerkleStoreKey, expected 27 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_type: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            tree_id: u64::from_le_bytes(bytes[2..10].try_into().unwrap()),
            level: bytes[10],
            index: u64::from_be_bytes(bytes[11..19].try_into().unwrap()),
            checkpoint_id: u64::from_be_bytes(bytes[19..27].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreKey {
    fn get_fixed_size() -> usize {
        27
    }
}
#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Ord, Eq, Debug, Serialize, Deserialize)]
pub struct QMerkleStoreBlobKey {
    pub table_type: u32, // 4  
    pub tree_id: u64, // 12
    pub level: u8, // 13
    pub index: u64, // 21
}
impl QPDSerializable for QMerkleStoreBlobKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 21] = [0u8; 21];
        data[0..4].copy_from_slice(&self.table_type.to_le_bytes());
        data[4..12].copy_from_slice(&self.tree_id.to_le_bytes());
        data[12] = self.level;

        data[13..21].copy_from_slice(&self.index.to_be_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 21 {
            anyhow::bail!("invalid length for QMerkleStoreBlobKey, expected 21 bytes, got {}",bytes.len());
        }
        Ok(Self {
            table_type: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            tree_id: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            level: bytes[12],
            index: u64::from_be_bytes(bytes[13..21].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreBlobKey {
    fn get_fixed_size() -> usize {
        21
    }
}

#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Ord, Eq, Debug, Serialize, Deserialize)]
pub struct QMerkleDoubleIdStoreBlobKey {
    pub table_type: u32, // 4  
    pub tree_id: u64, // 12
    pub tree_sub_id: u64, // 20
    pub level: u8, // 21
    pub index: u64, // 29
}
impl QPDSerializable for QMerkleDoubleIdStoreBlobKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 29] = [0u8; 29];
        data[0..4].copy_from_slice(&self.table_type.to_le_bytes());
        data[4..12].copy_from_slice(&self.tree_id.to_le_bytes());
        data[12..20].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[20] = self.level;

        data[21..29].copy_from_slice(&self.index.to_be_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 29 {
            anyhow::bail!("invalid length for QMerkleDoubleIdStoreBlobKey, expected 29 bytes, got {}",bytes.len());
        }
        Ok(Self {
            table_type: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            tree_id: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            level: bytes[20],
            index: u64::from_be_bytes(bytes[21..29].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleDoubleIdStoreBlobKey {
    fn get_fixed_size() -> usize {
        29
    }
}



