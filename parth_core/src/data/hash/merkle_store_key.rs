use serde::{Deserialize, Serialize};

use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};



#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Ord, Eq, Debug, Serialize, Deserialize)]
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
pub struct QMerkleStoreKeyNoCheckpoint {
    pub tree_type: u16, // 2
    pub tree_id: u64, // 10
    pub level: u8, // 11
    pub index: u64, // 19
}
impl QPDSerializable for QMerkleStoreKeyNoCheckpoint {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 19] = [0u8; 19];
        data[0..2].copy_from_slice(&self.tree_type.to_le_bytes());
        data[2..10].copy_from_slice(&self.tree_id.to_le_bytes());
        data[10] = self.level;

        data[11..19].copy_from_slice(&self.index.to_be_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 19 {
            anyhow::bail!("invalid length for QMerkleStoreKeyNoCheckpoint, expected 19 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_type: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            tree_id: u64::from_le_bytes(bytes[2..10].try_into().unwrap()),
            level: bytes[10],
            index: u64::from_be_bytes(bytes[11..19].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreKeyNoCheckpoint {
    fn get_fixed_size() -> usize {
        19
    }
}



