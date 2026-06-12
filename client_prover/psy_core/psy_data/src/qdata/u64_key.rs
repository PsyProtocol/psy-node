use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct U64TableKey<const TABLE_TYPE: u16>(pub u64);

impl<const TABLE_TYPE: u16> KVQSerializable for U64TableKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let id_be_bytes = self.0.to_be_bytes();
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            id_be_bytes[0],
            id_be_bytes[1],
            id_be_bytes[2],
            id_be_bytes[3],
            id_be_bytes[4],
            id_be_bytes[5],
            id_be_bytes[6],
            id_be_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 10 {
            anyhow::bail!("expected 10 bytes for deserializing BlockStateKeyCore, got {} bytes", bytes.len());
        }
        Ok(U64TableKey(u64::from_be_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ])))
    }
}
impl<const TABLE_TYPE: u16> From<u64> for U64TableKey<TABLE_TYPE> {
    fn from(checkpoint_id: u64) -> Self {
        U64TableKey(checkpoint_id)
    }
}
impl<const TABLE_TYPE: u16> From<U64TableKey<TABLE_TYPE>> for u64 {
    fn from(key: U64TableKey<TABLE_TYPE>) -> Self {
        key.0
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for U64TableKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        // Use table_type as partition key so all entries of same type are in same
        // partition
        TABLE_TYPE.to_be_bytes().to_vec()
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        // Use checkpoint_id as clustering key for proper sorting
        Some(self.0.to_be_bytes().to_vec())
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
