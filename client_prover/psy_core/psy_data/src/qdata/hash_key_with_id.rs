use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

use super::hash_key::Hash4x64Key;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash4x64KeyWithId<const TABLE_TYPE: u16> {
    pub hash: Hash4x64Key<TABLE_TYPE>,
    pub id: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for Hash4x64KeyWithId<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(42);
        result.push((TABLE_TYPE >> 8) as u8);
        result.push((TABLE_TYPE & 0xff) as u8);
        result.extend_from_slice(&u64::to_be_bytes(self.hash.elements[0]));
        result.extend_from_slice(&u64::to_be_bytes(self.hash.elements[1]));
        result.extend_from_slice(&u64::to_be_bytes(self.hash.elements[2]));
        result.extend_from_slice(&u64::to_be_bytes(self.hash.elements[3]));
        result.extend_from_slice(&u64::to_be_bytes(self.id));
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 42 {
            anyhow::bail!("expected 42 bytes for deserializing Hash4x64KeyWithId, got {} bytes", bytes.len());
        }

        let elements_0 = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let elements_1 = u64::from_be_bytes(bytes[10..18].try_into().unwrap());
        let elements_2 = u64::from_be_bytes(bytes[18..26].try_into().unwrap());
        let elements_3 = u64::from_be_bytes(bytes[26..34].try_into().unwrap());
        let id = u64::from_be_bytes(bytes[34..42].try_into().unwrap());

        Ok(Self {
            hash: Hash4x64Key {
                elements: [elements_0, elements_1, elements_2, elements_3],
            },
            id,
        })
    }
}
impl<const TABLE_TYPE: u16> Hash4x64KeyWithId<TABLE_TYPE> {
    pub fn new<H: Into<Hash4x64Key<TABLE_TYPE>>>(hash: H, id: u64) -> Self {
        Self { hash: hash.into(), id }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for Hash4x64KeyWithId<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(40);
        for element in &self.hash.elements {
            result.extend_from_slice(&element.to_be_bytes());
        }
        result.extend_from_slice(&self.id.to_be_bytes());
        result
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
