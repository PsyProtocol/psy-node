use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RealmTableIdKey<const TABLE_TYPE: u16> {
    pub realm_id: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for RealmTableIdKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let realm_id_be_bytes = self.realm_id.to_be_bytes();
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            realm_id_be_bytes[0],
            realm_id_be_bytes[1],
            realm_id_be_bytes[2],
            realm_id_be_bytes[3],
            realm_id_be_bytes[4],
            realm_id_be_bytes[5],
            realm_id_be_bytes[6],
            realm_id_be_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 10 {
            anyhow::bail!("expected 10 bytes for deserializing RealmTableIdKey, got {} bytes", bytes.len());
        }

        let realm_id = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        Ok(RealmTableIdKey { realm_id })
    }
}
impl<const TABLE_TYPE: u16> RealmTableIdKey<TABLE_TYPE> {
    pub fn new(realm_id: u64) -> Self {
        RealmTableIdKey { realm_id }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for RealmTableIdKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        self.realm_id.to_be_bytes().to_vec()
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
