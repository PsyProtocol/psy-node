use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventTableIdKey<const TABLE_TYPE: u16> {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub event_index: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for EventTableIdKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let checkpoint_id_be_bytes = self.checkpoint_id.to_be_bytes();
        let user_id_be_bytes = self.user_id.to_be_bytes();
        let event_index_be_bytes = self.event_index.to_be_bytes();
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            user_id_be_bytes[0],
            user_id_be_bytes[1],
            user_id_be_bytes[2],
            user_id_be_bytes[3],
            user_id_be_bytes[4],
            user_id_be_bytes[5],
            user_id_be_bytes[6],
            user_id_be_bytes[7],
            event_index_be_bytes[0],
            event_index_be_bytes[1],
            event_index_be_bytes[2],
            event_index_be_bytes[3],
            event_index_be_bytes[4],
            event_index_be_bytes[5],
            event_index_be_bytes[6],
            event_index_be_bytes[7],
            checkpoint_id_be_bytes[0],
            checkpoint_id_be_bytes[1],
            checkpoint_id_be_bytes[2],
            checkpoint_id_be_bytes[3],
            checkpoint_id_be_bytes[4],
            checkpoint_id_be_bytes[5],
            checkpoint_id_be_bytes[6],
            checkpoint_id_be_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 26 {
            anyhow::bail!("expected 26 bytes for deserializing EventTableIdKey, got {} bytes", bytes.len());
        }

        let mut user_id_be_bytes = [0u8; 8];
        user_id_be_bytes.copy_from_slice(&bytes[2..10]);
        let user_id = u64::from_be_bytes(user_id_be_bytes);
        let mut event_index_be_bytes = [0u8; 8];
        event_index_be_bytes.copy_from_slice(&bytes[10..18]);
        let event_index = u64::from_be_bytes(event_index_be_bytes);
        let mut checkpoint_id_be_bytes = [0u8; 8];
        checkpoint_id_be_bytes.copy_from_slice(&bytes[18..26]);
        let checkpoint_id = u64::from_be_bytes(checkpoint_id_be_bytes);

        Ok(EventTableIdKey {
            checkpoint_id,
            user_id,
            event_index,
        })
    }
}
impl<const TABLE_TYPE: u16> EventTableIdKey<TABLE_TYPE> {
    pub fn new(checkpoint_id: u64, user_id: u64, event_index: u64) -> Self {
        EventTableIdKey {
            checkpoint_id,
            user_id,
            event_index,
        }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for EventTableIdKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        self.user_id
            .to_be_bytes()
            .iter()
            .chain(self.event_index.to_be_bytes().iter())
            .cloned()
            .collect()
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        Some(self.checkpoint_id.to_be_bytes().to_vec())
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
