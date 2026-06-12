use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CheckpointTableIdKey<const TABLE_TYPE: u16> {
    pub id: u64,
    pub checkpoint_id: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for CheckpointTableIdKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let id_be_bytes = self.id.to_be_bytes();
        let checkpoint_id_be_bytes = self.checkpoint_id.to_be_bytes();
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
        if bytes.len() != 18 {
            anyhow::bail!("expected 18 bytes for deserializing DepositKeyByDepositIdCore, got {} bytes", bytes.len());
        }
        let mut id_be_bytes = [0u8; 8];
        id_be_bytes.copy_from_slice(&bytes[2..10]);
        let id = u64::from_be_bytes(id_be_bytes);

        let mut checkpoint_id_be_bytes = [0u8; 8];
        checkpoint_id_be_bytes.copy_from_slice(&bytes[10..18]);
        let checkpoint_id = u64::from_be_bytes(checkpoint_id_be_bytes);

        Ok(CheckpointTableIdKey { id, checkpoint_id })
    }
}
impl<const TABLE_TYPE: u16> CheckpointTableIdKey<TABLE_TYPE> {
    pub fn new(checkpoint_id: u64, id: u64) -> Self {
        CheckpointTableIdKey { id, checkpoint_id }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for CheckpointTableIdKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        Some(self.checkpoint_id.to_be_bytes().to_vec())
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
