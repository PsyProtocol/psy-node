use kvq::traits::{KVQSerializable, ScyllaKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StagingCheckpointKey<const TABLE_TYPE: u16> {
    pub uuid: u128,
    pub checkpoint_id: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for StagingCheckpointKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let uuid_be_bytes = self.uuid.to_be_bytes();
        let checkpoint_id_be_bytes = self.checkpoint_id.to_be_bytes();
        Ok(vec![
            (TABLE_TYPE >> 8) as u8,
            (TABLE_TYPE & 0xff) as u8,
            checkpoint_id_be_bytes[0],
            checkpoint_id_be_bytes[1],
            checkpoint_id_be_bytes[2],
            checkpoint_id_be_bytes[3],
            checkpoint_id_be_bytes[4],
            checkpoint_id_be_bytes[5],
            checkpoint_id_be_bytes[6],
            checkpoint_id_be_bytes[7],
            uuid_be_bytes[0],
            uuid_be_bytes[1],
            uuid_be_bytes[2],
            uuid_be_bytes[3],
            uuid_be_bytes[4],
            uuid_be_bytes[5],
            uuid_be_bytes[6],
            uuid_be_bytes[7],
            uuid_be_bytes[8],
            uuid_be_bytes[9],
            uuid_be_bytes[10],
            uuid_be_bytes[11],
            uuid_be_bytes[12],
            uuid_be_bytes[13],
            uuid_be_bytes[14],
            uuid_be_bytes[15],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 26 {
            anyhow::bail!("expected 26 bytes for deserializing StagingCheckpointKey, got {} bytes", bytes.len());
        }
        let mut checkpoint_id_be_bytes = [0u8; 8];
        checkpoint_id_be_bytes.copy_from_slice(&bytes[2..10]);
        let checkpoint_id = u64::from_be_bytes(checkpoint_id_be_bytes);

        let mut uuid_be_bytes = [0u8; 16];
        uuid_be_bytes.copy_from_slice(&bytes[10..26]);
        let uuid = u128::from_be_bytes(uuid_be_bytes);

        Ok(StagingCheckpointKey { uuid, checkpoint_id })
    }
}

impl<const TABLE_TYPE: u16> StagingCheckpointKey<TABLE_TYPE> {
    pub fn new(uuid: u128, checkpoint_id: u64) -> Self {
        StagingCheckpointKey { uuid, checkpoint_id }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for StagingCheckpointKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        TABLE_TYPE.to_be_bytes().to_vec()
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
