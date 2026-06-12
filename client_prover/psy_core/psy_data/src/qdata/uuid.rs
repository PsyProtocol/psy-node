use std::str::FromStr;

use kvq::traits::KVQSerializable;
use serde::{Deserialize, Serialize};

use crate::qdata::checkpoint_id_key::CheckpointTableIdKey;

pub type ContractUUID = CheckpointUUID;
pub type RegisterUserUUID = CheckpointUUID;
pub type TxHash = CheckpointUUID;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CheckpointUUID {
    pub checkpoint_id: u64,
    pub uuid: u64,
}

impl FromStr for CheckpointUUID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Self::from_bytes(&bytes)
    }
}

impl ToString for CheckpointUUID {
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes().unwrap())
    }
}

impl<const TABLE_TYPE: u16> Into<CheckpointTableIdKey<TABLE_TYPE>> for CheckpointUUID {
    fn into(self) -> CheckpointTableIdKey<TABLE_TYPE> {
        CheckpointTableIdKey::new(self.checkpoint_id, self.uuid)
    }
}

impl KVQSerializable for CheckpointUUID {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let checkpoint_id_be_bytes = self.checkpoint_id.to_be_bytes();
        let uuid_be_bytes = self.uuid.to_be_bytes();
        Ok(vec![
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
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 16 {
            anyhow::bail!("expected 16 bytes for deserializing CheckpointUUID, got {} bytes", bytes.len());
        }
        let checkpoint_id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let uuid = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        Ok(CheckpointUUID { checkpoint_id, uuid })
    }
}
