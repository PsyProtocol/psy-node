use kvq::traits::KVQSerializable;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct StagingCheckpointInfo {
    pub local_checkpoint_id: u64,
    pub canonical_checkpoint_id: u64,
}

impl KVQSerializable for StagingCheckpointInfo {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl StagingCheckpointInfo {
    pub fn new(local_checkpoint_id: u64, canonical_checkpoint_id: u64) -> Self {
        Self {
            local_checkpoint_id,
            canonical_checkpoint_id,
        }
    }
}
