use kvq::traits::KVQSerializable;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum PsyHashHelperHashType {
    Unknown = 0,
    CheckpointTreeRoot = 1,
    CheckpointTreeLeafHash = 2,
}
impl PsyHashHelperHashType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<PsyHashHelperHashType> for u8 {
    fn from(value: PsyHashHelperHashType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for PsyHashHelperHashType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PsyHashHelperHashType::Unknown),
            1 => Ok(PsyHashHelperHashType::CheckpointTreeRoot),
            2 => Ok(PsyHashHelperHashType::CheckpointTreeLeafHash),
            _ => Err(anyhow::format_err!("Invalid PsyHashHelperHashType value: {}", value)),
        }
    }
}

impl ToString for PsyHashHelperHashType {
    fn to_string(&self) -> String {
        match *self {
            PsyHashHelperHashType::Unknown => "Unknown".to_string(),
            PsyHashHelperHashType::CheckpointTreeRoot => "CheckpointTreeRoot".to_string(),
            PsyHashHelperHashType::CheckpointTreeLeafHash => "CheckpointTreeLeafHash".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PsyHashHelperResult {
    pub hash_type: PsyHashHelperHashType,
    pub checkpoint_id: u64,
    pub target_id: u64,
}

impl KVQSerializable for PsyHashHelperResult {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(17);
        result.push(self.hash_type.to_u8());
        result.extend_from_slice(&u64::to_be_bytes(self.checkpoint_id));
        result.extend_from_slice(&u64::to_be_bytes(self.target_id));
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 17 {
            anyhow::bail!("expected 17 bytes for deserializing PsyHashHelperResult, got {} bytes", bytes.len());
        }
        let hash_type = PsyHashHelperHashType::try_from(bytes[0])?;
        let checkpoint_id = u64::from_be_bytes(bytes[1..9].try_into()?);
        let target_id = u64::from_be_bytes(bytes[9..17].try_into()?);
        Ok(Self {
            hash_type,
            checkpoint_id,
            target_id,
        })
    }
}
impl PsyHashHelperResult {
    pub fn new(hash_type: PsyHashHelperHashType, checkpoint_id: u64, target_id: u64) -> Self {
        Self {
            hash_type,
            checkpoint_id,
            target_id,
        }
    }
    pub fn new_checkpoint_tree_root_hash(checkpoint_id: u64) -> Self {
        Self {
            hash_type: PsyHashHelperHashType::CheckpointTreeRoot,
            checkpoint_id,
            target_id: checkpoint_id,
        }
    }
    pub fn new_checkpoint_leaf_hash(checkpoint_id: u64) -> Self {
        Self {
            hash_type: PsyHashHelperHashType::CheckpointTreeLeafHash,
            checkpoint_id,
            target_id: checkpoint_id,
        }
    }
}
