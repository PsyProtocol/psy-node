use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{common::data::core::hash::hash256::Hash256, crypto::hash::sha256::CoreSha256Hasher};


#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QPSignatureActionType {
    None = 0,
    SignDataUpdate = 1,
}
impl QPSignatureActionType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<QPSignatureActionType> for u8 {
    fn from(value: QPSignatureActionType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for QPSignatureActionType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QPSignatureActionType::None),
            1 => Ok(QPSignatureActionType::SignDataUpdate),
            _ => Err(anyhow::format_err!("Invalid QPSignatureActionType value: {}", value)),
        }
    }
}


// Gets data for a user as it was at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPSignaturePreimage {
    pub action_type: QPSignatureActionType,
    pub user_id: u64,
    pub checkpoint_id: u64, // last checkpoint id the user submitted data before this signature was created
    pub new_data_hash: Hash256,
}


impl QPSignaturePreimage {
    pub fn to_signature_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 8 + 8 + 32);
        bytes.push(self.action_type.to_u8());
        bytes.extend_from_slice(&self.user_id.to_le_bytes());
        bytes.extend_from_slice(&self.checkpoint_id.to_le_bytes());
        bytes.extend_from_slice(&self.new_data_hash.0);
        bytes
    }
    pub fn to_signature_hash(&self) -> Hash256 {
        CoreSha256Hasher::hash_bytes(&self.to_signature_bytes())
    }
}