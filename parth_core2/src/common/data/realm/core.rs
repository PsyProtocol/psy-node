use std::hash::Hash;

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{common::{data::{core::secp256k1::QPSecp256K1CompressedPublicKey, protocol::{core::UniqueCheckpointId, job::QPWorkerJobDataID}}, traits::serializable::QPDSerializable}, impl_qpq_serialize_bincode};


#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QPDataFormatType {
    Raw = 0,
    CompressedGzip = 1,
}
impl QPDataFormatType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<QPDataFormatType> for u8 {
    fn from(value: QPDataFormatType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for QPDataFormatType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QPDataFormatType::Raw),
            1 => Ok(QPDataFormatType::CompressedGzip),
            _ => Err(anyhow::format_err!("Invalid QPDataFormatType value: {}", value)),
        }
    }
}



// the unique key for storing a random number when a user submits the data to a realm to prevent double submissions in a block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeUserAtUniqueCheckpointKey {
    pub unique_checkpoint_id: UniqueCheckpointId, 
    pub user_id: u64,
}


impl_qpq_serialize_bincode!(RealmEdgeUserAtUniqueCheckpointKey);


// the unique key for storing a random number when a user submits the data to a realm to prevent double submissions in a block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeRegisterUserMessageForProcessor {

    pub user_id: u64,
    pub public_key: QPSecp256K1CompressedPublicKey,
    // helps tell us where the data is stored
    pub job_id: QPWorkerJobDataID,
}


impl_qpq_serialize_bincode!(RealmEdgeRegisterUserMessageForProcessor);


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeUpdateUserDataMessageForProcessor {
    pub user_id: u64,
    pub public_key: QPSecp256K1CompressedPublicKey,
    // helps tell us where the data is stored
    pub job_id: QPWorkerJobDataID,
}


impl_qpq_serialize_bincode!(RealmEdgeUpdateUserDataMessageForProcessor);





