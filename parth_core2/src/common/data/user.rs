use serde::{Deserialize, Serialize};

use crate::{common::{data::core::{hash::hash256::Hash256, secp256k1::QPSecp256K1CompressedPublicKey}, traits::serializable::QPDSerializable}, crypto::hash::sha256::CoreSha256Hasher, impl_qpq_serialize_bincode};


// Gets data for a user as it was at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPUserDataRecord {
    pub user_id: u64,
    pub checkpoint_id: u64, // the checkpoint id that this data was finalized in (the last checkpoint the user submitted data before max_checkpoint_id)
    // the above is not the same as last SUBMITTED checkpoint id, as the submission may have failed
    pub public_key: QPSecp256K1CompressedPublicKey,
    pub data_hash: Hash256,
}


impl_qpq_serialize_bincode!(QPUserDataRecord);

impl QPUserDataRecord {
    pub fn new(user_id: u64, data_hash: Hash256, public_key: QPSecp256K1CompressedPublicKey, checkpoint_id: u64) -> Self {
        Self {
            user_id,
            data_hash,
            public_key,
            checkpoint_id,
        }
    }
    pub fn get_user_leaf_hash(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(8 + 8 + 33 + 32);
        bytes.extend_from_slice(&self.user_id.to_le_bytes());
        bytes.extend_from_slice(&self.checkpoint_id.to_le_bytes());
        bytes.extend_from_slice(&self.public_key.0);
        bytes.extend_from_slice(&self.data_hash.0);
        CoreSha256Hasher::hash_bytes(&bytes)
    }
}



