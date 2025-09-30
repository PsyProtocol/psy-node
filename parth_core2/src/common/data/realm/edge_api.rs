use serde::{Deserialize, Serialize};

use crate::{common::{data::{core::{hash::hash256::Hash256, merkle::merkle_proof::MerkleProofCore, secp256k1::{QPSecp256K1CompressedPublicKey, QPSecp256K1Signature}}, realm::core::QPDataFormatType}, traits::serializable::QPDSerializable}, impl_qpq_serialize_bincode};

// Gets a Merkle Proof from the Global User Tree Root to the User's data leaf node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetUserMerkleProofRequest {
    pub user_id: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct RealmEdgeAPIGetUserMerkleProofResponse {
    pub merkle_proof: MerkleProofCore<Hash256>,
}


// Gets a Merkle Proof from the Global User Tree Root to the User's data leaf node at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetHistoricalUserMerkleProofRequest {
    pub user_id: u64,
    pub max_checkpoint_id: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct RealmEdgeAPIGetHistoricalUserMerkleProofResponse {
    pub merkle_proof: MerkleProofCore<Hash256>,
}



// Gets the current finalized checkpoint id
/* 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetLastFinalizedCheckpointIdRequest {
}
*/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetLastFinalizedCheckpointIdResponse {
    pub checkpoint_id: u64,
}


// Gets the realm id, last finalized checkpoint id and root hash for this realm
/* 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetRealmInfoRequest {
}
*/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetRealmInfoResponse {
    pub checkpoint_id: u64,
    pub realm_id: u64,
    pub root_hash: Hash256,
}






// Gets data for a user as it was at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetHistoricalUserDataRequest {
    pub user_id: u64,
    pub max_checkpoint_id: u64,
    pub format: QPDataFormatType,
}
// Gets data for a user as it was at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetLatestUserDataRequest {
    pub user_id: u64,
    pub format: QPDataFormatType,
}

// Gets data for a user as it was at a specific checkpoint or earlier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetUserDataResponse {
    pub user_id: u64,
    pub checkpoint_id: u64, // the checkpoint id that this data was set in (the last checkpoint the user submitted data before max_checkpoint_id)
    pub public_key: QPSecp256K1CompressedPublicKey,
    pub format: QPDataFormatType,
    pub user_data_hash: Hash256,
    pub user_leaf_hash: Hash256,
    pub data: Vec<u8>,
}



// Returns a users data with a merkle proof that links it to the checkpoint root
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIGetUserDataWithMerkleProofResponse {
    pub user_id: u64,
    pub checkpoint_id: u64, // the checkpoint id that this data was set in (the last checkpoint the user submitted data before max_checkpoint_id)
    pub public_key: QPSecp256K1CompressedPublicKey,
    pub format: QPDataFormatType,
    pub user_data_hash: Hash256,
    pub user_leaf_hash: Hash256,
    pub merkle_proof: MerkleProofCore<Hash256>,
    pub data: Vec<u8>,
}


// submit new user data for the realm 
/*
submits new data for the user, signed by the user's key
What the edge does:
1. Checks the cache to see if the user has already submitted data for the current shared unique checkpoint id (reads from STORE_CACHE_DB_ALL_EDGE_FOR_REALM)
2. Marks that the user has submitted data for the current shared unique checkpoint id in the edge cache (stores in STORE_CACHE_DB_ALL_EDGE_FOR_REALM)
3. Gets the user leaf to find the user's public key and last submitted checkpoint id
3. 
*/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPISubmitUserDataRequest {
    pub user_id: u64, 
    pub data: Vec<u8>,
    pub checkpoint_id: u64, // the last checkpoint id the user submitted data before this signature was created, used for the primage
    pub signature: QPSecp256K1Signature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPISubmitUserDataResponse {
    pub has_error: bool, // does not guarantee it was accepted, just that it was submitted if has_error == false
}



impl_qpq_serialize_bincode!(RealmEdgeAPISubmitUserDataRequest);



// attempts to register a new user with realm at a given user id
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIRegisterUserRequest {
    pub user_id: u64, // the user id to register, if it is not already registered, we set the public key and initial data
    pub public_key: QPSecp256K1CompressedPublicKey,
    pub initial_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct RealmEdgeAPIRegisterUserResponse {
    pub has_error: bool, // does not guarantee it was accepted, just that it was submitted if has_error == false
}

impl_qpq_serialize_bincode!(RealmEdgeAPIRegisterUserRequest);

