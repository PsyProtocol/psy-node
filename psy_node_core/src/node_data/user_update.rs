use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::v1::qdata::{ffs_sizes::{PSY_OBJECT_FFS_SIZE_USER_LEAF, PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA}, user::PQEDUserLeaf};
use psy_serialize::FastFixedSerializable;

use crate::node_data::user_update_metadata::PsyNodeUserUpdateMetaData;
// realm_id + unique_pending_id + metadata + user_leaf
pub const PSY_NODE_USER_UPDATE_BUFFER_SIZE: usize = 16 + PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA + PSY_OBJECT_FFS_SIZE_USER_LEAF; 

pub fn create_node_user_update_buffer<F: QFelt64, Hash: Q256BitHash>(
    realm_id: u64,
    unique_pending_id: u64,
    metadata: &PsyNodeUserUpdateMetaData<Hash>,
    user_leaf: &PQEDUserLeaf<F, Hash>,
) -> [u8; PSY_NODE_USER_UPDATE_BUFFER_SIZE] {
    let mut buffer = [0u8; PSY_NODE_USER_UPDATE_BUFFER_SIZE];
    buffer[0..8].copy_from_slice(&realm_id.to_le_bytes());
    buffer[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    buffer[16..16 + PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA]
        .copy_from_slice(&metadata.ffs_to_bytes());
    buffer[16 + PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA..]
        .copy_from_slice(&user_leaf.ffs_to_bytes());
    buffer
}

pub fn verify_user_update_buffer_split_into_metadata_and_user_leaf_data<Hash: Q256BitHash>(realm_id: u64, unique_pending_id: u64, data: &[u8]) -> anyhow::Result<(PsyNodeUserUpdateMetaData<Hash>, [u8; PSY_OBJECT_FFS_SIZE_USER_LEAF])> {
    if data.len() != PSY_NODE_USER_UPDATE_BUFFER_SIZE {
        anyhow::bail!("Invalid data length for user update buffer");
    }
    let data_realm_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let data_unique_pending_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if data_realm_id != realm_id {
        anyhow::bail!("Realm ID does not match");
    }
    if data_unique_pending_id != unique_pending_id {
        anyhow::bail!("Unique pending ID does not match");
    }
    let metadata = PsyNodeUserUpdateMetaData::<Hash>::ffs_try_from_slice(&data[16..16 + PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA])?;
    let user_leaf_bytes: [u8; PSY_OBJECT_FFS_SIZE_USER_LEAF] = data[16 + PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA..].try_into().unwrap();
    Ok((metadata, user_leaf_bytes))
}