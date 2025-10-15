use parth_core::data::hash::fast_node_serializer::{QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE};
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum_macros::{Display, FromRepr};

pub const QBLOB_STANDARD_V1_MAGIC_U32: u32 = 0x31565142; // "QBV1" (litte-endian)
pub const QBLOB_STANDARD_V1_MAGIC_BYTES: [u8; 4] = [0x51, 0x42, 0x56, 0x31]; // "QBV1"

#[pderive::serialize_enum_repr_strum]
#[repr(u16)]
pub enum QBlobDataType {
    Unknown = 0,

    // Generic Merkle Node Batches
    GenericZeroIdMerkleNodeBatch = 1,
    GenericSingleIdMerkleNodeBatch = 2,
    GenericDoubleIdMerkleNodeBatch = 3,
}


#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, FromRepr, Display)]
#[repr(u16)]
pub enum QBlobMerkleNodeTreeType {
    Unknown = 0,

    // Zero ID Trees
    GlobalUserTree = 1,
    GlobalContractTree = 2,
    GlobalUserRegistrationTree = 3,


    // Single ID Trees
    UserContractTree = 256,
    ContractFunctionTree = 257,


    // Double ID Trees
    UserContractStateTree = 512,
}

pub const fn starts_with_qblob_v1_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == QBLOB_STANDARD_V1_MAGIC_BYTES[0]
        && data[1] == QBLOB_STANDARD_V1_MAGIC_BYTES[1]
        && data[2] == QBLOB_STANDARD_V1_MAGIC_BYTES[2]
        && data[3] == QBLOB_STANDARD_V1_MAGIC_BYTES[3]
}

pub const fn is_valid_qblob_merkle_node_batch_type(blob_data_type: QBlobDataType, tree_type: QBlobMerkleNodeTreeType) -> bool {
    match blob_data_type {
        QBlobDataType::GenericZeroIdMerkleNodeBatch => matches!(
            tree_type,
            QBlobMerkleNodeTreeType::GlobalUserTree
                | QBlobMerkleNodeTreeType::GlobalContractTree
                | QBlobMerkleNodeTreeType::GlobalUserRegistrationTree
        ),
        QBlobDataType::GenericSingleIdMerkleNodeBatch => matches!(
            tree_type,
            QBlobMerkleNodeTreeType::UserContractTree | QBlobMerkleNodeTreeType::ContractFunctionTree
        ),
        QBlobDataType::GenericDoubleIdMerkleNodeBatch => matches!(tree_type, QBlobMerkleNodeTreeType::UserContractStateTree),
        _ => false,
    }
}

pub const fn get_item_size_for_data_type(blob_data_type: QBlobDataType) -> Option<usize> {
    match blob_data_type {
        QBlobDataType::GenericZeroIdMerkleNodeBatch => Some(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE),
        QBlobDataType::GenericSingleIdMerkleNodeBatch => Some(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE),
        QBlobDataType::GenericDoubleIdMerkleNodeBatch => Some(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE),
        _ => None,
    }
}
pub const fn get_item_size_for_merkle_tree_type(tree_type: QBlobMerkleNodeTreeType) -> Option<usize> {
    match tree_type {
        QBlobMerkleNodeTreeType::GlobalUserTree
        | QBlobMerkleNodeTreeType::GlobalContractTree
        | QBlobMerkleNodeTreeType::GlobalUserRegistrationTree => Some(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE),
        QBlobMerkleNodeTreeType::UserContractTree | QBlobMerkleNodeTreeType::ContractFunctionTree => Some(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE),
        QBlobMerkleNodeTreeType::UserContractStateTree => Some(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE),
        _ => None,
    }
}