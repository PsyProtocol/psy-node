use anyhow::Context;
use parth_core::data::hash::fast_node_serializer::{QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE};

use crate::qblob::{blob_type::{get_item_size_for_data_type, is_valid_qblob_merkle_node_batch_type, QBlobDataType, QBlobMerkleNodeTreeType, QBLOB_STANDARD_V1_MAGIC_U32}, traits::common::QBlobStructHeaderBase};

pub const QBLOB_TREE_NODE_BATCH_HEADER_SIZE: usize = 80;

#[pderive::serialize_copy]
pub struct QBlobMerkleTreeNodeBatchHeaderV1 {
    // MUST always be QBV1 (QBLOB_STANDARD_V1_MAGIC_U32)
    pub blob_magic: u32, 
    // the chain ID this batch is for
    pub chain_id: u32, 

    // total size of the payload in bytes (including the header)
    pub total_size: u64, 
    
    // a unique ID for the node that created this batch 
    pub created_by_node_id: u32, 
     // seconds since the unix epoch 
    pub created_at_seconds: u32,

    // the type of blob, must be one of:
    // QBlobDataType::GenericZeroIdMerkleNodeBatch, 
    // QBlobDataType::GenericSingleIdMerkleNodeBatch,
    //  or QBlobDataType::GenericDoubleIdMerkleNodeBatch
    pub blob_type: QBlobDataType, // enum repr u16

    // The type of merkle tree these nodes belong to (GlobalUserTree, UserContractTree, etc.)
    pub tree_type: QBlobMerkleNodeTreeType, // enum repr u16

    // This is who created the node
    // For coordinators, this is the coordinator ID.
    // For realms, this is the realm ID.
    pub realm_id: u64, 

    // The sub ID of the realm/coordinator that created these nodes.
    pub realm_sub_id: u64, 
    

    // The current unique_pending_id of the realm/coordinator as of when these nodes were created.
    pub unique_pending_id: u64, 

    // The last checkpoint ID applied as of when these nodes were created.
    pub checkpoint_id: u64, 
    
    // If the nodes are associated with a specific target (e.g. user, contract, etc.), this is the ID of that target.
    // If not associated with a specific target, this will be zero.
    // For QBlobMerkleNodeTreeType::UserContractTree, this is the user ID.
    // For QBlobMerkleNodeTreeType::ContractFunctionTree, this is the contract ID.
    // For QBlobMerkleNodeTreeType::UserContractStateTree, this is the user ID.
    // For QBlobMerkleNodeTreeType::GlobalUserTree, GlobalContractTree, or GlobalUserRegistrationTree, this will be zero.
    pub for_target_id: u64, 

    // how many items are in this batch
    pub item_count: u64, 

    // size of each item in bytes
    pub item_size: u32, 
}

impl QBlobMerkleTreeNodeBatchHeaderV1 {
    pub fn new_double_id_header(tree_type: QBlobMerkleNodeTreeType, chain_id: u32, node_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64, for_target_id: u64) -> Self {
        Self {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id,
            total_size: 0,
            created_by_node_id: node_id,
            created_at_seconds: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
            blob_type: QBlobDataType::GenericDoubleIdMerkleNodeBatch,
            tree_type,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id: 0,
            for_target_id,
            item_count: 0,
            item_size: QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE as u32,
        }
    }
    pub fn new_single_id_header(tree_type: QBlobMerkleNodeTreeType, chain_id: u32, node_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64, for_target_id: u64) -> Self {
        Self {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id,
            total_size: 0,
            created_by_node_id: node_id,
            created_at_seconds: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
            blob_type: QBlobDataType::GenericSingleIdMerkleNodeBatch,
            tree_type,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id: 0,
            for_target_id,
            item_count: 0,
            item_size: QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u32,
        }
    }
    pub fn new_zero_id_header(tree_type: QBlobMerkleNodeTreeType, chain_id: u32, node_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64, for_target_id: u64) -> Self {
        Self {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id,
            total_size: 0,
            created_by_node_id: node_id,
            created_at_seconds: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
            blob_type: QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id: 0,
            for_target_id,
            item_count: 0,
            item_size: QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE as u32,
        }
    }
    pub fn modify_for_final_count_and_size(&mut self, item_size: u32, final_item_count: u64) {
        self.item_count = final_item_count;
        self.item_size = item_size;
        self.total_size = QBLOB_TREE_NODE_BATCH_HEADER_SIZE as u64 + (item_size as u64 * final_item_count);
    }
    pub fn is_valid_for_realm_context(&self, chain_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64) -> bool {
        self.is_header_valid() && 
        self.chain_id == chain_id &&
        self.realm_id == realm_id &&
        self.realm_sub_id == realm_sub_id &&
        self.unique_pending_id == unique_pending_id
    }
    pub fn to_bytes_fixed_size_array(&self) -> [u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE] {
        let mut buf = [0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.blob_magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.chain_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.total_size.to_le_bytes());
        buf[16..20].copy_from_slice(&self.created_by_node_id.to_le_bytes());
        buf[20..24].copy_from_slice(&self.created_at_seconds.to_le_bytes());
        buf[24..26].copy_from_slice(&(self.blob_type as u16).to_le_bytes());
        buf[26..28].copy_from_slice(&(self.tree_type as u16).to_le_bytes());
        buf[28..36].copy_from_slice(&self.realm_id.to_le_bytes());
        buf[36..44].copy_from_slice(&self.realm_sub_id.to_le_bytes());
        buf[44..52].copy_from_slice(&self.unique_pending_id.to_le_bytes());
        buf[52..60].copy_from_slice(&self.checkpoint_id.to_le_bytes());
        buf[60..68].copy_from_slice(&self.for_target_id.to_le_bytes());
        buf[68..76].copy_from_slice(&self.item_count.to_le_bytes());
        buf[76..80].copy_from_slice(&self.item_size.to_le_bytes());
        buf
    }
    pub fn clip_header_get_payload_for_blob_type_and_tree(full_data: Vec<u8>, expected_blob_type: QBlobDataType, expected_tree_type: QBlobMerkleNodeTreeType, exact_size: bool) -> anyhow::Result<(Self, Vec<u8>)> {
        Self::clip_header_get_payload_internal(full_data, Some(expected_blob_type), Some(expected_tree_type), exact_size)
    }
    pub fn clip_header_get_payload(full_data: Vec<u8>, expected_blob_type: Option<QBlobDataType>, expected_tree_type: Option<QBlobMerkleNodeTreeType>, exact_size: bool) -> anyhow::Result<(Self, Vec<u8>)> {
        Self::clip_header_get_payload_internal(full_data, expected_blob_type, expected_tree_type, exact_size)
    }

    pub fn clip_header_get_payload_for_blob_type_and_tree_ref(full_data: &[u8], expected_blob_type: QBlobDataType, expected_tree_type: QBlobMerkleNodeTreeType, exact_size: bool) -> anyhow::Result<(Self, &[u8])> {
        Self::clip_header_get_payload_internal_ref(full_data, Some(expected_blob_type), Some(expected_tree_type), exact_size)
    }
    pub fn clip_header_get_payload_ref(full_data: &[u8], expected_blob_type: Option<QBlobDataType>, expected_tree_type: Option<QBlobMerkleNodeTreeType>, exact_size: bool) -> anyhow::Result<(Self, &[u8])> {
        Self::clip_header_get_payload_internal_ref(full_data, expected_blob_type, expected_tree_type, exact_size)
    }

    fn clip_header_get_payload_internal(mut full_data: Vec<u8>, expected_blob_type: Option<QBlobDataType>, expected_tree_type: Option<QBlobMerkleNodeTreeType>, exact_size: bool) -> anyhow::Result<(Self, Vec<u8>)> {


        let full_data_len = full_data.len();
        if full_data_len < QBLOB_TREE_NODE_BATCH_HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Full data length is less than header size: {} < {}",
                full_data.len(),
                QBLOB_TREE_NODE_BATCH_HEADER_SIZE
            ));
        }
        let header = Self::try_read_header_from_slice(&full_data[0..QBLOB_TREE_NODE_BATCH_HEADER_SIZE])?;
        if !header.is_header_valid() {
            return Err(anyhow::anyhow!("Invalid header in clip_header_get_payload"));
        }
        if expected_blob_type.is_some() && header.blob_type != expected_blob_type.unwrap() {
            return Err(anyhow::anyhow!(
                "Header blob_type does not match expected: {:?} != {:?}",
                header.blob_type,
                expected_blob_type.unwrap()
            ));
        }
        if expected_tree_type.is_some() && header.tree_type != expected_tree_type.unwrap() {
            return Err(anyhow::anyhow!(
                "Header tree_type does not match expected: {:?} != {:?}",
                header.tree_type,
                expected_tree_type.unwrap()
            ));
        }
        let expected_item_size = get_item_size_for_data_type(header.blob_type);
        if expected_item_size.is_none() {
            return Err(anyhow::anyhow!(
                "Could not determine expected item size for blob_type: {:?}",
                header.blob_type
            ));
        }
        let expected_item_size = expected_item_size.unwrap();
        let full_data_len = full_data.len();
        let calculated_total_size = QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (header.item_count as usize * expected_item_size);
        if exact_size {
            if full_data_len != header.total_size as usize {
                return Err(anyhow::anyhow!(
                    "Full data length does not match total_size in header: {} != {}",
                    full_data_len,
                    header.total_size
                ));
            }else if full_data_len != calculated_total_size {
                return Err(anyhow::anyhow!(
                    "Full data length does not match calculated total size from header: {} != {}",
                    full_data_len,
                    calculated_total_size
                ));
            }
        }else{
            if full_data_len < header.total_size as usize {
                return Err(anyhow::anyhow!(
                    "Full data length is less than total_size in header: {} < {}",
                    full_data_len,
                    header.total_size
                ));
            }
            if full_data_len < calculated_total_size {
                return Err(anyhow::anyhow!(
                    "Full data length is less than expected for header item_count and item_size: {} < {}",
                    full_data_len,
                    calculated_total_size
                ));
            }
        }
        if expected_item_size != header.item_size as usize {
            return Err(anyhow::anyhow!(
                "Header item_size does not match expected: {} != {}",
                header.item_size,
                expected_item_size
            ));
        }
        let _ = full_data.drain(0..QBLOB_TREE_NODE_BATCH_HEADER_SIZE);
        Ok((header, full_data))

    }



    fn clip_header_get_payload_internal_ref(full_data: &[u8], expected_blob_type: Option<QBlobDataType>, expected_tree_type: Option<QBlobMerkleNodeTreeType>, exact_size: bool) -> anyhow::Result<(Self, &[u8])> {


        let full_data_len = full_data.len();
        if full_data_len < QBLOB_TREE_NODE_BATCH_HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Full data length is less than header size: {} < {}",
                full_data.len(),
                QBLOB_TREE_NODE_BATCH_HEADER_SIZE
            ));
        }
        let header = Self::try_read_header_from_slice(&full_data[0..QBLOB_TREE_NODE_BATCH_HEADER_SIZE])?;
        if !header.is_header_valid() {
            return Err(anyhow::anyhow!("Invalid header in clip_header_get_payload"));
        }
        if expected_blob_type.is_some() && header.blob_type != expected_blob_type.unwrap() {
            return Err(anyhow::anyhow!(
                "Header blob_type does not match expected: {:?} != {:?}",
                header.blob_type,
                expected_blob_type.unwrap()
            ));
        }
        if expected_tree_type.is_some() && header.tree_type != expected_tree_type.unwrap() {
            return Err(anyhow::anyhow!(
                "Header tree_type does not match expected: {:?} != {:?}",
                header.tree_type,
                expected_tree_type.unwrap()
            ));
        }
        let expected_item_size = get_item_size_for_data_type(header.blob_type);
        if expected_item_size.is_none() {
            return Err(anyhow::anyhow!(
                "Could not determine expected item size for blob_type: {:?}",
                header.blob_type
            ));
        }
        let expected_item_size = expected_item_size.unwrap();
        let full_data_len = full_data.len();
        let calculated_total_size = QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (header.item_count as usize * expected_item_size);
        if exact_size {
            if full_data_len != header.total_size as usize {
                return Err(anyhow::anyhow!(
                    "Full data length does not match total_size in header: {} != {}",
                    full_data_len,
                    header.total_size
                ));
            }else if full_data_len != calculated_total_size {
                return Err(anyhow::anyhow!(
                    "Full data length does not match calculated total size from header: {} != {}",
                    full_data_len,
                    calculated_total_size
                ));
            }
        }else{
            if full_data_len < header.total_size as usize {
                return Err(anyhow::anyhow!(
                    "Full data length is less than total_size in header: {} < {}",
                    full_data_len,
                    header.total_size
                ));
            }
            if full_data_len < calculated_total_size {
                return Err(anyhow::anyhow!(
                    "Full data length is less than expected for header item_count and item_size: {} < {}",
                    full_data_len,
                    calculated_total_size
                ));
            }
        }
        if expected_item_size != header.item_size as usize {
            return Err(anyhow::anyhow!(
                "Header item_size does not match expected: {} != {}",
                header.item_size,
                expected_item_size
            ));
        }
        Ok((header, &full_data[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..header.total_size as usize]))

    }
}

impl QBlobStructHeaderBase for QBlobMerkleTreeNodeBatchHeaderV1 {
    const BLOB_MAGIC: u32 = QBLOB_STANDARD_V1_MAGIC_U32;
    const IS_ARRAY: bool = false;
    const IS_FIXED_ITEM_ARRAY: bool = false;
    const HEADER_SIZE: usize = QBLOB_TREE_NODE_BATCH_HEADER_SIZE;

    fn total_size(&self) -> usize {
        self.total_size as usize
    }

    fn get_fixed_item_size(&self) -> usize {
        self.item_size as usize
    }

    fn get_array_length(&self) -> usize {
        let payload_size = self.total_size as usize - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        payload_size / (self.item_size as usize)
    }

    fn try_read_header_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != QBLOB_TREE_NODE_BATCH_HEADER_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid slice length for QBlobMerkleTreeNodeBatchHeaderV1: expected {}, got {}",
                QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
                data.len()
            ));
        }

        // The `.try_into().unwrap()` calls are safe because the total slice length is verified above,
        // and the hardcoded sub-slice lengths match the target array types.
        let blob_magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let chain_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let total_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let created_by_node_id = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let created_at_seconds = u32::from_le_bytes(data[20..24].try_into().unwrap());

        let blob_type_u16 = u16::from_le_bytes(data[24..26].try_into().unwrap());
        let blob_type = QBlobDataType::from_repr(blob_type_u16).with_context(|| {
            format!("Invalid QBlobDataType value: {}", blob_type_u16)
        })?;

        let tree_type_u16 = u16::from_le_bytes(data[26..28].try_into().unwrap());
        let tree_type = QBlobMerkleNodeTreeType::from_repr(tree_type_u16).with_context(|| {
            format!("Invalid QBlobMerkleNodeTreeType value: {}", tree_type_u16)
        })?;

        let realm_id = u64::from_le_bytes(data[28..36].try_into().unwrap());
        let realm_sub_id = u64::from_le_bytes(data[36..44].try_into().unwrap());
        let unique_pending_id = u64::from_le_bytes(data[44..52].try_into().unwrap());
        let checkpoint_id = u64::from_le_bytes(data[52..60].try_into().unwrap());
        let for_target_id = u64::from_le_bytes(data[60..68].try_into().unwrap());
        let item_count = u64::from_le_bytes(data[68..76].try_into().unwrap());
        let item_size = u32::from_le_bytes(data[76..80].try_into().unwrap());

        Ok(Self {
            blob_magic,
            chain_id,
            total_size,
            created_by_node_id,
            created_at_seconds,
            blob_type,
            tree_type,
            realm_id,
            realm_sub_id,
            unique_pending_id,
            checkpoint_id,
            for_target_id,
            item_count,
            item_size,
        })
    }
    
    fn header_to_bytes_vec(&self) -> Vec<u8> {
        self.to_bytes_fixed_size_array().to_vec()
    }
    
    fn is_header_valid(&self) -> bool {
        self.blob_magic == QBLOB_STANDARD_V1_MAGIC_U32 && 
        is_valid_qblob_merkle_node_batch_type(self.blob_type, self.tree_type) &&
        // self.item_count > 0 && // allow empty batches
        self.item_size > 0 &&
        self.total_size as usize == QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (self.item_count as usize * self.item_size as usize)
    }
}