use crate::qblob::{blob_type::QBlobMerkleNodeTreeType, structs::common::tree_node_batch_header::QBlobMerkleTreeNodeBatchHeaderV1, traits::common::QBlobStructHeaderBase};


pub struct QBlobDoubleMerkleNodeBatchDataView {

}

impl QBlobDoubleMerkleNodeBatchDataView {

    pub fn try_read_double_node_blob_header(full_data: &[u8]) -> anyhow::Result<QBlobMerkleTreeNodeBatchHeaderV1> {
        QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(full_data)
    }
    pub fn validate_uct_nodes_batch_header_for_realm_context(header: &QBlobMerkleTreeNodeBatchHeaderV1, chain_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64) -> bool {
        header.is_valid_for_realm_context(chain_id, realm_id, realm_sub_id, unique_pending_id) && 
        header.tree_type == QBlobMerkleNodeTreeType::UserContractStateTree
    }
    pub fn validate_uct_nodes_batch_header_for_realm_context_get_clipped(data: Vec<u8>, chain_id: u32, realm_id: u64, realm_sub_id: u64, unique_pending_id: u64) -> anyhow::Result<()> {
        todo!("tired");
    }

}