use parth_core::{
    data::{
        hash::{fast_node_serializer::QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE, merkle_store_key::QMerkleStoreZeroIdNode},
        serializable::FastFixedSerializable,
    },
    protocol::core_types::Q256BitHash,
};

use crate::qblob::{
    blob_type::{QBlobDataType, QBlobMerkleNodeTreeType, QBLOB_STANDARD_V1_MAGIC_U32},
    structs::common::{
        blob_metadata_header::QBlobWriterContextMetadataHeader,
        tree_node_batch_header::{QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE},
    },
    traits::common::QBlobStructHeaderBase,
};

pub struct QBlobZeroMerkleNodeBatchDataView {}

impl QBlobZeroMerkleNodeBatchDataView {
    pub fn try_read_zero_node_blob_header(full_data: &[u8]) -> anyhow::Result<QBlobMerkleTreeNodeBatchHeaderV1> {
        QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(full_data)
    }
    pub fn validate_zero_tree_nodes_batch_header_for_realm_context(
        header: &QBlobMerkleTreeNodeBatchHeaderV1,
        chain_id: u32,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> bool {
        header.is_valid_for_realm_context(chain_id, realm_id, realm_sub_id, unique_pending_id)
            && header.tree_type == tree_type
    }
    pub fn validate_zero_tree_nodes_batch_header_for_realm_context_get_clipped(
        data: Vec<u8>,
        chain_id: u32,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<(QBlobMerkleTreeNodeBatchHeaderV1, Vec<u8>)> {
        let (header, payload_data) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree(
            data,
            QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type,
            true,
        )?;
        if header.chain_id != chain_id
            || header.realm_id != realm_id
            || header.realm_sub_id != realm_sub_id
            || header.unique_pending_id != unique_pending_id
            || header.tree_type != tree_type
        {
            return Err(anyhow::anyhow!("Header context does not match expected context"));
        }
        Ok((header, payload_data))
    }
    pub fn generate_zero_merkle_node_batch_blob_data_from_ref<Hash: Q256BitHash>(
        context: QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
        nodes: &[QMerkleStoreZeroIdNode<Hash>],
    ) -> Vec<u8> {
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (nodes.len() * QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)) as u64;
        let item_count = nodes.len() as u64;
        let item_size = QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE as u32;

        let header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type: tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: item_count,
            item_size: item_size,
        };

        let mut result = Vec::with_capacity(total_size as usize);
        result.extend_from_slice(&header.to_bytes_fixed_size_array());
        for node in nodes {
            result.extend_from_slice(&node.ffs_into_bytes());
        }
        result
    }

    pub fn read_nth_zero_id_node_from_batch_data_no_check<Hash: Q256BitHash>(
        full_data: &[u8],
        index: usize,
    ) -> anyhow::Result<QMerkleStoreZeroIdNode<Hash>> {
        let offset = QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (index * QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        let end = offset + QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
        if end > full_data.len() {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }
        let node_data = &full_data[offset..end];
        let node = QMerkleStoreZeroIdNode::<Hash>::ffs_try_from_slice(node_data)?;
        Ok(node)
    }
    pub fn read_batch_zero_nodes_from_checked_payload<Hash: Q256BitHash>(payload: &[u8]) -> anyhow::Result<Vec<QMerkleStoreZeroIdNode<Hash>>> {
        if payload.len() % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE != 0 {
            return Err(anyhow::anyhow!("Payload size is not a multiple of zero ID node size"));
        }
        let count = payload.len() / QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
            let end = offset + QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
            let node_data = &payload[offset..end];
            let node = QMerkleStoreZeroIdNode::<Hash>::ffs_try_from_slice(node_data)?;
            nodes.push(node);
        }
        Ok(nodes)
    }
    pub fn gen_empty_zero_merkle_node_header_blob(context: QBlobWriterContextMetadataHeader, tree_type: QBlobMerkleNodeTreeType) -> Vec<u8> {

        let header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: QBLOB_TREE_NODE_BATCH_HEADER_SIZE as u64,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type: tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: 0,
            item_size: QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE as u32,
        };
        header.to_bytes_fixed_size_array().to_vec()
    }
    pub fn tree_header_from_context_and_counts(
        context: QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
        item_count: u64,
    ) -> QBlobMerkleTreeNodeBatchHeaderV1 {
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (item_count as usize * QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE)) as u64;
        QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: item_count,
            item_size: QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE as u32,
        }
    }
    pub fn combine_zero_merkle_node_batch_blobs_unvalidated<Hash: Q256BitHash>(
        blobs: Vec<Vec<u8>>,
        context: QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<Vec<u8>> {
        if blobs.is_empty() {
            return Ok(Self::gen_empty_zero_merkle_node_header_blob(context, tree_type));
        }
        let blob_len_sum = blobs.iter().map(|b| b.len()).sum::<usize>();
        let combined_payload_size = blob_len_sum - (blobs.len() * QBLOB_TREE_NODE_BATCH_HEADER_SIZE);
        if combined_payload_size % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE != 0 {
            return Err(anyhow::anyhow!("Combined payload size is not a multiple of zero ID node size"));
        }
        let item_count = combined_payload_size / QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE;
        if item_count == 0 {
            return Ok(Self::gen_empty_zero_merkle_node_header_blob(context, tree_type));
        }
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + blob_len_sum - (blobs.len() * QBLOB_TREE_NODE_BATCH_HEADER_SIZE)) as u64;

        let combined_header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericZeroIdMerkleNodeBatch,
            tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: item_count as u64,
            item_size: QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE as u32,
        };
        let mut result_buffer = Vec::with_capacity(total_size as usize);
        result_buffer.extend_from_slice(&combined_header.to_bytes_fixed_size_array());
        for blob in blobs {
            result_buffer.extend_from_slice(&blob[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..]);
        }
        Ok(result_buffer)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        data::hash::{hash256::Hash256, merkle_store_key::QMerkleStoreZeroIdNode},
        utils::QPGenRandom,
    };

    use crate::qblob::{
        blob_type::QBlobMerkleNodeTreeType, data_views::zero_merkle_node_batch::QBlobZeroMerkleNodeBatchDataView, structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader
    };

    #[test]
    fn check_round_trip() -> anyhow::Result<()> {
        type Hash = Hash256;
        let count = 10_000;
        let tree_type = QBlobMerkleNodeTreeType::UserContractTree;
        println!("Generating {} random zero ID nodes...", count);
        let context = QBlobWriterContextMetadataHeader::new_at_now(1, 42, 1001, 1, 2, 3, 4);
        let nodes: Vec<QMerkleStoreZeroIdNode<Hash>> = (0..count).map(|_| QPGenRandom::qp_rand_gen()).collect();
        let start_time = std::time::Instant::now();
        let serialized_blob = QBlobZeroMerkleNodeBatchDataView::generate_zero_merkle_node_batch_blob_data_from_ref(context, tree_type, &nodes);
        let duration = start_time.elapsed();
        println!("Serialization took: {:?}, ({}ms per node * {} nodes)", duration, duration.as_secs_f64() / (count as f64 * 1000f64), count);

        let start_time = std::time::Instant::now();
        let (header, payload) = QBlobZeroMerkleNodeBatchDataView::validate_zero_tree_nodes_batch_header_for_realm_context_get_clipped(
            serialized_blob,
            context.chain_id,
            context.realm_id,
            context.realm_sub_id,
            context.unique_pending_id,
            tree_type,
        )?;
        let duration = start_time.elapsed();
        println!("Validation took: {:?}", duration);
        let start_time = std::time::Instant::now();
        assert_eq!(header.item_count as usize, nodes.len());
        let deserialized_nodes = QBlobZeroMerkleNodeBatchDataView::read_batch_zero_nodes_from_checked_payload(&payload)?;
        let duration = start_time.elapsed();
        println!("Deserialization took: {:?}, ({}ms per node * {} nodes)", duration, duration.as_secs_f64() / (count as f64 * 1000f64), count);
        assert_eq!(deserialized_nodes.len(), nodes.len());
        for (original, deserialized) in nodes.iter().zip(deserialized_nodes.iter()) {
            assert_eq!(original, deserialized);
        }

        Ok(())
    }
    #[test]
    fn check_batches_unchecked() -> anyhow::Result<()> {
        type Hash = Hash256;
        let number_of_batches = 200_000;
        let nodes_per_batch = 200;
        let tree_type = QBlobMerkleNodeTreeType::UserContractTree;
        let context = QBlobWriterContextMetadataHeader::new_at_now(1, 42, 1001, 1, 2, 3, 4);

        let batch_nodes: Vec<Vec<QMerkleStoreZeroIdNode<Hash>>> = (0..number_of_batches)
            .map(|_| (0..nodes_per_batch).map(|_| QPGenRandom::qp_rand_gen()).collect())
            .collect();
        let batches = batch_nodes.iter().map(|batch| QBlobZeroMerkleNodeBatchDataView::generate_zero_merkle_node_batch_blob_data_from_ref(context,tree_type, batch)).collect::<Vec<_>>();
        
        let start_time = std::time::Instant::now();
        let serialized_blob = QBlobZeroMerkleNodeBatchDataView::combine_zero_merkle_node_batch_blobs_unvalidated::<Hash>(batches, context, tree_type)?;
        let duration = start_time.elapsed();
        println!("Serialization took: {:?}, ({}ms per batch * {} batches)", duration, duration.as_secs_f64() / (number_of_batches as f64 * 1000f64), number_of_batches);

        let start_time = std::time::Instant::now();
        let (header, payload) = QBlobZeroMerkleNodeBatchDataView::validate_zero_tree_nodes_batch_header_for_realm_context_get_clipped(
            serialized_blob,
            context.chain_id,
            context.realm_id,
            context.realm_sub_id,
            context.unique_pending_id,
            tree_type,
        )?;
        let duration = start_time.elapsed();
        println!("Validation took: {:?}", duration);
        assert_eq!(header.item_count as usize, number_of_batches * nodes_per_batch);
        let start_time = std::time::Instant::now();
        let deserialized_nodes = QBlobZeroMerkleNodeBatchDataView::read_batch_zero_nodes_from_checked_payload(&payload)?;
        let duration = start_time.elapsed();
        println!("Deserialization took: {:?}, ({}ms per batch * {} batches)", duration, duration.as_secs_f64() / (number_of_batches as f64 * 1000f64), number_of_batches);
        assert_eq!(deserialized_nodes.len(), number_of_batches * nodes_per_batch);

        let flat_batch_nodes = batch_nodes.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(flat_batch_nodes.len(), deserialized_nodes.len());
        for (original, deserialized) in flat_batch_nodes.iter().zip(deserialized_nodes.iter()) {
            assert_eq!(original, deserialized);
        }

        Ok(())
    }
}
