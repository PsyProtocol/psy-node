use std::collections::HashMap;

use parth_core::{
    crypto::hash::{merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore}, traits::MerkleHasher}, data::hash::{fast_node_serializer::{QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE}, merkle_store_key::{QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode}}, protocol::core_types::Q256BitHash
};
use psy_serialize::FastFixedSerializable;

use crate::qblob::{
    blob_type::{QBlobDataType, QBlobMerkleNodeTreeType, QBLOB_STANDARD_V1_MAGIC_U32}, data_views::double_merkle_node_batch::QBlobDoubleIdMerkleRecorder, structs::common::{
        blob_metadata_header::QBlobWriterContextMetadataHeader,
        tree_node_batch_header::{QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE},
    }, traits::common::QBlobStructHeaderBase
};

pub struct QBlobSingleMerkleNodeBatchDataView {}

impl QBlobSingleMerkleNodeBatchDataView {
    pub fn try_read_single_node_blob_header(full_data: &[u8]) -> anyhow::Result<QBlobMerkleTreeNodeBatchHeaderV1> {
        QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(full_data)
    }
    pub fn validate_single_tree_nodes_batch_header_for_realm_context(
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
    pub fn validate_single_tree_nodes_batch_header_for_realm_context_get_clipped(
        data: Vec<u8>,
        chain_id: u32,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<(QBlobMerkleTreeNodeBatchHeaderV1, Vec<u8>)> {
        let (header, payload_data) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree(
            data,
            QBlobDataType::GenericSingleIdMerkleNodeBatch,
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
    pub fn validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref(
        data: &[u8],
        chain_id: u32,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<(QBlobMerkleTreeNodeBatchHeaderV1, &[u8])> {
        let (header, payload_data) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
            data,
            QBlobDataType::GenericSingleIdMerkleNodeBatch,
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
    pub fn validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size(
        data: &[u8],
        chain_id: u32,
        realm_id: u64,
        realm_sub_id: u64,
        unique_pending_id: u64,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<(QBlobMerkleTreeNodeBatchHeaderV1, &[u8], &[u8])> {
        let (header, payload_data) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
            data,
            QBlobDataType::GenericSingleIdMerkleNodeBatch,
            tree_type,
            false,
        )?;
        if header.chain_id != chain_id
            || header.realm_id != realm_id
            || header.realm_sub_id != realm_sub_id
            || header.unique_pending_id != unique_pending_id
            || header.tree_type != tree_type
        {
            return Err(anyhow::anyhow!("Header context does not match expected context"));
        }



        Ok((header, payload_data, &data[header.total_size as usize..]))
    }
    pub fn generate_single_merkle_node_batch_blob_data_from_ref<Hash: Q256BitHash>(
        context: QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
        nodes: &[QMerkleStoreSingleIdNode<Hash>],
    ) -> Vec<u8> {
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (nodes.len() * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)) as u64;
        let item_count = nodes.len() as u64;
        let item_size = QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u32;

        let header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericSingleIdMerkleNodeBatch,
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

    pub fn read_nth_single_id_node_from_batch_data_no_check<Hash: Q256BitHash>(
        full_data: &[u8],
        index: usize,
    ) -> anyhow::Result<QMerkleStoreSingleIdNode<Hash>> {
        let offset = QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (index * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        let end = offset + QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
        if end > full_data.len() {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }
        let node_data = &full_data[offset..end];
        let node = QMerkleStoreSingleIdNode::<Hash>::ffs_try_from_slice(node_data)?;
        Ok(node)
    }
    pub fn read_batch_single_nodes_from_checked_payload<Hash: Q256BitHash>(payload: &[u8]) -> anyhow::Result<Vec<QMerkleStoreSingleIdNode<Hash>>> {
        if payload.len() % QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE != 0 {
            return Err(anyhow::anyhow!("Payload size is not a multiple of single ID node size"));
        }
        let count = payload.len() / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
            let end = offset + QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
            let node_data = &payload[offset..end];
            let node = QMerkleStoreSingleIdNode::<Hash>::ffs_try_from_slice(node_data)?;
            nodes.push(node);
        }
        Ok(nodes)
    }
    pub fn gen_empty_single_merkle_node_header_blob(context: &QBlobWriterContextMetadataHeader, tree_type: QBlobMerkleNodeTreeType) -> Vec<u8> {

        let header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: QBLOB_TREE_NODE_BATCH_HEADER_SIZE as u64,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericSingleIdMerkleNodeBatch,
            tree_type: tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: 0,
            item_size: QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u32,
        };
        header.to_bytes_fixed_size_array().to_vec()
    }
    pub fn tree_header_from_context_and_counts(
        context: &QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
        item_count: u64,
    ) -> QBlobMerkleTreeNodeBatchHeaderV1 {
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + (item_count as usize * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)) as u64;
        QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericSingleIdMerkleNodeBatch,
            tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: item_count,
            item_size: QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u32,
        }
    }
    pub fn combine_single_merkle_node_batch_blobs_unvalidated<Hash: Q256BitHash>(
        blobs: Vec<Vec<u8>>,
        context: &QBlobWriterContextMetadataHeader,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<Vec<u8>> {
        if blobs.is_empty() {
            return Ok(Self::gen_empty_single_merkle_node_header_blob(context, tree_type));
        }
        let blob_len_sum = blobs.iter().map(|b| b.len()).sum::<usize>();
        let combined_payload_size = blob_len_sum - (blobs.len() * QBLOB_TREE_NODE_BATCH_HEADER_SIZE);
        if combined_payload_size % QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE != 0 {
            return Err(anyhow::anyhow!("Combined payload size is not a multiple of single ID node size"));
        }
        let item_count = combined_payload_size / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE;
        if item_count == 0 {
            return Ok(Self::gen_empty_single_merkle_node_header_blob(context, tree_type));
        }
        let total_size = (QBLOB_TREE_NODE_BATCH_HEADER_SIZE + blob_len_sum - (blobs.len() * QBLOB_TREE_NODE_BATCH_HEADER_SIZE)) as u64;

        let combined_header = QBlobMerkleTreeNodeBatchHeaderV1 {
            blob_magic: QBLOB_STANDARD_V1_MAGIC_U32,
            chain_id: context.chain_id,
            total_size: total_size,
            created_by_node_id: context.created_by_node_id,
            created_at_seconds: context.created_at_seconds,
            blob_type: QBlobDataType::GenericSingleIdMerkleNodeBatch,
            tree_type,
            realm_id: context.realm_id,
            realm_sub_id: context.realm_sub_id,
            unique_pending_id: context.unique_pending_id,
            checkpoint_id: context.checkpoint_id,
            for_target_id: context.for_target_id,
            item_count: item_count as u64,
            item_size: QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u32,
        };
        let mut result_buffer = Vec::with_capacity(total_size as usize);
        result_buffer.extend_from_slice(&combined_header.to_bytes_fixed_size_array());
        for blob in blobs {
            result_buffer.extend_from_slice(&blob[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..]);
        }
        Ok(result_buffer)
    }
}

#[derive(Clone)]
pub struct QBlobSingleIdMerkleRecorder {
    map: HashMap<QMerkleStoreSingleIdKey, bool>,
    start_offset: usize,
    pub blob: Vec<u8>,
}

impl QBlobSingleIdMerkleRecorder {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            blob: Vec::new(),
            start_offset: 0,
        }
    }
    pub fn new_with_blob(blob: Vec<u8>) -> Self {
                let start_offset = blob.len();

        Self {
            map: HashMap::new(),
            blob,
            start_offset,
        }
    }
    pub fn new_from_blob_with_header(blob: Vec<u8>) -> Self {
        let mut blob = blob;
        let start_offset = blob.len();
        blob.extend_from_slice(&[0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE]);
        Self {
            map: HashMap::new(),
            blob,
            start_offset,
        }
    }
    pub fn new_with_multi_size_hints_with_header(single_size_hint: usize, double_size_hint: usize) -> Self {
        let total_size = single_size_hint*QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE + double_size_hint*QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE + 2*QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut blob = Vec::with_capacity(total_size);
        blob.extend(&[0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE]);
        Self {
            map: HashMap::with_capacity(single_size_hint),
            blob,
            start_offset: 0,
        }
    }
    pub fn new_with_size_hint(size_hint: usize) -> Self {
        Self {
            map: HashMap::with_capacity(size_hint),
            blob: Vec::with_capacity(size_hint * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE),
            start_offset: 0,
        }
    }
    pub fn new_with_header_and_size_hint(size_hint: usize) -> Self {
        let mut blob = Vec::with_capacity(QBLOB_TREE_NODE_BATCH_HEADER_SIZE + size_hint * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        blob.extend(&[0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE]);
        Self {
            map: HashMap::with_capacity(size_hint),
            blob,
            start_offset: 0,
        }
    }

    pub fn record_and_compute_merkle_root_validate_delta_merkle_proof<Hash: Q256BitHash + Copy, Hasher: MerkleHasher<Hash>>(
        &mut self,
        tree_id: u64,
        leaf_level: u8,
        proof: &DeltaMerkleProofCore<Hash>,
    ) -> anyhow::Result<Hash> {
        if (leaf_level as usize) < proof.siblings.len() {
            anyhow::bail!("leaf level is less than siblings length");
        }
        let old_proof_computed_root = compute_root_merkle_proof_generic::<Hash, Hasher>(
            proof.old_value,
            proof.index,
            &proof.siblings,
        );
        if old_proof_computed_root != proof.old_root {
            anyhow::bail!("Delta merkle proof old root does not match computed old root");
        }
        let new_computed_root = self.record_and_compute_merkle_root::<Hash, Hasher>(
            tree_id,
            proof.index,
            leaf_level,
            &proof.new_value,
            &proof.siblings,
        );
        if new_computed_root != proof.new_root {
            anyhow::bail!("Delta merkle proof new root does not match computed new root");
        }
        Ok(new_computed_root)
    }
    pub fn record_and_compute_merkle_root<Hash: Q256BitHash, Hasher: MerkleHasher<Hash>>(
        &mut self,
        tree_id: u64,
        index: u64,
        level: u8,
        value: &Hash,
        siblings: &[Hash],
    ) -> Hash {
        let mut current_node = QMerkleStoreSingleIdNode {
            key: QMerkleStoreSingleIdKey {
                tree_id,
                level,
                index,
            },
            value: value.clone(),
        };
        let mut should_record = self.map.insert(current_node.key.clone(), true).is_none();
        let mut counter = 0;
        let max_count = siblings.len().min(level as usize);
        while should_record && counter < max_count {
            self.blob.extend_from_slice(&current_node.ffs_to_bytes());
            current_node.value = Hasher::two_to_one_swap(current_node.key.index&1 == 1, &current_node.value, &siblings[counter]);
            current_node.key.level -= 1;
            current_node.key.index >>= 1;
            counter += 1;
            should_record = self.map.insert(current_node.key.clone(), true).is_none();
        }
        if !should_record {
            compute_root_merkle_proof_generic::<Hash, Hasher>(current_node.value, current_node.key.index, &siblings[counter..])
        }else{
            self.blob.extend_from_slice(&current_node.ffs_to_bytes());
            current_node.value
        }

    }
    pub fn finalize(self) -> Vec<u8> {
        self.blob
    }

    pub fn finalize_with_header(self, context: &QBlobWriterContextMetadataHeader, tree_type: QBlobMerkleNodeTreeType) -> Vec<u8> {
        let end_offset = self.blob.len();
        let size_without_header = end_offset - self.start_offset - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let item_count = size_without_header as u64 / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u64;
        let mut blob = self.blob;
        blob[self.start_offset..(self.start_offset + QBLOB_TREE_NODE_BATCH_HEADER_SIZE)].copy_from_slice(&QBlobSingleMerkleNodeBatchDataView::tree_header_from_context_and_counts(
            context,
            tree_type,
            item_count,
        ).to_bytes_fixed_size_array());
        blob
    }



    pub fn finalize_with_header_into_double(self, context: &QBlobWriterContextMetadataHeader, tree_type: QBlobMerkleNodeTreeType) -> QBlobDoubleIdMerkleRecorder {
        let end_offset = self.blob.len();
        let size_without_header = end_offset - self.start_offset - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let item_count = size_without_header as u64 / QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE as u64;
        let mut blob = self.blob;
        blob[self.start_offset..(self.start_offset + QBLOB_TREE_NODE_BATCH_HEADER_SIZE)].copy_from_slice(&QBlobSingleMerkleNodeBatchDataView::tree_header_from_context_and_counts(
            context,
            tree_type,
            item_count,
        ).to_bytes_fixed_size_array());
        QBlobDoubleIdMerkleRecorder::new_from_blob_with_header(blob)
    }
}


#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::{merkle_proof::{compute_path_merkle_proof_generic, compute_root_merkle_proof_generic}, traits::MerkleZeroHasher}, data::hash::{hash256::Hash256, merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::{QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode}}, pgoldilocks::PoseidonHasher, protocol::core_types::Q256BitHash, utils::QPGenRandom, PHash
    };
    use parth_crypto::hash::sha256::CoreSha256Hasher;

    use crate::qblob::{
        blob_type::QBlobMerkleNodeTreeType, data_views::single_merkle_node_batch::{QBlobSingleIdMerkleRecorder, QBlobSingleMerkleNodeBatchDataView}, structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader
    };
    

    fn fuzz_merkle_hash_recorder_with_sibling_values_helper<Hash: QPGenRandom + Q256BitHash + std::fmt::Debug + Default, Hasher: MerkleZeroHasher<Hash>>(
        height: u8,
        count: usize,
        with_context: Option<QBlobWriterContextMetadataHeader>,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<()>{

        let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(height);

        let tree_id = rand::random::<u64>();


        let proofs = (0..count).map(|_|{
            let index = if height != 64 {
                rand::random::<u64>() & rand::random::<u64>() & ((1u64 << height) -1)
            }else{
                rand::random::<u64>()
            };
            let value = Hash::qp_rand_gen();
            let proof = tree.set_leaf(index, value);
            proof
        }).collect::<Vec<_>>();

        let mut recorder = if with_context.is_none() {
            QBlobSingleIdMerkleRecorder::new()
        }else{
            QBlobSingleIdMerkleRecorder::new_with_header_and_size_hint(count*height as usize)
        };


        let mut reversed_proofs = proofs.clone();
        reversed_proofs.reverse();

        for i in 0..reversed_proofs.len() {
            recorder.record_and_compute_merkle_root::<Hash, Hasher>(
                tree_id,
                reversed_proofs[i].index,
                height,
                &reversed_proofs[i].new_value,
                &reversed_proofs[i].siblings,
            );

        }
        let keys = reversed_proofs.iter().map(|x|{
            
            [
                vec![SimpleMerkleNodeKey::new(height, x.index)],
                SimpleMerkleNodeKey::new(height, x.index).get_above_path_including_root()
            ].concat()

        }).flat_map(|v| v).collect::<Vec<_>>();

        let mut seen_keys = HashSet::<SimpleMerkleNodeKey>::new();
        let mut final_key_set= Vec::new();
        for i in 0..keys.len() {
            if !seen_keys.contains(&keys[i]) {
                seen_keys.insert(keys[i].clone());
                final_key_set.push(keys[i].clone());
            }
        }

        let expected_values = final_key_set.iter().map(|key| {
            tree.get_node_value(key)
        }).collect::<Vec<Hash>>();


        let expected_nodes = final_key_set.iter().zip(expected_values.iter()).map(|(key, value)| {
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id,
                    level: key.level,
                    index: key.index,
                },
                value: value.clone(),
            }
        }).collect::<Vec<_>>();

        let blob = if with_context.is_some() {
            recorder.finalize_with_header(&with_context.as_ref().unwrap(), tree_type)
        }else{
            recorder.finalize()
        };

        let got_nodes = if with_context.is_none() {
            QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(&blob)?
        }else{
            let context = with_context.unwrap();
            let chain_id = context.chain_id;
            let realm_id = context.realm_id;

            let realm_sub_id = context.realm_sub_id;
            let unique_pending_id = context.unique_pending_id;

            let (header, payload) = QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref(&blob, chain_id, realm_id, realm_sub_id, unique_pending_id, tree_type)?;
           

            assert_eq!(header.is_valid_for_realm_context(chain_id, realm_id, realm_sub_id, unique_pending_id), true, "Header is not valid for expected context");
            QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(&payload)?
        };

        assert_eq!(expected_nodes, got_nodes, "Expected nodes do not match recorded nodes");







        Ok(())

    }




    fn fuzz_merkle_hash_recorder_with_sibling_values_helper_proof<Hash: QPGenRandom + Q256BitHash + std::fmt::Debug + Default, Hasher: MerkleZeroHasher<Hash>>(
        height: u8,
        count: usize,
        with_context: Option<QBlobWriterContextMetadataHeader>,
        tree_type: QBlobMerkleNodeTreeType,
    ) -> anyhow::Result<()>{

        let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(height);

        let tree_id = rand::random::<u64>();


        let proofs = (0..count).map(|_|{
            let index = if height != 64 {
                rand::random::<u64>() & rand::random::<u64>() & ((1u64 << height) -1)
            }else{
                rand::random::<u64>()
            };
            let value = Hash::qp_rand_gen();
            let proof = tree.set_leaf(index, value);
            proof
        }).collect::<Vec<_>>();

        let mut recorder = if with_context.is_none() {
            QBlobSingleIdMerkleRecorder::new()
        }else{
            QBlobSingleIdMerkleRecorder::new_with_header_and_size_hint(count*height as usize)
        };


        let mut reversed_proofs = proofs.clone();
        reversed_proofs.reverse();

        for i in 0..reversed_proofs.len() {
            assert!(reversed_proofs[i].verify::<Hasher>(), "Delta merkle proof verification failed");
            let expected_root = reversed_proofs[i].new_root;
            let computed_root = compute_root_merkle_proof_generic::<Hash, Hasher>(reversed_proofs[i].new_value, reversed_proofs[i].index, &reversed_proofs[i].siblings);
            assert_eq!(expected_root, computed_root, "Computed root does not match expected root"); 

            recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
                tree_id,
                height,
                &reversed_proofs[i],
            )?;


        }
        let keys = reversed_proofs.iter().map(|x|{
            
            [
                vec![SimpleMerkleNodeKey::new(height, x.index)],
                SimpleMerkleNodeKey::new(height, x.index).get_above_path_including_root()
            ].concat()

        }).flat_map(|v| v).collect::<Vec<_>>();

        let mut seen_keys = HashSet::<SimpleMerkleNodeKey>::new();
        let mut final_key_set= Vec::new();
        for i in 0..keys.len() {
            if !seen_keys.contains(&keys[i]) {
                seen_keys.insert(keys[i].clone());
                final_key_set.push(keys[i].clone());
            }
        }

        let expected_values = final_key_set.iter().map(|key| {
            tree.get_node_value(key)
        }).collect::<Vec<Hash>>();


        let expected_nodes = final_key_set.iter().zip(expected_values.iter()).map(|(key, value)| {
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id,
                    level: key.level,
                    index: key.index,
                },
                value: value.clone(),
            }
        }).collect::<Vec<_>>();

        let blob = if with_context.is_some() {
            recorder.finalize_with_header(&with_context.as_ref().unwrap(), tree_type)
        }else{
            recorder.finalize()
        };

        let got_nodes = if with_context.is_none() {
            QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(&blob)?
        }else{
            let context = with_context.unwrap();
            let chain_id = context.chain_id;
            let realm_id = context.realm_id;

            let realm_sub_id = context.realm_sub_id;
            let unique_pending_id = context.unique_pending_id;

            let (header, payload) = QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref(&blob, chain_id, realm_id, realm_sub_id, unique_pending_id, tree_type)?;
           

            assert_eq!(header.is_valid_for_realm_context(chain_id, realm_id, realm_sub_id, unique_pending_id), true, "Header is not valid for expected context");
            QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(&payload)?
        };

        assert_eq!(expected_nodes, got_nodes, "Expected nodes do not match recorded nodes");







        Ok(())

    }

    #[test]
    fn test_merkle_hash_recorder_simple() -> anyhow::Result<()>{
        let height = 16;
        type Hash = Hash256;
        type Hasher = CoreSha256Hasher;

        let siblings = Hash::qp_rand_gen_vec(height);
        let value = Hash::qp_rand_gen();
        let index = rand::random::<u64>() & ((1u64 << height) -1);
        let tree_id = rand::random::<u64>();
        let mut recorder = QBlobSingleIdMerkleRecorder::new();
        let expected_root = compute_root_merkle_proof_generic::<Hash, Hasher>(value.clone(), index, &siblings);
        let expected_path = compute_path_merkle_proof_generic::<Hash, Hasher>(value, index, &siblings);
        let computed_recorded_root = recorder.record_and_compute_merkle_root::<Hash, Hasher>(tree_id, index, height as u8, &value, &siblings);
        assert_eq!(expected_path.len(), height + 1, "Expected path length does not match height");
        assert_eq!(expected_path.last().unwrap(), &expected_root, "last expected path node does not match root");
        assert_eq!(expected_path[0], value, "first expected path node does not match leaf value");
        assert_eq!(computed_recorded_root, expected_root, "Computed root does not match expected root");
        let decoded_path_nodes = QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(&recorder.blob)?;
        let decoded_path_hashes = decoded_path_nodes.iter().map(|x| x.value.clone()).collect::<Vec<_>>();
        assert_eq!(decoded_path_hashes, expected_path, "Decoded path hashes do not match expected path");
        let leaf_key = QMerkleStoreSingleIdKey {
            tree_id,
            level: height as u8,
            index,
        };

        let key_path_above = leaf_key.get_above_path_including_root();
        assert!(key_path_above.len() + 1 == expected_path.len(), "Key path length does not match expected path length");
        let mut combined_keys = Vec::new();
        combined_keys.push(leaf_key);
        combined_keys.extend_from_slice(&key_path_above);

        assert_eq!(combined_keys.len(), expected_path.len(), "Combined keys length does not match expected path length");

        let expected_single_id_nodes = combined_keys.into_iter().zip(expected_path.into_iter()).map(|(key, value)| {
            QMerkleStoreSingleIdNode {
                key,
                value,
            }
        }).collect::<Vec<_>>();

        assert_eq!(decoded_path_nodes, expected_single_id_nodes, "Decoded path nodes do not match expected nodes");

        





        Ok(())
    }


    #[test]
    fn test_merkle_hash_recorder_multiple_proofs() -> anyhow::Result<()>{
        for i in 0..16 {
            fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(3, i, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        }
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(3, 255, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(3, 2, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper_proof::<Hash256, CoreSha256Hasher>(3, 2, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(24, 10, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(32, 32, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper_proof::<Hash256, CoreSha256Hasher>(64, 23, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(54, 32, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(11, 6000, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();



        for i in 0..16 {
            fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, i, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        }
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 255, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 2, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 2, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(24, 10, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(32, 32, None, QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(64, 18, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper_proof::<PHash, PoseidonHasher>(54, 12, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(16, 142, None, QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();


        let context = QBlobWriterContextMetadataHeader::new_at_now(1337, 124, 99, 10, 18247124124, 100101201, 114881);

        for i in 0..16 {
            fuzz_merkle_hash_recorder_with_sibling_values_helper_proof::<Hash256, CoreSha256Hasher>(3, i, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        }
        fuzz_merkle_hash_recorder_with_sibling_values_helper_proof::<Hash256, CoreSha256Hasher>(3, 255, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(3, 2, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(3, 2, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(24, 10, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(32, 32, Some(context), QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(64, 23, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(54, 32, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<Hash256, CoreSha256Hasher>(11, 6000, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();




        for i in 0..16 {
            fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, i, Some(context), QBlobMerkleNodeTreeType::UserContractTree).unwrap();
        }
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 255, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 2, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(3, 2, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();

        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(24, 10, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(32, 32, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(64, 18, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(54, 12, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        fuzz_merkle_hash_recorder_with_sibling_values_helper::<PHash, PoseidonHasher>(16, 142, Some(context), QBlobMerkleNodeTreeType::ContractFunctionTree).unwrap();
        Ok(())
    }


    #[test]
    fn check_round_trip() -> anyhow::Result<()> {
        type Hash = Hash256;
        let count = 10_000;
        let tree_type = QBlobMerkleNodeTreeType::UserContractTree;
        println!("Generating {} random single ID nodes...", count);
        let context = QBlobWriterContextMetadataHeader::new_at_now(1, 42, 1001, 1, 2, 3, 4);
        let nodes: Vec<QMerkleStoreSingleIdNode<Hash>> = (0..count).map(|_| QPGenRandom::qp_rand_gen()).collect();
        let start_time = std::time::Instant::now();
        let serialized_blob = QBlobSingleMerkleNodeBatchDataView::generate_single_merkle_node_batch_blob_data_from_ref(context, tree_type, &nodes);
        let duration = start_time.elapsed();
        println!("Serialization took: {:?}, ({}ms per node * {} nodes)", duration, duration.as_secs_f64() / (count as f64 * 1000f64), count);

        let start_time = std::time::Instant::now();
        let (header, payload) = QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped(
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
        let deserialized_nodes = QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload(&payload)?;
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
        let number_of_batches = 2_000;
        let nodes_per_batch = 200;
        let tree_type = QBlobMerkleNodeTreeType::UserContractTree;
        let context = QBlobWriterContextMetadataHeader::new_at_now(1, 42, 1001, 1, 2, 3, 4);

        let batch_nodes: Vec<Vec<QMerkleStoreSingleIdNode<Hash>>> = (0..number_of_batches)
            .map(|_| (0..nodes_per_batch).map(|_| QPGenRandom::qp_rand_gen()).collect())
            .collect();
        let batches = batch_nodes.iter().map(|batch| QBlobSingleMerkleNodeBatchDataView::generate_single_merkle_node_batch_blob_data_from_ref(context,tree_type, batch)).collect::<Vec<_>>();
        
        let start_time = std::time::Instant::now();
        let serialized_blob = QBlobSingleMerkleNodeBatchDataView::combine_single_merkle_node_batch_blobs_unvalidated::<Hash>(batches, &context, tree_type)?;
        let duration = start_time.elapsed();
        println!("Serialization took: {:?}, ({}ms per batch * {} batches)", duration, duration.as_secs_f64() / (number_of_batches as f64 * 1000f64), number_of_batches);

        let start_time = std::time::Instant::now();
        let (header, payload) = QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped(
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
        let deserialized_nodes = QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload(&payload)?;
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


