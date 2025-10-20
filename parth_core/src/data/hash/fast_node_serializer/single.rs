use crate::{
    data::hash::
        merkle_store_key::{QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode}
    ,
    protocol::core_types::Q256BitHash, utils::signed_helpers::u8_to_i8_exact,
};

// tree_id (8 bytes) + level (1 byte) + index (8 bytes) + hash (32 bytes) = 49 bytes
pub const QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE: usize = 49;
pub type QMSFastSingleIdNodeSignedInsertTuple =  (i64, i8, i64, i64, [u8; 32]);

pub struct QMerkleStoreFastSingleNodeSerializer {}

impl QMerkleStoreFastSingleNodeSerializer {
    pub fn serialize_single_id_node_to_fixed<Hash: Q256BitHash>(
        node: &QMerkleStoreSingleIdNode<Hash>,
    ) -> [u8; QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE] {
        let mut bytes = [0u8; QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE];
        bytes[0..8].copy_from_slice(&node.key.tree_id.to_le_bytes());
        bytes[8] = node.key.level;
        bytes[9..17].copy_from_slice(&node.key.index.to_le_bytes());
        bytes[17..49].copy_from_slice(&node.value.into_owned_32bytes());

        bytes
    }
    pub fn serialize_single_id_node_to_vec<Hash: Q256BitHash>(node: &QMerkleStoreSingleIdNode<Hash>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        bytes.extend_from_slice(&node.key.tree_id.to_le_bytes());
        bytes.push(node.key.level);
        bytes.extend_from_slice(&node.key.index.to_le_bytes());
        bytes.extend_from_slice(&node.value.into_owned_32bytes());
        bytes
    }
    pub fn serialize_single_id_many_nodes<Hash: Q256BitHash>(nodes: &[QMerkleStoreSingleIdNode<Hash>]) -> Vec<u8> {
        let mut data = Vec::with_capacity(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE * nodes.len());
        for node in nodes {
            data.extend_from_slice(&Self::serialize_single_id_node_to_fixed(node));
        }
        data
    }

    pub fn write_single_id_node_to_slice<Hash: Q256BitHash>(node: &QMerkleStoreSingleIdNode<Hash>, slice: &mut [u8]) {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        slice[0..8].copy_from_slice(&node.key.tree_id.to_le_bytes());
        slice[8] = node.key.level;
        slice[9..17].copy_from_slice(&node.key.index.to_le_bytes());
        slice[17..49].copy_from_slice(&node.value.into_owned_32bytes());
    }
    pub fn deserialize_single_id_node_from_slice<Hash: Q256BitHash>(slice: &[u8]) -> QMerkleStoreSingleIdNode<Hash> {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        let tree_id = u64::from_le_bytes(slice[0..8].try_into().unwrap());
        let level = slice[8];
        let index = u64::from_le_bytes(slice[9..17].try_into().unwrap());
        let value = Hash::from_owned_32bytes(slice[17..49].try_into().unwrap());
        QMerkleStoreSingleIdNode {
            key: QMerkleStoreSingleIdKey { tree_id, level, index },
            value,
        }
    }

    //"INSERT INTO {}.{} (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)",
    pub fn deserialize_single_id_node_signed_insert_tuple<Hash: Q256BitHash>(slice: &[u8], checkpoint_id_i64: i64) -> QMSFastSingleIdNodeSignedInsertTuple {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        let tree_id = i64::from_le_bytes(slice[0..8].try_into().unwrap());
        let level = u8_to_i8_exact(slice[8]);
        let index = i64::from_le_bytes(slice[9..17].try_into().unwrap());
        let value: [u8; 32] = slice[17..49].try_into().unwrap();
        (tree_id, level, index, checkpoint_id_i64, value)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data::hash::hash256::Hash256, protocol::core_types::QHashBase, utils::QPGenRandom};
    fn gen_rand_single_id_nodes<Hash: QPGenRandom>(count: usize) -> Vec<QMerkleStoreSingleIdNode<Hash>> {
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let node = QMerkleStoreSingleIdNode::qp_rand_gen();
            nodes.push(node);
        }
        nodes
    }
    fn ensure_single_id_round_trip<Hash: Q256BitHash + QHashBase + std::fmt::Debug>(node: QMerkleStoreSingleIdNode<Hash>) {
        let serialized_fixed = QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_fixed(&node);
        let deserialized_fixed = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice(&serialized_fixed);
        assert_eq!(node, deserialized_fixed);

        let serialized_vec = QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&node);
        let deserialized_vec = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice(&serialized_vec);
        assert_eq!(node, deserialized_vec);

        let mut buffer = [0u8; QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE];
        QMerkleStoreFastSingleNodeSerializer::write_single_id_node_to_slice(&node, &mut buffer);
        let deserialized_buffer = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice(&buffer);
        assert_eq!(node, deserialized_buffer);
    }
    #[test]
    fn test_single_id_node_round_trip_serialization_hash256() {
        let base_examples = [
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id: 0,
                    level: 0,
                    index: 0,
                },
                value: Hash256::ZERO,
            },
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id: 0,
                    level: 0,
                    index: 0,
                },
                value: Hash256::rand(),
            },
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id: 0,
                    level: 1,
                    index: 1,
                },
                value: Hash256::rand(),
            },
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id: 0,
                    level: 255,
                    index: u64::MAX,
                },
                value: Hash256::rand(),
            },
        ];
        for example in base_examples {
            ensure_single_id_round_trip(example);
        }
        let rand_examples = gen_rand_single_id_nodes::<Hash256>(5000);
        for example in rand_examples {
            ensure_single_id_round_trip(example);
        }
    }
}
