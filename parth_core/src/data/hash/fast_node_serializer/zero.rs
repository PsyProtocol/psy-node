use crate::{
    data::hash::
        merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}
    ,
    protocol::core_types::Q256BitHash, utils::signed_helpers::u8_to_i8_exact,
};

// This file implements a fast serializer and deserializer for Merkle Store
// Nodes used to speed up the processor

// Below are the sizes of the QMS Fast Serializer outputs for different merkle
// level (1 byte) + index (8 bytes) + hash (32 bytes) = 41 bytes
pub const QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE: usize = 41;
pub struct QMerkleStoreFastZeroNodeSerializer {}
impl QMerkleStoreFastZeroNodeSerializer {
    pub fn serialize_zero_id_node_to_fixed<Hash: Q256BitHash>(node: &SimpleMerkleNode<Hash>) -> [u8; QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE] {
        let mut bytes = [0u8; QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE];
        bytes[0] = node.key.level;
        bytes[1..9].copy_from_slice(&node.key.index.to_le_bytes());
        bytes[9..41].copy_from_slice(&node.value.into_owned_32bytes());
        bytes
    }

    pub fn serialize_zero_id_node_to_vec<Hash: Q256BitHash>(node: &SimpleMerkleNode<Hash>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        bytes.push(node.key.level);
        bytes.extend_from_slice(&node.key.index.to_le_bytes());
        bytes.extend_from_slice(&node.value.into_owned_32bytes());
        bytes
    }
    pub fn write_zero_id_node_to_slice<Hash: Q256BitHash>(node: &SimpleMerkleNode<Hash>, slice: &mut [u8]) {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        slice[0] = node.key.level;
        slice[1..9].copy_from_slice(&node.key.index.to_le_bytes());
        slice[9..41].copy_from_slice(&node.value.into_owned_32bytes());
    }

    pub fn deserialize_zero_id_node_from_slice<Hash: Q256BitHash>(slice: &[u8]) -> SimpleMerkleNode<Hash> {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        let level = slice[0];
        let index = u64::from_le_bytes(slice[1..9].try_into().unwrap());
        let hash = Hash::from_owned_32bytes(slice[9..41].try_into().unwrap());
        SimpleMerkleNode {
            key: SimpleMerkleNodeKey { level, index },
            value: hash,
        }
    }

    //"INSERT INTO {}.{} (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?)"
    pub fn deserialize_zero_id_node_signed_insert_tuple<Hash: Q256BitHash>(slice: &[u8], checkpoint_id_i64: i64) ->(i8, i64, i64, [u8; 32]) {
        assert!(slice.len() >= QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
        let level = u8_to_i8_exact(slice[0]);
        let index = i64::from_le_bytes(slice[1..9].try_into().unwrap());
        let hash: [u8; 32] = slice[9..41].try_into().unwrap();
        (level, index, checkpoint_id_i64, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data::hash::hash256::Hash256, protocol::core_types::QHashBase, utils::QPGenRandom};
    fn gen_rand_zero_id_nodes<Hash: QPGenRandom>(count: usize) -> Vec<SimpleMerkleNode<Hash>> {
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let node = SimpleMerkleNode {
                key: SimpleMerkleNodeKey::qp_rand_gen(),
                value: Hash::qp_rand_gen(),
            };
            nodes.push(node);
        }
        nodes
    }

    fn ensure_zero_id_round_trip<Hash: Q256BitHash + QHashBase + std::fmt::Debug>(node: SimpleMerkleNode<Hash>) {
        let serialized_fixed = QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_fixed(&node);
        let deserialized_fixed = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_from_slice(&serialized_fixed);
        assert_eq!(node, deserialized_fixed);

        let serialized_vec = QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_vec(&node);
        let deserialized_vec = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_from_slice(&serialized_vec);
        assert_eq!(node, deserialized_vec);

        let mut buffer = [0u8; QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE];
        QMerkleStoreFastZeroNodeSerializer::write_zero_id_node_to_slice(&node, &mut buffer);
        let deserialized_buffer = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_from_slice(&buffer);
        assert_eq!(node, deserialized_buffer);
    }

    #[test]
    fn test_zero_id_node_round_trip_serialization_hash256() {
        let base_examples = [
            SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: 0, index: 0 },
                value: Hash256::ZERO,
            },
            SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: 0, index: 0 },
                value: Hash256::rand(),
            },
            SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: 1, index: 1 },
                value: Hash256::rand(),
            },
            SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: 255, index: u64::MAX },
                value: Hash256::rand(),
            },
        ];
        for example in base_examples {
            ensure_zero_id_round_trip(example);
        }
        let rand_examples = gen_rand_zero_id_nodes::<Hash256>(5000);
        for example in rand_examples {
            ensure_zero_id_round_trip(example);
        }
    }
}
