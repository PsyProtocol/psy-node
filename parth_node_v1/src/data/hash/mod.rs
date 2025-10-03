use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, serializable::QPDSerializableFixed}};



#[async_trait]
pub trait QPMerkleTreeStore<Hash: PartialEq + Copy + QPDSerializableFixed, Hasher: MerkleZeroHasher<Hash> + Send + Sync>: Send + Sync {
    // sets the tree nodes at a specific block height, used for checkpointing by block
    async fn set_tree_nodes(&self, block_height: u64, tree_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
    // gets the latest tree nodes where block_height <= max_block_height, used for historical queries and for actual latest, max_block_height = u64::MAX is used
    // Note: if a node is not found at or below max_block_height, it should return the zero hash for that level, ie. Hasher::get_zero_hash(level) (Zero Hash allows us to have sparse trees without storing every node)
    async fn get_tree_nodes(&self, max_block_height: u64, tree_id: u64, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}