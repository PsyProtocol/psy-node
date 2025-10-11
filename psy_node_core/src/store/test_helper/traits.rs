use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, protocol::core_types::QHashBase};

pub trait CreateRandomTestDataItem: Sized {
    fn create_random_test_data_item() -> Self;
}

pub trait CheckpointedTestableObject<TableIdentifier: Clone + Send + Sync, K: CreateRandomTestDataItem, V: CreateRandomTestDataItem>{
    fn get_latest_for_key(&self, table: &TableIdentifier, key: &K) -> anyhow::Result<Option<V>>;
    fn get_with_max_checkpoint(&self, table: &TableIdentifier, key: &K, max_checkpoint_id: u64) -> anyhow::Result<Option<V>>;
    fn set_value_at_checkpoint(&self, table: &TableIdentifier, key: &K, value: &V, checkpoint_id: u64) -> anyhow::Result<()>;
    fn get_latest_many(&self, table: &TableIdentifier, keys: &[K]) -> anyhow::Result<Vec<Option<V>>>;
    fn get_many_with_max_checkpoint(&self, table: &TableIdentifier, keys: &[K], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>>;
    fn set_one_at_checkpoint(&self, table: &TableIdentifier, key: &K, value: &V, checkpoint_id: u64) -> anyhow::Result<()>;
    fn set_many_at_checkpoint(&self, table: &TableIdentifier, items: &[(K, V)], checkpoint_id: u64) -> anyhow::Result<()>;
}

pub trait CheckpointedTestableZeroMerkle<TableIdentifier: Clone + Send + Sync, Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>{
    fn get_latest_for_key_merkle(&self, table: &TableIdentifier, key: &SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    fn get_with_max_checkpoint_merkle(&self, table: &TableIdentifier, key: &SimpleMerkleNodeKey, max_checkpoint_id: u64) -> anyhow::Result<Hash>;
    fn set_value_at_checkpoint_merkle(&self, table: &TableIdentifier, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn get_latest_many_merkle(&self, table: &TableIdentifier, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Option<Hash>>>;
    fn get_many_with_max_checkpoint_merkle(&self, table: &TableIdentifier, keys: &[SimpleMerkleNodeKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<Hash>>>;
    fn set_one_at_checkpoint_merkle(&self, table: &TableIdentifier, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn set_many_at_checkpoint_merkle(&self, table: &TableIdentifier, items: &[SimpleMerkleNode<Hash>], checkpoint_id: u64) -> anyhow::Result<()>;
}

pub trait CheckpointedTestableSingleMerkle<TableIdentifier: Clone + Send + Sync, Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>{
    fn get_latest_for_key_merkle(&self, table: &TableIdentifier, tree_id: u64, key: &SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    fn get_with_max_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, key: &SimpleMerkleNodeKey, max_checkpoint_id: u64) -> anyhow::Result<Hash>;
    fn set_value_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn get_latest_many_merkle(&self, table: &TableIdentifier, tree_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Option<Hash>>>;
    fn get_many_with_max_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, keys: &[SimpleMerkleNodeKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<Hash>>>;
    fn set_one_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn set_many_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, items: &[SimpleMerkleNode<Hash>], checkpoint_id: u64) -> anyhow::Result<()>;
}

pub trait CheckpointedTestableDoubleMerkle<TableIdentifier: Clone + Send + Sync, Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>{
    fn get_latest_for_key_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, key: &SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    fn get_with_max_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, key: &SimpleMerkleNodeKey, max_checkpoint_id: u64) -> anyhow::Result<Hash>;
    fn set_value_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn get_latest_many_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Option<Hash>>>;
    fn get_many_with_max_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, keys: &[SimpleMerkleNodeKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<Hash>>>;
    fn set_one_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, key: &SimpleMerkleNodeKey, value: &Hash, checkpoint_id: u64) -> anyhow::Result<()>;
    fn set_many_at_checkpoint_merkle(&self, table: &TableIdentifier, tree_id: u64, tree_sub_id: u64, items: &[SimpleMerkleNode<Hash>], checkpoint_id: u64) -> anyhow::Result<()>;
}

