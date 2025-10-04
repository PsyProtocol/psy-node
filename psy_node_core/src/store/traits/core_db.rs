use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey}, hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QHashBase};
use serde::{de::DeserializeOwned, Serialize};

pub trait CoreDatabaseValueDeserialize: DeserializeOwned + Send + Sync + Serialize {

}
impl<V: DeserializeOwned + Send + Sync + Serialize> CoreDatabaseValueDeserialize for V {

}

#[async_trait]
pub trait CoreDatabaseSingleIdCheckpointedReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>>;
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>>;
    async fn db_select_one_single_checkpointed_object_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>>;
    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>>;
    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_single_checkpointed_object_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
pub trait CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, rows: &[QDatabaseSingleIdTableRow<V>]) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowLike<V> + Send + Sync>(&self, table: &TableIdentifier, rows: &[R]) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, checkpoint_id: u64, rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &TableIdentifier, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>>;
    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>>;
    async fn db_select_one_double_checkpointed_object_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>>;
    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>>;
    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_double_checkpointed_object_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, secondary_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, rows: &[QDatabaseDoubleIdTableRow<V>]) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync>(&self, table: &TableIdentifier, rows: &[R]) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, checkpoint_id: u64, rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &TableIdentifier, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CoreDatabaseKivReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<V>>;
    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>>;
    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<R>>;
    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>>;
    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(&self, table: &TableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &TableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
pub trait CoreDatabaseKivWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, obj_id: u64, value: &V) -> anyhow::Result<()>;
    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(&self, table: &TableIdentifier, rows: &[QDatabaseKeyIdValueTableRow<V>]) -> anyhow::Result<()>;
    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(&self, table: &TableIdentifier, rows: &[R]) -> anyhow::Result<()>;
}
/* 
#[async_trait]
pub trait CoreDatabaseSingleIdMerkleReader<TableIdentifier: Clone + Send + Sync, Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_select_single_id_merkle_node_max_checkpoint(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(&self, table: &TableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseSingleIdMerkleWriter<TableIdentifier: Clone + Send + Sync, Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_insert_single_id_merkle_node(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_single_id_merkle_nodes_batch(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleReader<TableIdentifier: Clone + Send + Sync, Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_select_double_id_merkle_node_max_checkpoint(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(&self, table: &TableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleWriter<TableIdentifier: Clone + Send + Sync, Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_insert_double_id_merkle_node(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_double_id_merkle_nodes_batch(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}
*/


#[async_trait]
pub trait CoreDatabaseSingleIdMerkleReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_select_single_id_merkle_node_max_checkpoint(&self, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(&self, max_checkpoint_id: u64, tree_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseSingleIdMerkleWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_insert_single_id_merkle_node(&self, checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_single_id_merkle_nodes_batch(&self, checkpoint_id: u64, tree_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_select_double_id_merkle_node_max_checkpoint(&self, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(&self, max_checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    async fn db_insert_double_id_merkle_node(&self, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_double_id_merkle_nodes_batch(&self, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}

pub trait CoreDatabaseReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync>: CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier> + CoreDatabaseKivReader<KivTableIdentifier> + CoreDatabaseSingleIdMerkleReader<Hash, Hasher> + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, T: CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier> + CoreDatabaseKivReader<KivTableIdentifier> + CoreDatabaseSingleIdMerkleReader<Hash, Hasher> + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher>> CoreDatabaseReader<Hash, Hasher, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier> for T {
}

pub trait CoreDatabaseWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync>: CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier> + CoreDatabaseKivWriter<KivTableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, T: CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier> + CoreDatabaseKivWriter<KivTableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher>> CoreDatabaseWriter<Hash, Hasher, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier> for T {
}
