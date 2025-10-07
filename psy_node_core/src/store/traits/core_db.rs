use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::{data_types::{BiDirectionalMappingRow, CoreDatabaseValueDeserialize, QDatabasePrimitiveKey}, row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey}}, hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QHashBase};
use serde::{de::DeserializeOwned, Serialize};



#[async_trait]
pub trait CoreDatabaseBidirectionalMappingReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_by_k1< K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1: &K1) -> anyhow::Result<Option<K2>>;
    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k2: &K2) -> anyhow::Result<Option<K1>>;
    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1s: &[K1]) -> anyhow::Result<Vec<Option<K2>>>;
    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k2s: &[K2]) -> anyhow::Result<Vec<Option<K1>>>;
    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1s: &[K1]) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k2s: &[K2]) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, start_k1: Option<K1>, max_count: usize) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
}

#[async_trait]
pub trait CoreDatabaseBidirectionalMappingWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1: &K1, k2: &K2) -> anyhow::Result<()>;
    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1: K1, k2: K2) -> anyhow::Result<()>;
    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, keys: &[BiDirectionalMappingRow<K1, K2>]) -> anyhow::Result<()>;
}

pub trait CoreDatabaseBidirectionalMappingStore<TableIdentifier: Clone + Send + Sync>: CoreDatabaseBidirectionalMappingReader<TableIdentifier> + CoreDatabaseBidirectionalMappingWriter<TableIdentifier> {

}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseBidirectionalMappingReader<TableIdentifier> + CoreDatabaseBidirectionalMappingWriter<TableIdentifier>> CoreDatabaseBidirectionalMappingStore<TableIdentifier> for T {

}


#[async_trait]
pub trait CoreDatabaseBidirectionalU64MappingReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_u64_mapping_value_by_u64<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, key: u64) -> anyhow::Result<Option<V>>;
    async fn db_select_one_u64_mapping_key_by_value<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, value: &V) -> anyhow::Result<Option<u64>>;
    async fn db_select_many_u64_mapping_values_by_u64s<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, keys: &[u64]) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_u64_mapping_u64_keys_by_values<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, values: &[V]) -> anyhow::Result<Vec<Option<u64>>>;
    async fn db_select_many_u64_mapping_pairs_by_u64s<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1s: &[u64]) -> anyhow::Result<Vec<BiDirectionalMappingRow<u64, V>>>;
    async fn db_select_many_u64_mapping_pairs_by_values<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k2s: &[V]) -> anyhow::Result<Vec<BiDirectionalMappingRow<u64, V>>>;
    async fn db_select_all_u64_mapping_pairs_from_u64_key<V: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, start_k1: Option<u64>, max_count: usize) -> anyhow::Result<Vec<BiDirectionalMappingRow<u64, V>>>;
}

#[async_trait]
pub trait CoreDatabaseBidirectionalU64MappingWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_u64_mapping_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1: &K1, k2: &K2) -> anyhow::Result<()>;
    async fn db_insert_u64_mapping_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, k1: K1, k2: K2) -> anyhow::Result<()>;
    async fn db_insert_u64_mapping_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(&self, table: &TableIdentifier, keys: &[BiDirectionalMappingRow<K1, K2>]) -> anyhow::Result<()>;
}

pub trait CoreDatabaseBidirectionalU64MappingStore<TableIdentifier: Clone + Send + Sync>: CoreDatabaseBidirectionalU64MappingReader<TableIdentifier> + CoreDatabaseBidirectionalU64MappingWriter<TableIdentifier> {

}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseBidirectionalU64MappingReader<TableIdentifier> + CoreDatabaseBidirectionalU64MappingWriter<TableIdentifier>> CoreDatabaseBidirectionalU64MappingStore<TableIdentifier> for T {

}

#[async_trait]
pub trait CoreDatabaseU64Reader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_u64_value(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>>;
    async fn db_select_u64_values(&self, table: &TableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>>;
}

#[async_trait]
pub trait CoreDatabaseU64Writer<TableIdentifier: Clone + Send + Sync>{
    async fn db_inc_counter(&self, table: &TableIdentifier, obj_id: u64, amount: i64) -> anyhow::Result<u64>;
    async fn db_set_u64_value(&self, table: &TableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()>;
    async fn db_set_many_u64_values(&self, table: &TableIdentifier, rows: &[BiDirectionalMappingRow<u64, u64>]) -> anyhow::Result<()>;
}
pub trait CoreDatabaseU64Store<TableIdentifier: Clone + Send + Sync>: CoreDatabaseU64Reader<TableIdentifier> + CoreDatabaseU64Writer<TableIdentifier> {

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
pub trait CoreDatabaseSingleIdCheckpointedStore<TableIdentifier: Clone + Send + Sync>: CoreDatabaseSingleIdCheckpointedReader<TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier> {

}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseSingleIdCheckpointedReader<TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier>> CoreDatabaseSingleIdCheckpointedStore<TableIdentifier> for T {

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
pub trait CoreDatabaseDoubleIdCheckpointedStore<TableIdentifier: Clone + Send + Sync>: CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier> {

}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier>> CoreDatabaseDoubleIdCheckpointedStore<TableIdentifier> for T {
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
pub trait CoreDatabaseKivStore<TableIdentifier: Clone + Send + Sync>: CoreDatabaseKivReader<TableIdentifier> + CoreDatabaseKivWriter<TableIdentifier> {

}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseKivReader<TableIdentifier> + CoreDatabaseKivWriter<TableIdentifier>> CoreDatabaseKivStore<TableIdentifier> for T {

}

#[async_trait]
pub trait CoreDatabaseSingleIdMerkleReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_select_single_id_merkle_node_max_checkpoint(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(&self, table: &TableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseSingleIdMerkleWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_single_id_merkle_node(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_single_id_merkle_nodes_batch(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}
pub trait CoreDatabaseSingleIdMerkleStore<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync>: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync, T: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier>> CoreDatabaseSingleIdMerkleStore<Hash, Hasher, TableIdentifier> for T {}



#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_select_double_id_merkle_node_max_checkpoint(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash>;
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(&self, table: &TableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
pub trait CoreDatabaseDoubleIdMerkleWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_double_id_merkle_node(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()>;
    async fn db_set_double_id_merkle_nodes_batch(&self, table: &TableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()>;
}
pub trait CoreDatabaseDoubleIdMerkleStore<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync>: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync, T: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier>> CoreDatabaseDoubleIdMerkleStore<Hash, Hasher, TableIdentifier> for T {}



// full implementations

pub trait CoreDatabaseReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync>: CoreDatabaseBidirectionalMappingReader<BiDirectionalMappingTableIdentifier> + CoreDatabaseBidirectionalU64MappingReader<BiDirectionalU64MappingTableIdentifier>+ CoreDatabaseU64Reader<U64TableIdentifier> + CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier> + CoreDatabaseKivReader<KivTableIdentifier> + CoreDatabaseSingleIdMerkleReader<Hash, Hasher, SingleIdMerkleTableIdentifier> + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, DoubleIdMerkleTableIdentifier> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync, T: CoreDatabaseBidirectionalMappingReader<BiDirectionalMappingTableIdentifier> + CoreDatabaseBidirectionalU64MappingReader<BiDirectionalU64MappingTableIdentifier> + CoreDatabaseU64Reader<U64TableIdentifier> + CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier> + CoreDatabaseKivReader<KivTableIdentifier> + CoreDatabaseSingleIdMerkleReader<Hash, Hasher, SingleIdMerkleTableIdentifier> + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, DoubleIdMerkleTableIdentifier>> CoreDatabaseReader<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> for T {
}

pub trait CoreDatabaseWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync>: CoreDatabaseBidirectionalMappingWriter<BiDirectionalMappingTableIdentifier> + CoreDatabaseBidirectionalU64MappingWriter<BiDirectionalU64MappingTableIdentifier> +  CoreDatabaseU64Writer<U64TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier> + CoreDatabaseKivWriter<KivTableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, SingleIdMerkleTableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, DoubleIdMerkleTableIdentifier> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync, T: CoreDatabaseBidirectionalMappingWriter<BiDirectionalMappingTableIdentifier> + CoreDatabaseBidirectionalU64MappingWriter<BiDirectionalU64MappingTableIdentifier> + CoreDatabaseU64Writer<U64TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier> + CoreDatabaseKivWriter<KivTableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, SingleIdMerkleTableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, DoubleIdMerkleTableIdentifier>> CoreDatabaseWriter<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> for T {
}
pub trait CoreDatabaseStore<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync>: CoreDatabaseReader<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> + CoreDatabaseWriter<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> {

}
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, BiDirectionalMappingTableIdentifier: Clone + Send + Sync, BiDirectionalU64MappingTableIdentifier: Clone + Send + Sync, U64TableIdentifier: Clone + Send + Sync, SingleIdTableIdentifier: Clone + Send + Sync, DoubleIdTableIdentifier: Clone + Send + Sync, KivTableIdentifier: Clone + Send + Sync, SingleIdMerkleTableIdentifier: Clone + Send + Sync, DoubleIdMerkleTableIdentifier: Clone + Send + Sync, T: CoreDatabaseReader<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> + CoreDatabaseWriter<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier>> CoreDatabaseStore<Hash, Hasher, BiDirectionalMappingTableIdentifier, BiDirectionalU64MappingTableIdentifier, U64TableIdentifier, SingleIdTableIdentifier, DoubleIdTableIdentifier, KivTableIdentifier, SingleIdMerkleTableIdentifier, DoubleIdMerkleTableIdentifier> for T {
}

