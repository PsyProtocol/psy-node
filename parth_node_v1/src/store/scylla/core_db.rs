use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::{data_types::CoreDatabaseValueDeserialize, row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow, QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable, QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey}}, hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QHashBase};
use psy_node_core::store::traits::core_db::{CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter};
use serde::{de::DeserializeOwned, Serialize};

use crate::store::scylla::{core::ScyllaCoreStore, tables::{merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements}, object::{ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements, ScyllaGenericObjectSingleIdTablePreparedStatements}}};

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdCheckpointedReader<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_single_checkpointed_object_value<V: serde::Serialize + DeserializeOwned + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>> {
        self.select_one_single_checkpointed_object_value(table, obj_id, max_checkpoint_id).await
    }
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        self.select_one_single_checkpointed_object_value_and_ids(table, obj_id, max_checkpoint_id).await
    }
    async fn db_select_one_single_checkpointed_object_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>> {
        self.select_one_single_checkpointed_object_value_and_ids_t(table, obj_id, max_checkpoint_id).await
    }
    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        self.select_all_single_checkpointed_object(table).await
    }
    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>> {
        self.select_many_single_checkpointed_object_values(table, obj_ids, max_checkpoint_id).await
    }
    async fn db_select_many_single_checkpointed_object_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>> {
        self.select_many_single_checkpointed_object_keys_and_values(table, obj_ids, max_checkpoint_id).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdCheckpointedWriter<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, obj_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()> {
        self.insert_one_single_checkpointed_object(table, obj_id, checkpoint_id, value).await
    }
    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, rows: &[QDatabaseSingleIdTableRow<V>]) -> anyhow::Result<()> {
        self.insert_many_single_checkpointed_object_rows(table, rows).await
    }
    async fn db_insert_many_single_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        self.insert_many_single_checkpointed_object_rows_t(table, rows).await
    }
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, checkpoint_id: u64, rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()> {
        self.insert_many_single_checkpointed_objects_at_checkpoint(table, checkpoint_id, rows).await
    }
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()> {
        self.insert_many_single_checkpointed_objects_at_checkpoint_t(table, checkpoint_id, rows).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdCheckpointedReader<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<V>> {
        self.select_one_double_checkpointed_object_value(table, obj_id, secondary_id, max_checkpoint_id).await
    }
    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        self.select_one_double_checkpointed_object_value_and_ids(table, obj_id, secondary_id, max_checkpoint_id).await
    }
    async fn db_select_one_double_checkpointed_object_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<R>> {
        self.select_one_double_checkpointed_object_value_and_ids_t(table, obj_id, secondary_id, max_checkpoint_id).await  // Note: using the non-_t method, adjust if needed
    }
    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        self.select_all_double_checkpointed_object(table).await
    }
    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<V>>> {
        self.select_many_double_checkpointed_object_values(table, obj_ids, max_checkpoint_id).await
    }
    async fn db_select_many_double_checkpointed_object_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_ids: &[QDoubleIdKey], max_checkpoint_id: u64) -> anyhow::Result<Vec<R>> {
        self.select_many_double_checkpointed_object_keys_and_values(table, obj_ids, max_checkpoint_id).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdCheckpointedWriter<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, obj_id: u64, secondary_id: u64, checkpoint_id: u64, value: &V) -> anyhow::Result<()> {
        self.insert_one_double_checkpointed_object(table, obj_id, secondary_id, checkpoint_id, value).await
    }
    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, rows: &[QDatabaseDoubleIdTableRow<V>]) -> anyhow::Result<()> {
        self.insert_many_double_checkpointed_object_rows(table, rows).await
    }
    async fn db_insert_many_double_checkpointed_object_rows_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        self.insert_many_double_checkpointed_object_rows_t(table, rows).await
    }
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, checkpoint_id: u64, rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>]) -> anyhow::Result<()> {
        self.insert_many_double_checkpointed_objects_at_checkpoint(table, checkpoint_id, rows).await
    }
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(&self, table: &ScyllaGenericObjectDoubleIdTablePreparedStatements, checkpoint_id: u64, rows: &[R]) -> anyhow::Result<()> {
        self.insert_many_double_checkpointed_objects_at_checkpoint_t(table, checkpoint_id, rows).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseKivReader<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<V>> {
        self.select_one_kiv_value(table, obj_id).await
    }
    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        self.select_one_kiv_value_and_ids(table, obj_id).await
    }
    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<R>> {
        self.select_one_kiv_value_and_ids_t(table, obj_id).await
    }
    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        self.select_all_kiv(table).await
    }
    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<V>>> {
        self.select_many_kiv_values(table, obj_ids).await
    }
    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<R>> {
        self.select_many_kiv_keys_and_values(table, obj_ids).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseKivWriter<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, obj_id: u64, value: &V) -> anyhow::Result<()> {
        self.insert_one_kiv(table, obj_id, value).await
    }
    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, rows: &[QDatabaseKeyIdValueTableRow<V>]) -> anyhow::Result<()> {
        self.insert_many_kivs(table, rows).await
    }
    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, rows: &[R]) -> anyhow::Result<()> {
        self.insert_many_kivs_t(table, rows).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdMerkleReader<Hash, Hasher, ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_single_id_merkle_node_max_checkpoint(&self, table: &ScyllaMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        self.select_single_id_merkle_node_max_checkpoint_internal(&table, checkpoint_id, tree_id, tree_height, key).await
    }
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(&self, table: &ScyllaMerkleNodesPreparedStatements, max_checkpoint_id: u64, tree_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        self.select_many_single_id_merkle_nodes_max_checkpoint_internal(&table, max_checkpoint_id, tree_id, tree_height, keys).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_single_id_merkle_node(&self, table: &ScyllaMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()> {
        self.insert_single_id_merkle_node_internal(table, checkpoint_id, tree_id, key, &value.to_bytes()?).await
    }
    async fn db_set_single_id_merkle_nodes_batch(&self, table: &ScyllaMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()> {
        self.set_single_id_merkle_nodes_batch_internal(&table, checkpoint_id, tree_id, nodes).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_select_double_id_merkle_node_max_checkpoint(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        self.select_double_id_merkle_node_max_checkpoint_internal(&table, checkpoint_id, tree_id, tree_height, tree_sub_id, key).await
    }
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, max_checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        self.select_many_double_id_merkle_nodes_max_checkpoint_internal(&table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, keys).await
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher> {
    async fn db_insert_double_id_merkle_node(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()> {
        self.insert_double_id_merkle_node_internal(&table, checkpoint_id, tree_id, tree_sub_id, key, &value.to_bytes()?).await
    }
    async fn db_set_double_id_merkle_nodes_batch(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> anyhow::Result<()> {
        self.set_double_id_merkle_nodes_batch_internal(&table, checkpoint_id, tree_id, tree_sub_id, nodes).await
    }
}
