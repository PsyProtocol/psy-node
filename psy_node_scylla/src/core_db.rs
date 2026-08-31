use std::collections::HashMap;

use async_trait::async_trait;
use parth_core::{
    crypto::hash::{tag_tree::TagTreeMerkleProof, traits::MerkleZeroHasher},
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey},
            row::{
                QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike,
                QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow,
                QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable,
                QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey,
            },
        },
        hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::QMerkleStoreDoubleIdKeyWithHeight},
        serializable::QPDPair,
    },
    protocol::core_types::QDBHashBase,
};
use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter, CoreDatabaseBidirectionalPairPresence,
    CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter, CoreDatabaseBlobPairDeleter,
    CoreDatabaseBlobPairVerifier, CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter,
    CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseHashToManyIdsReader,
    CoreDatabaseHashToManyIdsWriter, CoreDatabaseHashUserPairDeleter, CoreDatabaseHashUserPairVerifier,
    CoreDatabaseIMTKeyIndexReader, CoreDatabaseIMTKeyIndexWriter, CoreDatabaseIMTLeafReader, CoreDatabaseIMTLeafWriter,
    CoreDatabaseIMTNextAppendIndexReader, CoreDatabaseIMTNextAppendIndexWriter, CoreDatabaseImtKeyDeleter,
    CoreDatabaseImtKeyVerifier, CoreDatabaseImtLeafDeleter, CoreDatabaseImtLeafVerifier,
    CoreDatabaseImtNextAppendIndexDeleter, CoreDatabaseImtNextAppendIndexVerifier, CoreDatabaseKivReader,
    CoreDatabaseKivWriter, CoreDatabaseMerkleDeleter, CoreDatabaseMerkleVerifier, CoreDatabaseObjectCheckpointDeleter,
    CoreDatabaseObjectCheckpointVerifier, CoreDatabaseObjectIdDeleter, CoreDatabaseObjectIdVerifier,
    CoreDatabasePendingIdPartitionDeleter, CoreDatabasePendingIdPartitionVerifier, CoreDatabaseSingleIdCheckpointedReader,
    CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter,
    CoreDatabaseTagTreeReader, CoreDatabaseTagTreeWriter, CoreDatabaseTreeMerkleDeleter, CoreDatabaseTreeMerkleVerifier,
    CoreDatabaseTreeSubtreeMerkleDeleter, CoreDatabaseTreeSubtreeMerkleVerifier, CoreDatabaseU64CounterReader,
    CoreDatabaseU64CounterWriter, CoreDatabaseU64Reader, CoreDatabaseU64U128PairDeleter,
    CoreDatabaseU64U128PairVerifier, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleDumpReader,
    CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter, MerkleTreeDumpStrategy,
};
use psy_serialize::PsySerializeCanonicalAsyncSafe;

use crate::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements, counter::u64_counter::ScyllaU64ToU64CounterTablePreparedStatements, hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements, imt::{ScyllaIMTKeyIndexPreparedStatements, ScyllaIMTLeafPreparedStatements, ScyllaIMTNextAppendIndexPreparedStatements}, merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}, object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        }, tag_tree::ScyllaTagTreeNodesPreparedStatements, u64_table::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements}
    },
};


#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseSingleIdCheckpointedReader<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_one_single_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        table
            .select_one_single_checkpointed_object_value(&self.session, obj_id, max_checkpoint_id)
            .await
    }
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        table
            .select_one_single_checkpointed_object_value_and_ids(&self.session, obj_id, max_checkpoint_id)
            .await
    }
    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        table
            .select_one_single_checkpointed_object_value_and_ids_t(&self.session, obj_id, max_checkpoint_id)
            .await
    }
    async fn db_select_all_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        table.select_all_single_checkpointed_object(&self.session).await
    }
    async fn db_select_many_single_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        table
            .select_many_single_checkpointed_object_values(&self.session, obj_ids, max_checkpoint_id)
            .await
    }
    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        table
            .select_many_single_checkpointed_object_keys_and_values(&self.session, obj_ids, max_checkpoint_id)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseSingleIdCheckpointedWriter<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    
    // first 8 bytes are the object_id, last_8 bytes 
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        object_size_without_id: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()>{
        table.insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(&self.session, object_size_without_id, checkpoint_id, rows).await
    }

    // for user leafs and similar, where we want to insert many objects at a checkpoint, but the id is at the end of the row
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        object_size: usize,
        object_id_location: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()>{
        table.insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(&self.session, object_size, object_id_location, checkpoint_id, rows).await

    }
    async fn db_insert_one_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        table
            .insert_one_single_checkpointed_object(&self.session, obj_id, checkpoint_id, value)
            .await
    }
    async fn db_insert_many_single_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        table.insert_many_single_checkpointed_object_rows(&self.session, rows).await
    }
    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        rows: &[R],
    ) -> anyhow::Result<()> {
        table.insert_many_single_checkpointed_object_rows_t(&self.session, rows).await
    }
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        table
            .insert_many_single_checkpointed_objects_at_checkpoint(&self.session, checkpoint_id, rows)
            .await
    }
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectSingleIdTablePreparedStatements,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        table
            .insert_many_single_checkpointed_objects_at_checkpoint_t(&self.session, checkpoint_id, rows)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseDoubleIdCheckpointedReader<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_one_double_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        table
            .select_one_double_checkpointed_object_value(&self.session, obj_id, secondary_id, max_checkpoint_id)
            .await
    }
    async fn db_select_one_double_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        table
            .select_one_double_checkpointed_object_value_and_ids(&self.session, obj_id, secondary_id, max_checkpoint_id)
            .await
    }
    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        table
            .select_one_double_checkpointed_object_value_and_ids_t(&self.session, obj_id, secondary_id, max_checkpoint_id)
            .await // Note: using the non-_t method, adjust if needed
    }
    async fn db_select_all_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        table.select_all_double_checkpointed_object(&self.session).await
    }
    async fn db_select_many_double_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        table
            .select_many_double_checkpointed_object_values(&self.session, obj_ids, max_checkpoint_id)
            .await
    }
    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        table
            .select_many_double_checkpointed_object_keys_and_values(&self.session, obj_ids, max_checkpoint_id)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseDoubleIdCheckpointedWriter<ScyllaGenericObjectDoubleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_one_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        table
            .insert_one_double_checkpointed_object(&self.session, obj_id, secondary_id, checkpoint_id, value)
            .await
    }
    async fn db_insert_many_double_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        table.insert_many_double_checkpointed_object_rows(&self.session, rows).await
    }
    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        rows: &[R],
    ) -> anyhow::Result<()> {
        table.insert_many_double_checkpointed_object_rows_t(&self.session, rows).await
    }
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        table
            .insert_many_double_checkpointed_objects_at_checkpoint(&self.session, checkpoint_id, rows)
            .await
    }
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &ScyllaGenericObjectDoubleIdTablePreparedStatements,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        table
            .insert_many_double_checkpointed_objects_at_checkpoint_t(&self.session, checkpoint_id, rows)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseKivReader<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_one_kiv_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_id: u64,
    ) -> anyhow::Result<Option<V>> {
        table.select_one_kiv_value(&self.session, obj_id).await
    }
    async fn db_select_one_kiv_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_id: u64,
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        table.select_one_kiv_value_and_ids(&self.session, obj_id).await
    }
    async fn db_select_one_kiv_value_and_ids_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_id: u64,
    ) -> anyhow::Result<Option<R>> {
        table.select_one_kiv_value_and_ids_t(&self.session, obj_id).await
    }
    async fn db_select_all_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        table.select_all_kiv(&self.session).await
    }
    async fn db_select_many_kiv_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        table.select_many_kiv_values(&self.session, obj_ids).await
    }
    async fn db_select_many_kiv_keys_and_values<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<R>> {
        table.select_many_kiv_keys_and_values(&self.session, obj_ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseKivWriter<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_one_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        obj_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        table.insert_one_kiv(&self.session, obj_id, value).await
    }
    async fn db_insert_many_kivs<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> anyhow::Result<()> {
        table.insert_many_kivs(&self.session, rows).await
    }
    async fn db_insert_many_kivs_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &ScyllaGenericKeyIdValueTablePreparedStatements,
        rows: &[R],
    ) -> anyhow::Result<()> {
        table.insert_many_kivs_t(&self.session, rows).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseZeroIdMerkleReader<Hash, Hasher, ScyllaMerkleNodesZeroPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        table
            .select_zero_id_merkle_node_max_checkpoint_internal::<Hash, Hasher>(&self.session, max_checkpoint_id, *key)
            .await
    }
    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        table
            .select_many_zero_id_merkle_nodes_max_checkpoint_internal::<Hash, Hasher>(&self.session, max_checkpoint_id, keys)
            .await
    }
    async fn db_select_zero_id_merkle_node_and_checkpoint_max_checkpoint(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<CheckpointedMerkleHash<Hash>> {
        table
            .select_zero_id_merkle_node_and_checkpoint_max_checkpoint_internal::<Hash, Hasher>(&self.session, max_checkpoint_id, *key)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, ScyllaMerkleNodesZeroPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_set_zero_id_merkle_nodes_batch_checkpoint_is_index(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()>{
        table.set_zero_id_merkle_nodes_batch_internal_checkpoint_is_index::<Hash>(&self.session, nodes).await
    }
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        table
            .insert_zero_id_merkle_node_internal(&self.session, checkpoint_id, *key, &value.to_bytes()?)
            .await
    }
    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        table
            .set_zero_id_merkle_nodes_batch_internal::<Hash>(&self.session, checkpoint_id, nodes)
            .await
    }

    async fn db_set_zero_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()>{
        table.set_zero_id_merkle_nodes_batch_fast_serialize::<Hash>(&self.session, checkpoint_id, nodes).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseZeroIdMerkleDumpReader<Hash, Hasher, ScyllaMerkleNodesZeroPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_dump_all_zero_id_merkle_node_leaves_chunked(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>> {
        table.dump_all_zero_id_merkle_node_leaves_sparse_sub_trees::<Hash>(&self.session, max_checkpoint_id).await
    }

    async fn db_dump_all_zero_id_merkle_node_leaves_vec(
        &self,
        table: &ScyllaMerkleNodesZeroPreparedStatements,
        max_checkpoint_id: u64,
        strategy: MerkleTreeDumpStrategy,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>>{
        table.dump_all_zero_id_merkle_node_leaves_vec::<Hash>(&self.session, max_checkpoint_id, strategy).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseSingleIdMerkleReader<Hash, Hasher, ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &ScyllaMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        table
            .select_single_id_merkle_node_max_checkpoint_internal::<Hash, Hasher>(&self.session, checkpoint_id, tree_id, tree_height, key)
            .await
    }
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ScyllaMerkleNodesPreparedStatements,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        table
            .select_many_single_id_merkle_nodes_max_checkpoint_internal::<Hash, Hasher>(&self.session, max_checkpoint_id, tree_id, tree_height, keys)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &ScyllaMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        table
            .insert_single_id_merkle_node_internal(&self.session, checkpoint_id, tree_id, key, &value.to_bytes()?)
            .await
    }
    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &ScyllaMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        table
            .set_single_id_merkle_nodes_batch_internal::<Hash>(&self.session, checkpoint_id, tree_id, nodes)
            .await
    }

    async fn db_set_single_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &ScyllaMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()>{
        table.set_single_id_merkle_nodes_batch_fast_serialize::<Hash>(&self.session, checkpoint_id, nodes).await

    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        table
            .select_double_id_merkle_node_max_checkpoint_internal::<Hash, Hasher>(
                &self.session,
                checkpoint_id,
                tree_id,
                tree_height,
                tree_sub_id,
                key,
            )
            .await
    }
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        table
            .select_many_double_id_merkle_nodes_max_checkpoint_internal::<Hash, Hasher>(
                &self.session,
                max_checkpoint_id,
                tree_id,
                tree_sub_id,
                tree_height,
                keys,
            )
            .await
    }

    async fn db_select_many_double_id_merkle_nodes_with_height_max_checkpoint(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        max_checkpoint_id: u64,
        keys: &[QMerkleStoreDoubleIdKeyWithHeight],
    ) -> anyhow::Result<Vec<Hash>>{
        table
            .select_many_double_id_merkle_nodes_with_height_max_checkpoint::<Hash, Hasher>(
                &self.session,
                max_checkpoint_id,
                keys,
            )
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        table
            .insert_double_id_merkle_node_internal(&self.session, checkpoint_id, tree_id, tree_sub_id, key, &value.to_bytes()?)
            .await
    }
    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        table
            .set_double_id_merkle_nodes_batch_internal(&self.session, checkpoint_id, tree_id, tree_sub_id, nodes)
            .await
    }
    async fn db_set_double_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &ScyllaDoubleMerkleNodesPreparedStatements,
        checkpoint_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        table
            .set_double_id_merkle_nodes_batch_fast_serialize::<Hash>(&self.session, checkpoint_id, data)
            .await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBidirectionalMappingReader<ScyllaBiDirectionalBlobToBlobTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k1: &K1,
    ) -> anyhow::Result<Option<K2>> {
        table.select_one_by_k1(self.session.clone(), k1).await
    }
    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k2: &K2,
    ) -> anyhow::Result<Option<K1>> {
        table.select_one_by_k2(self.session.clone(), k2).await
    }
    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<Option<K2>>> {
        table.select_many_by_k1(self.session.clone(), k1s).await
    }
    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<Option<K1>>> {
        table.select_many_by_k2(self.session.clone(), k2s).await
    }
    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        table.select_many_key_values_by_k1(self.session.clone(), k1s).await
    }
    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        table.select_many_key_values_by_k2(self.session.clone(), k2s).await
    }
    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        _table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        _start_k1: Option<K1>,
        _max_count: usize,
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        anyhow::bail!("db_select_all_pairs_from_k1: Not implemented");
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBidirectionalMappingWriter<ScyllaBiDirectionalBlobToBlobTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k1: &K1,
        k2: &K2,
    ) -> anyhow::Result<()> {
        table.set_or_insert_one_qpk(self.session.clone(), k1, k2).await
    }
    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        k1: K1,
        k2: K2,
    ) -> anyhow::Result<()> {
        table.set_or_insert_one_qpk(self.session.clone(), &k1, &k2).await
    }
    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        table.set_or_insert_many_qpk(self.session.clone(), keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseU64Reader<ScyllaU64ToU64TablePreparedStatements>
    for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_u64_value(&self, table: &ScyllaU64ToU64TablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<u64>> {
        table.select_one_single(&self.session, obj_id).await
    }
    async fn db_select_u64_values(&self, table: &ScyllaU64ToU64TablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        table.select_many_values(self.session.clone(), obj_ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseU64Writer<ScyllaU64ToU64TablePreparedStatements>
    for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_set_u64_value(&self, table: &ScyllaU64ToU64TablePreparedStatements, obj_id: u64, value: u64) -> anyhow::Result<()> {
        table.set_or_insert_one(&self.session, obj_id, value).await
    }
    async fn db_set_many_u64_values(&self, table: &ScyllaU64ToU64TablePreparedStatements, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        table.set_or_insert_many_qpd_pair(&self.session, rows).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseU64CounterReader<ScyllaU64ToU64CounterTablePreparedStatements>
    for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_u64_counter_value(&self, table: &ScyllaU64ToU64CounterTablePreparedStatements, obj_id: u64) -> anyhow::Result<Option<u64>> {
        table.select_one_single(&self.session, obj_id).await
    }
    async fn db_select_u64_counter_values(&self, table: &ScyllaU64ToU64CounterTablePreparedStatements, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        table.select_many_values(self.session.clone(), obj_ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync> CoreDatabaseU64CounterWriter<ScyllaU64ToU64CounterTablePreparedStatements>
    for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_inc_u64_counter(&self, table: &ScyllaU64ToU64CounterTablePreparedStatements, obj_id: u64, amount: i64) -> anyhow::Result<u64> {
        table.atomic_increment(&self.session, obj_id, amount as u64).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBidirectionalU64U128MappingReader<ScyllaBidirectionalU64U128MappingPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_one_u128_value_by_u64(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        key: u64,
    ) -> anyhow::Result<Option<u128>> {
        table.get_k2_from_k1(&self.session, key).await
    }
    async fn db_select_one_u64_key_by_u128(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        value: u128,
    ) -> anyhow::Result<Option<u64>> {
        table.get_k1_from_k2(&self.session, value).await
    }
    async fn db_select_many_u128_values_by_u64s(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        keys: &[u64],
    ) -> anyhow::Result<Vec<Option<u128>>> {
        table.get_k2s_from_k1s(self.session.clone(), keys).await
    }
    async fn db_select_many_u64_keys_by_u128s(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        values: &[u128],
    ) -> anyhow::Result<Vec<Option<u64>>> {
        table.get_k1s_from_k2s(self.session.clone(), values).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBidirectionalU64U128MappingWriter<ScyllaBidirectionalU64U128MappingPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_u64_u128_mapping_pair(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        k1: u64,
        k2: u128,
    ) -> anyhow::Result<()> {
        table.insert_u64_u128_mapping_pair(&self.session, k1, k2).await
    }
    async fn db_insert_u64_u128_mapping_pairs(
        &self,
        table: &ScyllaBidirectionalU64U128MappingPreparedStatements,
        keys: &[BiDirectionalMappingRow<u64, u128>],
    ) -> anyhow::Result<()> {
        table.insert_u64_u128_mapping_pairs(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTagTreeReader<Hash, Hasher, ScyllaTagTreeNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        table.select_one_tag_tree_value(&self.session, unique_pending_id, *key).await
    }
    async fn db_get_tag_tree_node_values(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        table.select_many_tag_tree_values(&self.session, unique_pending_id, keys).await
    }
    async fn db_get_tag_tree_node_tag(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let r = table.select_one_tag_tree_tag_and_value(&self.session, unique_pending_id, key).await?;
        if let Some(tts) = r {
            Ok(Some(tts.tag))
        } else {
            Ok(None)
        }
    }

    
    async fn db_get_tag_tree_node_tags(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        table.select_many_tag_tree_tags::<Hash>(&self.session, unique_pending_id, keys).await
    }
    async fn db_get_tag_tree_root(&self, table: &ScyllaTagTreeNodesPreparedStatements, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        let root_key = SimpleMerkleNodeKey::new_root();
        table.select_one_tag_tree_value(&self.session, unique_pending_id, root_key).await
    }
    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        table.select_tag_tree_proof::<Hash>(&self.session, unique_pending_id, *key).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTagTreeWriter<Hash, Hasher, ScyllaTagTreeNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_set_tag_tree_tag_known_height(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        tag_tree_height: u8,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        table
            .set_tag_only_computed::<Hash, Hasher>(&self.session, unique_pending_id, *key, Some(tag_tree_height), tag)
            .await
    }
    async fn db_set_tag_tree_tag_value(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let tag_vec = tag.to_bytes()?;
        let value_vec = value.to_bytes()?;
        table.set_or_insert_one(&self.session, unique_pending_id, key, &tag_vec, &value_vec).await
    }
    async fn db_set_tag_tree_tag(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        table
            .set_tag_only_computed::<Hash, Hasher>(&self.session, unique_pending_id, *key, None, tag)
            .await
    }
    async fn db_set_tag_tree_value_only(
        &self,
        table: &ScyllaTagTreeNodesPreparedStatements,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let value_vec = value.to_bytes()?;
        table.update_value_only(&self.session, unique_pending_id, key, &value_vec).await
    }
}





#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseHashToManyIdsReader<Hash, ScyllaHashToManyIdsTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_value_u64_ids_for_hash(
        &self,
        table: &ScyllaHashToManyIdsTablePreparedStatements,
        hash: Hash,
        count: usize,
        start_u64_value: u64, // The ID to start the query from (inclusive)
    ) -> anyhow::Result<Vec<u64>>{
        if count > i32::MAX as usize{
            anyhow::bail!("cannot select so many user ids!");
        }
        table.select_value_u64_ids_for_hash(&self.session, hash, count as i32, start_u64_value).await

    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseHashToManyIdsWriter<Hash, ScyllaHashToManyIdsTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_one_hash_to_u64(
        &self,
        table: &ScyllaHashToManyIdsTablePreparedStatements,
        hash_id: Hash, 
        value: u64,
    ) -> anyhow::Result<()>{

        table.insert_one_hash_to_u64(&self.session, hash_id, value).await
    }
    async fn db_insert_many_hash_to_u64s(
        &self,
        table: &ScyllaHashToManyIdsTablePreparedStatements,
        rows: &[(Hash, u64)],
    ) -> anyhow::Result<()>{

        table.insert_many_hash_to_u64s(&self.session, rows).await
    }
    async fn db_set_hash_256_to_u64_pairs_from_fast_serialized_data(
        &self,
        table: &ScyllaHashToManyIdsTablePreparedStatements,
        data: &[u8],
    ) -> anyhow::Result<()>{
        table.set_hash_256_to_u64_pairs_from_fast_serialized_data(&self.session, data).await
    }
}

// IMT Leaf table implementation for ScyllaCoreStore
#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTLeafReader<ScyllaIMTLeafPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_imt_leaf(
        &self,
        table: &ScyllaIMTLeafPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        max_checkpoint_id: i64,
    ) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>> {
        table.select_leaf(&self.session, tree_id, tree_sub_id, leaf_index, max_checkpoint_id).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTLeafWriter<ScyllaIMTLeafPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_imt_leaf(
        &self,
        table: &ScyllaIMTLeafPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        checkpoint_id: i64,
        leaf_hash: &[u8],
        leaf_key: &[u8],
        leaf_value: &[u8],
        next_key: &[u8],
        next_index: i64,
    ) -> anyhow::Result<()> {
        table.insert_leaf(&self.session, tree_id, tree_sub_id, leaf_index, checkpoint_id, leaf_hash, leaf_key, leaf_value, next_key, next_index).await
    }
}

// IMT Key Index table implementation for ScyllaCoreStore
#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTKeyIndexReader<ScyllaIMTKeyIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_imt_key_index_exact(
        &self,
        table: &ScyllaIMTKeyIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        encoded_key: &[u8],
    ) -> anyhow::Result<Option<(i64, i64)>> {
        table.select_exact(&self.session, tree_id, tree_sub_id, key_bucket, encoded_key).await
    }

    async fn db_select_imt_key_index_predecessor(
        &self,
        table: &ScyllaIMTKeyIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        target_encoded_key: &[u8],
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>, i64, i64)>> {
        table.select_predecessor(&self.session, tree_id, tree_sub_id, key_bucket, target_encoded_key).await
    }

    async fn db_select_imt_key_index_predecessor_full_bucket(
        &self,
        table: &ScyllaIMTKeyIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>, i64, i64)>> {
        table.select_predecessor_full_bucket(&self.session, tree_id, tree_sub_id, key_bucket).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTKeyIndexWriter<ScyllaIMTKeyIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_imt_key_index(
        &self,
        table: &ScyllaIMTKeyIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        key_bucket: i16,
        encoded_key: &[u8],
        leaf_key: &[u8],
        birth_checkpoint: i64,
        leaf_index: i64,
    ) -> anyhow::Result<()> {
        table.insert_key(&self.session, tree_id, tree_sub_id, key_bucket, encoded_key, leaf_key, birth_checkpoint, leaf_index).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTNextAppendIndexReader<ScyllaIMTNextAppendIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_select_imt_next_append_index(
        &self,
        table: &ScyllaIMTNextAppendIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
    ) -> anyhow::Result<Option<i64>> {
        table.select(&self.session, tree_id, tree_sub_id).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseIMTNextAppendIndexWriter<ScyllaIMTNextAppendIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_insert_imt_next_append_index(
        &self,
        table: &ScyllaIMTNextAppendIndexPreparedStatements,
        tree_id: i64,
        tree_sub_id: i64,
        next_append_index: i64,
    ) -> anyhow::Result<()> {
        table.insert(&self.session, tree_id, tree_sub_id, next_append_index).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectIdDeleter<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_object_ids(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, ids: &[u64]) -> anyhow::Result<()> {
        table.delete_many_object_ids(&self.session, ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectIdDeleter<ScyllaU64ToU64TablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_object_ids(&self, table: &ScyllaU64ToU64TablePreparedStatements, ids: &[u64]) -> anyhow::Result<()> {
        table.delete_many_object_ids(&self.session, ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectCheckpointDeleter<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_object_checkpoint(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, keys: &[(u64, u64)]) -> anyhow::Result<()> {
        table.delete_many_object_checkpoint(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseMerkleDeleter<ScyllaMerkleNodesZeroPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_merkle_nodes(&self, table: &ScyllaMerkleNodesZeroPreparedStatements, keys: &[(u8, u64, u64)]) -> anyhow::Result<()> {
        table.delete_many_merkle_nodes(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTreeMerkleDeleter<ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_tree_merkle_nodes(&self, table: &ScyllaMerkleNodesPreparedStatements, keys: &[(u64, u8, u64, u64)]) -> anyhow::Result<()> {
        table.delete_many_tree_merkle_nodes(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTreeSubtreeMerkleDeleter<ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_tree_subtree_merkle_nodes(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, keys: &[(u64, u64, u8, u64, u64)]) -> anyhow::Result<()> {
        table.delete_many_tree_subtree_merkle_nodes(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtLeafDeleter<ScyllaIMTLeafPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_imt_leaves(&self, table: &ScyllaIMTLeafPreparedStatements, keys: &[(i64, i64, i64, i64)]) -> anyhow::Result<()> {
        table.delete_many_leaves(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtKeyDeleter<ScyllaIMTKeyIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_imt_keys(&self, table: &ScyllaIMTKeyIndexPreparedStatements, keys: &[(i64, i64, i16, Vec<u8>)]) -> anyhow::Result<()> {
        table.delete_many_keys(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtNextAppendIndexDeleter<ScyllaIMTNextAppendIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_imt_next_append_indexes(&self, table: &ScyllaIMTNextAppendIndexPreparedStatements, keys: &[(i64, i64)]) -> anyhow::Result<()> {
        table.delete_many(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseHashUserPairDeleter<ScyllaHashToManyIdsTablePreparedStatements, Hash> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_hash_user_pairs(&self, table: &ScyllaHashToManyIdsTablePreparedStatements, keys: &[(Hash, u64)]) -> anyhow::Result<()> {
        table.delete_many_hash_user_pairs(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBlobPairDeleter<ScyllaBiDirectionalBlobToBlobTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_blob_pairs(&self, table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements, keys: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        table.delete_many_pairs(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseU64U128PairDeleter<ScyllaBidirectionalU64U128MappingPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_u64_u128_pairs(&self, table: &ScyllaBidirectionalU64U128MappingPreparedStatements, keys: &[(u64, u128)]) -> anyhow::Result<()> {
        table.delete_u64_u128_mapping_pairs(&self.session, keys).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabasePendingIdPartitionDeleter<ScyllaTagTreeNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_delete_many_pending_id_partitions(&self, table: &ScyllaTagTreeNodesPreparedStatements, pending_ids: &[u64]) -> anyhow::Result<()> {
        table.delete_many_pending_id_partitions(&self.session, pending_ids).await
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectIdVerifier<ScyllaGenericKeyIdValueTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_object_ids(&self, table: &ScyllaGenericKeyIdValueTablePreparedStatements, ids: &[u64]) -> anyhow::Result<Vec<u64>> {
        let mut existing = Vec::new();
        for &id in ids {
            if table.contains_object_id(&self.session, id).await? {
                existing.push(id);
            }
        }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectIdVerifier<ScyllaU64ToU64TablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_object_ids(&self, table: &ScyllaU64ToU64TablePreparedStatements, ids: &[u64]) -> anyhow::Result<Vec<u64>> {
        let mut existing = Vec::new();
        for &id in ids {
            if table.select_one_single(&self.session, id).await?.is_some() {
                existing.push(id);
            }
        }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseObjectCheckpointVerifier<ScyllaGenericObjectSingleIdTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_object_checkpoints(&self, table: &ScyllaGenericObjectSingleIdTablePreparedStatements, keys: &[(u64, u64)]) -> anyhow::Result<Vec<(u64, u64)>> {
        let mut existing = Vec::new();
        for &key in keys {
            if table.contains_exact_object_checkpoint(&self.session, key.0, key.1).await? { existing.push(key); }
        }
        Ok(existing)
    }
}


#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseMerkleVerifier<ScyllaMerkleNodesZeroPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_merkle_nodes(&self, table: &ScyllaMerkleNodesZeroPreparedStatements, keys: &[(u8, u64, u64)]) -> anyhow::Result<Vec<(u8, u64, u64)>> {
        let mut existing = Vec::new();
        for &key in keys { if table.contains_exact_merkle_node(&self.session, key).await? { existing.push(key); } }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTreeMerkleVerifier<ScyllaMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_tree_merkle_nodes(&self, table: &ScyllaMerkleNodesPreparedStatements, keys: &[(u64, u8, u64, u64)]) -> anyhow::Result<Vec<(u64, u8, u64, u64)>> {
        let mut existing = Vec::new();
        for &key in keys { if table.contains_exact_tree_merkle_node(&self.session, key).await? { existing.push(key); } }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseTreeSubtreeMerkleVerifier<ScyllaDoubleMerkleNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_tree_subtree_merkle_nodes(&self, table: &ScyllaDoubleMerkleNodesPreparedStatements, keys: &[(u64, u64, u8, u64, u64)]) -> anyhow::Result<Vec<(u64, u64, u8, u64, u64)>> {
        let mut existing = Vec::new();
        for &key in keys { if table.contains_exact_tree_subtree_merkle_node(&self.session, key).await? { existing.push(key); } }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtLeafVerifier<ScyllaIMTLeafPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_imt_leaves(&self, table: &ScyllaIMTLeafPreparedStatements, keys: &[(i64, i64, i64, i64)]) -> anyhow::Result<Vec<(i64, i64, i64, i64)>> {
        let mut existing = Vec::new();
        for &key in keys { if table.contains_exact_leaf(&self.session, key).await? { existing.push(key); } }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtKeyVerifier<ScyllaIMTKeyIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_imt_keys(&self, table: &ScyllaIMTKeyIndexPreparedStatements, keys: &[(i64, i64, i16, Vec<u8>)]) -> anyhow::Result<Vec<(i64, i64, i16, Vec<u8>)>> {
        let mut existing = Vec::new();
        for key in keys {
            if table.select_exact(&self.session, key.0, key.1, key.2, &key.3).await?.is_some() { existing.push(key.clone()); }
        }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseImtNextAppendIndexVerifier<ScyllaIMTNextAppendIndexPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_imt_next_append_indexes(&self, table: &ScyllaIMTNextAppendIndexPreparedStatements, keys: &[(i64, i64)]) -> anyhow::Result<Vec<(i64, i64)>> {
        let mut existing = Vec::new();
        for &key in keys { if table.select(&self.session, key.0, key.1).await?.is_some() { existing.push(key); } }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseHashUserPairVerifier<ScyllaHashToManyIdsTablePreparedStatements, Hash> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_hash_user_pairs(&self, table: &ScyllaHashToManyIdsTablePreparedStatements, keys: &[(Hash, u64)]) -> anyhow::Result<Vec<(Hash, u64)>> {
        let mut existing = Vec::new();
        for (hash, user_id) in keys {
            if table.contains_exact_hash_user_pair(&self.session, hash, *user_id).await? { existing.push((hash.clone(), *user_id)); }
        }
        Ok(existing)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseBlobPairVerifier<ScyllaBiDirectionalBlobToBlobTablePreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_blob_pair_presence(&self, table: &ScyllaBiDirectionalBlobToBlobTablePreparedStatements, keys: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<Vec<CoreDatabaseBidirectionalPairPresence<Vec<u8>, Vec<u8>>>> {
        let mut remaining = Vec::new();
        for (k1, k2) in keys {
            let forward_present = table.k1.contains_key(&self.session, k1).await?;
            let reverse_present = table.k2.contains_key(&self.session, k2).await?;
            if forward_present || reverse_present {
                remaining.push(CoreDatabaseBidirectionalPairPresence { key: (k1.clone(), k2.clone()), forward_present, reverse_present });
            }
        }
        Ok(remaining)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabaseU64U128PairVerifier<ScyllaBidirectionalU64U128MappingPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_u64_u128_pair_presence(&self, table: &ScyllaBidirectionalU64U128MappingPreparedStatements, keys: &[(u64, u128)]) -> anyhow::Result<Vec<CoreDatabaseBidirectionalPairPresence<u64, u128>>> {
        let mut remaining = Vec::new();
        for &(k1, k2) in keys {
            let forward_present = table.get_k2_from_k1(&self.session, k1).await?.is_some();
            let reverse_present = table.get_k1_from_k2(&self.session, k2).await?.is_some();
            if forward_present || reverse_present {
                remaining.push(CoreDatabaseBidirectionalPairPresence { key: (k1, k2), forward_present, reverse_present });
            }
        }
        Ok(remaining)
    }
}

#[async_trait]
impl<Hash: QDBHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync>
    CoreDatabasePendingIdPartitionVerifier<ScyllaTagTreeNodesPreparedStatements> for ScyllaCoreStore<Hash, Hasher>
{
    async fn db_get_existing_pending_id_partitions(&self, table: &ScyllaTagTreeNodesPreparedStatements, pending_ids: &[u64]) -> anyhow::Result<Vec<u64>> {
        let mut existing = Vec::new();
        for &pending_id in pending_ids { if table.contains_pending_id_partition(&self.session, pending_id).await? { existing.push(pending_id); } }
        Ok(existing)
    }
}
