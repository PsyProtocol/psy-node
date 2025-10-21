use std::collections::HashMap;

use async_trait::async_trait;
use auto_impl::auto_impl;
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
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        serializable::QPDPair,
    },
    protocol::core_types::QHashBase,
};
use psy_serialize::PsySerializeCanonicalAsyncSafe;

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseBidirectionalMappingReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: &K1,
    ) -> anyhow::Result<Option<K2>>;
    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2: &K2,
    ) -> anyhow::Result<Option<K1>>;
    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<Option<K2>>>;
    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<Option<K1>>>;
    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseBidirectionalMappingWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: &K1,
        k2: &K2,
    ) -> anyhow::Result<()>;
    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        k1: K1,
        k2: K2,
    ) -> anyhow::Result<()>;
    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &TableIdentifier,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()>;
}

pub trait CoreDatabaseBidirectionalMappingStore<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseBidirectionalMappingReader<TableIdentifier> + CoreDatabaseBidirectionalMappingWriter<TableIdentifier>
{
}
impl<
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseBidirectionalMappingReader<TableIdentifier> + CoreDatabaseBidirectionalMappingWriter<TableIdentifier>,
    > CoreDatabaseBidirectionalMappingStore<TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseBidirectionalU64U128MappingReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_u128_value_by_u64(&self, table: &TableIdentifier, key: u64) -> anyhow::Result<Option<u128>>;
    async fn db_select_one_u64_key_by_u128(&self, table: &TableIdentifier, value: u128) -> anyhow::Result<Option<u64>>;
    async fn db_select_many_u128_values_by_u64s(&self, table: &TableIdentifier, keys: &[u64]) -> anyhow::Result<Vec<Option<u128>>>;
    async fn db_select_many_u64_keys_by_u128s(&self, table: &TableIdentifier, values: &[u128]) -> anyhow::Result<Vec<Option<u64>>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseBidirectionalU64U128MappingWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_u64_u128_mapping_pair(&self, table: &TableIdentifier, k1: u64, k2: u128) -> anyhow::Result<()>;
    async fn db_insert_u64_u128_mapping_pairs(&self, table: &TableIdentifier, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()>;
}

pub trait CoreDatabaseBidirectionalU64U128MappingStore<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseBidirectionalU64U128MappingReader<TableIdentifier> + CoreDatabaseBidirectionalU64U128MappingWriter<TableIdentifier>
{
}
impl<
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseBidirectionalU64U128MappingReader<TableIdentifier> + CoreDatabaseBidirectionalU64U128MappingWriter<TableIdentifier>,
    > CoreDatabaseBidirectionalU64U128MappingStore<TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseU64Reader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_u64_value(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>>;
    async fn db_select_u64_values(&self, table: &TableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseU64Writer<TableIdentifier: Clone + Send + Sync> {
    async fn db_inc_counter(&self, table: &TableIdentifier, obj_id: u64, amount: i64) -> anyhow::Result<u64>;
    async fn db_set_u64_value(&self, table: &TableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()>;
    async fn db_set_many_u64_values(&self, table: &TableIdentifier, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()>;
}
pub trait CoreDatabaseU64Store<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseU64Reader<TableIdentifier> + CoreDatabaseU64Writer<TableIdentifier>
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseSingleIdCheckpointedReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_single_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>>;
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>>;
    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>>;
    async fn db_select_all_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>>;
    async fn db_select_many_single_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_object_rows_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseSingleIdTableRowLike<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()>;

    // first 8 bytes are the object_id, last_8 bytes
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
        &self,
        table: &TableIdentifier,
        object_size_without_id: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()>;

    // for user leafs and similar, where we want to insert many objects at a
    // checkpoint, but the id is at the end of the row
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(
        &self,
        table: &TableIdentifier,
        object_size: usize,
        object_id_location: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseSingleIdCheckpointedStore<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseSingleIdCheckpointedReader<TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier>
{
}
impl<
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseSingleIdCheckpointedReader<TableIdentifier> + CoreDatabaseSingleIdCheckpointedWriter<TableIdentifier>,
    > CoreDatabaseSingleIdCheckpointedStore<TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_double_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>>;
    async fn db_select_one_double_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>>;
    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>>;
    async fn db_select_all_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>>;
    async fn db_select_many_double_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_object_rows_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseDoubleIdCheckpointedStore<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier>
{
}
impl<
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseDoubleIdCheckpointedReader<TableIdentifier> + CoreDatabaseDoubleIdCheckpointedWriter<TableIdentifier>,
    > CoreDatabaseDoubleIdCheckpointedStore<TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseKivReader<TableIdentifier: Clone + Send + Sync> {
    async fn db_select_one_kiv_value<V: PsySerializeCanonicalAsyncSafe>(&self, table: &TableIdentifier, obj_id: u64) -> anyhow::Result<Option<V>>;
    async fn db_select_one_kiv_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>>;
    async fn db_select_one_kiv_value_and_ids_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<R>>;
    async fn db_select_all_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>>;
    async fn db_select_many_kiv_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>>;
    async fn db_select_many_kiv_keys_and_values<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<R>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseKivWriter<TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_kiv<V: PsySerializeCanonicalAsyncSafe>(&self, table: &TableIdentifier, obj_id: u64, value: &V) -> anyhow::Result<()>;
    async fn db_insert_many_kivs<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &TableIdentifier,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> anyhow::Result<()>;
    async fn db_insert_many_kivs_t<V: PsySerializeCanonicalAsyncSafe, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &TableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseKivStore<TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseKivReader<TableIdentifier> + CoreDatabaseKivWriter<TableIdentifier>
{
}
impl<TableIdentifier: Clone + Send + Sync, T: CoreDatabaseKivReader<TableIdentifier> + CoreDatabaseKivWriter<TableIdentifier>>
    CoreDatabaseKivStore<TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseSingleIdMerkleReader<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash>;
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseSingleIdMerkleWriter<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()>;
    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()>;
    async fn db_set_single_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseSingleIdMerkleStore<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier>,
    > CoreDatabaseSingleIdMerkleStore<Hash, Hasher, TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseTagTreeReader<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync>
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>>;
    async fn db_get_tag_tree_node_values(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>>;
    async fn db_get_tag_tree_node_tag(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>>;
    async fn db_get_tag_tree_node_tags(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>>;
    async fn db_get_tag_tree_root(&self, table: &TableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>>;
    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseTagTreeWriter<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync>
{
    async fn db_set_tag_tree_tag_value(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()>;
    async fn db_set_tag_tree_tag(&self, table: &TableIdentifier, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &Hash) -> anyhow::Result<()>;
    async fn db_set_tag_tree_tag_known_height(
        &self,
        table: &TableIdentifier,
        unique_pending_id: u64,
        tag_tree_height: u8,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseTagTreeStore<Hash: QHashBase + Send + Sync, Hasher: MerkleZeroHasher<Hash> + Send + Sync, TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseTagTreeReader<Hash, Hasher, TableIdentifier> + CoreDatabaseTagTreeWriter<Hash, Hasher, TableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseTagTreeReader<Hash, Hasher, TableIdentifier> + CoreDatabaseTagTreeWriter<Hash, Hasher, TableIdentifier>,
    > CoreDatabaseTagTreeStore<Hash, Hasher, TableIdentifier> for T
{
}
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum MerkleTreeDumpStrategy {
    AppendOnlyTreeStrategy = 0,
    DumpAllStrategy = 1,
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseZeroIdMerkleDumpReader<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_dump_all_zero_id_merkle_node_leaves_chunked(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<HashMap<u64, Hash>>;
    async fn db_dump_all_zero_id_merkle_node_leaves_vec(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        strategy: MerkleTreeDumpStrategy,
    ) -> anyhow::Result<Vec<SimpleMerkleNode<Hash>>>;
    /*
    async fn dump_all_zero_id_merkle_node_leaves_chunked<
        F: Send + Sync + FnMut(Vec<(u64, Hash)>) -> Fut,
        Fut: Send + Sync + Future<Output = anyhow::Result<()>>,
    >(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        mut on_chunk: F,
    ) -> anyhow::Result<()>;*/
}
#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseZeroIdMerkleReader<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash>;
    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseZeroIdMerkleWriter<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()>;
    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()>;
    async fn db_set_zero_id_merkle_nodes_from_fast_serialized(&self, table: &TableIdentifier, checkpoint_id: u64, nodes: &[u8])
        -> anyhow::Result<()>;
}
pub trait CoreDatabaseZeroIdMerkleStore<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier>,
    > CoreDatabaseZeroIdMerkleStore<Hash, Hasher, TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseDoubleIdMerkleReader<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash>;
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &TableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseDoubleIdMerkleWriter<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> anyhow::Result<()>;
    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()>;
    async fn db_set_double_id_merkle_nodes_from_fast_serialized(
        &self,
        table: &TableIdentifier,
        checkpoint_id: u64,
        nodes: &[u8],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseDoubleIdMerkleStore<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
>: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier>,
    > CoreDatabaseDoubleIdMerkleStore<Hash, Hasher, TableIdentifier> for T
{
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseHashToManyIdsReader<Hash: QHashBase + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_select_value_u64_ids_for_hash(
        &self,
        table: &TableIdentifier,
        hash: Hash,
        count: usize,
        start_u64_value: u64, // The ID to start the query from (inclusive)
    ) -> anyhow::Result<Vec<u64>>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait CoreDatabaseHashToManyIdsWriter<Hash: QHashBase + Send + Sync, TableIdentifier: Clone + Send + Sync> {
    async fn db_insert_one_hash_to_u64(&self, table: &TableIdentifier, hash_id: Hash, value: u64) -> anyhow::Result<()>;
    async fn db_insert_many_hash_to_u64s(&self, table: &TableIdentifier, rows: &[(Hash, u64)]) -> anyhow::Result<()>;
    async fn db_set_hash_256_to_u64_pairs_from_fast_serialized_data(
        &self,
        table: &TableIdentifier,
        data: &[u8],
    ) -> anyhow::Result<()>;
}
pub trait CoreDatabaseHashToManyIdsStore<Hash: QHashBase + Send + Sync, TableIdentifier: Clone + Send + Sync>:
    CoreDatabaseHashToManyIdsReader<Hash, TableIdentifier> + CoreDatabaseHashToManyIdsWriter<Hash, TableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        TableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseHashToManyIdsReader<Hash, TableIdentifier> + CoreDatabaseHashToManyIdsWriter<Hash, TableIdentifier>,
    > CoreDatabaseHashToManyIdsStore<Hash, TableIdentifier> for T
{
}

// full implementations

pub trait CoreDatabaseReader<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeMerkleTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
>:
    CoreDatabaseBidirectionalMappingReader<BiDirectionalMappingTableIdentifier>
    + CoreDatabaseBidirectionalU64U128MappingReader<BiDirectionalU64U128MappingTableIdentifier>
    + CoreDatabaseU64Reader<U64TableIdentifier>
    + CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier>
    + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier>
    + CoreDatabaseKivReader<KivTableIdentifier>
    + CoreDatabaseSingleIdMerkleReader<Hash, Hasher, SingleIdMerkleTableIdentifier>
    + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, DoubleIdMerkleTableIdentifier>
    + CoreDatabaseZeroIdMerkleReader<Hash, Hasher, ZeroIdMerkleTableIdentifier>
    + CoreDatabaseTagTreeReader<Hash, Hasher, TagTreeMerkleTableIdentifier>
    + CoreDatabaseHashToManyIdsReader<Hash, HashToManyIdsTableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeMerkleTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseBidirectionalMappingReader<BiDirectionalMappingTableIdentifier>
            + CoreDatabaseBidirectionalU64U128MappingReader<BiDirectionalU64U128MappingTableIdentifier>
            + CoreDatabaseU64Reader<U64TableIdentifier>
            + CoreDatabaseSingleIdCheckpointedReader<SingleIdTableIdentifier>
            + CoreDatabaseDoubleIdCheckpointedReader<DoubleIdTableIdentifier>
            + CoreDatabaseKivReader<KivTableIdentifier>
            + CoreDatabaseSingleIdMerkleReader<Hash, Hasher, SingleIdMerkleTableIdentifier>
            + CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, DoubleIdMerkleTableIdentifier>
            + CoreDatabaseZeroIdMerkleReader<Hash, Hasher, ZeroIdMerkleTableIdentifier>
            + CoreDatabaseTagTreeReader<Hash, Hasher, TagTreeMerkleTableIdentifier>
            + CoreDatabaseHashToManyIdsReader<Hash, HashToManyIdsTableIdentifier>,
    >
    CoreDatabaseReader<
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeMerkleTableIdentifier,
        HashToManyIdsTableIdentifier,
    > for T
{
}

pub trait CoreDatabaseWriter<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeMerkleTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
>:
    CoreDatabaseBidirectionalMappingWriter<BiDirectionalMappingTableIdentifier>
    + CoreDatabaseBidirectionalU64U128MappingWriter<BiDirectionalU64U128MappingTableIdentifier>
    + CoreDatabaseU64Writer<U64TableIdentifier>
    + CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier>
    + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier>
    + CoreDatabaseKivWriter<KivTableIdentifier>
    + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, SingleIdMerkleTableIdentifier>
    + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, DoubleIdMerkleTableIdentifier>
    + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, ZeroIdMerkleTableIdentifier>
    + CoreDatabaseTagTreeWriter<Hash, Hasher, TagTreeMerkleTableIdentifier>
    + CoreDatabaseHashToManyIdsWriter<Hash, HashToManyIdsTableIdentifier>
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeMerkleTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseBidirectionalMappingWriter<BiDirectionalMappingTableIdentifier>
            + CoreDatabaseBidirectionalU64U128MappingWriter<BiDirectionalU64U128MappingTableIdentifier>
            + CoreDatabaseU64Writer<U64TableIdentifier>
            + CoreDatabaseSingleIdCheckpointedWriter<SingleIdTableIdentifier>
            + CoreDatabaseDoubleIdCheckpointedWriter<DoubleIdTableIdentifier>
            + CoreDatabaseKivWriter<KivTableIdentifier>
            + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, SingleIdMerkleTableIdentifier>
            + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, DoubleIdMerkleTableIdentifier>
            + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, ZeroIdMerkleTableIdentifier>
            + CoreDatabaseTagTreeWriter<Hash, Hasher, TagTreeMerkleTableIdentifier>
            + CoreDatabaseHashToManyIdsWriter<Hash, HashToManyIdsTableIdentifier>
    >
    CoreDatabaseWriter<
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeMerkleTableIdentifier,
        HashToManyIdsTableIdentifier,
    > for T
{
}

pub trait CoreDatabaseTableConfig: Copy + Send + Sync + Clone + Sized {
    type BiDirectionalMappingTableIdentifier: Clone + Send + Sync;
    type BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync;
    type U64TableIdentifier: Clone + Send + Sync;
    type SingleIdTableIdentifier: Clone + Send + Sync;
    type DoubleIdTableIdentifier: Clone + Send + Sync;
    type KivTableIdentifier: Clone + Send + Sync;
    type SingleIdMerkleTableIdentifier: Clone + Send + Sync;
    type DoubleIdMerkleTableIdentifier: Clone + Send + Sync;
    type ZeroIdMerkleTableIdentifier: Clone + Send + Sync;
    type TagTreeMerkleTableIdentifier: Clone + Send + Sync;
    type HashToManyIdsTableIdentifier: Clone + Send + Sync;
}
pub trait CoreDatabaseStoreComboImpl<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    T: CoreDatabaseTableConfig,
>:
    CoreDatabaseStore<
        Hash,
        Hasher,
        T::BiDirectionalMappingTableIdentifier,
        T::BiDirectionalU64U128MappingTableIdentifier,
        T::U64TableIdentifier,
        T::SingleIdTableIdentifier,
        T::DoubleIdTableIdentifier,
        T::KivTableIdentifier,
        T::SingleIdMerkleTableIdentifier,
        T::DoubleIdMerkleTableIdentifier,
        T::ZeroIdMerkleTableIdentifier,
        T::TagTreeMerkleTableIdentifier,
        T::HashToManyIdsTableIdentifier,
    >
{
}


/* 
pub trait CoreDatabseStoreCombo<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    T: CoreDatabaseTableConfig,
>: CoreDatabaseStore<Hash, Hasher, T::BiDirectionalMappingTableIdentifier, T::BiDirectionalU64U128MappingTableIdentifier, T::U64TableIdentifier, T::SingleIdTableIdentifier, T::DoubleIdTableIdentifier, T::KivTableIdentifier, T::SingleIdMerkleTableIdentifier, T::DoubleIdMerkleTableIdentifier, T::ZeroIdMerkleTableIdentifier, T::TagTreeMerkleTableIdentifier, T::HashToManyIdsTableIdentifier> {
    
}
impl<

    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    T: CoreDatabaseTableConfig,
    > CoreDatabaseStore<Hash, Hasher, T::BiDirectionalMappingTableIdentifier, T::BiDirectionalU64U128MappingTableIdentifier, T::U64TableIdentifier, T::SingleIdTableIdentifier, T::DoubleIdTableIdentifier, T::KivTableIdentifier, T::SingleIdMerkleTableIdentifier, T::DoubleIdMerkleTableIdentifier, T::ZeroIdMerkleTableIdentifier, T::TagTreeMerkleTableIdentifier, T::HashToManyIdsTableIdentifier> for T{

    }*/
pub trait CoreDatabaseStore<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeMerkleTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
>:
    CoreDatabaseReader<
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeMerkleTableIdentifier,
        HashToManyIdsTableIdentifier,
    > + CoreDatabaseWriter<
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeMerkleTableIdentifier,
        HashToManyIdsTableIdentifier,
    >
{
}
impl<
        Hash: QHashBase + Send + Sync,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
        BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
        BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
        U64TableIdentifier: Clone + Send + Sync,
        SingleIdTableIdentifier: Clone + Send + Sync,
        DoubleIdTableIdentifier: Clone + Send + Sync,
        KivTableIdentifier: Clone + Send + Sync,
        SingleIdMerkleTableIdentifier: Clone + Send + Sync,
        DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
        ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
        TagTreeMerkleTableIdentifier: Clone + Send + Sync,
        HashToManyIdsTableIdentifier: Clone + Send + Sync,
        T: CoreDatabaseReader<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeMerkleTableIdentifier,
                HashToManyIdsTableIdentifier,
            > + CoreDatabaseWriter<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                TagTreeMerkleTableIdentifier,
                HashToManyIdsTableIdentifier,
            >,
    >
    CoreDatabaseStore<
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeMerkleTableIdentifier,
        HashToManyIdsTableIdentifier,
    > for T
{
}
