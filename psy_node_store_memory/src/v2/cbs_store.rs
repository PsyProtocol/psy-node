
use async_trait::async_trait;
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use futures::future;
use parth_core::{
    crypto::hash::{
        tag_tree::{
            hash_tag_tree_node, TagTreeMerkleProof,
            TagTreeNodePreimage, TagTreeProofNode, TagTreeStorageNode,
        },
        traits::MerkleZeroHasher,
    },
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey},
            row::{
                QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable,
                QDatabaseDoubleIdTableRowLike, QDatabaseDoubleIdTableRowNoCheckpointId,
                QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow,
                QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike,
                QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable,
                QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId,
                QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey,
            },
        },
        hash::{
            fast_node_serializer::{
                QMerkleStoreFastDoubleNodeSerializer, QMerkleStoreFastSingleNodeSerializer,
                QMerkleStoreFastZeroNodeSerializer, QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
                QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE,
            },
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        },
        serializable::QPDPair,
    },
    protocol::core_types::{QDBHashBase, QHashBase},
};
use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter, CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseHashToManyIdsReader, CoreDatabaseHashToManyIdsWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseTagTreeReader, CoreDatabaseTagTreeWriter, CoreDatabaseU64Reader, CoreDatabaseU64Store, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsySerializeCanonicalAsyncSafe};
use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[cfg(feature = "parallel_rayon")]
use rayon::{iter::ParallelIterator, slice::ParallelSlice};

// ================================================================================================
// 1. STRUCT & ENUM DEFINITIONS
// ================================================================================================

/// An in-memory, concurrent database implementation using `crossbeam-skiplist` and `dashmap`.
#[derive(Debug)]
pub struct InMemoryCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash> + Send + Sync> {
    /// Stores most tables as SkipMaps of byte vectors. The String key is the table name.
    tables: DashMap<String, Arc<SkipMap<Vec<u8>, Vec<u8>>>>,
    /// Stores U64-keyed tables for atomic operations.
    u64_tables: DashMap<String, Arc<DashMap<u64, AtomicU64>>>,
    _phantom_hash: PhantomData<Hash>,
    _phantom_hasher: PhantomData<Hasher>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash> + Send + Sync> Default for InMemoryCoreStore<Hash, Hasher> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash> + Send + Sync> InMemoryCoreStore<Hash, Hasher> {
    /// Creates a new, empty in-memory store.
    pub fn new() -> Self {
        Self {
            tables: DashMap::new(),
            u64_tables: DashMap::new(),
            _phantom_hash: PhantomData,
            _phantom_hasher: PhantomData,
        }
    }

    /// Gets a generic table, creating it if it doesn't exist.
    fn get_or_create_table(&self, name: &str) -> Arc<SkipMap<Vec<u8>, Vec<u8>>> {
        self.tables
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(SkipMap::new()))
            .clone()
    }

    /// Gets a U64-keyed table, creating it if it doesn't exist.
    fn get_or_create_u64_table(&self, name: &str) -> Arc<DashMap<u64, AtomicU64>> {
        self.u64_tables
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone()
    }

}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InMemoryTableIdentifier {
    pub full_name: String,
    pub tree_height: u8,
}
impl InMemoryTableIdentifier {
    pub fn new_tree(full_name: String, tree_height: u8) -> Self {
        Self { full_name, tree_height }
    }
    pub fn new_treee_with_keyspace(keyspace: &str, table_name: &str, tree_height: u8) -> Self {
        Self {
            full_name: format!("{}-{}", keyspace, table_name),
            tree_height,
        }
    }
    pub fn new(full_name: String) -> Self {
        Self { full_name, tree_height: 0 }
    }
    pub fn new_with_keyspace(keyspace: &str, table_name: &str) -> Self {
        Self {
            full_name: format!("{}-{}", keyspace, table_name),
            tree_height: 0,
        }
    }
}
impl ToString for InMemoryTableIdentifier{
    fn to_string(&self) -> String {
        self.full_name.clone()
    }
}
// ================================================================================================
// 2. KEY GENERATION HELPERS
// ================================================================================================

mod key_helpers {
    use super::*;

    pub fn key_single_id_checkpointed(obj_id: u64, checkpoint_id: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&obj_id.to_be_bytes());
        key.extend_from_slice(&checkpoint_id.to_be_bytes());
        key
    }

    pub fn key_double_id_checkpointed(
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(&obj_id.to_be_bytes());
        key.extend_from_slice(&secondary_id.to_be_bytes());
        key.extend_from_slice(&checkpoint_id.to_be_bytes());
        key
    }

    pub fn key_merkle_zero_id(key: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let mut db_key = Vec::with_capacity(1 + 8 + 8);
        db_key.push(key.level);
        db_key.extend_from_slice(&key.index.to_be_bytes());
        db_key.extend_from_slice(&checkpoint_id.to_be_bytes());
        db_key
    }

    pub fn key_merkle_single_id(
        tree_id: u64,
        key: &SimpleMerkleNodeKey,
        checkpoint_id: u64,
    ) -> Vec<u8> {
        let mut db_key = Vec::with_capacity(8 + 1 + 8 + 8);
        db_key.extend_from_slice(&tree_id.to_be_bytes());
        db_key.push(key.level);
        db_key.extend_from_slice(&key.index.to_be_bytes());
        db_key.extend_from_slice(&checkpoint_id.to_be_bytes());
        db_key
    }

    pub fn key_merkle_double_id(
        tree_id: u64,
        tree_sub_id: u64,
        key: &SimpleMerkleNodeKey,
        checkpoint_id: u64,
    ) -> Vec<u8> {
        let mut db_key = Vec::with_capacity(8 + 8 + 1 + 8 + 8);
        db_key.extend_from_slice(&tree_id.to_be_bytes());
        db_key.extend_from_slice(&tree_sub_id.to_be_bytes());
        db_key.push(key.level);
        db_key.extend_from_slice(&key.index.to_be_bytes());
        db_key.extend_from_slice(&checkpoint_id.to_be_bytes());
        db_key
    }

    pub fn key_tag_tree(unique_pending_id: u64, key: &SimpleMerkleNodeKey) -> Vec<u8> {
        let mut db_key = Vec::with_capacity(8 + 1 + 8);
        db_key.extend_from_slice(&unique_pending_id.to_be_bytes());
        db_key.push(key.level);
        db_key.extend_from_slice(&key.index.to_be_bytes());
        db_key
    }

    pub fn key_hash_to_u64<Hash: QDBHashBase>(hash: &Hash, value: u64) -> anyhow::Result<Vec<u8>> {
        let hash_bytes = hash.to_bytes()?;
        let mut key = Vec::with_capacity(hash_bytes.len() + 8);
        key.extend_from_slice(&hash_bytes);
        // Use big-endian for correct lexicographical sorting by u64
        key.extend_from_slice(&value.to_be_bytes()); 
        Ok(key)
    }

    // Helper to extract u64 from the key bytes
    pub fn extract_u64_from_hash_to_u64_key(key: &[u8]) -> anyhow::Result<u64> {
        let hash_len = key.len().checked_sub(8).ok_or_else(|| anyhow::anyhow!("Key too short for HashToU64"))?;
        let u64_bytes: [u8; 8] = key[hash_len..].try_into()?;
        Ok(u64::from_be_bytes(u64_bytes))
    }
}

// ================================================================================================
// 3. TRAIT IMPLEMENTATIONS
// ================================================================================================

#[async_trait]
impl<Hash, Hasher> CoreDatabaseKivReader<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_one_kiv_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let db = self.get_or_create_table(&table.to_string());
        let key = obj_id.to_be_bytes();
        Ok(db
            .get(&key[..])
            .map(|entry| V::psy_ser_from_slice(entry.value()))
            .transpose()?)
    }

    async fn db_select_one_kiv_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        self.db_select_one_kiv_value(table, obj_id)
            .await?
            .map(|value| {
                Ok(QDatabaseKeyIdValueTableRow {
                    obj_id,
                    value,
                })
            })
            .transpose()
    }

    async fn db_select_one_kiv_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
    ) -> anyhow::Result<Option<R>> {
        self.db_select_one_kiv_value(table, obj_id)
            .await?
            .map(|value| Ok(R::create_from_key_id_value_row(obj_id, value)))
            .transpose()
    }

    async fn db_select_all_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let db = self.get_or_create_table(&table.to_string());
        db.iter()
            .map(|entry| {
                let obj_id = u64::from_be_bytes(entry.key().as_slice().try_into()?);
                let value = V::psy_ser_from_slice(entry.value())?;
                Ok(QDatabaseKeyIdValueTableRow { obj_id, value })
            })
            .collect()
    }

    async fn db_select_many_kiv_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<Option<V>>> {
        let futures = obj_ids
            .iter()
            .map(|&id| self.db_select_one_kiv_value(table, id));
        future::try_join_all(futures).await
    }

    async fn db_select_many_kiv_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[u64],
    ) -> anyhow::Result<Vec<R>> {
        let futures = obj_ids
            .iter()
            .map(|&id| self.db_select_one_kiv_value_and_ids_t(table, id));
        let results = future::try_join_all(futures).await?;
        Ok(results.into_iter().flatten().collect())
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseKivWriter<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_one_kiv<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let key = obj_id.to_be_bytes().to_vec();
        let val_bytes = value.psy_ser_to_bytes_vec()?;
        db.insert(key, val_bytes);
        Ok(())
    }

    async fn db_insert_many_kivs<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> anyhow::Result<()> {
        let futures = rows
            .iter()
            .map(|row| self.db_insert_one_kiv(table, row.obj_id, &row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_kivs_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| {
            self.db_insert_one_kiv(table, row.get_row_obj_id(), row.get_row_value_ref())
        });
        future::try_join_all(futures).await?;
        Ok(())
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseBidirectionalMappingReader<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k1: &K1,
    ) -> anyhow::Result<Option<K2>> {
        let db = self.get_or_create_table(&format!("{}_k1", table.to_string()));
        let key = k1.psy_ser_to_bytes_vec()?;
        Ok(db
            .get(&key)
            .map(|entry| K2::psy_ser_from_slice(entry.value()))
            .transpose()?)
    }

    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k2: &K2,
    ) -> anyhow::Result<Option<K1>> {
        let db = self.get_or_create_table(&format!("{}_k2", table.to_string()));
        let key = k2.psy_ser_to_bytes_vec()?;
        Ok(db
            .get(&key)
            .map(|entry| K1::psy_ser_from_slice(entry.value()))
            .transpose()?)
    }

    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<Option<K2>>> {
        let futures = k1s.iter().map(|k1| self.db_select_one_by_k1(table, k1));
        future::try_join_all(futures).await
    }

    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<Option<K1>>> {
        let futures = k2s.iter().map(|k2| self.db_select_one_by_k2(table, k2));
        future::try_join_all(futures).await
    }

    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k1s: &[K1],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let futures = k1s.iter().map(|k1| async move {
            self.db_select_one_by_k1(table, k1)
                .await
                .map(|opt_k2| opt_k2.map(|k2| BiDirectionalMappingRow::new(k1.clone(), k2)))
        });
        let results = future::try_join_all(futures).await?;
        Ok(results.into_iter().flatten().collect())
    }

    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k2s: &[K2],
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let futures = k2s.iter().map(|k2| async move {
            self.db_select_one_by_k2(table, k2)
                .await
                .map(|opt_k1| opt_k1.map(|k1| BiDirectionalMappingRow::new(k1, k2.clone())))
        });
        let results: Vec<_> = future::try_join_all(futures)
            .await?
            .into_iter()
            .flatten()
            .collect();
        Ok(results)
    }

    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> anyhow::Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let db = self.get_or_create_table(&format!("{}_k1", table.to_string()));
        let mut results = Vec::new();
        
        match start_k1 {
            Some(k1) => {
                let start_key = k1.psy_ser_to_bytes_vec()?;
                for entry in db.range(start_key..).take(max_count) {
                    let k1 = K1::psy_ser_from_slice(entry.key())?;
                    let k2 = K2::psy_ser_from_slice(entry.value())?;
                    results.push(BiDirectionalMappingRow::new(k1, k2));
                }
            }
            None => {
                for entry in db.range::<[u8], _>(..).take(max_count) {
                    let k1 = K1::psy_ser_from_slice(entry.key())?;
                    let k2 = K2::psy_ser_from_slice(entry.value())?;
                    results.push(BiDirectionalMappingRow::new(k1, k2));
                }
            }
        };

        Ok(results)
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseBidirectionalMappingWriter<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k1: &K1,
        k2: &K2,
    ) -> anyhow::Result<()> {
        let db1 = self.get_or_create_table(&format!("{}_k1", table.to_string()));
        let db2 = self.get_or_create_table(&format!("{}_k2", table.to_string()));
        
        db1.insert(k1.psy_ser_to_bytes_vec()?, k2.psy_ser_to_bytes_vec()?);
        db2.insert(k2.psy_ser_to_bytes_vec()?, k1.psy_ser_to_bytes_vec()?);
        
        Ok(())
    }

    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        k1: K1,
        k2: K2,
    ) -> anyhow::Result<()> {
        self.db_insert_pair_ref(table, &k1, &k2).await
    }

    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryTableIdentifier,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        let futures = keys
            .iter()
            .map(|row| self.db_insert_pair_ref(table, &row.k1, &row.k2));
        future::try_join_all(futures).await?;
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher> CoreDatabaseBidirectionalU64U128MappingReader<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_one_u128_value_by_u64(&self, table: &InMemoryTableIdentifier, key: u64) -> anyhow::Result<Option<u128>> {
        let db = self.get_or_create_table(&format!("{}_u64_to_u128", table.to_string()));
        Ok(db.get(&key.to_be_bytes()[..]).map(|entry| u128::from_be_bytes(entry.value().as_slice().try_into().unwrap())))
    }

    async fn db_select_one_u64_key_by_u128(&self, table: &InMemoryTableIdentifier, value: u128) -> anyhow::Result<Option<u64>> {
        let db = self.get_or_create_table(&format!("{}_u128_to_u64", table.to_string()));
        Ok(db.get(&value.to_be_bytes()[..]).map(|entry| u64::from_be_bytes(entry.value().as_slice().try_into().unwrap())))
    }

    async fn db_select_many_u128_values_by_u64s(&self, table: &InMemoryTableIdentifier, keys: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        let futures = keys.iter().map(|&k| self.db_select_one_u128_value_by_u64(table, k));
        future::try_join_all(futures).await
    }

    async fn db_select_many_u64_keys_by_u128s(&self, table: &InMemoryTableIdentifier, values: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        let futures = values.iter().map(|&v| self.db_select_one_u64_key_by_u128(table, v));
        future::try_join_all(futures).await
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseBidirectionalU64U128MappingWriter<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_u64_u128_mapping_pair(&self, table: &InMemoryTableIdentifier, k1: u64, k2: u128) -> anyhow::Result<()> {
        let db1 = self.get_or_create_table(&format!("{}_u64_to_u128", table.to_string()));
        let db2 = self.get_or_create_table(&format!("{}_u128_to_u64", table.to_string()));
        
        db1.insert(k1.to_be_bytes().to_vec(), k2.to_be_bytes().to_vec());
        db2.insert(k2.to_be_bytes().to_vec(), k1.to_be_bytes().to_vec());
        
        Ok(())
    }

    async fn db_insert_u64_u128_mapping_pairs(&self, table: &InMemoryTableIdentifier, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()> {
        let futures = keys.iter().map(|row| self.db_insert_u64_u128_mapping_pair(table, row.k1, row.k2));
        future::try_join_all(futures).await?;
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher> CoreDatabaseU64Reader<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_u64_value(&self, table: &InMemoryTableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let db = self.get_or_create_u64_table(&table.to_string());
        Ok(db.get(&obj_id).map(|v| v.load(Ordering::Relaxed)))
    }

    async fn db_select_u64_values(&self, table: &InMemoryTableIdentifier, obj_ids: &[u64]) -> anyhow::Result<Vec<Option<u64>>> {
        let futures = obj_ids.iter().map(|&id| self.db_select_u64_value(table, id));
        future::try_join_all(futures).await
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseU64Writer<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_inc_counter(&self, table: &InMemoryTableIdentifier, obj_id: u64, amount: i64) -> anyhow::Result<u64> {
        let db = self.get_or_create_u64_table(&table.to_string());
        let entry = db.entry(obj_id).or_insert_with(|| AtomicU64::new(0));
        let new_val = if amount.is_negative() {
            let abs_amount = amount.wrapping_abs() as u64;
            entry.fetch_sub(abs_amount, Ordering::Relaxed)
                 .saturating_sub(abs_amount)
        } else {
            let abs_amount = amount as u64;
            entry.fetch_add(abs_amount, Ordering::Relaxed)
                 .saturating_add(abs_amount)
        };
        Ok(new_val)
    }

    async fn db_set_u64_value(&self, table: &InMemoryTableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()> {
        let db = self.get_or_create_u64_table(&table.to_string());
        db.entry(obj_id).or_insert_with(|| AtomicU64::new(0)).store(value, Ordering::Relaxed);
        Ok(())
    }

    async fn db_set_many_u64_values(&self, table: &InMemoryTableIdentifier, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| self.db_set_u64_value(table, row.key, row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }
}

impl<Hash, Hasher> CoreDatabaseU64Store<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
}

// ... Implementations for Checkpointed and Merkle traits follow ...
// The full implementation is very long, so I'm showing the pattern for one and
// then including the final, complete code.

#[async_trait]
impl<Hash, Hasher> CoreDatabaseSingleIdCheckpointedReader<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_one_single_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_single_id_checkpointed(obj_id, 0);
        let end_key = key_helpers::key_single_id_checkpointed(obj_id, max_checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            Ok(Some(V::psy_ser_from_slice(e.value())?))
        } else {
            Ok(None)
        }
    }

    // ... other methods implemented similarly ...
    async fn db_select_one_single_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_single_id_checkpointed(obj_id, 0);
        let end_key = key_helpers::key_single_id_checkpointed(obj_id, max_checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            let key_bytes = e.key();
            let checkpoint_id = u64::from_be_bytes(key_bytes[8..16].try_into()?);
            let value = V::psy_ser_from_slice(e.value())?;
            Ok(Some(QDatabaseSingleIdTableRow { obj_id, checkpoint_id, value }))
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        self.db_select_one_single_checkpointed_object_value_and_ids(table, obj_id, max_checkpoint_id)
            .await?
            .map(|row| Ok(R::create_from_single_row(row.obj_id, row.checkpoint_id, row.value)))
            .transpose()
    }

    async fn db_select_all_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let db = self.get_or_create_table(&table.to_string());
        db.iter()
            .map(|entry| {
                let key_bytes = entry.key();
                let obj_id = u64::from_be_bytes(key_bytes[0..8].try_into()?);
                let checkpoint_id = u64::from_be_bytes(key_bytes[8..16].try_into()?);
                let value = V::psy_ser_from_slice(entry.value())?;
                Ok(QDatabaseSingleIdTableRow { obj_id, checkpoint_id, value })
            })
            .collect()
    }

    async fn db_select_many_single_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let futures = obj_ids.iter().map(|&id| self.db_select_one_single_checkpointed_object_value(table, id, max_checkpoint_id));
        future::try_join_all(futures).await
    }

    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        let futures = obj_ids.iter().map(|&id| self.db_select_one_single_checkpointed_object_value_and_ids_t(table, id, max_checkpoint_id));
        let results = future::try_join_all(futures).await?;
        Ok(results.into_iter().flatten().collect())
    }
}

// ... All other trait implementations from the previous response are included here ...
// They follow the same patterns as the implementations above.
// The full code is included below.
// ...

// Due to length limitations, I'm providing the rest of the implementations here.
// You would merge this with the code above.

#[async_trait]
impl<Hash, Hasher> CoreDatabaseSingleIdCheckpointedWriter<InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_one_single_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let key = key_helpers::key_single_id_checkpointed(obj_id, checkpoint_id);
        let val_bytes = value.psy_ser_to_bytes_vec()?;
        db.insert(key, val_bytes);
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        let futures = rows
            .iter()
            .map(|row| self.db_insert_one_single_checkpointed_object(table, row.obj_id, row.checkpoint_id, &row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| {
            self.db_insert_one_single_checkpointed_object(table, row.get_row_obj_id(), row.get_row_checkpoint_id(), row.get_row_value_ref())
        });
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        let futures = rows
            .iter()
            .map(|row| self.db_insert_one_single_checkpointed_object(table, row.obj_id, checkpoint_id, &row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| {
            self.db_insert_one_single_checkpointed_object(table, row.get_row_obj_id(), checkpoint_id, row.get_row_value_ref())
        });
        future::try_join_all(futures).await?;
        Ok(())
    }
    
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(
        &self,
        table: &InMemoryTableIdentifier,
        object_size_without_id: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()> {
        let object_size = object_size_without_id + 8;
        if rows.len() % object_size != 0 {
            anyhow::bail!("Invalid data length for ffs insert");
        }
        let db = self.get_or_create_table(&table.to_string());
        let process_chunk = |chunk: &[u8]| {
            let obj_id = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let value = &chunk[8..];
            let key = key_helpers::key_single_id_checkpointed(obj_id, checkpoint_id);
            db.insert(key, value.to_vec());
        };

        #[cfg(feature = "parallel_rayon")]
        rows.par_chunks_exact(object_size).for_each(process_chunk);

        #[cfg(not(feature = "parallel_rayon"))]
        rows.chunks_exact(object_size).for_each(process_chunk);
        Ok(())
    }
    
    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(
        &self,
        table: &InMemoryTableIdentifier,
        object_size: usize,
        object_id_location: usize,
        checkpoint_id: u64,
        rows: &[u8],
    ) -> anyhow::Result<()> {
        if rows.len() % object_size != 0 {
            anyhow::bail!("Invalid data length for ffs insert");
        }
        let db = self.get_or_create_table(&table.to_string());
        #[cfg(feature = "parallel_rayon")]
        rows.par_chunks_exact(object_size).for_each(|chunk| {
            let obj_id = u64::from_le_bytes(chunk[object_id_location..object_id_location+8].try_into().unwrap());
            let key = key_helpers::key_single_id_checkpointed(obj_id, checkpoint_id);
            db.insert(key, chunk.to_vec());
        });
        #[cfg(not(feature = "parallel_rayon"))]
        rows.chunks_exact(object_size).for_each(|chunk| {
            let obj_id = u64::from_le_bytes(chunk[object_id_location..object_id_location+8].try_into().unwrap());
            let key = key_helpers::key_single_id_checkpointed(obj_id, checkpoint_id);
            db.insert(key, chunk.to_vec());
        });
        Ok(())
    }
}

// --- Double ID Checkpointed Object Store ---

#[async_trait]
impl<Hash, Hasher> CoreDatabaseDoubleIdCheckpointedReader<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_one_double_checkpointed_object_value<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_double_id_checkpointed(obj_id, secondary_id, 0);
        let end_key = key_helpers::key_double_id_checkpointed(obj_id, secondary_id, max_checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            Ok(Some(V::psy_ser_from_slice(e.value())?))
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_double_id_checkpointed(obj_id, secondary_id, 0);
        let end_key = key_helpers::key_double_id_checkpointed(obj_id, secondary_id, max_checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();

        if let Some(e) = entry {
            let key_bytes = e.key();
            let checkpoint_id = u64::from_be_bytes(key_bytes[16..24].try_into()?);
            let value = V::psy_ser_from_slice(e.value())?;
            Ok(Some(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id, value }))
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<R>> {
        self.db_select_one_double_checkpointed_object_value_and_ids(table, obj_id, secondary_id, max_checkpoint_id)
            .await?
            .map(|row| Ok(R::create_from_double_row(row.obj_id, row.secondary_id, row.checkpoint_id, row.value)))
            .transpose()
    }

    async fn db_select_all_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let db = self.get_or_create_table(&table.to_string());
        db.iter()
            .map(|entry| {
                let key_bytes = entry.key();
                let obj_id = u64::from_be_bytes(key_bytes[0..8].try_into()?);
                let secondary_id = u64::from_be_bytes(key_bytes[8..16].try_into()?);
                let checkpoint_id = u64::from_be_bytes(key_bytes[16..24].try_into()?);
                let value = V::psy_ser_from_slice(entry.value())?;
                Ok(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id, value })
            })
            .collect()
    }

    async fn db_select_many_double_checkpointed_object_values<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let futures = obj_ids.iter().map(|key| self.db_select_one_double_checkpointed_object_value(table, key.obj_id, key.secondary_id, max_checkpoint_id));
        future::try_join_all(futures).await
    }

    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<R>> {
        let futures = obj_ids.iter().map(|key| self.db_select_one_double_checkpointed_object_value_and_ids_t(table, key.obj_id, key.secondary_id, max_checkpoint_id));
        let results = future::try_join_all(futures).await?;
        Ok(results.into_iter().flatten().collect())
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseDoubleIdCheckpointedWriter<InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_one_double_checkpointed_object<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let key = key_helpers::key_double_id_checkpointed(obj_id, secondary_id, checkpoint_id);
        let val_bytes = value.psy_ser_to_bytes_vec()?;
        db.insert(key, val_bytes);
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> anyhow::Result<()> {
        let futures = rows
            .iter()
            .map(|row| self.db_insert_one_double_checkpointed_object(table, row.obj_id, row.secondary_id, row.checkpoint_id, &row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| {
            self.db_insert_one_double_checkpointed_object(table, row.get_row_obj_id(), row.get_row_secondary_id(), row.get_row_checkpoint_id(), row.get_row_value_ref())
        });
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: PsySerializeCanonicalAsyncSafe>(
        &self,
        table: &InMemoryTableIdentifier,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> anyhow::Result<()> {
        let futures = rows
            .iter()
            .map(|row| self.db_insert_one_double_checkpointed_object(table, row.obj_id, row.secondary_id, checkpoint_id, &row.value));
        future::try_join_all(futures).await?;
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: PsySerializeCanonicalAsyncSafe,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryTableIdentifier,
        checkpoint_id: u64,
        rows: &[R],
    ) -> anyhow::Result<()> {
        let futures = rows.iter().map(|row| {
            self.db_insert_one_double_checkpointed_object(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id, row.get_row_value_ref())
        });
        future::try_join_all(futures).await?;
        Ok(())
    }
}


// --- Merkle Tree Stores ---

#[async_trait]
impl<Hash, Hasher> CoreDatabaseZeroIdMerkleReader<Hash, Hasher, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &InMemoryTableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_merkle_zero_id(key, 0);
        let end_key = key_helpers::key_merkle_zero_id(key, max_checkpoint_id);


        assert_ne!(table.tree_height, 0, "Tree height cannot be zero for table {}", table.to_string());
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            Ok(Hash::from_bytes(e.value())?)
        } else {
            Ok(Hasher::get_zero_hash((table.tree_height - key.level) as usize))
        }
    }

    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &InMemoryTableIdentifier,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let futures = keys.iter().map(|key| self.db_select_zero_id_merkle_node_max_checkpoint(table, max_checkpoint_id, key));
        future::try_join_all(futures).await
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn db_insert_zero_id_merkle_node( &self, table: &InMemoryTableIdentifier, checkpoint_id: u64, key: &SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_merkle_zero_id(key, checkpoint_id);
        db.insert(db_key, value.to_bytes()?);
        Ok(())
    }
    async fn db_set_zero_id_merkle_nodes_batch(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()> {
        let futures = nodes.iter().map(|node| self.db_insert_zero_id_merkle_node(table, checkpoint_id, &node.key, &node.value));
        future::try_join_all(futures).await?;
        Ok(())
    }
    async fn db_set_zero_id_merkle_nodes_from_fast_serialized(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());

        #[cfg(feature = "parallel_rayon")]
        nodes.par_chunks_exact(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE).for_each(|chunk| {
            let (level, index, _cp, value_bytes) = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_zero_id(&key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });
        #[cfg(not(feature = "parallel_rayon"))]
        nodes.chunks_exact(QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE).for_each(|chunk| {
            let (level, index, _cp, value_bytes) = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_zero_id(&key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });
        Ok(())
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseSingleIdMerkleReader<Hash, Hasher, InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_select_single_id_merkle_node_max_checkpoint(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_merkle_single_id(tree_id, &key, 0);
        let end_key = key_helpers::key_merkle_single_id(tree_id, &key, checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            Ok(Hash::from_bytes(e.value())?)
        } else {
            Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
        }
    }
    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(&self, table: &InMemoryTableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        let futures = keys.iter().map(|&key| self.db_select_single_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, key));
        future::try_join_all(futures).await
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_insert_single_id_merkle_node(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_merkle_single_id(tree_id, &key, checkpoint_id);
        db.insert(db_key, value.to_bytes()?);
        Ok(())
    }
    async fn db_set_single_id_merkle_nodes_batch(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()> {
        let futures = nodes.iter().map(|node| self.db_insert_single_id_merkle_node(table, checkpoint_id, tree_id, node.key, &node.value));
        future::try_join_all(futures).await?;
        Ok(())
    }
    async fn db_set_single_id_merkle_nodes_from_fast_serialized(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        
        #[cfg(feature = "parallel_rayon")]
        nodes.par_chunks_exact(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE).for_each(|chunk| {
            let (tree_id, level, index, _cp, value_bytes) = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_single_id(tree_id as u64, &key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });

        #[cfg(not(feature = "parallel_rayon"))]
        nodes.chunks_exact(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE).for_each(|chunk| {
            let (tree_id, level, index, _cp, value_bytes) = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_single_id(tree_id as u64, &key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });

        Ok(())
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_select_double_id_merkle_node_max_checkpoint(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        let db = self.get_or_create_table(&table.to_string());
        let start_key = key_helpers::key_merkle_double_id(tree_id, tree_sub_id, &key, 0);
        let end_key = key_helpers::key_merkle_double_id(tree_id, tree_sub_id, &key, checkpoint_id);
        
        let entry = db.range(start_key..=end_key).next_back();
        if let Some(e) = entry {
            Ok(Hash::from_bytes(e.value())?)
        } else {
            Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
        }
    }
    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(&self, table: &InMemoryTableIdentifier, max_checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        let futures = keys.iter().map(|&key| self.db_select_double_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, key));
        future::try_join_all(futures).await
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, InMemoryTableIdentifier> for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_insert_double_id_merkle_node(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, key: SimpleMerkleNodeKey, value: &Hash) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_merkle_double_id(tree_id, tree_sub_id, &key, checkpoint_id);
        db.insert(db_key, value.to_bytes()?);
        Ok(())
    }
    async fn db_set_double_id_merkle_nodes_batch(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()> {
        let futures = nodes.iter().map(|node| self.db_insert_double_id_merkle_node(table, checkpoint_id, tree_id, tree_sub_id, node.key, &node.value));
        future::try_join_all(futures).await?;
        Ok(())
    }
    async fn db_set_double_id_merkle_nodes_from_fast_serialized(&self, table: &InMemoryTableIdentifier, checkpoint_id: u64, nodes: &[u8]) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());

        #[cfg(feature = "parallel_rayon")]
        nodes.par_chunks_exact(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE).for_each(|chunk| {
            let (tree_id, tree_sub_id, level, index, _cp, value_bytes) = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_double_id(tree_id as u64, tree_sub_id as u64, &key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });
        #[cfg(not(feature = "parallel_rayon"))]
        nodes.chunks_exact(QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE).for_each(|chunk| {
            let (tree_id, tree_sub_id, level, index, _cp, value_bytes) = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_signed_insert_tuple::<Hash>(chunk, checkpoint_id as i64);
            let key = SimpleMerkleNodeKey { level: level as u8, index: index as u64 };
            let value = Hash::from_owned_32bytes(value_bytes);
            let db_key = key_helpers::key_merkle_double_id(tree_id as u64, tree_sub_id as u64, &key, checkpoint_id);
            db.insert(db_key, value.to_bytes().unwrap());
        });
        Ok(())
    }
}

// --- Tag Tree Store ---
#[async_trait]
impl<Hash, Hasher> CoreDatabaseTagTreeReader<Hash, Hasher, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_tag_tree(unique_pending_id, key);
        Ok(db
            .get(&db_key)
            .map(|entry| TagTreeStorageNode::<Hash>::psy_ser_from_slice(entry.value()).map(|node| node.value))
            .transpose()?)
    }

    async fn db_get_tag_tree_node_values(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let futures = keys.iter().map(|key| self.db_get_tag_tree_node_value(table, unique_pending_id, key));
        future::try_join_all(futures).await
    }

    async fn db_get_tag_tree_node_tag(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
         let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_tag_tree(unique_pending_id, key);
        Ok(db
            .get(&db_key)
            .map(|entry| TagTreeStorageNode::<Hash>::psy_ser_from_slice(entry.value()).map(|node| node.tag))
            .transpose()?)
    }
    
    async fn db_get_tag_tree_node_tags(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let futures = keys.iter().map(|key| self.db_get_tag_tree_node_tag(table, unique_pending_id, key));
        future::try_join_all(futures).await

    }

    async fn db_get_tag_tree_root(&self, table: &InMemoryTableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        self.db_get_tag_tree_node_value(table, unique_pending_id, &SimpleMerkleNodeKey::new_root()).await
    }

    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let root = self.db_get_tag_tree_root(table, unique_pending_id).await?.unwrap_or_default();

        let left = self.db_get_tag_tree_node_value(table, unique_pending_id, &key.left_child()).await?.unwrap_or_default();
        let right = self.db_get_tag_tree_node_value(table, unique_pending_id, &key.right_child()).await?.unwrap_or_default();
        let tag = self.db_get_tag_tree_node_tag(table, unique_pending_id, key).await?.unwrap_or_default();

        let leaf = TagTreeNodePreimage { left, right, tag };

        let mut siblings = Vec::new();
        let mut current_key = *key;
        while current_key.level > 0 {
            let sibling_key = current_key.sibling();
            let parent_key = current_key.parent();

            let sibling_value = self.db_get_tag_tree_node_value(table, unique_pending_id, &sibling_key).await?.unwrap_or_default();
            let parent_tag_value = self.db_get_tag_tree_node_tag(table, unique_pending_id, &parent_key).await?.unwrap_or_default();
            
            siblings.push(TagTreeProofNode {
                sibling: sibling_value,
                parent_tag: parent_tag_value,
            });
            current_key = parent_key;
        }

        Ok(TagTreeMerkleProof {
            index: key.index,
            leaf,
            root,
            siblings,
        })
    }
}

#[async_trait]
impl<Hash, Hasher> CoreDatabaseTagTreeWriter<Hash, Hasher, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_set_tag_tree_tag_value(
        &self,
        table: &InMemoryTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        let db = self.get_or_create_table(&table.to_string());
        let db_key = key_helpers::key_tag_tree(unique_pending_id, key);
        let node = TagTreeStorageNode { value: *value, tag: *tag };
        let val_bytes = node.psy_ser_to_bytes_vec()?;
        db.insert(db_key, val_bytes);
        Ok(())
    }

    async fn db_set_tag_tree_tag(&self, table: &InMemoryTableIdentifier, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &Hash) -> anyhow::Result<()> {
        let left = self.db_get_tag_tree_node_value(table, unique_pending_id, &key.left_child()).await?.unwrap_or_default();
        let right = self.db_get_tag_tree_node_value(table, unique_pending_id, &key.right_child()).await?.unwrap_or_default();
        let value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, tag);
        self.db_set_tag_tree_tag_value(table, unique_pending_id, key, tag, &value).await
    }

    async fn db_set_tag_tree_tag_known_height(&self, table: &InMemoryTableIdentifier, unique_pending_id: u64, _tag_tree_height: u8, key: &SimpleMerkleNodeKey, tag: &Hash) -> anyhow::Result<()> {
        // Height is not needed for this implementation, just call the base method
        self.db_set_tag_tree_tag(table, unique_pending_id, key, tag).await
    }
}


#[async_trait]
impl<Hash, Hasher> CoreDatabaseHashToManyIdsWriter<Hash, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_insert_one_hash_to_u64(&self, table: &InMemoryTableIdentifier, hash_id: Hash, value: u64) -> anyhow::Result<()>{
        let db = self.get_or_create_table(&table.to_string());
        let key = key_helpers::key_hash_to_u64(&hash_id, value)?;
        // Value is an empty vec, as we only store the composite key (Hash, u64)
        db.insert(key, Vec::new()); 
        Ok(())
    }

    async fn db_insert_many_hash_to_u64s(&self, table: &InMemoryTableIdentifier, rows: &[(Hash, u64)]) -> anyhow::Result<()>{
        let db = self.get_or_create_table(&table.to_string());
        
        let results: anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> = rows
            .iter()
            .map(|(hash_id, value)| {
                let key = key_helpers::key_hash_to_u64(hash_id, *value)?;
                Ok((key, Vec::new()))
            })
            .collect();

        for (key, val) in results? {
            db.insert(key, val);
        }
        Ok(())
    }

    async fn db_set_hash_256_to_u64_pairs_from_fast_serialized_data(
        &self,
        table: &InMemoryTableIdentifier,
        data: &[u8],
    ) -> anyhow::Result<()>{
        // Based on Scylla implementation, the input format is: [Hash (32 bytes), u64 (8 bytes)] repeating.
        // Total size per entry: 40 bytes. Hash is 32 bytes.
        const ENTRY_SIZE: usize = 40;
        const HASH_SIZE: usize = 32;

        if data.len() % ENTRY_SIZE != 0 {
            anyhow::bail!("Invalid data length for fast serialized hash-to-u64 pairs: expected multiple of 40, got {}", data.len());
        }

        let db = self.get_or_create_table(&table.to_string());
        let empty_val = Vec::new();
        
        let process_chunk = |chunk: &[u8]| -> anyhow::Result<()> {
            // Hash bytes are chunk[0..32]
            // u64 bytes are chunk[32..40] (Little Endian in the FFS struct definition, but Scylla binds BLOB (Hash) and BIGINT (u64) separately)
            
            // Note on Endianness: The Scylla `read_hash256_refs_and_i64s_from_buffer` uses LE for i64/u64.
            // However, for the key sort order in SkipMap, we must use BE for the u64 component.
            // Since this is InMemoryCoreStore, we must reconstruct the BE key manually.

            let hash_bytes = &chunk[0..HASH_SIZE];
            let value_le_bytes: [u8; 8] = chunk[HASH_SIZE..ENTRY_SIZE].try_into()?;
            let value_u64 = u64::from_le_bytes(value_le_bytes);

            // Construct the BE key for SkipMap sorting: Hash || u64_BE
            let mut key = Vec::with_capacity(HASH_SIZE + 8);
            key.extend_from_slice(hash_bytes);
            key.extend_from_slice(&value_u64.to_be_bytes()); 

            db.insert(key, empty_val.clone());
            Ok(())
        };

        #[cfg(feature = "parallel_rayon")]
        {
            use rayon::prelude::*;
            let results: Vec<anyhow::Result<()>> = data.par_chunks_exact(ENTRY_SIZE).map(process_chunk).collect();
            results.into_iter().collect::<anyhow::Result<Vec<()>>>()?;
        }

        #[cfg(not(feature = "parallel_rayon"))]
        {
            for chunk in data.chunks_exact(ENTRY_SIZE) {
                process_chunk(chunk)?;
            }
        }
        
        Ok(())
    }
}


#[async_trait]
impl<Hash, Hasher> CoreDatabaseHashToManyIdsReader<Hash, InMemoryTableIdentifier>
    for InMemoryCoreStore<Hash, Hasher>
where
    Hash: QDBHashBase,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync 
{
    async fn db_select_value_u64_ids_for_hash(
        &self,
        table: &InMemoryTableIdentifier,
        hash: Hash,
        count: usize,
        start_u64_value: u64, // The ID to start the query from (inclusive)
    ) -> anyhow::Result<Vec<u64>> {
        let db = self.get_or_create_table(&table.to_string());

        // 1. Determine the start key for the range query
        let start_key = key_helpers::key_hash_to_u64(&hash, start_u64_value)?;
        
        // 2. Determine the end boundary key (exclusive)
        // This is the hash immediately following the target hash.
        // We assume Hash has a fixed size (e.g., 32 bytes).
        let hash_bytes = hash.to_bytes()?;
        let hash_len = hash_bytes.len();

        //let mut next_hash_bytes = hash_bytes.clone();
        
        // Increment the hash bytes. This is complex and error-prone for arbitrary Hash types.
        // A safer approach for fixed-size hash (like Hash256) is to increment the last byte
        // and handle overflow, or simply construct a key that is guaranteed to be lexicographically
        // greater than any key starting with `hash`.
        
        // Since we are iterating over a SkipMap, we can simply define the range start.
        // The iteration naturally stops when the first `hash_id` component changes.
        
        let mut results = Vec::with_capacity(count.min(100)); // Pre-allocate

        // Use `SkipMap::range(start_key..)` and manually check the hash prefix
        let iterator = db.range(start_key..);
        
        for entry in iterator.take(count) {
            let key = entry.key();

            // Check if the hash prefix still matches the target hash
            if key.len() < hash_len || &key[0..hash_len] != hash_bytes.as_slice() {
                // We've moved past the target hash or the key is malformed
                break;
            }

            // Extract the u64 value
            let u64_value = key_helpers::extract_u64_from_hash_to_u64_key(key)?;
            results.push(u64_value);
        }

        Ok(results)
    }
}