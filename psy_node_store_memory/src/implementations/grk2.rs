use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use parth_core::crypto::hash::tag_tree::{TagTreeNodePreimage, TagTreeProofNode};
use std::collections::BTreeMap;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use serde::{de::DeserializeOwned, Serialize};
use bincode::{serialize, deserialize};
use anyhow::{Result, bail};
use parth_core::{
    crypto::hash::{tag_tree::TagTreeMerkleProof, traits::{MerkleZeroHasher, MerkleHasher}},
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, CoreDatabaseValueDeserialize, QDatabasePrimitiveKey},
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

use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter, CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter, CoreDatabaseDoubleIdCheckpointedReader, CoreDatabaseDoubleIdCheckpointedStore, CoreDatabaseDoubleIdCheckpointedWriter, CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseKivReader, CoreDatabaseKivWriter, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdCheckpointedStore, CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseStore, CoreDatabaseTagTreeReader, CoreDatabaseTagTreeStore, CoreDatabaseTagTreeWriter, CoreDatabaseU64Reader, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter
};

#[derive(Clone)]
pub struct InMemoryCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    bi_dir_tables: Arc<DashMap<String, BiDirInner>>,
    bi_u64_u128_tables: Arc<DashMap<String, BiU64U128Inner>>,
    u64_tables: Arc<DashMap<String, U64Inner>>,
    single_checkpoint_tables: Arc<DashMap<String, SingleCheckpointInner>>,
    double_checkpoint_tables: Arc<DashMap<String, DoubleCheckpointInner>>,
    kiv_tables: Arc<DashMap<String, KivInner>>,
    single_merkle_tables: Arc<DashMap<String, SingleMerkleInner<Hash>>>,
    double_merkle_tables: Arc<DashMap<String, DoubleMerkleInner<Hash>>>,
    zero_merkle_tables: Arc<DashMap<String, ZeroMerkleInner<Hash>>>,
    tag_tree_tables: Arc<DashMap<String, TagTreeInner<Hash>>>,
    _phantom: std::marker::PhantomData<Hasher>,
}

type KeyBytes = Vec<u8>;
type ValueBytes = Vec<u8>;

type BiDirInner = (DashMap<KeyBytes, KeyBytes>, DashMap<KeyBytes, KeyBytes>);

type BiU64U128Inner = (DashMap<u64, u128>, DashMap<u128, u64>);

type U64Inner = DashMap<u64, AtomicU64>;

type SingleCheckpointInner = DashMap<u64, RwLock<BTreeMap<u64, ValueBytes>>>;

type DoubleCheckpointInner = DashMap<QDoubleIdKey, RwLock<BTreeMap<u64, ValueBytes>>>;

type KivInner = DashMap<u64, ValueBytes>;

type SingleMerkleInner<Hash> = DashMap<u64, DashMap<SimpleMerkleNodeKey, Hash>>; // tree_id -> nodes

type DoubleMerkleInner<Hash> = DashMap<(u64, u64), DashMap<SimpleMerkleNodeKey, Hash>>; // (tree_id, sub_id) -> nodes

type ZeroMerkleInner<Hash> = DashMap<SimpleMerkleNodeKey, Hash>;

type TagTreeInner<Hash> = DashMap<u64, DashMap<SimpleMerkleNodeKey, (Hash, Hash)>>; // pending_id -> nodes (value, tag)

impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static> InMemoryCoreStore<Hash, Hasher> {
    pub fn new() -> Self {
        Self {
            bi_dir_tables: Arc::new(DashMap::new()),
            bi_u64_u128_tables: Arc::new(DashMap::new()),
            u64_tables: Arc::new(DashMap::new()),
            single_checkpoint_tables: Arc::new(DashMap::new()),
            double_checkpoint_tables: Arc::new(DashMap::new()),
            kiv_tables: Arc::new(DashMap::new()),
            single_merkle_tables: Arc::new(DashMap::new()),
            double_merkle_tables: Arc::new(DashMap::new()),
            zero_merkle_tables: Arc::new(DashMap::new()),
            tag_tree_tables: Arc::new(DashMap::new()),
            _phantom: std::marker::PhantomData,
        }
    }

    fn get_or_create_bi_dir(&self, name: &str) -> BiDirInner {
        self.bi_dir_tables.entry(name.to_string()).or_insert_with(|| (DashMap::new(), DashMap::new())).clone()
    }

    fn get_or_create_bi_u64_u128(&self, name: &str) -> BiU64U128Inner {
        self.bi_u64_u128_tables.entry(name.to_string()).or_insert_with(|| (DashMap::new(), DashMap::new())).clone()
    }

    fn get_or_create_u64(&self, name: &str) -> U64Inner {
        self.u64_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_single_checkpoint(&self, name: &str) -> SingleCheckpointInner {
        self.single_checkpoint_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_double_checkpoint(&self, name: &str) -> DoubleCheckpointInner {
        self.double_checkpoint_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_kiv(&self, name: &str) -> KivInner {
        self.kiv_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_single_merkle(&self, name: &str) -> SingleMerkleInner<Hash> {
        self.single_merkle_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_double_merkle(&self, name: &str) -> DoubleMerkleInner<Hash> {
        self.double_merkle_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_zero_merkle(&self, name: &str) -> ZeroMerkleInner<Hash> {
        self.zero_merkle_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }

    fn get_or_create_tag_tree(&self, name: &str) -> TagTreeInner<Hash> {
        self.tag_tree_tables.entry(name.to_string()).or_insert_with(DashMap::new).clone()
    }
}

#[derive(Clone)]
pub struct InMemoryBiDirectionalTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryBiU64U128Table {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryU64Table {
    name: String,
}

#[derive(Clone)]
pub struct InMemorySingleCheckpointTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryDoubleCheckpointTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryKivTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemorySingleMerkleTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryDoubleMerkleTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryZeroMerkleTable {
    name: String,
}

#[derive(Clone)]
pub struct InMemoryTagTreeTable {
    name: String,
}

// Implementations

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalMappingReader<InMemoryBiDirectionalTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k1: &K1,
    ) -> Result<Option<K2>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let k1_bytes = k1.to_bytes()?;
        if let Some(v) = inner.0.get(&k1_bytes) {
            K2::from_bytes(&v).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k2: &K2,
    ) -> Result<Option<K1>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let k2_bytes = k2.to_bytes()?;
        if let Some(v) = inner.1.get(&k2_bytes) {
            K1::from_bytes(&v).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn db_select_many_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k1s: &[K1],
    ) -> Result<Vec<Option<K2>>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        k1s.iter().map(|k1| {
            let k1_bytes = k1.to_bytes()?;
            if let Some(v) = inner.0.get(&k1_bytes) {
                K2::from_bytes(&v).map(Some)
            } else {
                Ok(None)
            }
        }).collect()
    }

    async fn db_select_many_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k2s: &[K2],
    ) -> Result<Vec<Option<K1>>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        k2s.iter().map(|k2| {
            let k2_bytes = k2.to_bytes()?;
            if let Some(v) = inner.1.get(&k2_bytes) {
                K1::from_bytes(&v).map(Some)
            } else {
                Ok(None)
            }
        }).collect()
    }

    async fn db_select_many_pairs_by_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k1s: &[K1],
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let mut res = Vec::with_capacity(k1s.len());
        for k1 in k1s {
            let k1_bytes = k1.to_bytes()?;
            if let Some(v) = inner.0.get(&k1_bytes) {
                let k2 = K2::from_bytes(&v)?;
                res.push(BiDirectionalMappingRow { k1: k1.clone(), k2 });
            }
        }
        Ok(res)
    }

    async fn db_select_many_pairs_by_k2<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k2s: &[K2],
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let mut res = Vec::with_capacity(k2s.len());
        for k2 in k2s {
            let k2_bytes = k2.to_bytes()?;
            if let Some(v) = inner.1.get(&k2_bytes) {
                let k1 = K1::from_bytes(&v)?;
                res.push(BiDirectionalMappingRow { k1, k2: k2.clone() });
            }
        }
        Ok(res)
    }

    async fn db_select_all_pairs_from_k1<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        start_k1: Option<K1>,
        max_count: usize,
    ) -> Result<Vec<BiDirectionalMappingRow<K1, K2>>> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let mut res = Vec::new();
        let start_bytes = start_k1.map(|k| k.to_bytes()).transpose()?;
        let mut started = start_bytes.is_none();
        for pair in inner.0.iter() {
            let k1_bytes = pair.key();
            if !started {
                if Some(k1_bytes) == start_bytes.as_ref() {
                    started = true;
                } else {
                    continue;
                }
            }
            let k1 = K1::from_bytes(k1_bytes)?;
            let k2 = K2::from_bytes(pair.value())?;
            res.push(BiDirectionalMappingRow { k1, k2 });
            if res.len() == max_count {
                break;
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalMappingWriter<InMemoryBiDirectionalTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_pair_ref<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k1: &K1,
        k2: &K2,
    ) -> Result<()> {
        let inner = self.get_or_create_bi_dir(&table.name);
        let k1_bytes = k1.to_bytes()?;
        let k2_bytes = k2.to_bytes()?;
        inner.0.insert(k1_bytes.clone(), k2_bytes.clone());
        inner.1.insert(k2_bytes, k1_bytes);
        Ok(())
    }

    async fn db_insert_pair<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        k1: K1,
        k2: K2,
    ) -> Result<()> {
        self.db_insert_pair_ref(table, &k1, &k2).await
    }

    async fn db_insert_pairs<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &InMemoryBiDirectionalTable,
        keys: &[BiDirectionalMappingRow<K1, K2>],
    ) -> Result<()> {
        let inner = self.get_or_create_bi_dir(&table.name);
        for row in keys {
            let k1_bytes = row.k1.to_bytes()?;
            let k2_bytes = row.k2.to_bytes()?;
            inner.0.insert(k1_bytes.clone(), k2_bytes.clone());
            inner.1.insert(k2_bytes, k1_bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalU64U128MappingReader<InMemoryBiU64U128Table> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_u128_value_by_u64(&self, table: &InMemoryBiU64U128Table, key: u64) -> Result<Option<u128>> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        Ok(inner.0.get(&key).map(|v| *v))
    }

    async fn db_select_one_u64_key_by_u128(&self, table: &InMemoryBiU64U128Table, value: u128) -> Result<Option<u64>> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        Ok(inner.1.get(&value).map(|v| *v))
    }

    async fn db_select_many_u128_values_by_u64s(&self, table: &InMemoryBiU64U128Table, keys: &[u64]) -> Result<Vec<Option<u128>>> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        Ok(keys.iter().map(|k| inner.0.get(k).map(|v| *v)).collect())
    }

    async fn db_select_many_u64_keys_by_u128s(&self, table: &InMemoryBiU64U128Table, values: &[u128]) -> Result<Vec<Option<u64>>> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        Ok(values.iter().map(|v| inner.1.get(v).map(|k| *k)).collect())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseBidirectionalU64U128MappingWriter<InMemoryBiU64U128Table> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_u64_u128_mapping_pair(&self, table: &InMemoryBiU64U128Table, k1: u64, k2: u128) -> Result<()> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        inner.0.insert(k1, k2);
        inner.1.insert(k2, k1);
        Ok(())
    }

    async fn db_insert_u64_u128_mapping_pairs(&self, table: &InMemoryBiU64U128Table, keys: &[BiDirectionalMappingRow<u64, u128>]) -> Result<()> {
        let inner = self.get_or_create_bi_u64_u128(&table.name);
        for row in keys {
            inner.0.insert(row.k1, row.k2);
            inner.1.insert(row.k2, row.k1);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseU64Reader<InMemoryU64Table> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_u64_value(&self, table: &InMemoryU64Table, obj_id: u64) -> Result<Option<u64>> {
        let inner = self.get_or_create_u64(&table.name);
        Ok(inner.get(&obj_id).map(|a| a.load(Ordering::Relaxed)))
    }

    async fn db_select_u64_values(&self, table: &InMemoryU64Table, obj_ids: &[u64]) -> Result<Vec<Option<u64>>> {
        let inner = self.get_or_create_u64(&table.name);
        Ok(obj_ids.iter().map(|id| inner.get(id).map(|a| a.load(Ordering::Relaxed))).collect())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseU64Writer<InMemoryU64Table> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_inc_counter(&self, table: &InMemoryU64Table, obj_id: u64, amount: i64) -> Result<u64> {
        let inner = self.get_or_create_u64(&table.name);
        let entry = inner.entry(obj_id).or_insert(AtomicU64::new(0));
        let amount_u64 = amount.abs() as u64;
        if amount > 0 {
            Ok(entry.fetch_add(amount_u64, Ordering::Relaxed) + amount_u64)
        } else {
            Ok(entry.fetch_sub(amount_u64, Ordering::Relaxed) - amount_u64)
        }
    }

    async fn db_set_u64_value(&self, table: &InMemoryU64Table, obj_id: u64, value: u64) -> Result<()> {
        let inner = self.get_or_create_u64(&table.name);
        inner.insert(obj_id, AtomicU64::new(value));
        Ok(())
    }

    async fn db_set_many_u64_values(&self, table: &InMemoryU64Table, rows: &[QPDPair<u64, u64>]) -> Result<()> {
        let inner = self.get_or_create_u64(&table.name);
        for row in rows {
            inner.insert(row.key, AtomicU64::new(row.value));
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdCheckpointedReader<InMemorySingleCheckpointTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<V>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&obj_id) {
            let bt = bt_lock.read();
            if let Some((_, v)) = bt.range(..=max_checkpoint_id).next_back() {
                deserialize(v).map(Some).map_err(Into::into)
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<QDatabaseSingleIdTableRow<V>>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&obj_id) {
            let bt = bt_lock.read();
            if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                let value = deserialize(v)?;
                Ok(Some(QDatabaseSingleIdTableRow { obj_id, checkpoint_id: cp, value }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_single_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<R>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&obj_id) {
            let bt = bt_lock.read();
            if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                let value = deserialize(v)?;
                Ok(Some(R::create_from_single_row(obj_id, cp, value)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_all_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemorySingleCheckpointTable,
    ) -> Result<Vec<QDatabaseSingleIdTableRow<V>>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        let mut res = Vec::new();
        for entry in inner.iter() {
            let obj_id = *entry.key();
            let bt = entry.value().read();
            for (&cp, v) in bt.iter() {
                let value = deserialize(v)?;
                res.push(QDatabaseSingleIdTableRow { obj_id, checkpoint_id: cp, value });
            }
        }
        Ok(res)
    }

    async fn db_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> Result<Vec<Option<V>>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        obj_ids.iter().map(|id| {
            if let Some(bt_lock) = inner.get(id) {
                let bt = bt_lock.read();
                if let Some((_, v)) = bt.range(..=max_checkpoint_id).next_back() {
                    deserialize(v).map(Some)
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }).collect()
    }

    async fn db_select_many_single_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseSingleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> Result<Vec<R>> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        let mut res = Vec::new();
        for id in obj_ids {
            if let Some(bt_lock) = inner.get(id) {
                let bt = bt_lock.read();
                if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                    let value = deserialize(v)?;
                    res.push(R::create_from_single_row(*id, cp, value));
                }
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdCheckpointedWriter<InMemorySingleCheckpointTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_single_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &InMemorySingleCheckpointTable,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> Result<()> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        let v_bytes = serialize(value)?;
        let bt_lock = inner.entry(obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
        let mut bt = bt_lock.write();
        bt.insert(checkpoint_id, v_bytes);
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &InMemorySingleCheckpointTable,
        rows: &[QDatabaseSingleIdTableRow<V>],
    ) -> Result<()> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        for row in rows {
            let v_bytes = serialize(&row.value)?;
            let bt_lock = inner.entry(row.obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(row.checkpoint_id, v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemorySingleCheckpointTable,
        rows: &[R],
    ) -> Result<()> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        for row in rows {
            let v_bytes = serialize(row.get_row_value_ref())?;
            let bt_lock = inner.entry(row.get_row_obj_id()).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(row.get_row_checkpoint_id(), v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &InMemorySingleCheckpointTable,
        checkpoint_id: u64,
        rows: &[QDatabaseSingleIdTableRowNoCheckpointId<V>],
    ) -> Result<()> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        for row in rows {
            let v_bytes = serialize(&row.value)?;
            let bt_lock = inner.entry(row.obj_id).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(checkpoint_id, v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_single_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemorySingleCheckpointTable,
        checkpoint_id: u64,
        rows: &[R],
    ) -> Result<()> {
        let inner = self.get_or_create_single_checkpoint(&table.name);
        for row in rows {
            let v_bytes = serialize(row.get_row_value_ref())?;
            let bt_lock = inner.entry(row.get_row_obj_id()).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(checkpoint_id, v_bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdCheckpointedReader<InMemoryDoubleCheckpointTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_double_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<V>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let inner = self.get_or_create_double_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&key) {
            let bt = bt_lock.read();
            if let Some((_, v)) = bt.range(..=max_checkpoint_id).next_back() {
                deserialize(v).map(Some).map_err(Into::into)
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<QDatabaseDoubleIdTableRow<V>>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let inner = self.get_or_create_double_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&key) {
            let bt = bt_lock.read();
            if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                let value = deserialize(v)?;
                Ok(Some(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id: cp, value }))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_double_checkpointed_object_value_and_ids_t<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> Result<Option<R>> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let inner = self.get_or_create_double_checkpoint(&table.name);
        if let Some(bt_lock) = inner.get(&key) {
            let bt = bt_lock.read();
            if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                let value = deserialize(v)?;
                Ok(Some(R::create_from_double_row(obj_id, secondary_id, cp, value)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn db_select_all_double_checkpointed_object<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
    ) -> Result<Vec<QDatabaseDoubleIdTableRow<V>>> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        let mut res = Vec::new();
        for entry in inner.iter() {
            let key = entry.key();
            let obj_id = key.obj_id;
            let secondary_id = key.secondary_id;
            let bt = entry.value().read();
            for (&cp, v) in bt.iter() {
                let value = deserialize(v)?;
                res.push(QDatabaseDoubleIdTableRow { obj_id, secondary_id, checkpoint_id: cp, value });
            }
        }
        Ok(res)
    }

    async fn db_select_many_double_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> Result<Vec<Option<V>>> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        obj_ids.iter().map(|key| {
            if let Some(bt_lock) = inner.get(key) {
                let bt = bt_lock.read();
                if let Some((_, v)) = bt.range(..=max_checkpoint_id).next_back() {
                    deserialize(v).map(Some)
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }).collect()
    }

    async fn db_select_many_double_checkpointed_object_keys_and_values<
        V: CoreDatabaseValueDeserialize,
        R: QDatabaseDoubleIdTableRowCreatable<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> Result<Vec<R>> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        let mut res = Vec::new();
        for key in obj_ids {
            if let Some(bt_lock) = inner.get(key) {
                let bt = bt_lock.read();
                if let Some((&cp, v)) = bt.range(..=max_checkpoint_id).next_back() {
                    let value = deserialize(v)?;
                    res.push(R::create_from_double_row(key.obj_id, key.secondary_id, cp, value));
                }
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdCheckpointedWriter<InMemoryDoubleCheckpointTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_double_checkpointed_object<V: Serialize + Send + Sync>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> Result<()> {
        let key = QDoubleIdKey { obj_id, secondary_id };
        let inner = self.get_or_create_double_checkpoint(&table.name);
        let v_bytes = serialize(value)?;
        let bt_lock = inner.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
        let mut bt = bt_lock.write();
        bt.insert(checkpoint_id, v_bytes);
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows<V: Serialize + Send + Sync>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        rows: &[QDatabaseDoubleIdTableRow<V>],
    ) -> Result<()> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let v_bytes = serialize(&row.value)?;
            let bt_lock = inner.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(row.checkpoint_id, v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_object_rows_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        rows: &[R],
    ) -> Result<()> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let v_bytes = serialize(row.get_row_value_ref())?;
            let bt_lock = inner.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(row.get_row_checkpoint_id(), v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint<V: Serialize + Send + Sync>(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        checkpoint_id: u64,
        rows: &[QDatabaseDoubleIdTableRowNoCheckpointId<V>],
    ) -> Result<()> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.obj_id, secondary_id: row.secondary_id };
            let v_bytes = serialize(&row.value)?;
            let bt_lock = inner.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(checkpoint_id, v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_double_checkpointed_objects_at_checkpoint_t<
        V: Serialize + DeserializeOwned + Send + Sync,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &InMemoryDoubleCheckpointTable,
        checkpoint_id: u64,
        rows: &[R],
    ) -> Result<()> {
        let inner = self.get_or_create_double_checkpoint(&table.name);
        for row in rows {
            let key = QDoubleIdKey { obj_id: row.get_row_obj_id(), secondary_id: row.get_row_secondary_id() };
            let v_bytes = serialize(row.get_row_value_ref())?;
            let bt_lock = inner.entry(key).or_insert_with(|| RwLock::new(BTreeMap::new()));
            let mut bt = bt_lock.write();
            bt.insert(checkpoint_id, v_bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseKivReader<InMemoryKivTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_one_kiv_value<V: CoreDatabaseValueDeserialize>(&self, table: &InMemoryKivTable, obj_id: u64) -> Result<Option<V>> {
        let inner = self.get_or_create_kiv(&table.name);
        if let Some(v) = inner.get(&obj_id) {
            deserialize(&v).map(Some).map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_kiv_value_and_ids<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryKivTable,
        obj_id: u64,
    ) -> Result<Option<QDatabaseKeyIdValueTableRow<V>>> {
        let inner = self.get_or_create_kiv(&table.name);
        if let Some(v) = inner.get(&obj_id) {
            let value = deserialize(&v)?;
            Ok(Some(QDatabaseKeyIdValueTableRow { obj_id, value }))
        } else {
            Ok(None)
        }
    }

    async fn db_select_one_kiv_value_and_ids_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &InMemoryKivTable,
        obj_id: u64,
    ) -> Result<Option<R>> {
        let inner = self.get_or_create_kiv(&table.name);
        if let Some(v) = inner.get(&obj_id) {
            let value = deserialize(&v)?;
            Ok(Some(R::create_from_key_id_value_row(obj_id, value)))
        } else {
            Ok(None)
        }
    }

    async fn db_select_all_kiv<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryKivTable,
    ) -> Result<Vec<QDatabaseKeyIdValueTableRow<V>>> {
        let inner = self.get_or_create_kiv(&table.name);
        let mut res = Vec::new();
        for entry in inner.iter() {
            let obj_id = *entry.key();
            let value = deserialize(entry.value())?;
            res.push(QDatabaseKeyIdValueTableRow { obj_id, value });
        }
        Ok(res)
    }

    async fn db_select_many_kiv_values<V: CoreDatabaseValueDeserialize>(
        &self,
        table: &InMemoryKivTable,
        obj_ids: &[u64],
    ) -> Result<Vec<Option<V>>> {
        let inner = self.get_or_create_kiv(&table.name);
        obj_ids.iter().map(|id| {
            if let Some(v) = inner.get(id) {
                deserialize(&v).map(Some)
            } else {
                Ok(None)
            }
        }).collect()
    }

    async fn db_select_many_kiv_keys_and_values<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowCreatable<V> + Send + Sync>(
        &self,
        table: &InMemoryKivTable,
        obj_ids: &[u64],
    ) -> Result<Vec<R>> {
        let inner = self.get_or_create_kiv(&table.name);
        let mut res = Vec::new();
        for id in obj_ids {
            if let Some(v) = inner.get(id) {
                let value = deserialize(&v)?;
                res.push(R::create_from_key_id_value_row(*id, value));
            }
        }
        Ok(res)
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseKivWriter<InMemoryKivTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_one_kiv<V: Serialize + Send + Sync>(&self, table: &InMemoryKivTable, obj_id: u64, value: &V) -> Result<()> {
        let inner = self.get_or_create_kiv(&table.name);
        let v_bytes = serialize(value)?;
        inner.insert(obj_id, v_bytes);
        Ok(())
    }

    async fn db_insert_many_kivs<V: Serialize + Send + Sync>(
        &self,
        table: &InMemoryKivTable,
        rows: &[QDatabaseKeyIdValueTableRow<V>],
    ) -> Result<()> {
        let inner = self.get_or_create_kiv(&table.name);
        for row in rows {
            let v_bytes = serialize(&row.value)?;
            inner.insert(row.obj_id, v_bytes);
        }
        Ok(())
    }

    async fn db_insert_many_kivs_t<V: Serialize + DeserializeOwned + Send + Sync, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &InMemoryKivTable,
        rows: &[R],
    ) -> Result<()> {
        let inner = self.get_or_create_kiv(&table.name);
        for row in rows {
            let v_bytes = serialize(row.get_row_value_ref())?;
            inner.insert(row.get_row_obj_id(), v_bytes);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdMerkleReader<Hash, Hasher, InMemorySingleMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &InMemorySingleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let inner = self.get_or_create_single_merkle(&table.name);
        if let Some(nodes) = inner.get(&tree_id) {
            if let Some(h) = nodes.get(&key) {
                Ok(*h)
            } else {
                Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
            }
        } else {
            Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
        }
    }

    async fn db_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &InMemorySingleMerkleTable,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let inner = self.get_or_create_single_merkle(&table.name);
        let nodes_opt = inner.get(&tree_id);
        keys.iter().map(|key| {
            if let Some(nodes) = &nodes_opt {
                if let Some(h) = nodes.get(key) {
                    Ok(*h)
                } else {
                    Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
                }
            } else {
                Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
            }
        }).collect()
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, InMemorySingleMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_single_id_merkle_node(
        &self,
        table: &InMemorySingleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        let inner = self.get_or_create_single_merkle(&table.name);
        let nodes = inner.entry(tree_id).or_insert_with(DashMap::new);
        nodes.insert(key, *value);
        Ok(())
    }

    async fn db_set_single_id_merkle_nodes_batch(
        &self,
        table: &InMemorySingleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> Result<()> {
        let inner = self.get_or_create_single_merkle(&table.name);
        let map = inner.entry(tree_id).or_insert_with(DashMap::new);
        for node in nodes {
            map.insert(node.key, node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, InMemoryDoubleMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &InMemoryDoubleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let inner = self.get_or_create_double_merkle(&table.name);
        let key_tuple = (tree_id, tree_sub_id);
        if let Some(nodes) = inner.get(&key_tuple) {
            if let Some(h) = nodes.get(&key) {
                Ok(*h)
            } else {
                Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
            }
        } else {
            Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
        }
    }

    async fn db_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &InMemoryDoubleMerkleTable,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let inner = self.get_or_create_double_merkle(&table.name);
        let key_tuple = (tree_id, tree_sub_id);
        let nodes_opt = inner.get(&key_tuple);
        keys.iter().map(|key| {
            if let Some(nodes) = &nodes_opt {
                if let Some(h) = nodes.get(key) {
                    Ok(*h)
                } else {
                    Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
                }
            } else {
                Ok(Hasher::get_zero_hash((tree_height - key.level) as usize))
            }
        }).collect()
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, InMemoryDoubleMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_double_id_merkle_node(
        &self,
        table: &InMemoryDoubleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        let inner = self.get_or_create_double_merkle(&table.name);
        let key_tuple = (tree_id, tree_sub_id);
        let nodes = inner.entry(key_tuple).or_insert_with(DashMap::new);
        nodes.insert(key, *value);
        Ok(())
    }

    async fn db_set_double_id_merkle_nodes_batch(
        &self,
        table: &InMemoryDoubleMerkleTable,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: Vec<SimpleMerkleNode<Hash>>,
    ) -> Result<()> {
        let inner = self.get_or_create_double_merkle(&table.name);
        let key_tuple = (tree_id, tree_sub_id);
        let map = inner.entry(key_tuple).or_insert_with(DashMap::new);
        for node in nodes {
            map.insert(node.key, node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseZeroIdMerkleReader<Hash, Hasher, InMemoryZeroMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &InMemoryZeroMerkleTable,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Hash> {
        let inner = self.get_or_create_zero_merkle(&table.name);
        if let Some(h) = inner.get(key) {
            Ok(*h)
        } else {
            bail!("Tree height unknown for zero id, cannot compute zero hash");
        }
    }

    async fn db_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &InMemoryZeroMerkleTable,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Hash>> {
        let inner = self.get_or_create_zero_merkle(&table.name);
        keys.iter().map(|key| {
            if let Some(h) = inner.get(key) {
                Ok(*h)
            } else {
                bail!("Tree height unknown for zero id, cannot compute zero hash");
            }
        }).collect()
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, InMemoryZeroMerkleTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_insert_zero_id_merkle_node(
        &self,
        table: &InMemoryZeroMerkleTable,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        value: &Hash,
    ) -> Result<()> {
        let inner = self.get_or_create_zero_merkle(&table.name);
        inner.insert(*key, *value);
        Ok(())
    }

    async fn db_set_zero_id_merkle_nodes_batch(
        &self,
        table: &InMemoryZeroMerkleTable,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> Result<()> {
        let inner = self.get_or_create_zero_merkle(&table.name);
        for node in nodes {
            inner.insert(node.key, node.value);
        }
        Ok(())
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseTagTreeReader<Hash, Hasher, InMemoryTagTreeTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn db_get_tag_tree_node_value(
        &self,
        table: &InMemoryTagTreeTable,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Option<Hash>> {
        let inner = self.get_or_create_tag_tree(&table.name);
        if let Some(nodes) = inner.get(&unique_pending_id) {
            Ok(nodes.get(key).map(|(v, _)| *v))
        } else {
            Ok(None)
        }
    }

    async fn db_get_tag_tree_node_values(
        &self,
        table: &InMemoryTagTreeTable,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> Result<Vec<Option<Hash>>> {
        let inner = self.get_or_create_tag_tree(&table.name);
        let nodes_opt = inner.get(&unique_pending_id);
        Ok(keys.iter().map(|key| nodes_opt.as_ref().and_then(|nodes| nodes.get(key).map(|(v, _)| *v))).collect())
    }

    async fn db_get_tag_tree_node_tag(
        &self,
        table: &InMemoryTagTreeTable,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<Option<Hash>> {
        let inner = self.get_or_create_tag_tree(&table.name);
        if let Some(nodes) = inner.get(&unique_pending_id) {
            Ok(nodes.get(key).map(|(_, t)| *t))
        } else {
            Ok(None)
        }
    }

    async fn db_get_tag_tree_root(&self, table: &InMemoryTagTreeTable, unique_pending_id: u64) -> Result<Option<Hash>> {
        self.db_get_tag_tree_node_value(table, unique_pending_id, &SimpleMerkleNodeKey::new_root()).await
    }

    async fn db_get_tag_tree_merkle_proof(
        &self,
        table: &InMemoryTagTreeTable,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> Result<TagTreeMerkleProof<Hash>> {
        let inner = self.get_or_create_tag_tree(&table.name);
        let nodes_opt = inner.get(&unique_pending_id);
        if nodes_opt.is_none() {
            bail!("No tag tree for pending_id");
        }
        let nodes = nodes_opt.unwrap();

        let siblings = key.siblings();
        let sibling_values = siblings.iter().map(|s| nodes.get(s).map(|(v, _)| *v).unwrap_or_default()).collect::<Vec<_>>();

        let parents = siblings.iter().map(|s| s.parent()).collect::<Vec<_>>();
        let parent_tags = parents.iter().map(|p| nodes.get(p).map(|(_, t)| *t).unwrap_or_default()).collect::<Vec<_>>();

        let left = key.left_child();
        let right = key.right_child();
        let left_value = nodes.get(&left).map(|(v, _)| *v).unwrap_or_default();
        let right_value = nodes.get(&right).map(|(v, _)| *v).unwrap_or_default();

        let self_pair = nodes.get(key).ok_or(anyhow::anyhow!("Missing self node"))?;
        let tag = self_pair.1;
        let leaf = TagTreeNodePreimage { left: left_value, right: right_value, tag };

        let root_key = SimpleMerkleNodeKey::new_root();
        let root = nodes.get(&root_key).map(|(v, _)| *v).ok_or(anyhow::anyhow!("Missing root"))?;

        let proof_nodes = sibling_values.into_iter().zip(parent_tags).map(|(sib, pt)| TagTreeProofNode { sibling: sib, parent_tag: pt }).collect();

        Ok(TagTreeMerkleProof {
            index: key.index,
            leaf,
            root,
            siblings: proof_nodes,
        })
    }
}

#[async_trait]
impl<Hash: QHashBase + Send + Sync + 'static, Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static>
    CoreDatabaseTagTreeWriter<Hash, Hasher, InMemoryTagTreeTable> for InMemoryCoreStore<Hash, Hasher>
{
    async fn set_tag_tree_tag_value(
        &self,
        table: &InMemoryTagTreeTable,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> Result<()> {
        let inner = self.get_or_create_tag_tree(&table.name);
        let nodes = inner.entry(unique_pending_id).or_insert_with(DashMap::new);
        nodes.insert(*key, (*value, *tag));
        Ok(())
    }

    async fn set_tag_tree_tag(&self, table: &InMemoryTagTreeTable, unique_pending_id: u64, key: &SimpleMerkleNodeKey, tag: &Hash) -> Result<()> {
        let inner = self.get_or_create_tag_tree(&table.name);
        let nodes_opt = inner.get(&unique_pending_id);
        if nodes_opt.is_none() {
            bail!("No tag tree for pending_id");
        }
        let nodes = nodes_opt.unwrap();

        let left_child = key.left_child();
        let right_child = key.right_child();
        let left = nodes.get(&left_child).map(|(v, _)| *v).unwrap_or_default();
        let right = nodes.get(&right_child).map(|(v, _)| *v).unwrap_or_default();

        let value = Hasher::two_to_one(&left, &right);

        nodes.insert(*key, (value, *tag));
        Ok(())
    }
}

// Combined traits
